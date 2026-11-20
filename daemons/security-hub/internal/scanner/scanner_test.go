package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type fakeRunner struct {
	handler func(name string, args ...string) ([]byte, error)
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.handler(name, args...)
}

func TestParseComposeImageRefs_EnvExpansionAndFloatingTags(t *testing.T) {
	root := t.TempDir()

	// 1. services/auth with ${VAR:-default} and .env override
	authDir := filepath.Join(root, "auth")
	_ = os.MkdirAll(authDir, 0755)
	_ = os.WriteFile(filepath.Join(authDir, "compose.yml"), []byte(`services:
  server:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
    container_name: authentik-server
  worker:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
    container_name: authentik-worker
`), 0644)
	_ = os.WriteFile(filepath.Join(authDir, ".env"), []byte("AUTHENTIK_TAG=2026.5.4\n"), 0644)

	refs, err := ParseComposeImageRefs(authDir)
	if err != nil {
		t.Fatalf("ParseComposeImageRefs(auth) failed: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected deduplicated 1 image ref for auth stack, got %d", len(refs))
	}
	if refs[0].ImageRepo != "ghcr.io/goauthentik/server" || refs[0].Tag != "2026.5.4" {
		t.Fatalf("unexpected auth ref: %+v", refs[0])
	}

	// 2. services/llm with ${WEBUI_DOCKER_TAG-main}
	llmDir := filepath.Join(root, "llm")
	_ = os.MkdirAll(llmDir, 0755)
	_ = os.WriteFile(filepath.Join(llmDir, "docker-compose.yml"), []byte(`services:
  open-webui:
    image: ghcr.io/open-webui/open-webui:${WEBUI_DOCKER_TAG-main}
    container_name: open-webui
`), 0644)
	llmRefs, err := ParseComposeImageRefs(llmDir)
	if err != nil || len(llmRefs) != 1 {
		t.Fatalf("ParseComposeImageRefs(llm) failed: %v", err)
	}
	if llmRefs[0].Tag != "main" || !llmRefs[0].Floating {
		t.Fatalf("expected floating tag 'main', got %+v", llmRefs[0])
	}
}

func TestRegistryClient_CheckImageUpdates_PinnedAndLatest(t *testing.T) {
	client := NewRegistryClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u := req.URL.String()
			switch {
			case strings.Contains(u, "token"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"token":"tok"}`)),
					Header:     make(http.Header),
				}, nil
			case strings.HasSuffix(u, "/manifests/latest"):
				h := make(http.Header)
				h.Set("Docker-Content-Digest", "sha256:999999")
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
					Header:     h,
				}, nil
			case strings.Contains(u, "cloudflare/cloudflared/tags/list"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["latest","2026.8.0","2026.10.2","2026.10.1"]}`)),
					Header:     make(http.Header),
				}, nil
			case strings.Contains(u, "library/postgres/tags/list"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["16-alpine","16.4-alpine","16.6-alpine","17.2-alpine","16.6"]}`)),
					Header:     make(http.Header),
				}, nil
			default:
				return &http.Response{
					StatusCode: 404,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			}
		}),
	})

	// 1. Floating latest with differing digest
	latestVer, tags, remDigest, outdated, err := client.CheckImageUpdates(context.Background(), "cloudflare/cloudflared:latest", "sha256:111111")
	if err != nil {
		t.Fatalf("CheckImageUpdates(cloudflared) error: %v", err)
	}
	if !outdated || remDigest != "sha256:999999" || latestVer != "2026.10.2" || len(tags) < 3 {
		t.Fatalf("unexpected cloudflared update result: latest=%s outdated=%v digest=%s tags=%v", latestVer, outdated, remDigest, tags)
	}

	// 2. Flavor-pinned postgres:16.4-alpine -> preserves -alpine suffix
	pgLatest, pgTags, _, pgOutdated, err := client.CheckImageUpdates(context.Background(), "docker.io/library/postgres:16.4-alpine", "sha256:222")
	if err != nil {
		t.Fatalf("CheckImageUpdates(postgres) error: %v", err)
	}
	if !pgOutdated || pgLatest != "16.6-alpine" {
		t.Fatalf("expected 16.6-alpine as same-major latest, got latest=%s outdated=%v tags=%v", pgLatest, pgOutdated, pgTags)
	}
}

func TestBrewScanner_OutdatedAndBrokenLinkage(t *testing.T) {
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case strings.Contains(cmdLine, "brew info --json=v2 --installed"):
				return []byte(`{
					"formulae": [
						{"name":"node@22","full_name":"node@22","versions":{"stable":"22.24.0"},"installed":[{"version":"22.23.2_2"}],"deprecated":false},
						{"name":"openssl@3","full_name":"openssl@3","versions":{"stable":"3.4.0"},"installed":[{"version":"3.3.1"}],"deprecated":false}
					],
					"casks": []
				}`), nil
			case strings.Contains(cmdLine, "brew outdated --json=v2"):
				return []byte(`{
					"formulae": [
						{"name":"node@22","installed_versions":["22.23.2_2"],"current_version":"22.24.0"},
						{"name":"openssl@3","installed_versions":["3.3.1"],"current_version":"3.4.0"}
					],
					"casks": []
				}`), nil
			case strings.Contains(cmdLine, "brew linkage --test node@22"):
				return []byte("Missing libraries:\n  /opt/homebrew/opt/simdjson/lib/libsimdjson.33.dylib\n"), errors.New("exit status 1")
			case strings.Contains(cmdLine, "brew linkage --test openssl@3"):
				return []byte(""), nil
			default:
				return nil, nil
			}
		},
	}

	bs := NewBrewScanner(runner)
	items, err := bs.ScanBrew(context.Background())
	if err != nil {
		t.Fatalf("ScanBrew failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 brew items, got %d", len(items))
	}
	var nodeItem *struct {
		broken  bool
		details string
	}
	for _, it := range items {
		if it.Name == "node@22" {
			nodeItem = &struct {
				broken  bool
				details string
			}{it.BrokenLinkage, it.LinkageDetails}
		}
	}
	if nodeItem == nil || !nodeItem.broken || !strings.Contains(nodeItem.details, "libsimdjson.33.dylib") {
		t.Fatalf("expected node@22 to be flagged with broken linkage libsimdjson.33.dylib, got %+v", nodeItem)
	}
}

func TestVulnScanner_OSVAndTrivyAndEoLAndSecurityOverride(t *testing.T) {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u := req.URL.String()
			switch {
			case strings.Contains(u, "osv.dev"):
				return &http.Response{
					StatusCode: 200,
					Body: io.NopCloser(strings.NewReader(`{
						"results": [
							{
								"vulns": [
									{
										"id": "GHSA-cf-compromise-2026",
										"summary": "Cloudflare tunnel critical compromise",
										"database_specific": {"severity": "CRITICAL"},
										"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2026.10.2"}]}]}]
									}
								]
							},
							{"vulns": []}
						]
					}`)),
					Header: make(http.Header),
				}, nil
			case strings.HasSuffix(u, "/products/postgresql"):
				return &http.Response{
					StatusCode: 200,
					Body: io.NopCloser(strings.NewReader(`{
						"result": {
							"releases": [
								{"name": "16", "eolFrom": "2028-11-09"}
							]
						}
					}`)),
					Header: make(http.Header),
				}, nil
			case strings.HasSuffix(u, "/products/authentik"):
				return &http.Response{
					StatusCode: 200,
					Body: io.NopCloser(strings.NewReader(`{
						"name": "authentik",
						"releases": [
							{"name": "2026.5", "eolFrom": "2026-11-18"}
						]
					}`)),
					Header: make(http.Header),
				}, nil
			default:
				return &http.Response{
					StatusCode: 404,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
					Header:     make(http.Header),
				}, nil
			}
		}),
	}

	items := []models.ManagedItem{
		{
			TargetType:     models.TargetDocker,
			Name:           "cloudflare-tunnel",
			ImageRef:       "cloudflare/cloudflared:2026.8.0",
			CurrentVersion: "2026.8.0",
			LatestVersion:  "2026.10.2",
			Outdated:       true,
		},
		{
			TargetType:     models.TargetDocker,
			Name:           "auth",
			ImageRef:       "ghcr.io/goauthentik/server:2026.5.3",
			CurrentVersion: "2026.5.3",
			LatestVersion:  "2026.5.5",
			Outdated:       true,
		},
	}

	vs := NewVulnScanner("https://api.osv.dev/v1/querybatch", httpClient, nil)
	if err := vs.CheckVulnerabilities(context.Background(), items); err != nil {
		t.Fatalf("CheckVulnerabilities failed: %v", err)
	}
	if items[0].CritCount != 1 || len(items[0].Vulnerabilities) != 1 || items[0].Vulnerabilities[0].FixedVersion != "2026.10.2" {
		t.Fatalf("expected 1 critical CVE on cloudflare-tunnel fixed in 2026.10.2, got %+v", items[0])
	}

	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	ec := NewEoLChecker("https://endoflife.date/api/v1/products", httpClient)
	if err := ec.CheckEoL(context.Background(), items, now, 30); err != nil {
		t.Fatalf("CheckEoL failed: %v", err)
	}
	if items[0].EoL.Status != models.EoLSupported {
		t.Fatalf("expected cloudflared 2026.8.0 to be supported within 1yr window, got %+v", items[0].EoL)
	}
	if items[1].EoL.Status != models.EoLExpiringSoon || items[1].EoL.DaysRemaining != 19 {
		t.Fatalf("expected authentik 2026.5.3 to be expiring_soon with 19 days remaining, got %+v", items[1].EoL)
	}

	// Verify SecurityOverride when a version is skipped but current version has a CRITICAL CVE
	skippedMap := map[string]string{
		"docker:cloudflare-tunnel": "2026.10.2",
		"docker:auth":              "2026.5.5",
	}
	ApplySkippedAndSummarize(items, skippedMap)
	if !items[0].SecurityOverride || items[0].Skipped || !items[0].Outdated {
		t.Fatalf("expected SecurityOverride on cloudflare-tunnel due to CRITICAL CVE, got %+v", items[0])
	}
	if !items[1].Skipped || items[1].Outdated {
		t.Fatalf("expected auth 2026.5.5 (0 CVEs) to be marked Skipped and not Outdated, got %+v", items[1])
	}
}

func TestBrewCasksAndDaemonSoftwareUpdate(t *testing.T) {
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case strings.Contains(cmdLine, "brew info --json=v2 --installed"):
				return []byte(`{
					"formulae": [],
					"casks": [
						{"token":"orbstack","version":"1.8.0","installed":"1.7.0","deprecated":false}
					]
				}`), nil
			case strings.Contains(cmdLine, "brew outdated --json=v2"):
				return []byte(`{
					"formulae": [],
					"casks": [
						{"name":"orbstack","installed_versions":["1.7.0"],"current_version":"1.8.0"}
					]
				}`), nil
			case strings.Contains(cmdLine, "ollama --version"):
				return []byte("ollama version is 0.4.1"), nil
			case strings.Contains(cmdLine, "sw_vers -productVersion"):
				return []byte("15.1\n"), nil
			case strings.Contains(cmdLine, "softwareupdate -l"):
				return []byte("Software Update found the following new or updated software:\n* Label: macOS Sequoia 15.2-24C101\n"), nil
			default:
				return nil, nil
			}
		},
	}

	bs := NewBrewScanner(runner)
	brewItems, err := bs.ScanBrew(context.Background())
	if err != nil || len(brewItems) != 1 || brewItems[0].Name != "orbstack" || !brewItems[0].Outdated {
		t.Fatalf("expected outdated cask orbstack 1.7.0->1.8.0, got err=%v items=%+v", err, brewItems)
	}

	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v0.5.0"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	ds := NewDaemonScannerWithHTTP("..", runner, httpClient)
	dItems, err := ds.ScanDaemonsAndOS(context.Background())
	if err != nil {
		t.Fatalf("ScanDaemonsAndOS failed: %v", err)
	}
	var ollamaOutdated, macOutdated bool
	for _, it := range dItems {
		if it.Name == "ollama" && it.Outdated && it.LatestVersion == "0.5.0" {
			ollamaOutdated = true
		}
		if it.TargetType == models.TargetMacOS && it.Outdated {
			macOutdated = true
		}
	}
	if !ollamaOutdated || !macOutdated {
		t.Fatalf("expected both ollama (0.4.1->0.5.0) and macOS (15.1->15.2) marked outdated, got %+v", dItems)
	}
}

func TestDockerScanner_GracefullyIgnoresStoppedOrMissingDocker(t *testing.T) {
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			if name == "docker" && len(args) > 0 && args[0] == "info" {
				return []byte("Cannot connect to the Docker daemon"), errors.New("exit status 1")
			}
			return nil, nil
		},
	}
	ds := NewDockerScanner(t.TempDir(), nil, nil, runner, nil)
	items, err := ds.ScanDockerServices(context.Background())
	if err != nil || len(items) != 0 {
		t.Fatalf("expected graceful empty slice and nil error when Docker is stopped/uninstalled, got items=%v err=%v", items, err)
	}
}

func TestOrchestrator_ScanMutex(t *testing.T) {
	orch := &Orchestrator{}

	scanning, active := orch.IsScanning()
	if scanning || active != "" {
		t.Fatalf("expected idle orchestrator, got scanning=%v active=%q", scanning, active)
	}

	started, active := orch.StartScan("task-123")
	if !started || active != "" {
		t.Fatalf("expected successful StartScan, got started=%v active=%q", started, active)
	}

	scanning, active = orch.IsScanning()
	if !scanning || active != "task-123" {
		t.Fatalf("expected scanning=true active=task-123, got scanning=%v active=%q", scanning, active)
	}

	// Attempt second scan while active
	started2, active2 := orch.StartScan("task-456")
	if started2 || active2 != "task-123" {
		t.Fatalf("expected second StartScan to fail with active task-123, got started=%v active=%q", started2, active2)
	}

	orch.FinishScan()

	scanning, active = orch.IsScanning()
	if scanning || active != "" {
		t.Fatalf("expected idle orchestrator after FinishScan, got scanning=%v active=%q", scanning, active)
	}

	// Default task ID when taskID == ""
	started3, _ := orch.StartScan("")
	if !started3 || !strings.HasPrefix(orch.activeTaskID, "scan_") {
		t.Fatalf("expected default scan_ task ID, got started=%v activeTaskID=%q", started3, orch.activeTaskID)
	}
	orch.FinishScan()
}

func TestOrchestrator_FetchRemoteAgentScan_TokenFallback(t *testing.T) {
	var receivedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-NAL-Node-Token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node":  "remote-node",
			"items": []models.ManagedItem{},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentToken: "shared-cluster-secret",
	}
	orch := &Orchestrator{
		cfg:        cfg,
		httpClient: srv.Client(),
	}

	// 1. Node without token should fall back to cfg.AgentToken
	_, err := orch.fetchRemoteAgentScan(context.Background(), models.NodeInfo{
		Name: "remote-node",
		URL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("fetchRemoteAgentScan failed: %v", err)
	}
	if receivedToken != "shared-cluster-secret" {
		t.Fatalf("expected fallback token 'shared-cluster-secret', got %q", receivedToken)
	}

	// 2. Node with explicit token should override cfg.AgentToken
	_, err = orch.fetchRemoteAgentScan(context.Background(), models.NodeInfo{
		Name:  "remote-node",
		URL:   srv.URL,
		Token: "node-specific-secret",
	})
	if err != nil {
		t.Fatalf("fetchRemoteAgentScan failed: %v", err)
	}
	if receivedToken != "node-specific-secret" {
		t.Fatalf("expected explicit token 'node-specific-secret', got %q", receivedToken)
	}
}

func TestOrchestrator_RunFullScanWithTask_ContextCancelled(t *testing.T) {
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSpoolStore failed: %v", err)
	}
	task, err := store.CreateTask(context.Background(), &models.Task{
		TaskType:    "scan",
		TriggeredBy: "manual",
	})
	if err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	cfg := &config.Config{}
	orch := &Orchestrator{
		cfg:   cfg,
		store: store,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	res, err := orch.RunFullScanWithTask(ctx, task.ID)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if res != nil {
		t.Fatalf("expected nil result on cancelled context, got %+v", res)
	}

	finishedTask, _, err := store.GetTaskWithLogs(context.Background(), task.ID)
	if err != nil {
		t.Fatalf("GetTaskWithLogs failed: %v", err)
	}
	if finishedTask.Status != "failed" {
		t.Fatalf("expected task status 'failed', got %q", finishedTask.Status)
	}
}

func TestOrchestrator_ScanLocalNode_NilCfg(t *testing.T) {
	orch := &Orchestrator{}
	items, err := orch.ScanLocalNode(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on nil cfg, got: %v", err)
	}
	if items != nil && len(items) != 0 {
		t.Fatalf("expected 0 items on nil scanners, got %d", len(items))
	}
}

func TestAptScanner_OutdatedManualAndBrokenDependencies(t *testing.T) {
	var sawSudoUpdate bool
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case name == "dpkg-query":
				return []byte(strings.Join([]string{
					"openssl\t3.0.11-1~deb12u2\tinstall\tinstalled",
					"nginx\t1.22.1-9\tinstall\tinstalled",
					"dpkg\t1.21.22\tinstall\tinstalled",
					"linux-image-rpi\t6.6.51\thold\tinstalled",
					"libc6:arm64\t2.36-9+deb12u4\tinstall\tinstalled",
					"libc6:armhf\t2.36-9+deb12u4\tinstall\tinstalled",
					"halfpkg\t\tinstall\thalf-configured",
					"libfoo\t1.0-1\tinstall\tinstalled",
					"nodejs\t18.19.0+dfsg-6\tinstall\tinstalled",
					"removedpkg\t0.1\tdeinstall\tconfig-files",
				}, "\n")), nil
			case cmdLine == "apt-get update -qq":
				return []byte("E: Could not open lock file - open (13: Permission denied)"), errors.New("exit status 100")
			case cmdLine == "sudo -n apt-get update -qq":
				sawSudoUpdate = true
				return []byte(""), nil
			case strings.Contains(cmdLine, "apt list --upgradable"):
				return []byte(strings.Join([]string{
					"Listing...",
					"W: Some warning about /etc/apt/sources.list",
					"openssl/stable-security 3.0.14-1~deb12u1 arm64 [upgradable from: 3.0.11-1~deb12u2]",
					"linux-image-rpi/stable 6.6.62 arm64 [upgradable from: 6.6.51]",
					"libc6/stable 2.36-9+deb12u8 armhf [upgradable from: 2.36-9+deb12u4]",
				}, "\n")), nil
			case strings.Contains(cmdLine, "apt-mark showhold"):
				return []byte("linux-image-rpi\n"), nil
			case strings.Contains(cmdLine, "apt-mark showmanual"):
				return []byte("openssl\nnginx\ndpkg\nlinux-image-rpi\nlibc6:arm64\nlibc6:armhf\nnodejs\n"), nil
			case strings.Contains(cmdLine, "dpkg --audit"):
				return []byte("The following packages are in a mess due to serious problems:\n nginx: broken post-installation script\nThey must be configured using dpkg --configure.\n"), nil
			case strings.Contains(cmdLine, "apt-get -o Debug::NoLocking=true check"):
				return []byte("Reading package lists...\nYou might want to run 'apt --fix-broken install' to correct these.\nThe following packages have unmet dependencies:\n nginx : Pre-Depends: libfoo (>= 2.0) but 1.0-1 is installed\n"), errors.New("exit status 100")
			default:
				return nil, nil
			}
		},
	}

	as := NewAptScanner(runner)
	items, err := as.ScanApt(context.Background())
	if err != nil {
		t.Fatalf("ScanApt failed: %v", err)
	}
	if !sawSudoUpdate {
		t.Fatal("expected apt-get update Permission denied to retry via sudo -n apt-get update -qq")
	}
	if len(items) != 8 {
		t.Fatalf("expected 8 apt items (libfoo/removedpkg excluded), got %d: %+v", len(items), items)
	}

	byName := make(map[string]models.ManagedItem)
	for _, it := range items {
		byName[it.Name] = it
	}

	ossl, ok := byName["openssl"]
	if !ok {
		t.Fatal("expected openssl item")
	}
	if ossl.TargetType != models.TargetApt || !ossl.Outdated || ossl.LatestVersion != "3.0.14-1~deb12u1" {
		t.Fatalf("unexpected openssl item: %+v", ossl)
	}
	if ossl.ReleaseNotesURL != "https://tracker.debian.org/pkg/openssl" {
		t.Fatalf("unexpected ReleaseNotesURL: %q", ossl.ReleaseNotesURL)
	}

	// Held package must not offer an outdated one-click upgrade
	heldPkg, ok := byName["linux-image-rpi"]
	if !ok || heldPkg.Outdated || !strings.Contains(heldPkg.EoL.Message, "Held") {
		t.Fatalf("expected held package linux-image-rpi with Outdated=false and Held EoL message, got %+v", heldPkg)
	}

	// Multiarch: libc6:armhf outdated, libc6:arm64 up-to-date, arch stripped on ReleaseNotesURL
	c6Arm64, ok64 := byName["libc6:arm64"]
	c6Armhf, okhf := byName["libc6:armhf"]
	if !ok64 || !okhf || c6Arm64.Outdated || !c6Armhf.Outdated || c6Armhf.LatestVersion != "2.36-9+deb12u8" {
		t.Fatalf("unexpected multiarch libc6 state: arm64=%+v armhf=%+v", c6Arm64, c6Armhf)
	}
	if c6Armhf.ReleaseNotesURL != "https://tracker.debian.org/pkg/libc6" {
		t.Fatalf("expected stripped arch in ReleaseNotesURL, got %q", c6Armhf.ReleaseNotesURL)
	}

	// Unhealthy dpkg status + Pre-Depends check
	halfPkg, ok := byName["halfpkg"]
	if !ok || !halfPkg.BrokenLinkage || !strings.Contains(halfPkg.LinkageDetails, "half-configured") {
		t.Fatalf("expected halfpkg flagged with dpkg status: half-configured, got %+v", halfPkg)
	}

	ngx, ok := byName["nginx"]
	if !ok || !ngx.BrokenLinkage || !strings.Contains(ngx.LinkageDetails, "Pre-Depends:") {
		t.Fatalf("expected nginx to be flagged with Pre-Depends detail, got %+v", ngx)
	}

	dpkgItem, ok := byName["dpkg"]
	if !ok || dpkgItem.BrokenLinkage {
		t.Fatalf("expected dpkg NOT to be falsely flagged by header prose in dpkg --audit, got %+v", dpkgItem)
	}

	if _, hasLib := byName["libfoo"]; hasLib {
		t.Fatal("expected auto-installed non-upgradable libfoo to be excluded (not falsely matched by Pre-Depends check)")
	}

	// Verify fallback to `apt-get -s -o Debug::NoLocking=true upgrade` when `apt list --upgradable` fails,
	// AND fallback to all packages when `apt-mark showmanual` fails.
	simRunner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case name == "dpkg-query":
				return []byte("openssl\t3.0.11-1~deb12u2\tinstalled\nlibbar\t1.0\tinstalled\n"), nil
			case strings.Contains(cmdLine, "apt list --upgradable"):
				return nil, errors.New("apt wrapper unavailable")
			case strings.Contains(cmdLine, "apt-get -s -o Debug::NoLocking=true upgrade"):
				return []byte("Reading package lists...\nInst openssl [3.0.11-1~deb12u2] (3.0.14-1~deb12u1 Debian-Security:12/bookworm-security [arm64])\n"), nil
			case strings.Contains(cmdLine, "apt-mark showmanual"):
				return nil, errors.New("apt-mark unavailable")
			default:
				return nil, nil
			}
		},
	}
	simItems, err := NewAptScanner(simRunner).ScanApt(context.Background())
	if err != nil || len(simItems) != 2 || !simItems[0].Outdated || simItems[0].LatestVersion != "3.0.14-1~deb12u1" {
		t.Fatalf("expected apt-get -s upgrade & showmanual failure fallback, got err=%v items=%+v", err, simItems)
	}

	// Verify OSV & EoL mapping with Debian epoch + arch suffix
	eco, osvPkg, cleanVer, osvOK := mapItemToOSVPackage(models.ManagedItem{
		TargetType:     models.TargetApt,
		Name:           "matter-hub:armhf",
		CurrentVersion: "1:2.0.57-1~deb12u1",
	})
	if !osvOK || eco != "npm" || osvPkg != "home-assistant-matter-hub" || cleanVer != "2.0.57" {
		t.Fatalf("unexpected OSV mapping for Debian epoch/arch: eco=%q pkg=%q ver=%q ok=%v", eco, osvPkg, cleanVer, osvOK)
	}

	// Verify Debian epoch & suffix stripping in EoL mapping
	prod, cycle := mapItemToEoLProductAndCycle(models.ManagedItem{
		TargetType:     models.TargetApt,
		Name:           "openssl",
		CurrentVersion: "1:3.0.11-1~deb12u2",
	})
	if prod != "openssl" || cycle != "3.0" {
		t.Fatalf("expected openssl cycle 3.0 from Debian epoch version, got (%q, %q)", prod, cycle)
	}
	nProd, nCycle := mapItemToEoLProductAndCycle(models.ManagedItem{
		TargetType:     models.TargetApt,
		Name:           "nodejs",
		CurrentVersion: "18.19.0+dfsg-6",
	})
	if nProd != "nodejs" || nCycle != "18" {
		t.Fatalf("expected nodejs cycle 18, got (%q, %q)", nProd, nCycle)
	}

	// Verify graceful no-op on non-Debian hosts (e.g. macOS without dpkg-query)
	noAptRunner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			if name == "dpkg-query" {
				return nil, errors.New("executable file not found")
			}
			return nil, nil
		},
	}
	noItems, err := NewAptScanner(noAptRunner).ScanApt(context.Background())
	if err != nil || len(noItems) != 0 {
		t.Fatalf("expected nil, nil when dpkg-query is absent, got items=%v err=%v", noItems, err)
	}
}

func TestScanner_HardeningChecks(t *testing.T) {
	ctx := context.Background()

	// 1. cleanUpstreamVersion strips epoch before leading v
	if got := cleanUpstreamVersion("1:v2.0.1-1~deb12u1"); got != "2.0.1" {
		t.Fatalf("expected '2.0.1' from epoch+v version, got %q", got)
	}

	// 2. Live OSV querybatch minimal items hydrate from /v1/vulns/{id} preserving CRITICAL severity & FixedVersion
	osvClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/v1/querybatch":
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"results":[{"vulns":[{"id":"GHSA-crit-999","modified":"2026-11-01T00:00:00Z"}]}]}`)),
					Header:     make(http.Header),
				}, nil
			case "/v1/vulns/GHSA-crit-999":
				return &http.Response{
					StatusCode: 200,
					Body: io.NopCloser(strings.NewReader(`{
						"id":"GHSA-crit-999",
						"summary":"Hydrated Critical Bug",
						"database_specific":{"severity":"CRITICAL"},
						"affected":[{"ranges":[{"events":[{"fixed":"2026.11.0"}]}]}]
					}`)),
					Header: make(http.Header),
				}, nil
			default:
				return &http.Response{StatusCode: 404, Body: http.NoBody, Header: make(http.Header)}, nil
			}
		}),
	}
	vs := NewVulnScanner("https://api.osv.dev/v1/querybatch", osvClient, nil)
	vItems := []models.ManagedItem{
		{TargetType: models.TargetDocker, Name: "cloudflare-tunnel", ImageRef: "cloudflare/cloudflared:2026.8.0", CurrentVersion: "2026.8.0"},
	}
	_ = vs.CheckVulnerabilities(ctx, vItems)
	if vItems[0].CritCount != 1 || len(vItems[0].Vulnerabilities) != 1 || vItems[0].Vulnerabilities[0].FixedVersion != "2026.11.0" {
		t.Fatalf("expected hydrated CRITICAL CVE with fixed version 2026.11.0, got %+v", vItems[0])
	}

	// 3. EoLChecker sets EoLUnknown on API outage / unmapped, truncates cloudflared UTC midnight, preserves Apt held notice
	failEoLClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 503, Body: http.NoBody, Header: make(http.Header)}, nil
		}),
	}
	ec := NewEoLChecker("https://endoflife.date/api/v1/products", failEoLClient)
	eolItems := []models.ManagedItem{
		{TargetType: models.TargetDocker, Name: "unmapped-svc", CurrentVersion: "1.0.0"},
		{TargetType: models.TargetApt, Name: "openssl", CurrentVersion: "3.0.11", EoL: models.EoLInfo{Status: models.EoLSupported, Message: "Held via apt-mark (pinned)"}},
		{TargetType: models.TargetDocker, Name: "cloudflare-tunnel", CurrentVersion: "2025.11.0"},
	}
	nowLate := time.Date(2026, 11, 14, 23, 30, 0, 0, time.UTC) // eol is 2026-11-15 -> should be 1 day remaining!
	_ = ec.CheckEoL(ctx, eolItems, nowLate, 30)
	if eolItems[0].EoL.Status != models.EoLUnknown {
		t.Fatalf("expected EoLUnknown for unmapped product, got %+v", eolItems[0].EoL)
	}
	if eolItems[1].EoL.Status != models.EoLUnknown || !strings.Contains(eolItems[1].EoL.Message, "Held via apt-mark") {
		t.Fatalf("expected EoLUnknown preserving Held notice on API 503, got %+v", eolItems[1].EoL)
	}
	if eolItems[2].EoL.DaysRemaining != 1 {
		t.Fatalf("expected cloudflared UTC midnight diff = 1 day remaining, got %d", eolItems[2].EoL.DaysRemaining)
	}

	// 4. DaemonScanner skips ollama when runner nil, skips server-monitor when dir missing, skips macOS on sw_vers error
	linuxRunner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			return nil, errors.New("command not found")
		},
	}
	if items, _ := NewDaemonScanner(t.TempDir(), nil).ScanDaemonsAndOS(ctx); len(items) != 0 {
		t.Fatalf("expected 0 daemon items when runner is nil and server-monitor missing, got %+v", items)
	}
	if items, _ := NewDaemonScanner(t.TempDir(), linuxRunner).ScanDaemonsAndOS(ctx); len(items) != 0 {
		t.Fatalf("expected 0 daemon/macOS items when sw_vers/ollama/server-monitor absent, got %+v", items)
	}

	// 5. RegistryClient supports generic hosts (quay.io), Link pagination, non-semver safety, and error propagation
	regClient := NewRegistryClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u := req.URL.String()
			switch {
			case strings.Contains(u, "quay.io/v2/org/app/tags/list") && strings.Contains(u, "page=2"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["1.2.0","bookworm"]}`)),
					Header:     make(http.Header),
				}, nil
			case strings.Contains(u, "quay.io/v2/org/app/tags/list"):
				h := make(http.Header)
				h.Set("Link", `</v2/org/app/tags/list?page=2>; rel="next"`)
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["1.0.0"]}`)),
					Header:     h,
				}, nil
			default:
				return &http.Response{StatusCode: 500, Body: http.NoBody, Header: make(http.Header)}, nil
			}
		}),
	})
	latest, _, _, outdated, err := regClient.CheckImageUpdates(ctx, "quay.io/org/app:1.0.0", "")
	if err != nil || !outdated || latest != "1.2.0" {
		t.Fatalf("expected quay.io paginated upgrade 1.0.0->1.2.0, got latest=%q outdated=%v err=%v", latest, outdated, err)
	}
	_, _, _, flavorOutdated, _ := regClient.CheckImageUpdates(ctx, "quay.io/org/app:bookworm", "")
	if flavorOutdated {
		t.Fatal("expected non-semver flavor tag bookworm not to be flagged outdated")
	}
	if _, _, _, _, err := regClient.CheckImageUpdates(ctx, "quay.io/missing/app:1.0.0", ""); err == nil {
		t.Fatal("expected registry HTTP 500 to propagate error when digest & tags both failed")
	}

	// 6. BrewScanner does not flag pinned formula outdated
	pinnedBrew := NewBrewScanner(&fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "info" {
				return []byte(`{"formulae":[{"name":"node","versions":{"stable":"22.0.0"},"installed":[{"version":"20.0.0"}],"pinned":true}],"casks":[]}`), nil
			}
			if len(args) > 0 && args[0] == "outdated" {
				return nil, errors.New("exit 1")
			}
			return []byte(""), nil
		},
	})
	brewItems, _ := pinnedBrew.ScanBrew(ctx)
	if len(brewItems) != 1 || brewItems[0].Outdated {
		t.Fatalf("expected pinned brew formula not marked Outdated, got %+v", brewItems)
	}

	// 7. ApplySkippedAndSummarize restores unskipped item to Outdated=true
	unskipped := []models.ManagedItem{
		{TargetType: models.TargetDocker, Name: "auth", CurrentVersion: "1.0", LatestVersion: "2.0", Skipped: true, SkippedVersion: "2.0", Outdated: false},
	}
	res := ApplySkippedAndSummarize(unskipped, map[string]string{})
	if res.Items[0].Skipped || !res.Items[0].Outdated || res.Items[0].SkippedVersion != "" {
		t.Fatalf("expected unskipped item restored to Skipped=false Outdated=true, got %+v", res.Items[0])
	}

	// 8. Orchestrator.fetchRemoteAgentScan blocks redirects
	redirected := false
	redirTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
	}))
	defer redirTarget.Close()
	redirAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer redirAgent.Close()
	orch := NewOrchestrator(nil, nil, nil, redirAgent.Client())
	if _, err := orch.fetchRemoteAgentScan(ctx, models.NodeInfo{Name: "n", URL: redirAgent.URL, Token: "sec"}); err == nil {
		t.Fatal("expected error when agent returns redirect")
	}
	if redirected {
		t.Fatal("fetchRemoteAgentScan followed redirect and leaked token")
	}
}

func TestRegistryAndOrchestrator_Round2Regressions(t *testing.T) {
	ctx := context.Background()

	// 1. CheckImageUpdates preserves currentTag when latest candidate has equal semver (e.g. v1.2.3 vs 1.2.3),
	// and always includes same-major latestVersion in availableTags even when >=12 newer-major tags exist.
	reg := NewRegistryClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u := req.URL.String()
			switch {
			case strings.Contains(u, "/v2/org/vprefix/tags/list"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["1.2.3","v1.1.0"]}`)),
					Header:     make(http.Header),
				}, nil
			case strings.Contains(u, "/v2/org/manymajor/tags/list"):
				tags := []string{
					"2.0.12", "2.0.11", "2.0.10", "2.0.9", "2.0.8", "2.0.7",
					"2.0.6", "2.0.5", "2.0.4", "2.0.3", "2.0.2", "2.0.1", "2.0.0",
					"1.5.0", "1.0.0",
				}
				b, _ := json.Marshal(map[string][]string{"tags": tags})
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader(b)),
					Header:     make(http.Header),
				}, nil
			default:
				return &http.Response{StatusCode: 404, Body: http.NoBody, Header: make(http.Header)}, nil
			}
		}),
	})

	latest, _, _, outdated, err := reg.CheckImageUpdates(ctx, "quay.io/org/vprefix:v1.2.3", "")
	if err != nil {
		t.Fatalf("vprefix CheckImageUpdates error: %v", err)
	}
	if outdated || latest != "v1.2.3" {
		t.Fatalf("expected equal semver v1.2.3 vs 1.2.3 to stay latestVersion='v1.2.3' outdated=false, got latest=%q outdated=%v", latest, outdated)
	}

	latest2, avail2, _, outdated2, err := reg.CheckImageUpdates(ctx, "quay.io/org/manymajor:1.0.0", "")
	if err != nil {
		t.Fatalf("manymajor CheckImageUpdates error: %v", err)
	}
	if !outdated2 || latest2 != "1.5.0" {
		t.Fatalf("expected latestVersion='1.5.0' outdated=true, got latest=%q outdated=%v", latest2, outdated2)
	}
	foundInAvail := false
	for _, tg := range avail2 {
		if tg == "1.5.0" {
			foundInAvail = true
			break
		}
	}
	if !foundInAvail {
		t.Fatalf("expected availableTags to include same-major target '1.5.0', got %v", avail2)
	}

	// 2. Orchestrator.RunFullScanWithTask uses UpdateNodeHealth so concurrent RemoveNode or RejectNode
	// during remote scan is neither resurrected nor overwritten back to approved.
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var agentDelSrv, agentRejSrv *httptest.Server
	agentDelSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = store.RemoveNode(ctx, "node-del")
		_, _ = w.Write([]byte(`{"node":"node-del","items":[{"target_type":"apt","name":"curl","current_version":"1.0"}]}`))
	}))
	defer agentDelSrv.Close()

	agentRejSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = store.RejectNode(ctx, "node-rej")
		_, _ = w.Write([]byte(`{"node":"node-rej","items":[]}`))
	}))
	defer agentRejSrv.Close()

	_ = store.UpsertNode(ctx, models.NodeInfo{Name: "node-del", URL: agentDelSrv.URL, Status: models.NodeStatusApproved, Online: true})
	_ = store.UpsertNode(ctx, models.NodeInfo{Name: "node-rej", URL: agentRejSrv.URL, Status: models.NodeStatusApproved, Online: true})

	cfg := config.DefaultConfig()
	cfg.NodeName = "hub"
	cfg.Scanner.ServicesDir = t.TempDir()
	cfg.Scanner.DaemonsDir = t.TempDir()
	cfg.Scanner.EoLAPIURL = "http://127.0.0.1:0"
	cfg.Scanner.OSVAPIURL = "http://127.0.0.1:0"

	runner := &fakeRunner{handler: func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("not installed in unit test")
	}}
	orch := NewOrchestrator(cfg, store, runner, agentDelSrv.Client())
	res, err := orch.RunFullScanWithTask(ctx, "")
	if err != nil {
		t.Fatalf("RunFullScanWithTask error: %v", err)
	}
	if _, err := store.GetNode(ctx, "node-del"); err == nil {
		t.Fatal("expected deleted node-del not to be resurrected by scan completion")
	}
	rejNode, err := store.GetNode(ctx, "node-rej")
	if err != nil {
		t.Fatalf("expected node-rej to still exist: %v", err)
	}
	if rejNode.Status != models.NodeStatusRejected {
		t.Fatalf("expected node-rej status to remain rejected, got %q", rejNode.Status)
	}
	for _, n := range res.Nodes {
		if n.Name == "node-del" {
			t.Fatalf("expected deleted node-del omitted from scan Nodes, got %+v", res.Nodes)
		}
		if n.Name == "node-rej" && n.Status != models.NodeStatusRejected {
			t.Fatalf("expected res.Nodes entry for node-rej to have rejected status, got %q", n.Status)
		}
	}
}

func TestParseComposeImageRefs_ContainerNameEnvExpansion(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.25.0\n    container_name: ${APP_PREFIX:-nal}_web_1\n  worker:\n    image: alpine:3.19\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_PREFIX=prod\n"), 0600); err != nil {
		t.Fatal(err)
	}
	refs, err := ParseComposeImageRefs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 compose refs, got %d", len(refs))
	}
	if refs[0].ServiceKey != "web" || refs[0].ContainerName != "prod_web_1" {
		t.Fatalf("expected expanded container_name 'prod_web_1', got %+v", refs[0])
	}
	if refs[1].ServiceKey != "worker" || refs[1].ContainerName != "worker" {
		t.Fatalf("expected omitted container_name to default to service key 'worker', got %+v", refs[1])
	}
}

func TestOrchestrator_ScanningNodesTracking(t *testing.T) {
	orch := &Orchestrator{}

	started, active := orch.StartScanWithNodes("task-abc", []string{"Hub", "Node1", "Node1", ""})
	if !started || active != "" {
		t.Fatalf("StartScanWithNodes failed: started=%v active=%q", started, active)
	}

	scanning, activeID, nodes := orch.GetScanState()
	if !scanning || activeID != "task-abc" || len(nodes) != 2 || nodes[0] != "Hub" || nodes[1] != "Node1" {
		t.Fatalf("unexpected scan state: scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	orch.removeScanningNodeIfMultiple("Hub")
	nodes = orch.ScanningNodes()
	if len(nodes) != 1 || nodes[0] != "Node1" {
		t.Fatalf("expected only Node1 left after removing Hub, got %v", nodes)
	}

	// Removing last remaining node must be a no-op so chip indicator stays visible until FinishScan
	orch.removeScanningNodeIfMultiple("Node1")
	nodes = orch.ScanningNodes()
	if len(nodes) != 1 || nodes[0] != "Node1" {
		t.Fatalf("expected final node Node1 to be preserved until FinishScan, got %v", nodes)
	}

	// FinishScanTask with mismatched ID must not clear active task
	orch.FinishScanTask("wrong-task-id")
	if scanning, _, _ := orch.GetScanState(); !scanning {
		t.Fatal("expected FinishScanTask(wrong-task-id) not to clear active scan")
	}

	orch.FinishScan()
	scanning, activeID, nodes = orch.GetScanState()
	if scanning || activeID != "" || len(nodes) != 0 {
		t.Fatalf("expected clean idle state after FinishScan, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	// Verify FinishScanTask("wrong-id") also does not clear placeholder "scan_..." active task
	if started, _ := orch.StartScan(""); !started {
		t.Fatal("StartScan(\"\") failed")
	}
	orch.FinishScanTask("other-id")
	if scanning, _, _ := orch.GetScanState(); !scanning {
		t.Fatal("expected FinishScanTask(other-id) not to clear scan_ active task")
	}
	orch.FinishScan()
}

func TestOrchestrator_ResolveTargetNode(t *testing.T) {
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "ApprovedAgent",
		URL:    "http://approved.lan:10247",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "PendingAgent",
		URL:    "http://pending.lan:10247",
		Role:   "agent",
		Status: models.NodeStatusPending,
	})

	cfg := &config.Config{NodeName: "Axis"}
	orch := NewOrchestrator(cfg, store, nil, nil)

	// 1. Hub by empty name and explicit name (case-insensitive)
	hub1, err := orch.ResolveTargetNode(ctx, "")
	if err != nil || hub1.Name != "Axis" || hub1.Role != "hub" {
		t.Fatalf("expected Axis hub by empty name, got %+v, err=%v", hub1, err)
	}
	hub2, err := orch.ResolveTargetNode(ctx, "axis")
	if err != nil || hub2.Name != "Axis" || hub2.Role != "hub" {
		t.Fatalf("expected Axis hub by lowercase name, got %+v, err=%v", hub2, err)
	}

	// 2. Approved agent
	ag, err := orch.ResolveTargetNode(ctx, "ApprovedAgent")
	if err != nil || ag.Name != "ApprovedAgent" || ag.Role != "agent" {
		t.Fatalf("expected ApprovedAgent, got %+v, err=%v", ag, err)
	}

	// 3. Pending agent -> ErrScanNodeNotApproved
	_, err = orch.ResolveTargetNode(ctx, "PendingAgent")
	if !errors.Is(err, ErrScanNodeNotApproved) {
		t.Fatalf("expected ErrScanNodeNotApproved for pending agent, got: %v", err)
	}

	// 4. Unknown node -> ErrScanNodeNotFound
	_, err = orch.ResolveTargetNode(ctx, "GhostNode")
	if !errors.Is(err, ErrScanNodeNotFound) {
		t.Fatalf("expected ErrScanNodeNotFound for unknown node, got: %v", err)
	}
}

func TestOrchestrator_RunNodeScan_SingleNodeAndCacheMerge(t *testing.T) {
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Seed previous scan result with items from Hub (Axis), Atlas, and lowercase "aegis" to verify case-insensitive canonicalization
	_ = store.SaveScanResult(ctx, &models.ScanResult{
		ScannedAt: time.Now().UTC().Add(-1 * time.Hour),
		Items: []models.ManagedItem{
			{Node: "Axis", TargetType: models.TargetDocker, Name: "hub-auth", CurrentVersion: "1.0"},
			{Node: "Atlas", TargetType: models.TargetDocker, Name: "old-atlas-service", CurrentVersion: "0.9"},
			{Node: "aegis", TargetType: models.TargetDocker, Name: "aegis-worker", CurrentVersion: "2.5"},
		},
	})

	var atlasContacted, aegisContacted bool
	var orch *Orchestrator
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.Host, "atlas"):
			atlasContacted = true
			if orch != nil {
				scanning, activeTaskID, scanningNodes := orch.GetScanState()
				if !scanning || activeTaskID == "" || len(scanningNodes) != 1 || scanningNodes[0] != "Atlas" {
					t.Errorf("expected live GetScanState(true, non-empty, [Atlas]) during direct RunNodeScan, got scanning=%v taskID=%q nodes=%v", scanning, activeTaskID, scanningNodes)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node": "Atlas",
				"items": []models.ManagedItem{
					{
						Node:           "Atlas",
						TargetType:     models.TargetDocker,
						Name:           "new-atlas-service",
						CurrentVersion: "1.0",
						LatestVersion:  "1.1",
						Outdated:       true,
					},
				},
			})
		case strings.Contains(r.Host, "aegis"):
			aegisContacted = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node":  "Aegis",
				"items": []models.ManagedItem{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "Atlas",
		URL:    "http://atlas.local",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "Aegis",
		URL:    "http://aegis.local",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})

	cfg := &config.Config{NodeName: "Axis"}
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			// Redirect host calls to test server
			r2 := req.Clone(req.Context())
			r2.URL.Scheme = "http"
			r2.URL.Host = server.Listener.Addr().String()
			return server.Client().Transport.RoundTrip(r2)
		}),
	}
	orch = NewOrchestrator(cfg, store, nil, client)

	// Execute single node scan for Atlas
	res, err := orch.RunNodeScan(ctx, "Atlas")
	if err != nil {
		t.Fatalf("RunNodeScan(Atlas) failed: %v", err)
	}
	if scanning, activeID, nodes := orch.GetScanState(); scanning || activeID != "" || len(nodes) != 0 {
		t.Fatalf("expected clean idle scan state after RunNodeScan, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	if !atlasContacted {
		t.Fatal("expected Atlas agent to be contacted")
	}
	if aegisContacted {
		t.Fatal("expected Aegis agent NOT to be contacted during Atlas single-node scan")
	}

	// Verify items: old Atlas item replaced with new Atlas item, Axis and Aegis items preserved
	itemsByNodeAndName := make(map[string]models.ManagedItem)
	for _, it := range res.Items {
		itemsByNodeAndName[it.Node+":"+it.Name] = it
	}

	if _, hasOld := itemsByNodeAndName["Atlas:old-atlas-service"]; hasOld {
		t.Fatal("expected old-atlas-service to be removed/replaced for Atlas")
	}
	if newAtlas, hasNew := itemsByNodeAndName["Atlas:new-atlas-service"]; !hasNew || !newAtlas.Outdated {
		t.Fatalf("expected new-atlas-service with Outdated=true, got %+v", newAtlas)
	}
	if hubItem, hasHub := itemsByNodeAndName["Axis:hub-auth"]; !hasHub || hubItem.CurrentVersion != "1.0" {
		t.Fatalf("expected Axis:hub-auth preserved, got %+v", hubItem)
	}
	if aegisItem, hasAegis := itemsByNodeAndName["Aegis:aegis-worker"]; !hasAegis || aegisItem.CurrentVersion != "2.5" {
		t.Fatalf("expected Aegis:aegis-worker preserved, got %+v", aegisItem)
	}

	// Verify Atlas node health was updated online
	atlasNode, _ := store.GetNode(ctx, "Atlas")
	if !atlasNode.Online || !atlasNode.LastSeenAt.After(time.Now().UTC().Add(-10*time.Second)) {
		t.Fatalf("expected Atlas node health updated, got %+v", atlasNode)
	}

	// Verify Hub context cancellation during remote scan does NOT mark healthy Atlas node offline
	cancelCtx, cancelFunc := context.WithCancel(ctx)
	cancelOrch := NewOrchestrator(cfg, store, nil, &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cancelFunc()
			return nil, context.Canceled
		}),
	})
	if _, cancelErr := cancelOrch.RunNodeScan(cancelCtx, "Atlas"); cancelErr == nil {
		t.Fatal("expected error on cancelled RunNodeScan")
	}
	atlasAfterCancel, _ := store.GetNode(ctx, "Atlas")
	if !atlasAfterCancel.Online {
		t.Fatalf("expected healthy Atlas node NOT to be marked offline on Hub context cancellation, got %+v", atlasAfterCancel)
	}
}

func TestOrchestrator_DirectScanRejectsWhenScanInProgress(t *testing.T) {
	ctx := context.Background()
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.NodeName = "Axis"
	cfg.Scanner.ServicesDir = t.TempDir()
	cfg.Scanner.DaemonsDir = t.TempDir()
	orch := NewOrchestrator(cfg, store, nil, nil)

	orch.LockScanStart()
	started, existingID := orch.StartScanWithNodes("active-task", []string{"Atlas"})
	orch.UnlockScanStart()
	if !started || existingID != "" {
		t.Fatalf("expected active-task to acquire scan lock, got started=%v existingID=%q", started, existingID)
	}

	if _, err := orch.RunFullScan(ctx); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunFullScan, got: %v", err)
	}
	if _, err := orch.RunFullScanWithTask(ctx, "other-task"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunFullScanWithTask(other-task), got: %v", err)
	}
	if _, err := orch.RunNodeScan(ctx, "Axis"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunNodeScan, got: %v", err)
	}
	if _, err := orch.RunNodeScanWithTask(ctx, "Axis", "other-task"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunNodeScanWithTask(other-task), got: %v", err)
	}

	scanning, activeID, nodes := orch.GetScanState()
	if !scanning || activeID != "active-task" || len(nodes) != 1 || nodes[0] != "Atlas" {
		t.Fatalf("expected active scan state preserved after rejected calls, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	orch.FinishScan()
	scanning, activeID, nodes = orch.GetScanState()
	if scanning || activeID != "" || len(nodes) != 0 {
		t.Fatalf("expected clean idle scan state after FinishScan, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}
}
