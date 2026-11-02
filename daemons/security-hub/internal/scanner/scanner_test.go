package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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



