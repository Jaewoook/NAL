package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

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

func TestVulnScanner_TrivyImageScanAndDeduplication(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`{
					"results": [
						{
							"vulns": [
								{
									"id": "CVE-2026-0001",
									"summary": "Shared CVE",
									"database_specific": {"severity": "CRITICAL"}
								}
							]
						}
					]
				}`)),
				Header: make(http.Header),
			}, nil
		}),
	}
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			if name == "trivy" && len(args) > 0 && args[0] == "--version" {
				return []byte("Version: 0.58.0"), nil
			}
			if name == "trivy" && len(args) > 0 && args[0] == "image" {
				return []byte(`{
					"Results": [
						{
							"Vulnerabilities": [
								{"VulnerabilityID": "CVE-2026-0001", "Title": "Shared CVE", "Severity": "CRITICAL"},
								{"VulnerabilityID": "CVE-2026-0002", "Title": "Base image HIGH vuln", "Severity": "HIGH", "FixedVersion": "1.2.4", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-0002"}
							]
						}
					]
				}`), nil
			}
			return nil, errors.New("unexpected command")
		},
	}

	items := []models.ManagedItem{
		{
			TargetType:     models.TargetDocker,
			Name:           "cloudflare-tunnel",
			ImageRef:       "cloudflare/cloudflared:2026.8.0",
			CurrentVersion: "2026.8.0",
		},
		{
			TargetType:     models.TargetDocker,
			Name:           "cloudflare-tunnel-replica",
			ImageRef:       "cloudflare/cloudflared:2026.8.0",
			CurrentVersion: "latest",
		},
	}

	vs := NewVulnScanner("https://api.osv.dev/v1/querybatch", httpClient, runner)
	if err := vs.CheckVulnerabilities(ctx, items); err != nil {
		t.Fatalf("CheckVulnerabilities failed: %v", err)
	}
	if len(items[0].Vulnerabilities) != 2 || items[0].CritCount != 1 || items[0].HighCount != 1 {
		t.Fatalf("expected deduplicated 1 CRIT + 1 HIGH on item[0], got %+v", items[0])
	}
	if len(items[1].Vulnerabilities) != 2 || items[1].CritCount != 1 || items[1].HighCount != 1 {
		t.Fatalf("expected Trivy 1 CRIT + 1 HIGH on item[1] sharing ImageRef, got %+v", items[1])
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
