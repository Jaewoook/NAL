package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestDaemonScanner_ServerMonitorInstalledRunningStoppedAndNotInstalled(t *testing.T) {
	daemonsDir := t.TempDir()
	smDir := filepath.Join(daemonsDir, "server-monitor")
	if err := os.MkdirAll(smDir, 0o755); err != nil {
		t.Fatal(err)
	}
	smBin := filepath.Join(smDir, "server-monitor")
	if err := os.WriteFile(smBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name              string
		statusOut         string
		versionOut        string
		versionErr        error
		wantPresent       bool
		wantVersion       string
		wantServiceStatus string
	}{
		{
			name:              "launchd running",
			statusOut:         "● server-monitor (macOS launchd)\n   State:       Active (running)\n   PID:         1234\n",
			versionOut:        "2026-11-27.16.17\n",
			wantPresent:       true,
			wantVersion:       "2026-11-27.16.17",
			wantServiceStatus: "running",
		},
		{
			name:              "systemd running",
			statusOut:         "● server-monitor.service\n   Loaded: loaded (/etc/systemd/system/server-monitor.service; enabled)\n   Active: active (running) since Fri 2026-11-27\n",
			versionOut:        "2026-11-27.16.17\n",
			wantPresent:       true,
			wantVersion:       "2026-11-27.16.17",
			wantServiceStatus: "running",
		},
		{
			name:              "launchd installed stopped",
			statusOut:         "● server-monitor (macOS launchd)\n   State:       Installed (stopped / not loaded)\n",
			versionOut:        "2026-11-27.15.00\n",
			wantPresent:       true,
			wantVersion:       "2026-11-27.15.00",
			wantServiceStatus: "stopped",
		},
		{
			name:        "launchd not installed",
			statusOut:   "● server-monitor (macOS launchd)\n   State:       Not installed\n",
			versionOut:  "2026-11-27.16.17\n",
			wantPresent: false,
		},
		{
			name:        "systemd not found",
			statusOut:   "Unit server-monitor.service could not be found.\n",
			versionOut:  "2026-11-27.16.17\n",
			wantPresent: false,
		},
		{
			name:        "generic cli error containing failed is not treated as installed",
			statusOut:   "failed to get service status: permission denied\n",
			versionOut:  "2026-11-27.16.17\n",
			wantPresent: false,
		},
		{
			name:              "legacy binary without version subcommand",
			statusOut:         "● server-monitor (macOS launchd)\n   State:       Active (running)\n",
			versionOut:        `unknown command: "version". Run 'server-monitor help' for usage.`,
			versionErr:        errors.New("exit status 1"),
			wantPresent:       true,
			wantVersion:       "unknown",
			wantServiceStatus: "running",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{
				handler: func(name string, args ...string) ([]byte, error) {
					if name == smBin && len(args) == 2 && args[0] == "service" && args[1] == "status" {
						return []byte(tc.statusOut), nil
					}
					if name == smBin && len(args) == 1 && args[0] == "version" {
						return []byte(tc.versionOut), tc.versionErr
					}
					return nil, errors.New("not installed")
				},
			}
			ds := NewDaemonScannerWithHTTP(daemonsDir, runner, nil)
			items, err := ds.ScanDaemonsAndOS(context.Background())
			if err != nil {
				t.Fatalf("ScanDaemonsAndOS failed: %v", err)
			}
			var found *models.ManagedItem
			for i := range items {
				if items[i].Name == "server-monitor" {
					found = &items[i]
					break
				}
			}
			if !tc.wantPresent {
				if found != nil {
					t.Fatalf("expected server-monitor to be omitted, got %+v", *found)
				}
				return
			}
			if found == nil {
				t.Fatalf("expected server-monitor item, got %+v", items)
			}
			if found.CurrentVersion != tc.wantVersion {
				t.Fatalf("expected version %q, got %q", tc.wantVersion, found.CurrentVersion)
			}
			if found.ServiceStatus != tc.wantServiceStatus {
				t.Fatalf("expected ServiceStatus %q, got %q", tc.wantServiceStatus, found.ServiceStatus)
			}
			if found.EoL.Status != models.EoLSupported {
				t.Fatalf("expected EoL.Status %q, got %q", models.EoLSupported, found.EoL.Status)
			}
		})
	}
}

func TestDaemonScanner_ServerMonitorRootLaunchDaemonFallback(t *testing.T) {
	daemonsDir := t.TempDir()
	smDir := filepath.Join(daemonsDir, "server-monitor")
	if err := os.MkdirAll(smDir, 0o755); err != nil {
		t.Fatal(err)
	}
	smBin := filepath.Join(smDir, "server-monitor")
	if err := os.WriteFile(smBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	origGOOS := currentGOOS
	origEUID := currentEUIDFn
	origGlob := userLaunchAgentGlobFn
	t.Cleanup(func() {
		currentGOOS = origGOOS
		currentEUIDFn = origEUID
		userLaunchAgentGlobFn = origGlob
	})
	currentGOOS = "darwin"
	currentEUIDFn = func() int { return 0 }
	userLaunchAgentGlobFn = func(pattern string) ([]string, error) {
		return []string{"/Users/alice/Library/LaunchAgents/com.servermonitor.plist"}, nil
	}

	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			if name == smBin && len(args) == 2 && args[0] == "service" && args[1] == "status" {
				return []byte("● server-monitor (macOS launchd)\n   State:       Not installed\n"), nil
			}
			if name == "pgrep" && len(args) == 2 && args[0] == "-x" && args[1] == "server-monitor" {
				return []byte("4242\n"), nil
			}
			if name == smBin && len(args) == 1 && args[0] == "version" {
				return []byte("2026-11-27.16.25\n"), nil
			}
			return nil, errors.New("not installed")
		},
	}

	ds := NewDaemonScannerWithHTTP(daemonsDir, runner, nil)
	items, err := ds.ScanDaemonsAndOS(context.Background())
	if err != nil {
		t.Fatalf("ScanDaemonsAndOS failed: %v", err)
	}
	var found *models.ManagedItem
	for i := range items {
		if items[i].Name == "server-monitor" {
			found = &items[i]
			break
		}
	}
	if found == nil || found.CurrentVersion != "2026-11-27.16.25" || found.ServiceStatus != "running" {
		t.Fatalf("expected user LaunchAgent fallback to detect running server-monitor 2026-11-27.16.25, got %+v", found)
	}
}
