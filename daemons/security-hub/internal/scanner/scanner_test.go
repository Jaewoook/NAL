package scanner

import (
	"context"
	"io"
	"net/http"
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
