package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/models"
)

type DaemonScanner struct {
	daemonsDir string
	runner     CommandRunner
	httpClient *http.Client
}

func NewDaemonScanner(daemonsDir string, runner CommandRunner) *DaemonScanner {
	return NewDaemonScannerWithHTTP(daemonsDir, runner, nil)
}

func NewDaemonScannerWithHTTP(daemonsDir string, runner CommandRunner, httpClient *http.Client) *DaemonScanner {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 8 * time.Second}
	}
	return &DaemonScanner{
		daemonsDir: daemonsDir,
		runner:     runner,
		httpClient: httpClient,
	}
}

var ollamaVerRe = regexp.MustCompile(`(\d+\.\d+\.\d+)`)

func (ds *DaemonScanner) fetchLatestOllamaVersion(ctx context.Context, fallback string) string {
	if ds.httpClient == nil {
		return fallback
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/ollama/ollama/releases/latest", nil)
	if err != nil {
		return fallback
	}
	resp, err := ds.httpClient.Do(req)
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if json.NewDecoder(resp.Body).Decode(&rel) == nil && rel.TagName != "" {
		return strings.TrimPrefix(rel.TagName, "v")
	}
	return fallback
}

func (ds *DaemonScanner) ScanDaemonsAndOS(ctx context.Context) ([]models.ManagedItem, error) {
	var items []models.ManagedItem

	// 1. Ollama host daemon (gracefully skip if ollama binary is not installed)
	ollamaVer := "installed"
	ollamaInstalled := true
	if ds.runner != nil {
		if out, err := ds.runner.Run(ctx, "ollama", "--version"); err == nil {
			if m := ollamaVerRe.FindStringSubmatch(string(out)); len(m) > 1 {
				ollamaVer = m[1]
			}
		} else {
			ollamaInstalled = false
		}
	}
	if ollamaInstalled {
		latestOllama := ds.fetchLatestOllamaVersion(ctx, ollamaVer)
		ollamaOutdated := ollamaVer != "installed" && latestOllama != "" && latestOllama != ollamaVer
		items = append(items, models.ManagedItem{
			TargetType:      models.TargetDaemon,
			Name:            "ollama",
			CurrentVersion:  ollamaVer,
			LatestVersion:   latestOllama,
			Outdated:        ollamaOutdated,
			AvailableTags:   []string{latestOllama},
			ReleaseNotesURL: "https://github.com/ollama/ollama/releases",
			EoL:             models.EoLInfo{Status: models.EoLSupported, Message: "Active host daemon"},
			LastCheckedAt:   time.Now().UTC(),
		})
	}

	// 2. Server Monitor daemon
	items = append(items, models.ManagedItem{
		TargetType:     models.TargetDaemon,
		Name:           "server-monitor",
		CurrentVersion: "local-go-binary",
		LatestVersion:  "local-go-binary",
		AvailableTags:  []string{"local-go-binary"},
		EoL:            models.EoLInfo{Status: models.EoLSupported, Message: "Internal NAL daemon"},
		LastCheckedAt:  time.Now().UTC(),
	})

	// 3. macOS softwareupdate check
	macVer := "up-to-date"
	latestMacVer := macVer
	macOutdated := false
	if ds.runner != nil {
		if swVer, err := ds.runner.Run(ctx, "sw_vers", "-productVersion"); err == nil {
			if v := strings.TrimSpace(string(swVer)); v != "" {
				macVer = v
				latestMacVer = v
			}
		}
		if suOut, err := ds.runner.Run(ctx, "softwareupdate", "-l"); err == nil {
			s := string(suOut)
			if strings.Contains(s, "Label:") || strings.Contains(s, "Software Update found") {
				macOutdated = true
				for _, line := range strings.Split(s, "\n") {
					if idx := strings.Index(line, "Label:"); idx >= 0 {
						latestMacVer = strings.TrimSpace(line[idx+len("Label:"):])
						break
					}
				}
			}
		}
	}
	items = append(items, models.ManagedItem{
		TargetType:     models.TargetMacOS,
		Name:           "macOS Host",
		CurrentVersion: macVer,
		LatestVersion:  latestMacVer,
		Outdated:       macOutdated,
		AvailableTags:  []string{latestMacVer},
		EoL:            models.EoLInfo{Product: "macos", Status: models.EoLSupported},
		LastCheckedAt:  time.Now().UTC(),
	})

	return items, nil
}
