package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
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
	if resp.StatusCode != http.StatusOK {
		return fallback
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel) == nil && rel.TagName != "" {
		return strings.TrimPrefix(rel.TagName, "v")
	}
	return fallback
}

func isValidVersionPrefix(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

func (ds *DaemonScanner) ScanDaemonsAndOS(ctx context.Context) ([]models.ManagedItem, error) {
	var items []models.ManagedItem

	// 1. Ollama host daemon (only report when binary is confirmed present)
	if ds.runner != nil {
		if out, err := ds.runner.Run(ctx, "ollama", "--version"); err == nil {
			if m := ollamaVerRe.FindStringSubmatch(string(out)); len(m) > 1 {
				ollamaVer := m[1]
				latestOllama := ds.fetchLatestOllamaVersion(ctx, ollamaVer)
				ollamaOutdated := latestOllama != "" && latestOllama != ollamaVer
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
		}
	}

	// 2. Server Monitor daemon (only emit on hosts where server-monitor exists)
	if ds.daemonsDir != "" {
		if info, err := os.Stat(filepath.Join(ds.daemonsDir, "server-monitor")); err == nil && info.IsDir() {
			items = append(items, models.ManagedItem{
				TargetType:     models.TargetDaemon,
				Name:           "server-monitor",
				CurrentVersion: "local-go-binary",
				LatestVersion:  "local-go-binary",
				AvailableTags:  []string{"local-go-binary"},
				EoL:            models.EoLInfo{Status: models.EoLSupported, Message: "Internal NAL daemon"},
				LastCheckedAt:  time.Now().UTC(),
			})
		}
	}

	// 3. macOS softwareupdate check (only emit on macOS hosts where sw_vers returns an OS version)
	if ds.runner != nil {
		if swVer, err := ds.runner.Run(ctx, "sw_vers", "-productVersion"); err == nil {
			macVer := strings.TrimSpace(string(swVer))
			if isValidVersionPrefix(macVer) {
				latestMacVer := macVer
				macOutdated := false
				if suOut, suErr := ds.runner.Run(ctx, "softwareupdate", "-l"); suErr == nil {
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
			}
		}
	}

	return items, nil
}
