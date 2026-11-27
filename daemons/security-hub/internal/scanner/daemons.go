package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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

func (ds *DaemonScanner) findServerMonitorBinary() string {
	if ds.daemonsDir != "" {
		candidate := filepath.Join(ds.daemonsDir, "server-monitor", "server-monitor")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	if p, err := exec.LookPath("server-monitor"); err == nil && p != "" {
		return p
	}
	return ""
}

var (
	launchdInactiveStateRe = regexp.MustCompile(`(?m)^\s*state:\s+inactive\b`)
	userLaunchAgentGlobFn  = filepath.Glob
	currentEUIDFn          = os.Geteuid
	currentGOOS            = runtime.GOOS
)

func parseServerMonitorStatus(output string) (installed bool, running bool) {
	lower := strings.ToLower(strings.TrimSpace(output))
	if lower == "" {
		return false, false
	}
	if strings.Contains(lower, "not installed") ||
		strings.Contains(lower, "could not be found") ||
		strings.Contains(lower, "loaded: not-found") ||
		strings.Contains(lower, "not-found (reason:") {
		return false, false
	}
	if strings.Contains(lower, "active (running)") {
		return true, true
	}
	if strings.Contains(lower, "installed (stopped") ||
		strings.Contains(lower, "active: inactive") ||
		strings.Contains(lower, "active: failed") ||
		launchdInactiveStateRe.MatchString(lower) ||
		strings.Contains(lower, "loaded: loaded") {
		return true, false
	}
	return false, false
}

func (ds *DaemonScanner) detectUserLaunchAgentServerMonitor(ctx context.Context) (installed bool, running bool) {
	if currentGOOS != "darwin" || currentEUIDFn() != 0 {
		return false, false
	}
	patterns := []string{
		"/Users/*/Library/LaunchAgents/com.servermonitor.plist",
		"/Users/*/Library/LaunchAgents/*server-monitor*.plist",
	}
	for _, pat := range patterns {
		if matches, err := userLaunchAgentGlobFn(pat); err == nil && len(matches) > 0 {
			installed = true
			break
		}
	}
	if !installed {
		return false, false
	}
	if ds.runner != nil {
		if out, err := ds.runner.Run(ctx, "pgrep", "-x", "server-monitor"); err == nil && strings.TrimSpace(string(out)) != "" {
			return true, true
		}
	}
	return true, false
}

func parseServerMonitorVersion(output string) string {
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "unknown command") || strings.HasPrefix(lower, "usage:") {
			return "unknown"
		}
		return line
	}
	return "unknown"
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

	// 2. Server Monitor daemon (only emit on hosts where the OS service is installed)
	if ds.runner != nil {
		if binPath := ds.findServerMonitorBinary(); binPath != "" {
			statusOut, _ := ds.runner.Run(ctx, binPath, "service", "status")
			installed, running := parseServerMonitorStatus(string(statusOut))
			if !installed {
				installed, running = ds.detectUserLaunchAgentServerMonitor(ctx)
			}
			if installed {
				ver := "unknown"
				if verOut, verErr := ds.runner.Run(ctx, binPath, "version"); verErr == nil {
					ver = parseServerMonitorVersion(string(verOut))
				}
				svcStatus := "stopped"
				if running {
					svcStatus = "running"
				}
				items = append(items, models.ManagedItem{
					TargetType:     models.TargetDaemon,
					Name:           "server-monitor",
					CurrentVersion: ver,
					LatestVersion:  ver,
					AvailableTags:  []string{ver},
					EoL:            models.EoLInfo{Status: models.EoLSupported, Message: "Internal NAL daemon"},
					ServiceStatus:  svcStatus,
					LastCheckedAt:  time.Now().UTC(),
				})
			}
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
