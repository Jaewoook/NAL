package scanner

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/models"
)

type DaemonScanner struct {
	daemonsDir string
	runner     CommandRunner
}

func NewDaemonScanner(daemonsDir string, runner CommandRunner) *DaemonScanner {
	return &DaemonScanner{
		daemonsDir: daemonsDir,
		runner:     runner,
	}
}

var ollamaVerRe = regexp.MustCompile(`(\d+\.\d+\.\d+)`)

func (ds *DaemonScanner) ScanDaemonsAndOS(ctx context.Context) ([]models.ManagedItem, error) {
	var items []models.ManagedItem

	// 1. Ollama host daemon
	ollamaVer := "installed"
	if ds.runner != nil {
		if out, err := ds.runner.Run(ctx, "ollama", "--version"); err == nil {
			if m := ollamaVerRe.FindStringSubmatch(string(out)); len(m) > 1 {
				ollamaVer = m[1]
			}
		}
	}
	items = append(items, models.ManagedItem{
		TargetType:      models.TargetDaemon,
		Name:            "ollama",
		CurrentVersion:  ollamaVer,
		LatestVersion:   ollamaVer,
		AvailableTags:   []string{ollamaVer},
		ReleaseNotesURL: "https://github.com/ollama/ollama/releases",
		EoL:             models.EoLInfo{Status: models.EoLSupported, Message: "Active host daemon"},
		LastCheckedAt:   time.Now().UTC(),
	})

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
	macOutdated := false
	if ds.runner != nil {
		if swVer, err := ds.runner.Run(ctx, "sw_vers", "-productVersion"); err == nil {
			if v := strings.TrimSpace(string(swVer)); v != "" {
				macVer = v
			}
		}
	}
	items = append(items, models.ManagedItem{
		TargetType:     models.TargetMacOS,
		Name:           "macOS Host",
		CurrentVersion: macVer,
		LatestVersion:  macVer,
		Outdated:       macOutdated,
		AvailableTags:  []string{macVer},
		EoL:            models.EoLInfo{Product: "macos", Status: models.EoLSupported},
		LastCheckedAt:  time.Now().UTC(),
	})

	return items, nil
}
