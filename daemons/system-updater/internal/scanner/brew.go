package scanner

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/models"
)

type BrewScanner struct {
	runner CommandRunner
}

func NewBrewScanner(runner CommandRunner) *BrewScanner {
	return &BrewScanner{runner: runner}
}

func (b *BrewScanner) ScanBrew(ctx context.Context) ([]models.ManagedItem, error) {
	if b.runner == nil {
		return nil, nil
	}
	infoOut, err := b.runner.Run(ctx, "brew", "info", "--json=v2", "--installed")
	if err != nil {
		// Gracefully ignore Homebrew if not installed or unavailable on this host
		return nil, nil
	}

	var infoPayload struct {
		Formulae []struct {
			Name     string `json:"name"`
			Versions struct {
				Stable string `json:"stable"`
			} `json:"versions"`
			Installed []struct {
				Version string `json:"version"`
			} `json:"installed"`
			Deprecated bool `json:"deprecated"`
			Disabled   bool `json:"disabled"`
		} `json:"formulae"`
		Casks []struct {
			Token      string `json:"token"`
			Version    string `json:"version"`
			Installed  string `json:"installed"`
			Deprecated bool   `json:"deprecated"`
			Disabled   bool   `json:"disabled"`
		} `json:"casks"`
	}
	if err := json.Unmarshal(infoOut, &infoPayload); err != nil {
		return nil, err
	}

	outdatedMap := make(map[string]string)
	if outRaw, err := b.runner.Run(ctx, "brew", "outdated", "--json=v2"); err == nil {
		var outPayload struct {
			Formulae []struct {
				Name           string `json:"name"`
				CurrentVersion string `json:"current_version"`
			} `json:"formulae"`
			Casks []struct {
				Name           string `json:"name"`
				CurrentVersion string `json:"current_version"`
			} `json:"casks"`
		}
		if json.Unmarshal(outRaw, &outPayload) == nil {
			for _, f := range outPayload.Formulae {
				outdatedMap[f.Name] = f.CurrentVersion
			}
			for _, c := range outPayload.Casks {
				outdatedMap[c.Name] = c.CurrentVersion
			}
		}
	}

	var items []models.ManagedItem
	for _, f := range infoPayload.Formulae {
		curVer := ""
		if len(f.Installed) > 0 {
			curVer = f.Installed[len(f.Installed)-1].Version
		}
		latestVer := f.Versions.Stable
		if ov, ok := outdatedMap[f.Name]; ok && ov != "" {
			latestVer = ov
		}
		_, isOutdated := outdatedMap[f.Name]
		if !isOutdated && latestVer != "" && curVer != "" && !strings.HasPrefix(curVer, latestVer) {
			isOutdated = true
		}

		broken := false
		details := ""
		if linkOut, linkErr := b.runner.Run(ctx, "brew", "linkage", "--test", f.Name); linkErr != nil {
			broken = true
			details = strings.TrimSpace(string(linkOut))
		}

		eol := models.EoLInfo{Status: models.EoLUnknown}
		if f.Deprecated || f.Disabled {
			eol = models.EoLInfo{
				Product: f.Name,
				Status:  models.EoLExpired,
				Message: "Formula deprecated/disabled in Homebrew",
			}
		}

		avail := []string{latestVer}
		if curVer != "" && curVer != latestVer {
			avail = []string{latestVer, curVer}
		}

		items = append(items, models.ManagedItem{
			TargetType:      models.TargetBrew,
			Name:            f.Name,
			CurrentVersion:  curVer,
			LatestVersion:   latestVer,
			AvailableTags:   avail,
			Outdated:        isOutdated,
			BrokenLinkage:   broken,
			LinkageDetails:  details,
			ReleaseNotesURL: "https://formulae.brew.sh/formula/" + f.Name,
			EoL:             eol,
			LastCheckedAt:   time.Now().UTC(),
		})
	}

	for _, c := range infoPayload.Casks {
		curVer := c.Installed
		latestVer := c.Version
		if ov, ok := outdatedMap[c.Token]; ok && ov != "" {
			latestVer = ov
		}
		_, isOutdated := outdatedMap[c.Token]
		if !isOutdated && latestVer != "" && curVer != "" && curVer != latestVer {
			isOutdated = true
		}
		eol := models.EoLInfo{Status: models.EoLSupported, Message: "Homebrew Cask"}
		if c.Deprecated || c.Disabled {
			eol = models.EoLInfo{Product: c.Token, Status: models.EoLExpired, Message: "Cask deprecated/disabled"}
		}
		avail := []string{latestVer}
		if curVer != "" && curVer != latestVer {
			avail = []string{latestVer, curVer}
		}
		items = append(items, models.ManagedItem{
			TargetType:      models.TargetBrew,
			Name:            c.Token,
			CurrentVersion:  curVer,
			LatestVersion:   latestVer,
			AvailableTags:   avail,
			Outdated:        isOutdated,
			ReleaseNotesURL: "https://formulae.brew.sh/cask/" + c.Token,
			EoL:             eol,
			LastCheckedAt:   time.Now().UTC(),
		})
	}
	return items, nil
}
