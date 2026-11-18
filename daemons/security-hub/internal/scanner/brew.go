package scanner

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

type BrewScanner struct {
	runner CommandRunner
}

func NewBrewScanner(runner CommandRunner) *BrewScanner {
	return &BrewScanner{runner: runner}
}

func brewFormulaNotesURL(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) == 3 {
		// Tap-qualified formula: owner/tap/formula -> GitHub tap URL when unambiguous
		repo := parts[1]
		if !strings.HasPrefix(repo, "homebrew-") {
			repo = "homebrew-" + repo
		}
		return "https://github.com/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(repo)
	}
	return "https://formulae.brew.sh/formula/" + url.PathEscape(name)
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
			Pinned     bool `json:"pinned"`
			Outdated   bool `json:"outdated"`
			Deprecated bool `json:"deprecated"`
			Disabled   bool `json:"disabled"`
		} `json:"formulae"`
		Casks []struct {
			Token      string `json:"token"`
			Version    string `json:"version"`
			Installed  string `json:"installed"`
			Outdated   bool   `json:"outdated"`
			Deprecated bool   `json:"deprecated"`
			Disabled   bool   `json:"disabled"`
		} `json:"casks"`
	}
	if err := json.Unmarshal(infoOut, &infoPayload); err != nil {
		return nil, err
	}

	outdatedMap := make(map[string]string)
	outdatedSucceeded := false
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
			outdatedSucceeded = true
			for _, f := range outPayload.Formulae {
				outdatedMap[f.Name] = f.CurrentVersion
			}
			for _, c := range outPayload.Casks {
				outdatedMap[c.Name] = c.CurrentVersion
			}
		}
	}

	// Bounded concurrent `brew linkage --test` checks across installed formulae
	nFormulae := len(infoPayload.Formulae)
	brokenFlags := make([]bool, nFormulae)
	linkageDetails := make([]string, nFormulae)
	if nFormulae > 0 {
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for idx, f := range infoPayload.Formulae {
			wg.Add(1)
			go func(i int, formulaName string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				lCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				if linkOut, linkErr := b.runner.Run(lCtx, "brew", "linkage", "--test", formulaName); linkErr != nil && ctx.Err() == nil {
					brokenFlags[i] = true
					linkageDetails[i] = strings.TrimSpace(string(linkOut))
				}
			}(idx, f.Name)
		}
		wg.Wait()
	}

	var items []models.ManagedItem
	for idx, f := range infoPayload.Formulae {
		curVer := ""
		if len(f.Installed) > 0 {
			curVer = f.Installed[len(f.Installed)-1].Version
		}
		latestVer := f.Versions.Stable
		if ov, ok := outdatedMap[f.Name]; ok && ov != "" {
			latestVer = ov
		}
		_, isOutdated := outdatedMap[f.Name]
		if !isOutdated && f.Outdated {
			isOutdated = true
		}
		if !isOutdated && !outdatedSucceeded && !f.Pinned && latestVer != "" && curVer != "" && !strings.HasPrefix(curVer, latestVer) {
			isOutdated = true
		}
		if f.Pinned {
			isOutdated = false
		}

		eol := models.EoLInfo{Status: models.EoLUnknown}
		if f.Deprecated || f.Disabled {
			eol = models.EoLInfo{
				Product: f.Name,
				Status:  models.EoLExpired,
				Message: "Formula deprecated/disabled in Homebrew",
			}
		} else if f.Pinned {
			eol = models.EoLInfo{
				Product: f.Name,
				Status:  models.EoLSupported,
				Message: "Pinned in Homebrew",
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
			BrokenLinkage:   brokenFlags[idx],
			LinkageDetails:  linkageDetails[idx],
			ReleaseNotesURL: brewFormulaNotesURL(f.Name),
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
		if !isOutdated && c.Outdated {
			isOutdated = true
		}
		if !isOutdated && !outdatedSucceeded && latestVer != "" && curVer != "" && curVer != latestVer {
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
			ReleaseNotesURL: "https://formulae.brew.sh/cask/" + url.PathEscape(c.Token),
			EoL:             eol,
			LastCheckedAt:   time.Now().UTC(),
		})
	}
	return items, nil
}
