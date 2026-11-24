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

type brewFormulaInfo struct {
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
}

type brewCaskInfo struct {
	Token      string `json:"token"`
	Version    string `json:"version"`
	Installed  string `json:"installed"`
	Outdated   bool   `json:"outdated"`
	Deprecated bool   `json:"deprecated"`
	Disabled   bool   `json:"disabled"`
}

type brewItemInput struct {
	name              string
	curVer            string
	stableVer         string
	reportedOutdated  bool
	pinned            bool
	isCask            bool
	outdatedMap       map[string]string
	outdatedSucceeded bool
	releaseNotesURL   string
	eol               models.EoLInfo
	brokenLinkage     bool
	linkageDetails    string
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

func (b *BrewScanner) queryBrewOutdated(ctx context.Context) (map[string]string, bool) {
	outdatedMap := make(map[string]string)
	outRaw, err := b.runner.Run(ctx, "brew", "outdated", "--json=v2")
	if err != nil {
		return outdatedMap, false
	}
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
	if json.Unmarshal(outRaw, &outPayload) != nil {
		return outdatedMap, false
	}
	for _, f := range outPayload.Formulae {
		outdatedMap[f.Name] = f.CurrentVersion
	}
	for _, c := range outPayload.Casks {
		outdatedMap[c.Name] = c.CurrentVersion
	}
	return outdatedMap, true
}

func (b *BrewScanner) checkFormulaLinkage(ctx context.Context, formulae []brewFormulaInfo) ([]bool, []string) {
	nFormulae := len(formulae)
	brokenFlags := make([]bool, nFormulae)
	linkageDetails := make([]string, nFormulae)
	if nFormulae == 0 {
		return brokenFlags, linkageDetails
	}

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for idx, f := range formulae {
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
	return brokenFlags, linkageDetails
}

func brewFormulaEoL(f brewFormulaInfo) models.EoLInfo {
	if f.Deprecated || f.Disabled {
		return models.EoLInfo{
			Product: f.Name,
			Status:  models.EoLExpired,
			Message: "Formula deprecated/disabled in Homebrew",
		}
	}
	if f.Pinned {
		return models.EoLInfo{
			Product: f.Name,
			Status:  models.EoLSupported,
			Message: "Pinned in Homebrew",
		}
	}
	// Preserve EoLUnknown default so downstream EoLChecker.CheckEoL enriches mapped formulae.
	return models.EoLInfo{Status: models.EoLUnknown}
}

func brewCaskEoL(c brewCaskInfo) models.EoLInfo {
	if c.Deprecated || c.Disabled {
		return models.EoLInfo{
			Product: c.Token,
			Status:  models.EoLExpired,
			Message: "Cask deprecated/disabled",
		}
	}
	return models.EoLInfo{Status: models.EoLSupported, Message: "Homebrew Cask"}
}

func buildBrewManagedItem(in brewItemInput) models.ManagedItem {
	latestVer := in.stableVer
	if ov, ok := in.outdatedMap[in.name]; ok && ov != "" {
		latestVer = ov
	}

	_, isOutdated := in.outdatedMap[in.name]
	if !isOutdated && in.reportedOutdated {
		isOutdated = true
	}
	if !isOutdated && !in.outdatedSucceeded && !in.pinned && latestVer != "" && in.curVer != "" {
		if in.isCask {
			isOutdated = in.curVer != latestVer
		} else {
			isOutdated = !strings.HasPrefix(in.curVer, latestVer)
		}
	}
	if in.pinned {
		isOutdated = false
	}

	avail := []string{latestVer}
	if in.curVer != "" && in.curVer != latestVer {
		avail = []string{latestVer, in.curVer}
	}

	return models.ManagedItem{
		TargetType:      models.TargetBrew,
		Name:            in.name,
		CurrentVersion:  curVerOrEmpty(in.curVer),
		LatestVersion:   latestVer,
		AvailableTags:   avail,
		Outdated:        isOutdated,
		BrokenLinkage:   in.brokenLinkage,
		LinkageDetails:  in.linkageDetails,
		ReleaseNotesURL: in.releaseNotesURL,
		EoL:             in.eol,
		LastCheckedAt:   time.Now().UTC(),
	}
}

func curVerOrEmpty(s string) string {
	return s
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
		Formulae []brewFormulaInfo `json:"formulae"`
		Casks    []brewCaskInfo    `json:"casks"`
	}
	if err := json.Unmarshal(infoOut, &infoPayload); err != nil {
		return nil, err
	}

	outdatedMap, outdatedSucceeded := b.queryBrewOutdated(ctx)
	brokenFlags, linkageDetails := b.checkFormulaLinkage(ctx, infoPayload.Formulae)

	var items []models.ManagedItem
	for idx, f := range infoPayload.Formulae {
		curVer := ""
		if len(f.Installed) > 0 {
			curVer = f.Installed[len(f.Installed)-1].Version
		}
		items = append(items, buildBrewManagedItem(brewItemInput{
			name:              f.Name,
			curVer:            curVer,
			stableVer:         f.Versions.Stable,
			reportedOutdated:  f.Outdated,
			pinned:            f.Pinned,
			isCask:            false,
			outdatedMap:       outdatedMap,
			outdatedSucceeded: outdatedSucceeded,
			releaseNotesURL:   brewFormulaNotesURL(f.Name),
			eol:               brewFormulaEoL(f),
			brokenLinkage:     brokenFlags[idx],
			linkageDetails:    linkageDetails[idx],
		}))
	}

	for _, c := range infoPayload.Casks {
		items = append(items, buildBrewManagedItem(brewItemInput{
			name:              c.Token,
			curVer:            c.Installed,
			stableVer:         c.Version,
			reportedOutdated:  c.Outdated,
			isCask:            true,
			outdatedMap:       outdatedMap,
			outdatedSucceeded: outdatedSucceeded,
			releaseNotesURL:   "https://formulae.brew.sh/cask/" + url.PathEscape(c.Token),
			eol:               brewCaskEoL(c),
		}))
	}
	return items, nil
}
