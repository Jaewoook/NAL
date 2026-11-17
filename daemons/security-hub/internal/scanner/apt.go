package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

// AptScanner inspects installed Debian/Ubuntu/Raspberry Pi OS packages via dpkg and apt.
type AptScanner struct {
	runner CommandRunner
}

// NewAptScanner creates an AptScanner backed by the provided CommandRunner.
func NewAptScanner(runner CommandRunner) *AptScanner {
	return &AptScanner{runner: runner}
}

type dpkgPackage struct {
	Name    string
	Version string
}

func stripAptArch(name string) string {
	s := strings.TrimSpace(name)
	if idx := strings.IndexByte(s, ':'); idx > 0 {
		s = s[:idx]
	}
	return s
}

func isAptPermissionError(out string) bool {
	return strings.Contains(out, "Permission denied") ||
		strings.Contains(out, "are you root") ||
		strings.Contains(out, "List directory /var/lib/apt/lists/partial is missing")
}

func firstTokenPackage(line string, pkgSet map[string]bool) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	rawTok := strings.TrimSpace(strings.TrimRight(fields[0], ":,;()"))
	if pkgSet[rawTok] {
		return rawTok
	}
	base := stripAptArch(rawTok)
	if pkgSet[base] {
		return base
	}
	return ""
}

func appendBrokenDetail(brokenMap map[string]string, pkgName, detail string) {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return
	}
	if prev := brokenMap[pkgName]; prev == "" {
		brokenMap[pkgName] = detail
	} else if !strings.Contains(prev, detail) {
		brokenMap[pkgName] = prev + "\n" + detail
	}
}

func queryAptUpgradable(ctx context.Context, runner CommandRunner, pkgSet map[string]bool) map[string]string {
	upgradableMap := make(map[string]string)
	if upgOut, err := runner.Run(ctx, "apt", "list", "--upgradable"); err == nil {
		for _, line := range strings.Split(string(upgOut), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Listing") ||
				strings.HasPrefix(line, "WARNING:") || strings.HasPrefix(line, "W:") ||
				strings.HasPrefix(line, "E:") || strings.HasPrefix(line, "N:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || !strings.Contains(fields[0], "/") || strings.Contains(fields[0], "://") || strings.HasPrefix(fields[0], "/") {
				continue
			}
			if len(fields) >= 4 && !strings.Contains(line, "[upgradable") {
				continue
			}
			namePart := fields[0]
			if slash := strings.IndexByte(namePart, '/'); slash >= 0 {
				namePart = namePart[:slash]
			}
			pkgKey := strings.TrimSpace(namePart)
			if !strings.Contains(pkgKey, ":") && len(fields) >= 3 {
				arch := strings.TrimSpace(fields[2])
				if arch != "" && !strings.HasPrefix(arch, "[") && pkgSet[pkgKey+":"+arch] {
					pkgKey = pkgKey + ":" + arch
				}
			}
			candVer := strings.TrimSpace(fields[1])
			if pkgKey != "" && candVer != "" {
				upgradableMap[pkgKey] = candVer
			}
		}
		return upgradableMap
	}

	if simOut, simErr := runner.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"); simErr == nil {
		for _, line := range strings.Split(string(simOut), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "Inst ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			pkgName := strings.TrimSpace(fields[1])
			candIdx := 2
			if strings.HasPrefix(fields[2], "[") {
				if len(fields) < 4 {
					continue
				}
				candIdx = 3
			}
			candVer := strings.Trim(fields[candIdx], "()")
			if pkgName != "" && candVer != "" {
				upgradableMap[pkgName] = candVer
			}
		}
	}
	return upgradableMap
}

// ScanApt queries local dpkg/apt tooling and returns ManagedItem records for APT packages.
// Hosts without dpkg-query return nil, nil gracefully.
func (a *AptScanner) ScanApt(ctx context.Context) ([]models.ManagedItem, error) {
	if a.runner == nil {
		return nil, nil
	}

	dpkgOut, err := a.runner.Run(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Want}\t${db:Status-Status}\n")
	if err != nil {
		// Gracefully ignore APT if not installed or unavailable on this host
		return nil, nil
	}

	var pkgs []dpkgPackage
	seen := make(map[string]bool)
	pkgSet := make(map[string]bool)
	holdSet := make(map[string]bool)
	brokenMap := make(map[string]string)

	for _, line := range strings.Split(string(dpkgOut), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		pkgName := strings.TrimSpace(fields[0])
		ver := strings.TrimSpace(fields[1])
		want := "install"
		status := strings.TrimSpace(fields[2])
		if len(fields) >= 4 {
			want = strings.TrimSpace(fields[2])
			status = strings.TrimSpace(fields[3])
		}
		if pkgName == "" || status == "not-installed" || status == "config-files" || status == "deinstall" {
			continue
		}
		if status != "installed" {
			brokenMap[pkgName] = "dpkg status: " + status
		} else if ver == "" {
			continue
		}
		if want == "hold" {
			holdSet[pkgName] = true
		}
		if !seen[pkgName] {
			seen[pkgName] = true
			pkgSet[pkgName] = true
			pkgSet[stripAptArch(pkgName)] = true
			pkgs = append(pkgs, dpkgPackage{Name: pkgName, Version: ver})
		}
	}

	if len(pkgs) == 0 {
		return nil, nil
	}

	// Best-effort bounded index refresh; only elevate with sudo -n on permission errors.
	updCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	updOut, updErr := a.runner.Run(updCtx, "apt-get", "update", "-qq")
	if updErr != nil && ctx.Err() == nil && updCtx.Err() == nil && isAptPermissionError(string(updOut)) {
		_, _ = a.runner.Run(updCtx, "sudo", "-n", "apt-get", "update", "-qq")
	}
	cancel()

	upgradableMap := queryAptUpgradable(ctx, a.runner, pkgSet)

	if holdOut, err := a.runner.Run(ctx, "apt-mark", "showhold"); err == nil {
		for _, line := range strings.Split(string(holdOut), "\n") {
			raw := strings.TrimSpace(line)
			if raw != "" {
				holdSet[raw] = true
			}
		}
	}

	manualSet := make(map[string]bool)
	hasManualMatch := false
	if manOut, err := a.runner.Run(ctx, "apt-mark", "showmanual"); err == nil {
		for _, line := range strings.Split(string(manOut), "\n") {
			raw := strings.TrimSpace(line)
			base := stripAptArch(raw)
			if raw != "" {
				manualSet[raw] = true
				if pkgSet[raw] || pkgSet[base] {
					hasManualMatch = true
				}
			}
		}
	}

	if auditOut, err := a.runner.Run(ctx, "dpkg", "--audit"); err == nil {
		auditText := strings.TrimSpace(string(auditOut))
		if auditText != "" {
			for _, line := range strings.Split(string(auditOut), "\n") {
				line = strings.TrimRight(line, "\r")
				if len(line) == 0 || (line[0] != ' ' && line[0] != '\t') {
					continue
				}
				if pkgName := firstTokenPackage(line, pkgSet); pkgName != "" {
					appendBrokenDetail(brokenMap, pkgName, line)
				}
			}
		}
	}

	if chkOut, chkErr := a.runner.Run(ctx, "apt-get", "-o", "Debug::NoLocking=true", "check"); chkErr != nil {
		chkText := strings.TrimSpace(string(chkOut))
		for _, line := range strings.Split(chkText, "\n") {
			if strings.Contains(line, "Depends:") ||
				strings.Contains(line, "PreDepends:") ||
				strings.Contains(line, "Pre-Depends:") ||
				strings.Contains(line, "Conflicts:") ||
				strings.Contains(line, "Breaks:") ||
				strings.Contains(line, "but it is not") {
				if pkgName := firstTokenPackage(line, pkgSet); pkgName != "" {
					appendBrokenDetail(brokenMap, pkgName, line)
				}
			}
		}
	}

	var items []models.ManagedItem
	for _, p := range pkgs {
		baseName := stripAptArch(p.Name)
		isManual := manualSet[p.Name] || manualSet[baseName]
		cand, hasUpgradable := upgradableMap[p.Name]
		if !hasUpgradable && !strings.Contains(p.Name, ":") {
			cand, hasUpgradable = upgradableMap[baseName]
		}
		brokenDetails := brokenMap[p.Name]
		if brokenDetails == "" && !strings.Contains(p.Name, ":") {
			brokenDetails = brokenMap[baseName]
		}
		isHeld := holdSet[p.Name] || holdSet[baseName]

		if hasManualMatch && !isManual && !hasUpgradable && brokenDetails == "" {
			continue
		}

		curVer := p.Version
		latestVer := curVer
		isOutdated := false
		if hasUpgradable && cand != "" && cand != curVer {
			latestVer = cand
			isOutdated = true
		}

		eol := models.EoLInfo{Status: models.EoLUnknown}
		if isHeld {
			isOutdated = false
			eol = models.EoLInfo{
				Status:  models.EoLSupported,
				Message: "Held via apt-mark (pinned)",
			}
		}

		items = append(items, models.ManagedItem{
			TargetType:      models.TargetApt,
			Name:            p.Name,
			CurrentVersion:  curVer,
			LatestVersion:   latestVer,
			AvailableTags:   []string{latestVer},
			Outdated:        isOutdated,
			BrokenLinkage:   brokenDetails != "",
			LinkageDetails:  brokenDetails,
			ReleaseNotesURL: "https://tracker.debian.org/pkg/" + url.PathEscape(baseName),
			EoL:             eol,
			LastCheckedAt:   time.Now().UTC(),
		})
	}
	return items, nil
}
