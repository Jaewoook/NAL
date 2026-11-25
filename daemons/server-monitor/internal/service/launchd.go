package service

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	launchdPrintStateRe  = regexp.MustCompile(`(?m)^\s*state\s*=\s*(\w+)`)
	launchdPrintPIDRe    = regexp.MustCompile(`(?m)^\s*pid\s*=\s*(\d+)`)
	launchdPrintPathRe   = regexp.MustCompile(`(?m)^\s*path\s*=\s*(.+)`)
	launchdPrintStdoutRe = regexp.MustCompile(`(?m)^\s*stdout path\s*=\s*(.+)`)
	launchdPrintStderrRe = regexp.MustCompile(`(?m)^\s*stderr path\s*=\s*(.+)`)

	launchdListPIDRe    = regexp.MustCompile(`"PID"\s*=\s*(\d+)`)
	launchdListStdoutRe = regexp.MustCompile(`"StandardOutPath"\s*=\s*"([^"]+)"`)
	launchdListStderrRe = regexp.MustCompile(`"StandardErrorPath"\s*=\s*"([^"]+)"`)
)

type launchdBackend struct {
	run          CommandRunner
	pollInterval time.Duration
}

type launchdInfo struct {
	Loaded     bool
	State      string
	PID        int
	PlistPath  string
	StdoutPath string
	StderrPath string
}

func findLaunchdPlist(serviceName string, customPath string) string {
	if customPath != "" {
		return ExpandHome(customPath)
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "Library", "LaunchAgents", "com.servermonitor.plist"),
		filepath.Join(home, "Library", "LaunchAgents", serviceName+".plist"),
		filepath.Join(home, "Library", "LaunchAgents", "com."+serviceName+".plist"),
		filepath.Join("/Library", "LaunchDaemons", serviceName+".plist"),
		filepath.Join("/Library", "LaunchDaemons", "com."+serviceName+".plist"),
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	if home != "" {
		return filepath.Join(home, "Library", "LaunchAgents", "com.servermonitor.plist")
	}
	return "/Library/LaunchDaemons/" + serviceName + ".plist"
}

func getLaunchdTarget(serviceName string) (domain string, target string) {
	if os.Geteuid() == 0 {
		return "system", "system/" + serviceName
	}
	uid := strconv.Itoa(os.Getuid())
	return "gui/" + uid, "gui/" + uid + "/" + serviceName
}

func parseLaunchdPrint(output string, info *launchdInfo) {
	if m := launchdPrintStateRe.FindStringSubmatch(output); len(m) > 1 {
		info.State = m[1]
	}
	if m := launchdPrintPIDRe.FindStringSubmatch(output); len(m) > 1 {
		info.PID, _ = strconv.Atoi(m[1])
	}
	if m := launchdPrintPathRe.FindStringSubmatch(output); len(m) > 1 && info.PlistPath == "" {
		info.PlistPath = strings.TrimSpace(m[1])
	}
	if m := launchdPrintStdoutRe.FindStringSubmatch(output); len(m) > 1 {
		info.StdoutPath = strings.TrimSpace(m[1])
	}
	if m := launchdPrintStderrRe.FindStringSubmatch(output); len(m) > 1 {
		info.StderrPath = strings.TrimSpace(m[1])
	}
}

func parseLaunchdList(output string, info *launchdInfo) {
	if m := launchdListPIDRe.FindStringSubmatch(output); len(m) > 1 {
		info.PID, _ = strconv.Atoi(m[1])
		info.State = "running"
	} else {
		info.State = "not running"
	}
	if m := launchdListStdoutRe.FindStringSubmatch(output); len(m) > 1 {
		info.StdoutPath = m[1]
	}
	if m := launchdListStderrRe.FindStringSubmatch(output); len(m) > 1 {
		info.StderrPath = m[1]
	}
}

func (b *launchdBackend) query(serviceName, customPath string) launchdInfo {
	var info launchdInfo
	info.PlistPath = findLaunchdPlist(serviceName, customPath)
	_, target := getLaunchdTarget(serviceName)

	if out, err := b.run("launchctl", "print", target); err == nil {
		info.Loaded = true
		parseLaunchdPrint(string(out), &info)
		return info
	}

	// In headless SSH sessions on macOS, gui/<uid> is inactive. Fall back to user/<uid>.
	if os.Geteuid() != 0 {
		userTarget := "user/" + strconv.Itoa(os.Getuid()) + "/" + serviceName
		if userOut, userErr := b.run("launchctl", "print", userTarget); userErr == nil {
			info.Loaded = true
			parseLaunchdPrint(string(userOut), &info)
			return info
		}
	}

	// Fallback to launchctl list
	if listOut, listErr := b.run("launchctl", "list", serviceName); listErr == nil {
		info.Loaded = true
		parseLaunchdList(string(listOut), &info)
		return info
	}

	info.Loaded = false
	return info
}

func (b *launchdBackend) waitUntil(attempts int, check func() bool) bool {
	interval := b.pollInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	for i := 0; i < attempts; i++ {
		time.Sleep(interval)
		if check() {
			return true
		}
	}
	return false
}

func (b *launchdBackend) bootstrap(serviceName, domain, target, plistPath string) (string, error) {
	out, err := b.run("launchctl", "bootstrap", domain, plistPath)
	if err == nil {
		return target, nil
	}

	// If gui/<uid> bootstrap failed on headless SSH, try user/<uid>.
	altDomain := "user/" + strconv.Itoa(os.Getuid())
	if domain != altDomain && os.Geteuid() != 0 {
		if altOut, altErr := b.run("launchctl", "bootstrap", altDomain, plistPath); altErr == nil {
			return altDomain + "/" + serviceName, nil
		} else {
			out = altOut
		}
	}

	if _, loadErr := b.run("launchctl", "load", plistPath); loadErr == nil {
		return target, nil
	}
	return "", fmt.Errorf("failed to load service into launchd: %s (%v)", strings.TrimSpace(string(out)), err)
}

func (b *launchdBackend) Start(serviceName, targetPath string) (string, error) {
	info := b.query(serviceName, targetPath)
	if info.Loaded && info.State == "running" && info.PID > 0 {
		return fmt.Sprintf("Service %s is already running (PID: %d).", serviceName, info.PID), nil
	}

	domain, target := getLaunchdTarget(serviceName)
	plistPath := findLaunchdPlist(serviceName, targetPath)
	if _, err := os.Stat(plistPath); err != nil {
		return "", fmt.Errorf("service file not found at %s. Run 'server-monitor service install' first", plistPath)
	}

	if !info.Loaded {
		var err error
		target, err = b.bootstrap(serviceName, domain, target, plistPath)
		if err != nil {
			return "", err
		}
	}

	_, _ = b.run("launchctl", "kickstart", "-p", target)

	var startedPID int
	if b.waitUntil(6, func() bool {
		check := b.query(serviceName, targetPath)
		if check.State == "running" && check.PID > 0 {
			startedPID = check.PID
			return true
		}
		return false
	}) {
		return fmt.Sprintf("Successfully started %s service (PID: %d).", serviceName, startedPID), nil
	}
	return fmt.Sprintf("Service %s start command issued.", serviceName), nil
}

func (b *launchdBackend) Stop(serviceName, targetPath string) (string, error) {
	info := b.query(serviceName, targetPath)
	if !info.Loaded || info.State != "running" {
		return fmt.Sprintf("Service %s is not currently running.", serviceName), nil
	}

	_, target := getLaunchdTarget(serviceName)
	plistPath := findLaunchdPlist(serviceName, targetPath)

	out, err := b.run("launchctl", "bootout", target)
	if err != nil {
		if _, unloadErr := b.run("launchctl", "unload", plistPath); unloadErr != nil {
			return "", fmt.Errorf("failed to stop service: %s (%v)", strings.TrimSpace(string(out)), err)
		}
	}

	b.waitUntil(6, func() bool {
		check := b.query(serviceName, targetPath)
		return !check.Loaded || check.State != "running"
	})
	return fmt.Sprintf("Successfully stopped %s service.", serviceName), nil
}

func (b *launchdBackend) Restart(serviceName, targetPath string) (string, error) {
	info := b.query(serviceName, targetPath)
	if !info.Loaded {
		return b.Start(serviceName, targetPath)
	}

	_, target := getLaunchdTarget(serviceName)
	if _, err := b.run("launchctl", "kickstart", "-k", "-p", target); err != nil {
		if _, stopErr := b.Stop(serviceName, targetPath); stopErr != nil {
			return "", stopErr
		}
		return b.Start(serviceName, targetPath)
	}

	var newPID int
	if b.waitUntil(6, func() bool {
		check := b.query(serviceName, targetPath)
		if check.State == "running" && check.PID > 0 && check.PID != info.PID {
			newPID = check.PID
			return true
		}
		return false
	}) {
		return fmt.Sprintf("Successfully restarted %s service (new PID: %d).", serviceName, newPID), nil
	}
	return fmt.Sprintf("Triggered restart for %s service.", serviceName), nil
}

func (b *launchdBackend) Uninstall(serviceName, targetPath string) (string, error) {
	plistPath := findLaunchdPlist(serviceName, targetPath)
	_, target := getLaunchdTarget(serviceName)

	_, _ = b.run("launchctl", "bootout", target)
	_, _ = b.run("launchctl", "unload", plistPath)

	if _, err := os.Stat(plistPath); err == nil {
		if err := os.Remove(plistPath); err != nil {
			return "", fmt.Errorf("failed to remove service file %s: %w", plistPath, err)
		}
		return fmt.Sprintf("Successfully stopped and uninstalled %s service (removed %s).", serviceName, plistPath), nil
	}
	return fmt.Sprintf("Service %s uninstalled from launchd.", serviceName), nil
}

type processStats struct {
	uptime string
	memory string
	cpu    string
}

func (b *launchdBackend) queryProcessStats(pid int) (processStats, bool) {
	procOut, err := b.run("ps", "-p", strconv.Itoa(pid), "-o", "%cpu,%mem,rss,etime")
	if err != nil {
		return processStats{}, false
	}
	lines := strings.Split(strings.TrimSpace(string(procOut)), "\n")
	if len(lines) < 2 {
		return processStats{}, false
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return processStats{}, false
	}
	rssKB, _ := strconv.Atoi(fields[2])
	return processStats{
		uptime: fields[3],
		memory: fmt.Sprintf("%.1f MB RSS (%s%%)", float64(rssKB)/1024.0, fields[1]),
		cpu:    fields[0] + "%",
	}, true
}

func (b *launchdBackend) Status(serviceName, targetPath string) (string, error) {
	plistPath := findLaunchdPlist(serviceName, targetPath)
	info := b.query(serviceName, targetPath)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("● %s (macOS launchd)\n", serviceName))
	sb.WriteString(fmt.Sprintf("   Label:       %s\n", serviceName))

	if !info.Loaded {
		if _, err := os.Stat(plistPath); err == nil {
			sb.WriteString("   State:       Installed (stopped / not loaded)\n")
			sb.WriteString(fmt.Sprintf("   Plist:       %s\n", plistPath))
			sb.WriteString("   Tip:         Run 'server-monitor service start' to start the service.\n")
		} else {
			sb.WriteString("   State:       Not installed\n")
			sb.WriteString("   Tip:         Run 'server-monitor service install' to install the service.\n")
		}
		return sb.String(), nil
	}

	if info.State == "running" && info.PID > 0 {
		sb.WriteString("   State:       Active (running)\n")
		sb.WriteString(fmt.Sprintf("   PID:         %d\n", info.PID))
		if stats, ok := b.queryProcessStats(info.PID); ok {
			sb.WriteString(fmt.Sprintf("   Uptime:      %s\n", stats.uptime))
			sb.WriteString(fmt.Sprintf("   Memory:      %s\n", stats.memory))
			sb.WriteString(fmt.Sprintf("   CPU:         %s\n", stats.cpu))
		}
	} else {
		sb.WriteString(fmt.Sprintf("   State:       Inactive (%s)\n", info.State))
	}

	if info.PlistPath != "" {
		sb.WriteString(fmt.Sprintf("   Plist:       %s\n", info.PlistPath))
	}
	if info.StdoutPath != "" {
		sb.WriteString(fmt.Sprintf("   Stdout Log:  %s\n", info.StdoutPath))
	}
	if info.StderrPath != "" {
		sb.WriteString(fmt.Sprintf("   Stderr Log:  %s\n", info.StderrPath))
	}

	return sb.String(), nil
}
