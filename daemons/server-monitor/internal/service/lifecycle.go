package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var execCommand = func(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// SetCommandRunner allows overriding the command execution function for testing.
func SetCommandRunner(runner func(name string, args ...string) ([]byte, error)) {
	if runner != nil {
		execCommand = runner
	} else {
		execCommand = func(name string, args ...string) ([]byte, error) {
			cmd := exec.Command(name, args...)
			return cmd.CombinedOutput()
		}
	}
}

func resolveServiceType(st string) string {
	if st != "" {
		return strings.ToLower(st)
	}
	if runtime.GOOS == "darwin" {
		return "launchd"
	}
	return "systemd"
}

// findLaunchdPlist attempts to locate the plist file on disk for a service.
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

type launchdInfo struct {
	Loaded     bool
	State      string
	PID        int
	PlistPath  string
	StdoutPath string
	StderrPath string
}

func parseLaunchdPrint(output string, info *launchdInfo) {
	stateRe := regexp.MustCompile(`(?m)^\s*state\s*=\s*(\w+)`)
	pidRe := regexp.MustCompile(`(?m)^\s*pid\s*=\s*(\d+)`)
	pathRe := regexp.MustCompile(`(?m)^\s*path\s*=\s*(.+)`)
	stdoutRe := regexp.MustCompile(`(?m)^\s*stdout path\s*=\s*(.+)`)
	stderrRe := regexp.MustCompile(`(?m)^\s*stderr path\s*=\s*(.+)`)

	if m := stateRe.FindStringSubmatch(output); len(m) > 1 {
		info.State = m[1]
	}
	if m := pidRe.FindStringSubmatch(output); len(m) > 1 {
		info.PID, _ = strconv.Atoi(m[1])
	}
	if m := pathRe.FindStringSubmatch(output); len(m) > 1 && info.PlistPath == "" {
		info.PlistPath = strings.TrimSpace(m[1])
	}
	if m := stdoutRe.FindStringSubmatch(output); len(m) > 1 {
		info.StdoutPath = strings.TrimSpace(m[1])
	}
	if m := stderrRe.FindStringSubmatch(output); len(m) > 1 {
		info.StderrPath = strings.TrimSpace(m[1])
	}
}

func parseLaunchdList(output string, info *launchdInfo) {
	pidRe := regexp.MustCompile(`"PID"\s*=\s*(\d+)`)
	stdoutRe := regexp.MustCompile(`"StandardOutPath"\s*=\s*"([^"]+)"`)
	stderrRe := regexp.MustCompile(`"StandardErrorPath"\s*=\s*"([^"]+)"`)

	if m := pidRe.FindStringSubmatch(output); len(m) > 1 {
		info.PID, _ = strconv.Atoi(m[1])
		info.State = "running"
	} else {
		info.State = "not running"
	}
	if m := stdoutRe.FindStringSubmatch(output); len(m) > 1 {
		info.StdoutPath = m[1]
	}
	if m := stderrRe.FindStringSubmatch(output); len(m) > 1 {
		info.StderrPath = m[1]
	}
}

func queryLaunchd(serviceName, customPath string) launchdInfo {
	var info launchdInfo
	info.PlistPath = findLaunchdPlist(serviceName, customPath)
	_, target := getLaunchdTarget(serviceName)

	out, err := execCommand("launchctl", "print", target)
	if err == nil {
		info.Loaded = true
		parseLaunchdPrint(string(out), &info)
		return info
	}

	// Fallback to launchctl list
	listOut, listErr := execCommand("launchctl", "list", serviceName)
	if listErr == nil {
		info.Loaded = true
		parseLaunchdList(string(listOut), &info)
		return info
	}

	info.Loaded = false
	return info
}

// StartService starts the background service.
func StartService(serviceType, serviceName, targetPath string) (string, error) {
	if serviceName == "" {
		serviceName = "server-monitor"
	}
	st := resolveServiceType(serviceType)

	switch st {
	case "launchd":
		info := queryLaunchd(serviceName, targetPath)
		if info.Loaded && info.State == "running" && info.PID > 0 {
			return fmt.Sprintf("Service %s is already running (PID: %d).", serviceName, info.PID), nil
		}

		domain, target := getLaunchdTarget(serviceName)
		plistPath := findLaunchdPlist(serviceName, targetPath)
		if _, err := os.Stat(plistPath); err != nil {
			return "", fmt.Errorf("service file not found at %s. Run 'server-monitor service install' first", plistPath)
		}

		if !info.Loaded {
			if out, err := execCommand("launchctl", "bootstrap", domain, plistPath); err != nil {
				if _, loadErr := execCommand("launchctl", "load", plistPath); loadErr != nil {
					return "", fmt.Errorf("failed to load service into launchd: %s (%v)", strings.TrimSpace(string(out)), err)
				}
			}
		}

		_, _ = execCommand("launchctl", "kickstart", "-p", target)

		for i := 0; i < 6; i++ {
			time.Sleep(500 * time.Millisecond)
			check := queryLaunchd(serviceName, targetPath)
			if check.State == "running" && check.PID > 0 {
				return fmt.Sprintf("Successfully started %s service (PID: %d).", serviceName, check.PID), nil
			}
		}
		return fmt.Sprintf("Service %s start command issued.", serviceName), nil

	case "systemd":
		unitName := serviceName + ".service"
		out, err := execCommand("systemctl", "start", unitName)
		if err != nil {
			return "", fmt.Errorf("failed to start %s: %s (%v)", unitName, strings.TrimSpace(string(out)), err)
		}
		return fmt.Sprintf("Successfully started %s.", unitName), nil

	default:
		return "", fmt.Errorf("unsupported service type: %s", st)
	}
}

// StopService stops the background service.
func StopService(serviceType, serviceName, targetPath string) (string, error) {
	if serviceName == "" {
		serviceName = "server-monitor"
	}
	st := resolveServiceType(serviceType)

	switch st {
	case "launchd":
		info := queryLaunchd(serviceName, targetPath)
		if !info.Loaded || info.State != "running" {
			return fmt.Sprintf("Service %s is not currently running.", serviceName), nil
		}

		_, target := getLaunchdTarget(serviceName)
		plistPath := findLaunchdPlist(serviceName, targetPath)

		out, err := execCommand("launchctl", "bootout", target)
		if err != nil {
			if _, unloadErr := execCommand("launchctl", "unload", plistPath); unloadErr != nil {
				return "", fmt.Errorf("failed to stop service: %s (%v)", strings.TrimSpace(string(out)), err)
			}
		}

		for i := 0; i < 6; i++ {
			time.Sleep(500 * time.Millisecond)
			check := queryLaunchd(serviceName, targetPath)
			if !check.Loaded || check.State != "running" {
				break
			}
		}
		return fmt.Sprintf("Successfully stopped %s service.", serviceName), nil

	case "systemd":
		unitName := serviceName + ".service"
		out, err := execCommand("systemctl", "stop", unitName)
		if err != nil {
			return "", fmt.Errorf("failed to stop %s: %s (%v)", unitName, strings.TrimSpace(string(out)), err)
		}
		return fmt.Sprintf("Successfully stopped %s.", unitName), nil

	default:
		return "", fmt.Errorf("unsupported service type: %s", st)
	}
}

// RestartService restarts the background service.
func RestartService(serviceType, serviceName, targetPath string) (string, error) {
	if serviceName == "" {
		serviceName = "server-monitor"
	}
	st := resolveServiceType(serviceType)

	switch st {
	case "launchd":
		info := queryLaunchd(serviceName, targetPath)
		if !info.Loaded {
			return StartService(serviceType, serviceName, targetPath)
		}

		_, target := getLaunchdTarget(serviceName)
		_, err := execCommand("launchctl", "kickstart", "-k", "-p", target)
		if err != nil {
			if _, stopErr := StopService(serviceType, serviceName, targetPath); stopErr != nil {
				return "", stopErr
			}
			return StartService(serviceType, serviceName, targetPath)
		}

		for i := 0; i < 6; i++ {
			time.Sleep(500 * time.Millisecond)
			check := queryLaunchd(serviceName, targetPath)
			if check.State == "running" && check.PID > 0 && check.PID != info.PID {
				return fmt.Sprintf("Successfully restarted %s service (new PID: %d).", serviceName, check.PID), nil
			}
		}
		return fmt.Sprintf("Triggered restart for %s service.", serviceName), nil

	case "systemd":
		unitName := serviceName + ".service"
		out, err := execCommand("systemctl", "restart", unitName)
		if err != nil {
			return "", fmt.Errorf("failed to restart %s: %s (%v)", unitName, strings.TrimSpace(string(out)), err)
		}
		return fmt.Sprintf("Successfully restarted %s.", unitName), nil

	default:
		return "", fmt.Errorf("unsupported service type: %s", st)
	}
}

// UninstallService unloads and removes the background service.
func UninstallService(serviceType, serviceName, targetPath string) (string, error) {
	if serviceName == "" {
		serviceName = "server-monitor"
	}
	st := resolveServiceType(serviceType)

	switch st {
	case "launchd":
		plistPath := findLaunchdPlist(serviceName, targetPath)
		_, target := getLaunchdTarget(serviceName)

		_, _ = execCommand("launchctl", "bootout", target)
		_, _ = execCommand("launchctl", "unload", plistPath)

		if _, err := os.Stat(plistPath); err == nil {
			if err := os.Remove(plistPath); err != nil {
				return "", fmt.Errorf("failed to remove service file %s: %w", plistPath, err)
			}
			return fmt.Sprintf("Successfully stopped and uninstalled %s service (removed %s).", serviceName, plistPath), nil
		}
		return fmt.Sprintf("Service %s uninstalled from launchd.", serviceName), nil

	case "systemd":
		unitName := serviceName + ".service"
		_, _ = execCommand("systemctl", "stop", unitName)
		_, _ = execCommand("systemctl", "disable", unitName)

		unitPath := targetPath
		if unitPath == "" {
			unitPath = "/etc/systemd/system/" + unitName
		}
		if _, err := os.Stat(unitPath); err == nil {
			if err := os.Remove(unitPath); err != nil {
				return "", fmt.Errorf("failed to remove unit file %s: %w", unitPath, err)
			}
		}
		_, _ = execCommand("systemctl", "daemon-reload")
		return fmt.Sprintf("Successfully uninstalled %s (removed %s).", unitName, unitPath), nil

	default:
		return "", fmt.Errorf("unsupported service type: %s", st)
	}
}

// StatusService queries and formats the status of the background service.
func StatusService(serviceType, serviceName, targetPath string) (string, error) {
	if serviceName == "" {
		serviceName = "server-monitor"
	}
	st := resolveServiceType(serviceType)

	switch st {
	case "launchd":
		plistPath := findLaunchdPlist(serviceName, targetPath)
		info := queryLaunchd(serviceName, targetPath)

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

			// Query process metrics via ps
			if procOut, err := execCommand("ps", "-p", strconv.Itoa(info.PID), "-o", "%cpu,%mem,rss,etime"); err == nil {
				lines := strings.Split(strings.TrimSpace(string(procOut)), "\n")
				if len(lines) >= 2 {
					fields := strings.Fields(lines[1])
					if len(fields) >= 4 {
						cpu := fields[0] + "%"
						rssKB, _ := strconv.Atoi(fields[2])
						memMB := fmt.Sprintf("%.1f MB RSS (%s%%)", float64(rssKB)/1024.0, fields[1])
						uptime := fields[3]
						sb.WriteString(fmt.Sprintf("   Uptime:      %s\n", uptime))
						sb.WriteString(fmt.Sprintf("   Memory:      %s\n", memMB))
						sb.WriteString(fmt.Sprintf("   CPU:         %s\n", cpu))
					}
				}
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

	case "systemd":
		unitName := serviceName + ".service"
		out, _ := execCommand("systemctl", "status", unitName)
		if len(out) > 0 {
			return string(out), nil
		}
		return fmt.Sprintf("● %s (Linux systemd)\n   State: Not active or not installed\n", unitName), nil

	default:
		return "", fmt.Errorf("unsupported service type: %s", st)
	}
}
