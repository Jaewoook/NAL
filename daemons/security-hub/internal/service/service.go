package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jaewoook/security-hub/internal/fsutil"
)

var cmdRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// SetCmdRunner overrides the command runner for tests and returns a restore function.
func SetCmdRunner(fn func(name string, args ...string) ([]byte, error)) func() {
	prev := cmdRunner
	if fn != nil {
		cmdRunner = fn
	}
	return func() {
		cmdRunner = prev
	}
}

const LaunchdLabel = "me.jaewook.nal.security-hub"

const (
	AgentLaunchdLabel = "me.jaewook.nal.security-hub-agent"
	AgentSystemdUnit  = "security-hub-agent.service"
)

var systemPlistPath = filepath.Join("/Library", "LaunchDaemons", LaunchdLabel+".plist")

func DefaultPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist")
}

func DefaultSystemPlistPath() string {
	return systemPlistPath
}

// SetSystemPlistPath overrides the LaunchDaemon plist path for tests and returns a restore function.
func SetSystemPlistPath(p string) func() {
	prev := systemPlistPath
	systemPlistPath = p
	return func() {
		systemPlistPath = prev
	}
}

// IsSystemHubInstalled reports whether the Hub LaunchDaemon plist is installed in /Library/LaunchDaemons.
func IsSystemHubInstalled() bool {
	return hasSystemHubPlist()
}

// RemoveLegacyUserHubAgent stops and removes a legacy user LaunchAgent plist if present.
func RemoveLegacyUserHubAgent() error {
	plist := DefaultPlistPath()
	if _, err := os.Stat(plist); os.IsNotExist(err) {
		return nil
	}
	if err := stopLaunchdService(plist, LaunchdLabel); err != nil {
		return err
	}
	if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func DefaultAgentPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", AgentLaunchdLabel+".plist")
}

func DefaultAgentSystemdPath() string {
	if os.Geteuid() == 0 {
		return filepath.Join("/etc", "systemd", "system", AgentSystemdUnit)
	}
	if isDirWritable("/etc/systemd/system") {
		return filepath.Join("/etc", "systemd", "system", AgentSystemdUnit)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", AgentSystemdUnit)
}

func isDirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	tmpFile := filepath.Join(dir, fmt.Sprintf(".perm_test_%d", os.Getpid()))
	if err := os.WriteFile(tmpFile, []byte(""), 0600); err != nil {
		return false
	}
	_ = os.Remove(tmpFile)
	return true
}

func validateNoControlChars(field, val string) error {
	for i := 0; i < len(val); i++ {
		if val[i] == '\n' || val[i] == '\r' || val[i] == 0 {
			return fmt.Errorf("%s contains disallowed control character", field)
		}
	}
	return nil
}

func stripControlChars(val string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(val)
}

func GenerateLaunchdPlist(binaryPath, workingDir string) string {
	return GenerateLaunchdPlistWithUser(binaryPath, workingDir, "", "")
}

func GenerateLaunchdPlistWithUser(binaryPath, workingDir, userName, homeDir string) string {
	escapedBin := escapeXML(stripControlChars(binaryPath))
	escapedDir := escapeXML(stripControlChars(workingDir))

	userBlock := ""
	if strings.TrimSpace(userName) != "" {
		userBlock = fmt.Sprintf("    <key>UserName</key>\n    <string>%s</string>\n", escapeXML(stripControlChars(strings.TrimSpace(userName))))
	}
	homeEnvBlock := ""
	if strings.TrimSpace(homeDir) != "" {
		homeEnvBlock = fmt.Sprintf("        <key>HOME</key>\n        <string>%s</string>\n", escapeXML(stripControlChars(strings.TrimSpace(homeDir))))
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
%s    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>hub</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>%s</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s/security-hub.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>%s/security-hub.stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
%s        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
`, LaunchdLabel, userBlock, escapedBin, escapedDir, escapedDir, escapedDir, homeEnvBlock)
}

func InstallPlist(destPath, binaryPath, workingDir string) error {
	return InstallHubPlist(destPath, binaryPath, workingDir, "", "")
}

func InstallHubPlist(destPath, binaryPath, workingDir, userName, homeDir string) error {
	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve executable path: %w", err)
		}
		binaryPath = exe
	}
	if err := validateNoControlChars("binaryPath", binaryPath); err != nil {
		return err
	}
	absBin, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to resolve binaryPath %q: %w", binaryPath, err)
	}

	workingDir = strings.TrimSpace(workingDir)
	if workingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to resolve working directory: %w", err)
		}
		workingDir = wd
	}
	if err := validateNoControlChars("workingDir", workingDir); err != nil {
		return err
	}
	absWD, err := filepath.Abs(workingDir)
	if err != nil {
		return fmt.Errorf("failed to resolve workingDir %q: %w", workingDir, err)
	}
	if err := validateNoControlChars("userName", userName); err != nil {
		return err
	}
	if err := validateNoControlChars("homeDir", homeDir); err != nil {
		return err
	}

	if destPath == "" {
		if os.Geteuid() == 0 {
			destPath = DefaultSystemPlistPath()
		} else {
			destPath = DefaultPlistPath()
		}
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	perm := os.FileMode(0600)
	if strings.HasPrefix(destPath, "/Library/LaunchDaemons/") {
		perm = 0644
	}
	content := GenerateLaunchdPlistWithUser(absBin, absWD, userName, homeDir)
	return fsutil.WriteFileAtomic(destPath, []byte(content), perm)
}

func startLaunchdService(plist, label, installCmd string) error {
	if _, err := os.Stat(plist); os.IsNotExist(err) {
		return fmt.Errorf("launchd plist not found at %s; run '%s' first", plist, installCmd)
	}
	if err := stopLaunchdService(plist, label); err != nil {
		return err
	}
	if out, err := cmdRunner("launchctl", "load", "-w", plist); err != nil {
		return fmt.Errorf("failed to load launchd service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := cmdRunner("launchctl", "start", label); err != nil {
		return fmt.Errorf("failed to start launchd service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func hasSystemHubPlist() bool {
	_, err := os.Stat(DefaultSystemPlistPath())
	return err == nil
}

func startSystemLaunchdService(plist, label string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("hub LaunchDaemon at %s requires root privileges; run with sudo", plist)
	}
	_ = stopSystemLaunchdService(label)
	if out, err := cmdRunner("launchctl", "bootstrap", "system", plist); err != nil {
		return fmt.Errorf("failed to bootstrap LaunchDaemon %s: %w (%s)", plist, err, strings.TrimSpace(string(out)))
	}
	if out, err := cmdRunner("launchctl", "kickstart", "-k", "system/"+label); err != nil {
		return fmt.Errorf("failed to kickstart LaunchDaemon %s: %w (%s)", label, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopSystemLaunchdService(label string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("hub LaunchDaemon requires root privileges; run with sudo")
	}
	if out, err := cmdRunner("launchctl", "bootout", "system/"+label); err != nil && !isLaunchctlNotLoaded(err, string(out)) {
		return fmt.Errorf("launchctl bootout system/%s failed: %w (%s)", label, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func systemLaunchdStatus(label string) (string, error) {
	out, err := cmdRunner("launchctl", "print", "system/"+label)
	if err != nil {
		if isLaunchctlNotLoaded(err, string(out)) {
			return "not running / not loaded (LaunchDaemon)", nil
		}
		return "", fmt.Errorf("launchctl print system/%s failed: %w (%s)", label, err, strings.TrimSpace(string(out)))
	}
	pid := ""
	state := ""
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "pid = ") {
			pid = strings.TrimPrefix(trimmed, "pid = ")
		} else if strings.HasPrefix(trimmed, "state = ") {
			state = strings.TrimPrefix(trimmed, "state = ")
		}
	}
	if pid != "" {
		return fmt.Sprintf("running (LaunchDaemon, pid=%s, state=%s)", pid, state), nil
	}
	if state != "" {
		return fmt.Sprintf("loaded (LaunchDaemon, state=%s)", state), nil
	}
	return "loaded (LaunchDaemon)", nil
}

func Start() error {
	if hasSystemHubPlist() {
		return startSystemLaunchdService(DefaultSystemPlistPath(), LaunchdLabel)
	}
	return startLaunchdService(DefaultPlistPath(), LaunchdLabel, "security-hub hub service install")
}

func isLaunchctlNotLoaded(err error, out string) bool {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		code := coded.ExitCode()
		if code == 3 || code == 113 {
			return true
		}
	}
	lower := strings.ToLower(out)
	return strings.Contains(lower, "could not find specified service") ||
		strings.Contains(lower, "could not find service") ||
		strings.Contains(lower, "no such process") ||
		strings.Contains(lower, "unload failed: 5:")
}

func stopLaunchdService(plist, label string) error {
	if out, err := cmdRunner("launchctl", "list", label); err != nil {
		if isLaunchctlNotLoaded(err, string(out)) {
			return nil
		}
		return fmt.Errorf("launchctl list failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(plist); err == nil {
		if out, err := cmdRunner("launchctl", "unload", "-w", plist); err != nil && !isLaunchctlNotLoaded(err, string(out)) {
			return fmt.Errorf("launchctl unload failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if out, err := cmdRunner("launchctl", "remove", label); err != nil && !isLaunchctlNotLoaded(err, string(out)) {
		return fmt.Errorf("launchctl remove failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func Stop() error {
	if hasSystemHubPlist() {
		return stopSystemLaunchdService(LaunchdLabel)
	}
	return stopLaunchdService(DefaultPlistPath(), LaunchdLabel)
}

func Restart() error {
	if err := Stop(); err != nil {
		return err
	}
	return Start()
}

func launchdStatus(label string) (string, error) {
	out, err := cmdRunner("launchctl", "list")
	if err != nil {
		return "", fmt.Errorf("launchctl list failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[len(fields)-1] == label {
			return strings.TrimSpace(line), nil
		}
	}
	return "not running / not loaded", nil
}

func Status() (string, error) {
	if hasSystemHubPlist() {
		return systemLaunchdStatus(LaunchdLabel)
	}
	return launchdStatus(LaunchdLabel)
}
