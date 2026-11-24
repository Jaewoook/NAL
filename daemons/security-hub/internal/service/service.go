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

func DefaultPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist")
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
	escapedBin := escapeXML(stripControlChars(binaryPath))
	escapedDir := escapeXML(stripControlChars(workingDir))
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
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
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
`, LaunchdLabel, escapedBin, escapedDir, escapedDir, escapedDir)
}

func InstallPlist(destPath, binaryPath, workingDir string) error {
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

	if destPath == "" {
		destPath = DefaultPlistPath()
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	content := GenerateLaunchdPlist(absBin, absWD)
	return fsutil.WriteFileAtomic(destPath, []byte(content), 0600)
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

func Start() error {
	return startLaunchdService(DefaultPlistPath(), LaunchdLabel, "security-hub service install")
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
	return launchdStatus(LaunchdLabel)
}
