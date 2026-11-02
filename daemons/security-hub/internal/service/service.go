package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const LaunchdLabel = "me.jaewook.nal.security-hub"

func DefaultPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist")
}

func GenerateLaunchdPlist(binaryPath, workingDir string) string {
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
`, LaunchdLabel, binaryPath, workingDir, workingDir, workingDir)
}

func InstallPlist(destPath, binaryPath, workingDir string) error {
	if destPath == "" {
		destPath = DefaultPlistPath()
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	content := GenerateLaunchdPlist(binaryPath, workingDir)
	return os.WriteFile(destPath, []byte(content), 0644)
}

func Start() error {
	plist := DefaultPlistPath()
	_ = exec.Command("launchctl", "load", "-w", plist).Run()
	return exec.Command("launchctl", "start", LaunchdLabel).Run()
}

func Stop() error {
	return exec.Command("launchctl", "stop", LaunchdLabel).Run()
}

func Restart() error {
	_ = Stop()
	return Start()
}

func Status() (string, error) {
	out, err := exec.Command("launchctl", "list").CombinedOutput()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, LaunchdLabel) {
			return strings.TrimSpace(line), nil
		}
	}
	return "not running / not loaded", nil
}
