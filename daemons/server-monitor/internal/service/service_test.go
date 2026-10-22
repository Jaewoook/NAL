package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSystemdUnit(t *testing.T) {
	opts := ServiceOptions{
		BinaryPath:  "/usr/local/bin/server-monitor",
		ConfigPath:  "/etc/server-monitor/config.yaml",
		User:        "monitoruser",
		WorkingDir:  "/var/lib/server-monitor",
		ServiceName: "server-monitor",
		Description: "Physical Server Monitor Service",
	}

	unit := GenerateSystemdUnit(opts)

	expectedStrings := []string{
		"[Unit]",
		"Description=Physical Server Monitor Service",
		"After=network.target",
		"[Service]",
		"Type=simple",
		"User=monitoruser",
		"WorkingDirectory=/var/lib/server-monitor",
		"ExecStart=/usr/local/bin/server-monitor run -config /etc/server-monitor/config.yaml",
		"Restart=always",
		"RestartSec=5s",
		"[Install]",
		"WantedBy=multi-user.target",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(unit, s) {
			t.Errorf("systemd unit missing expected string %q\nFull output:\n%s", s, unit)
		}
	}
}

func TestGenerateLaunchdPlist(t *testing.T) {
	opts := ServiceOptions{
		BinaryPath:  "/opt/homebrew/bin/server-monitor",
		ConfigPath:  "/Users/admin/.config/server-monitor/config.yaml",
		ServiceName: "com.jaewook.server-monitor",
	}

	plist := GenerateLaunchdPlist(opts)

	expectedStrings := []string{
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
		"<plist version=\"1.0\">",
		"<key>Label</key>",
		"<string>com.jaewook.server-monitor</string>",
		"<key>ProgramArguments</key>",
		"<string>/opt/homebrew/bin/server-monitor</string>",
		"<string>run</string>",
		"<string>-config</string>",
		"<string>/Users/admin/.config/server-monitor/config.yaml</string>",
		"<key>RunAtLoad</key>",
		"<true/>",
		"<key>KeepAlive</key>",
		"<true/>",
		"<key>StandardErrorPath</key>",
		"<key>StandardOutPath</key>",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(plist, s) {
			t.Errorf("launchd plist missing expected string %q\nFull output:\n%s", s, plist)
		}
	}
}

func TestGenerateDispatch(t *testing.T) {
	opts := ServiceOptions{
		BinaryPath: "/usr/bin/server-monitor",
		ConfigPath: "/etc/config.yaml",
	}

	sysd, err := Generate("systemd", opts)
	if err != nil {
		t.Fatalf("unexpected error generating systemd: %v", err)
	}
	if !strings.Contains(sysd, "[Unit]") {
		t.Errorf("expected systemd content, got: %s", sysd)
	}

	launchd, err := Generate("launchd", opts)
	if err != nil {
		t.Fatalf("unexpected error generating launchd: %v", err)
	}
	if !strings.Contains(launchd, "<plist") {
		t.Errorf("expected launchd content, got: %s", launchd)
	}

	_, err = Generate("invalid_type", opts)
	if err == nil {
		t.Fatalf("expected error for unsupported service type, got nil")
	}
}

func TestInstallWriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "server-monitor.service")

	opts := ServiceOptions{
		BinaryPath: "/usr/bin/server-monitor",
		ConfigPath: "/etc/server-monitor.yaml",
	}

	err := Install("systemd", opts, targetPath)
	if err != nil {
		t.Fatalf("unexpected error installing service: %v", err)
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed to read installed service file: %v", err)
	}

	if !strings.Contains(string(data), "ExecStart=/usr/bin/server-monitor run -config /etc/server-monitor.yaml") {
		t.Errorf("installed content incorrect: %s", string(data))
	}
}
