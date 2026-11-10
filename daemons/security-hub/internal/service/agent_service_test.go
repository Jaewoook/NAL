package service_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaewoook/security-hub/internal/service"
)

func TestAgentService_GenerateLaunchdAndSystemd(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath:   "/usr/local/bin/security-hub",
		WorkingDir:   "/var/lib/security-hub",
		Name:         "MacStudio-M2",
		Host:         "0.0.0.0",
		Port:         10247,
		Token:        "super-secret-token",
		HubURL:       "http://hub.lan:10311",
		AdvertiseURL: "http://192.168.1.50:10247",
	}

	// 1. Launchd plist verification
	plist := service.GenerateAgentLaunchdPlist(opts)
	if !strings.Contains(plist, "me.jaewook.nal.security-hub-agent") {
		t.Errorf("expected AgentLaunchdLabel in plist, got: %s", plist)
	}
	for _, expected := range []string{
		"<string>agent</string>",
		"<string>-host</string>",
		"<string>0.0.0.0</string>",
		"<string>-port</string>",
		"<string>10247</string>",
		"<string>-token</string>",
		"<string>super-secret-token</string>",
		"<string>-hub</string>",
		"<string>http://hub.lan:10311</string>",
		"<string>-name</string>",
		"<string>MacStudio-M2</string>",
		"<string>-advertise-url</string>",
		"<string>http://192.168.1.50:10247</string>",
		"/var/lib/security-hub/security-hub-agent.stdout.log",
		"/var/lib/security-hub/security-hub-agent.stderr.log",
	} {
		if !strings.Contains(plist, expected) {
			t.Errorf("expected plist to contain %q, but it did not:\n%s", expected, plist)
		}
	}

	// Also verify service.AgentService.GenerateLaunchdPlist(opts)
	if service.AgentService.GenerateLaunchdPlist(opts) != plist {
		t.Errorf("AgentService.GenerateLaunchdPlist mismatch")
	}

	// 2. Systemd unit verification
	unit := service.GenerateAgentSystemdUnit(opts)
	for _, expected := range []string{
		"[Unit]",
		"[Service]",
		"ExecStart=/usr/local/bin/security-hub agent",
		"-host 0.0.0.0",
		"-port 10247",
		"-token super-secret-token",
		"-hub http://hub.lan:10311",
		"-name MacStudio-M2",
		"-advertise-url http://192.168.1.50:10247",
		"Restart=always",
		"[Install]",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("expected systemd unit to contain %q, but it did not:\n%s", expected, unit)
		}
	}

	// Also verify GenerateSystemdUnit alias
	if service.GenerateSystemdUnit(opts) != unit {
		t.Errorf("GenerateSystemdUnit alias mismatch")
	}
	if service.AgentService.GenerateSystemdUnit(opts) != unit {
		t.Errorf("AgentService.GenerateSystemdUnit mismatch")
	}
}

func TestAgentService_InstallCustomPath(t *testing.T) {
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "custom-agent-service.file")

	opts := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		WorkingDir: tmpDir,
		Host:       "127.0.0.1",
		Port:       10247,
		Token:      "tok123",
		HubURL:     "http://hub.lan:10311",
		CustomPath: customPath,
	}

	if err := service.InstallAgent(opts); err != nil {
		t.Fatalf("InstallAgent with CustomPath failed: %v", err)
	}

	content, err := os.ReadFile(customPath)
	if err != nil {
		t.Fatalf("failed to read installed custom service file: %v", err)
	}
	sContent := string(content)
	if !strings.Contains(sContent, "agent") || !strings.Contains(sContent, "tok123") {
		t.Fatalf("installed content missing expected fields: %s", sContent)
	}
}

func TestAgentService_SystemdWhitespaceQuoting(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath: "/opt/My Security Hub/security-hub",
		WorkingDir: "/var/lib/security-hub",
		Name:       "Mac Studio M2",
		Token:      "super secret token",
		HubURL:     "http://hub.lan:10311",
	}

	unit := service.GenerateAgentSystemdUnit(opts)
	for _, expected := range []string{
		`ExecStart="/opt/My Security Hub/security-hub" agent`,
		`-name "Mac Studio M2"`,
		`-token "super secret token"`,
		`-hub http://hub.lan:10311`,
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("expected systemd unit to contain %q, but it did not:\n%s", expected, unit)
		}
	}
}

func TestAgentService_SystemdUserVsSystemTarget(t *testing.T) {
	optsSystem := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		IsUser:     false,
	}
	unitSystem := service.GenerateAgentSystemdUnit(optsSystem)
	if !strings.Contains(unitSystem, "WantedBy=multi-user.target") {
		t.Fatalf("expected system unit to have WantedBy=multi-user.target, got:\n%s", unitSystem)
	}

	optsUser := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		IsUser:     true,
	}
	unitUser := service.GenerateAgentSystemdUnit(optsUser)
	if !strings.Contains(unitUser, "WantedBy=default.target") {
		t.Fatalf("expected user unit to have WantedBy=default.target, got:\n%s", unitUser)
	}
	if strings.Contains(unitUser, "WantedBy=multi-user.target") {
		t.Fatalf("did not expect user unit to have WantedBy=multi-user.target, got:\n%s", unitUser)
	}
}

