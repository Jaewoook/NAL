package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/service"
)

func TestCLI_LoginLinkAndServicePlist(t *testing.T) {
	plist := service.GenerateLaunchdPlist("/Users/jaewookahn/repos/NAL/daemons/security-hub/security-hub", "/Users/jaewookahn/repos/NAL/daemons/security-hub")
	if !strings.Contains(plist, "me.jaewook.nal.security-hub") || !strings.Contains(plist, "<string>run</string>") {
		t.Fatalf("unexpected launchd plist: %s", plist)
	}

	tmpDir := t.TempDir()
	t.Setenv("SECURITY_HUB_DATA_DIR", tmpDir)
	t.Setenv("SECURITY_HUB_PUBLIC_URL", "http://localhost:10311")
	isoCfgDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(isoCfgDir, "config.yml"), []byte("database:\n  container_name: nonexistent-unit-test-pg\n"), 0600)
	startWD, _ := os.Getwd()
	_ = os.Chdir(isoCfgDir)
	defer func() { _ = os.Chdir(startWD) }()

	var out bytes.Buffer
	code := runCLI([]string{"auth", "login-link"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for auth login-link, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "http://localhost:10311/api/auth/token-login?token=") {
		t.Fatalf("expected break-glass login URL in output, got: %s", out.String())
	}

	// Verify plist install to file
	plistPath := filepath.Join(tmpDir, "me.jaewook.nal.security-hub.plist")
	out.Reset()
	code = runCLI([]string{"service", "install", "-path", plistPath}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for service install, got %d (%s)", code, out.String())
	}

	// Verify CLI node add / list / remove
	out.Reset()
	if code := runCLI([]string{"node", "add", "Atlas", "http://192.168.1.50:10247/", "-token", "sec"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for node add, got %d (%s)", code, out.String())
	}
	out.Reset()
	if code := runCLI([]string{"node", "list"}, &out); code != 0 || !strings.Contains(out.String(), "Atlas") {
		t.Fatalf("expected Atlas in node list output, got code=%d out=%s", code, out.String())
	}
	// Verify trailing slash was trimmed in node list
	if strings.Contains(out.String(), "http://192.168.1.50:10247/") {
		t.Fatalf("expected trailing slash to be trimmed from node URL, got: %s", out.String())
	}
	// Verify node add conflicts with hub name
	hubName := config.DefaultNodeName()
	out.Reset()
	if code := runCLI([]string{"node", "add", hubName, "http://192.168.1.50:10247"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 when node name matches hub name, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "conflicts with hub node name") {
		t.Fatalf("expected conflict error message, got: %s", out.String())
	}
	out.Reset()
	if code := runCLI([]string{"node", "remove", "Atlas"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for node remove, got %d (%s)", code, out.String())
	}

	// Verify CLI node add with un-schemed URL normalizes to http://
	out.Reset()
	if code := runCLI([]string{"node", "add", "SchemelessNode", "192.168.1.188:10247", "-token", "sec"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for schemeless node add, got %d (%s)", code, out.String())
	}
	out.Reset()
	if code := runCLI([]string{"node", "list"}, &out); code != 0 || !strings.Contains(out.String(), "http://192.168.1.188:10247") {
		t.Fatalf("expected http://192.168.1.188:10247 in node list output, got code=%d out=%s", code, out.String())
	}
	out.Reset()
	_ = runCLI([]string{"node", "remove", "SchemelessNode"}, &out)

	// Verify agent requires token
	out.Reset()
	if code := runCLI([]string{"agent", "-hub", "http://hub.lan:10311", "-advertise-url", "http://192.168.1.100:10247"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 when token missing, got %d", code)
	}
	if !strings.Contains(out.String(), "agent_token") {
		t.Fatalf("expected error mentioning agent_token, got: %s", out.String())
	}

	// Verify agent service unknown returns error code
	out.Reset()
	if code := runCLI([]string{"agent", "service", "unknown"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 for agent service unknown, got %d", code)
	}
	if !strings.Contains(out.String(), "Unknown agent service action") {
		t.Fatalf("expected unknown action message, got: %s", out.String())
	}

	// Verify agent service without action returns error code
	out.Reset()
	if code := runCLI([]string{"agent", "service"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 for bare agent service, got %d", code)
	}

	// Verify agent service install with -path works cleanly
	agentPlistPath := filepath.Join(tmpDir, "me.jaewook.nal.security-hub-agent.plist")
	out.Reset()
	code = runCLI([]string{"agent", "service", "install", "-path", agentPlistPath, "-token", "sec123", "-hub", "http://hub.lan:10311"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for agent service install, got %d (%s)", code, out.String())
	}
	content, err := os.ReadFile(agentPlistPath)
	if err != nil {
		t.Fatalf("failed to read installed agent plist: %v", err)
	}
	if !strings.Contains(string(content), "me.jaewook.nal.security-hub-agent") || !strings.Contains(string(content), "sec123") {
		t.Fatalf("agent plist missing expected content: %s", string(content))
	}
	if strings.Contains(string(content), "<string>-token</string>") {
		t.Fatalf("expected agent plist not to pass -token in ProgramArguments:\n%s", string(content))
	}
	if st, sErr := os.Stat(agentPlistPath); sErr != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on agent plist, got err=%v perm=%v", sErr, st)
	}

	// Verify corrupt config.yml in CWD fails loudly
	cfgDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yml"), []byte("web: [broken\n"), 0600)
	origWD, _ := os.Getwd()
	_ = os.Chdir(cfgDir)
	defer func() { _ = os.Chdir(origWD) }()
	if _, lErr := loadAppConfig(""); lErr == nil {
		t.Fatal("expected loadAppConfig to fail on corrupt config.yml")
	}
	_ = os.Chdir(origWD)

	// Verify unknown CLI flags return non-zero
	out.Reset()
	if code := runCLI([]string{"service", "install", "-unknown-flag"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 on unknown service install flag, got %d", code)
	}

	// Verify agent service status runs cleanly
	out.Reset()
	code = runCLI([]string{"agent", "service", "status"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for agent service status, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "Agent service") {
		t.Fatalf("expected agent service status in output, got: %s", out.String())
	}

	// Verify CLI node add rejects non-HTTP URLs and CLI node list does not abort running daemon tasks
	out.Reset()
	if code := runCLI([]string{"node", "add", "BadNode", "ftp://files.internal/pkg"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 for non-HTTP node URL, got %d (%s)", code, out.String())
	}

	cliCoexDir := t.TempDir()
	t.Setenv("SECURITY_HUB_DATA_DIR", cliCoexDir)
	daemonStore, err := db.NewSpoolStore(cliCoexDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	task, err := daemonStore.CreateTask(context.Background(), &models.Task{
		TaskType:   "security_scan",
		TargetType: "system",
		TargetName: "all",
	})
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := runCLI([]string{"node", "list"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for node list, got %d (%s)", code, out.String())
	}
	stillRunning, _, err := daemonStore.GetTaskWithLogs(context.Background(), task.ID)
	if err != nil || stillRunning.Status != "running" {
		t.Fatalf("expected CLI node list not to abort daemon task, got status=%v err=%v", stillRunning, err)
	}
}
