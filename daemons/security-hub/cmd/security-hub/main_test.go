package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaewoook/security-hub/internal/config"
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

	// Verify agent service status runs cleanly
	out.Reset()
	code = runCLI([]string{"agent", "service", "status"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for agent service status, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "Agent service") {
		t.Fatalf("expected agent service status in output, got: %s", out.String())
	}
}
