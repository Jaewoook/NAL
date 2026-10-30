package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaewoook/system-updater/internal/service"
)

func TestCLI_LoginLinkAndServicePlist(t *testing.T) {
	plist := service.GenerateLaunchdPlist("/Users/jaewookahn/repos/NAL/daemons/system-updater/system-updater", "/Users/jaewookahn/repos/NAL/daemons/system-updater")
	if !strings.Contains(plist, "me.jaewook.nal.system-updater") || !strings.Contains(plist, "<string>run</string>") {
		t.Fatalf("unexpected launchd plist: %s", plist)
	}

	tmpDir := t.TempDir()
	t.Setenv("UPDATER_DATA_DIR", tmpDir)
	t.Setenv("UPDATER_PUBLIC_URL", "http://localhost:10246")

	var out bytes.Buffer
	code := runCLI([]string{"auth", "login-link"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for auth login-link, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "http://localhost:10246/api/auth/token-login?token=") {
		t.Fatalf("expected break-glass login URL in output, got: %s", out.String())
	}

	// Verify plist install to file
	plistPath := filepath.Join(tmpDir, "me.jaewook.nal.system-updater.plist")
	out.Reset()
	code = runCLI([]string{"service", "install", "-path", plistPath}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for service install, got %d (%s)", code, out.String())
	}
}
