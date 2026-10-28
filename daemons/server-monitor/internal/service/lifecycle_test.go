package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusServiceLaunchdRunning(t *testing.T) {
	tmpDir := t.TempDir()
	plistPath := filepath.Join(tmpDir, "com.servermonitor.plist")
	if err := os.WriteFile(plistPath, []byte("<plist></plist>"), 0644); err != nil {
		t.Fatal(err)
	}

	SetCommandRunner(func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && len(args) >= 2 && args[0] == "print" {
			output := `
gui/501/server-monitor = {
	state = running
	pid = 12345
	path = ` + plistPath + `
	stdout path = /tmp/server-monitor.log
	stderr path = /tmp/server-monitor.err
}
`
			return []byte(output), nil
		}
		if name == "ps" {
			output := "%CPU %MEM RSS ELAPSED\n 0.5 0.2 25600 01:23:45\n"
			return []byte(output), nil
		}
		return nil, errors.New("unexpected command")
	})
	defer SetCommandRunner(nil)

	res, err := StatusService("launchd", "server-monitor", plistPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(res, "Active (running)") {
		t.Errorf("expected running state, got: %s", res)
	}
	if !strings.Contains(res, "PID:         12345") {
		t.Errorf("expected PID 12345, got: %s", res)
	}
	if !strings.Contains(res, "25.0 MB RSS") {
		t.Errorf("expected 25.0 MB RSS, got: %s", res)
	}
	if !strings.Contains(res, "01:23:45") {
		t.Errorf("expected uptime, got: %s", res)
	}
	if !strings.Contains(res, "/tmp/server-monitor.log") {
		t.Errorf("expected stdout log path, got: %s", res)
	}
}

func TestStatusServiceLaunchdStopped(t *testing.T) {
	tmpDir := t.TempDir()
	plistPath := filepath.Join(tmpDir, "com.servermonitor.plist")
	if err := os.WriteFile(plistPath, []byte("<plist></plist>"), 0644); err != nil {
		t.Fatal(err)
	}

	SetCommandRunner(func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("service not found")
	})
	defer SetCommandRunner(nil)

	res, err := StatusService("launchd", "server-monitor", plistPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(res, "Installed (stopped / not loaded)") {
		t.Errorf("expected stopped / not loaded state, got: %s", res)
	}
}

func TestStatusServiceLaunchdNotInstalled(t *testing.T) {
	SetCommandRunner(func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("service not found")
	})
	defer SetCommandRunner(nil)

	res, err := StatusService("launchd", "server-monitor", "/non/existent/path/plist.plist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(res, "Not installed") {
		t.Errorf("expected not installed state, got: %s", res)
	}
}

func TestStopServiceLaunchd(t *testing.T) {
	commandsRun := []string{}

	SetCommandRunner(func(name string, args ...string) ([]byte, error) {
		commandsRun = append(commandsRun, name+" "+strings.Join(args, " "))
		if name == "launchctl" && args[0] == "print" {
			if strings.Contains(strings.Join(commandsRun, ","), "bootout") {
				return nil, errors.New("not loaded")
			}
			return []byte("state = running\npid = 9999\n"), nil
		}
		return []byte("ok"), nil
	})
	defer SetCommandRunner(nil)

	msg, err := StopService("launchd", "server-monitor", "/tmp/test.plist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(msg, "Successfully stopped server-monitor service") {
		t.Errorf("expected stop message, got: %s", msg)
	}

	bootoutFound := false
	for _, cmd := range commandsRun {
		if strings.Contains(cmd, "launchctl bootout") {
			bootoutFound = true
			break
		}
	}
	if !bootoutFound {
		t.Errorf("expected launchctl bootout command to be run, got: %v", commandsRun)
	}
}

func TestUninstallServiceLaunchd(t *testing.T) {
	tmpDir := t.TempDir()
	plistPath := filepath.Join(tmpDir, "com.servermonitor.plist")
	if err := os.WriteFile(plistPath, []byte("<plist></plist>"), 0644); err != nil {
		t.Fatal(err)
	}

	SetCommandRunner(func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	})
	defer SetCommandRunner(nil)

	msg, err := UninstallService("launchd", "server-monitor", plistPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(msg, "Successfully stopped and uninstalled server-monitor service") {
		t.Errorf("expected uninstall message, got: %s", msg)
	}

	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Errorf("expected plist file to be removed from disk")
	}
}

func TestSystemdLifecycle(t *testing.T) {
	commandsRun := []string{}
	SetCommandRunner(func(name string, args ...string) ([]byte, error) {
		commandsRun = append(commandsRun, name+" "+strings.Join(args, " "))
		if name == "systemctl" && args[0] == "status" {
			return []byte("Active: active (running)"), nil
		}
		return []byte("ok"), nil
	})
	defer SetCommandRunner(nil)

	if _, err := StartService("systemd", "server-monitor", ""); err != nil {
		t.Errorf("unexpected error starting systemd: %v", err)
	}
	if _, err := StopService("systemd", "server-monitor", ""); err != nil {
		t.Errorf("unexpected error stopping systemd: %v", err)
	}
	if _, err := RestartService("systemd", "server-monitor", ""); err != nil {
		t.Errorf("unexpected error restarting systemd: %v", err)
	}
	status, err := StatusService("systemd", "server-monitor", "")
	if err != nil {
		t.Errorf("unexpected error checking status systemd: %v", err)
	}
	if !strings.Contains(status, "active (running)") {
		t.Errorf("expected status output, got: %s", status)
	}
}
