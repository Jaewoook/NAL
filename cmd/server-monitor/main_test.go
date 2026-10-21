package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 for help, got %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "Usage: server-monitor") {
		t.Errorf("expected usage instructions in output, got: %s", out)
	}
}

func TestNoArgsShowsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 for no args, got %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "Usage: server-monitor") {
		t.Errorf("expected usage instructions, got: %s", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"unknown-cmd"}, &stdout, &stderr)
	if code == 0 {
		t.Errorf("expected non-zero exit code for unknown command, got %d", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "unknown command") {
		t.Errorf("expected unknown command error, got: %s", errOut)
	}
}

func TestCheckCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"check"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for check, got %d (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()
	expectedFragments := []string{
		"System Health Check",
		"CPU Utilization",
		"Memory Utilization",
		"Disk Utilization",
		"Load Averages",
	}
	for _, frag := range expectedFragments {
		if !strings.Contains(out, frag) {
			t.Errorf("check output missing fragment %q\nFull output:\n%s", frag, out)
		}
	}
}

func TestCheckCommandWithInvalidConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"check", "-config", "nonexistent_cfg_123.yaml"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for nonexistent config, got %d", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "failed to read config file") {
		t.Errorf("expected 'failed to read config file' in stderr, got: %s", errOut)
	}
}

func TestTestAlertNoChannelsEnabled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"test-alert"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when no channels are enabled, got %d", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "no notification channels are enabled") {
		t.Errorf("expected no notification channels error, got: %s", errOut)
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTestAlertWithMockChannel(t *testing.T) {
	var receivedBody string
	origTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
			Header:     make(http.Header),
		}, nil
	})
	defer func() {
		http.DefaultTransport = origTransport
	}()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	cfgContent := `
server:
  name: "test-server"
notifications:
  webhook:
    enabled: true
    url: "http://webhook.local/alerts"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runApp([]string{"test-alert", "-config", cfgPath, "-channel", "webhook"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for test-alert, got %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Test alert successfully sent") {
		t.Errorf("expected success message in stdout, got: %s", out)
	}
	if !strings.Contains(receivedBody, "Test Alert") {
		t.Errorf("expected webhook server to receive test alert body, got: %s", receivedBody)
	}
}

func TestServiceInstallStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"service", "install", "-type", "systemd"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for service install systemd, got %d (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "[Unit]") || !strings.Contains(out, "ExecStart=") {
		t.Errorf("expected systemd unit output, got: %s", out)
	}
}

func TestServiceInstallLaunchdStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"service", "install", "-type", "launchd"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for service install launchd, got %d (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "<plist") || !strings.Contains(out, "ProgramArguments") {
		t.Errorf("expected launchd plist output, got: %s", out)
	}
}

func TestServiceInstallToFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "test-unit.service")

	var stdout, stderr bytes.Buffer
	code := runApp([]string{"service", "install", "-type", "systemd", "-path", targetPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for service install to file, got %d (stderr: %s)", code, stderr.String())
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed to read installed service file: %v", err)
	}
	if !strings.Contains(string(data), "[Unit]") {
		t.Errorf("expected systemd content in file, got: %s", string(data))
	}
}
