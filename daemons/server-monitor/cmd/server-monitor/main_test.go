package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/service"
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
	mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
			Header:     make(http.Header),
		}, nil
	})

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
	code := runApp([]string{"test-alert", "-config", cfgPath, "-channel", "webhook"}, &stdout, &stderr, WithHTTPTransport(mockTransport))
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

func TestResolveConfigWithoutFileAppliesEnv(t *testing.T) {
	t.Setenv("SERVER_NAME", "custom-host-env")
	t.Setenv("BOT_TOKEN", "tg-bot-1234")
	t.Setenv("DEFAULT_CHAT_ID", "tg-chat-5678")

	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tempDir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	cfg, err := resolveConfig("")
	if err != nil {
		t.Fatalf("expected nil error from resolveConfig, got: %v", err)
	}
	if cfg.Server.Name != "custom-host-env" {
		t.Errorf("expected Server.Name 'custom-host-env', got: %s", cfg.Server.Name)
	}
	if !cfg.Notifications.Telegram.Enabled {
		t.Errorf("expected Telegram.Enabled to be true via env")
	}
	if cfg.Notifications.Telegram.BotToken != "tg-bot-1234" {
		t.Errorf("expected Telegram.BotToken 'tg-bot-1234', got: %s", cfg.Notifications.Telegram.BotToken)
	}
	if cfg.Notifications.Telegram.ChatID != "tg-chat-5678" {
		t.Errorf("expected Telegram.ChatID 'tg-chat-5678', got: %s", cfg.Notifications.Telegram.ChatID)
	}
}

func TestResolveConfigWithConfigYml(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tempDir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	ymlContent := `
server:
  name: "yml-detected-server"
notifications:
  telegram:
    enabled: true
    bot_token: "test-token-from-yml"
    chat_id: "test-chat-from-yml"
`
	if err := os.WriteFile("config.yml", []byte(ymlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := resolveConfig("")
	if err != nil {
		t.Fatalf("resolveConfig failed: %v", err)
	}
	if cfg.Server.Name != "yml-detected-server" {
		t.Errorf("expected Server.Name 'yml-detected-server', got: %s", cfg.Server.Name)
	}
	if !cfg.Notifications.Telegram.Enabled {
		t.Errorf("expected Telegram.Enabled to be true from config.yml")
	}
}

func TestServiceUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"service", "nonexistent"}, &stdout, &stderr)
	if code == 0 {
		t.Errorf("expected non-zero exit code for unknown service subcommand")
	}
	if !strings.Contains(stderr.String(), "unknown service subcommand") {
		t.Errorf("expected unknown service subcommand error, got: %s", stderr.String())
	}
}

func TestServiceNoSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runApp([]string{"service"}, &stdout, &stderr)
	if code == 0 {
		t.Errorf("expected non-zero exit code for service with no args")
	}
	if !strings.Contains(stderr.String(), "usage: server-monitor service") {
		t.Errorf("expected usage message, got: %s", stderr.String())
	}
}

func TestServiceStatusLaunchd(t *testing.T) {
	service.SetCommandRunner(func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" {
			return []byte("state = running\npid = 4321\npath = /tmp/test.plist\nstdout path = /tmp/out.log\nstderr path = /tmp/err.log\n"), nil
		}
		if name == "ps" {
			return []byte("%CPU %MEM RSS ELAPSED\n 1.2 0.3 30720 02:00:00\n"), nil
		}
		return nil, errors.New("unexpected command")
	})
	defer service.SetCommandRunner(nil)

	var stdout, stderr bytes.Buffer
	code := runApp([]string{"service", "status", "-type", "launchd"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for service status, got %d (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Active (running)") {
		t.Errorf("expected running in status, got: %s", out)
	}
	if !strings.Contains(out, "PID:         4321") {
		t.Errorf("expected PID 4321, got: %s", out)
	}
	if !strings.Contains(out, "30.0 MB RSS") {
		t.Errorf("expected 30.0 MB RSS, got: %s", out)
	}
}

func TestRunCommandLogging(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test-daemon.log")
	cfgPath := filepath.Join(tmpDir, "config.yml")

	cfgContent := `
server:
  name: "log-test-node"
  check_interval_seconds: 1
logging:
  enabled: true
  file_path: "` + logPath + `"
  max_size_mb: 5
  max_backups: 2
  console: true
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	code := runApp([]string{"run", "-config", cfgPath}, &stdout, &stderr, WithContext(ctx))
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean run shutdown, got %d (stderr: %s)", code, stderr.String())
	}

	// Verify log file was created and contains startup banner
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read created log file: %v", err)
	}
	logContent := string(logBytes)
	if !strings.Contains(logContent, "[daemon] starting server-monitor daemon for \"log-test-node\"") {
		t.Errorf("expected log file to contain startup line, got:\n%s", logContent)
	}

	// Verify stdout contains the startup line because console: true
	if !strings.Contains(stdout.String(), "starting server-monitor daemon") {
		t.Errorf("expected stdout to contain daemon output, got:\n%s", stdout.String())
	}
}


