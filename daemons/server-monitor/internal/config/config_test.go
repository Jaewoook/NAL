package config

import (
	"os"
	"path/filepath"
	"testing"
)

func testConfigYaml() string {
	return `
server:
  name: "test-server"
  check_interval_seconds: 5
cpu:
  spike:
    enabled: true
    threshold_percent: 85.0
    sustained_seconds: 15
    cooldown_minutes: 30
  plunge_drop:
    enabled: true
    delta_percent: 40.0
    from_min_percent: 50.0
notifications:
  telegram:
    enabled: true
    bot_token: "test-token"
    chat_id: "123456"
`
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(testConfigYaml()), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Name != "test-server" {
		t.Errorf("expected test-server, got %s", cfg.Server.Name)
	}
	if cfg.Server.CheckIntervalSeconds != 5 {
		t.Errorf("expected 5, got %d", cfg.Server.CheckIntervalSeconds)
	}
	if cfg.CPU.Spike.ThresholdPercent != 85.0 {
		t.Errorf("expected 85.0, got %f", cfg.CPU.Spike.ThresholdPercent)
	}
	if cfg.CPU.Spike.SustainedSeconds != 15 {
		t.Errorf("expected 15, got %d", cfg.CPU.Spike.SustainedSeconds)
	}
	if cfg.CPU.Spike.CooldownMinutes != 30 {
		t.Errorf("expected 30, got %d", cfg.CPU.Spike.CooldownMinutes)
	}
	if cfg.CPU.PlungeDrop.DeltaPercent != 40.0 {
		t.Errorf("expected 40.0, got %f", cfg.CPU.PlungeDrop.DeltaPercent)
	}
	if cfg.CPU.PlungeDrop.FromMinPercent != 50.0 {
		t.Errorf("expected 50.0, got %f", cfg.CPU.PlungeDrop.FromMinPercent)
	}
	if !cfg.Notifications.Telegram.Enabled {
		t.Errorf("expected telegram to be enabled")
	}
	if cfg.Notifications.Telegram.BotToken != "test-token" {
		t.Errorf("expected test-token, got %s", cfg.Notifications.Telegram.BotToken)
	}
	if cfg.Notifications.Telegram.ChatID != "123456" {
		t.Errorf("expected 123456, got %s", cfg.Notifications.Telegram.ChatID)
	}
	if cfg.CPU.FloorDrop.Enabled {
		t.Errorf("expected floor drop to be disabled by default")
	}
}

func TestConfigEnvOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("server:\n  name: 'original'"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SERVER_NAME", "override-server")
	t.Setenv("TELEGRAM_BOT_TOKEN", "override-bot-token")
	t.Setenv("TELEGRAM_CHAT_ID", "override-chat-id")
	t.Setenv("DISCORD_WEBHOOK_URL", "https://discord.example/webhook")
	t.Setenv("SLACK_WEBHOOK_URL", "https://slack.example/webhook")
	t.Setenv("HEARTBEAT_URL", "https://heartbeat.example/ping")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Name != "override-server" {
		t.Errorf("expected override-server, got %s", cfg.Server.Name)
	}
	if cfg.Notifications.Telegram.BotToken != "override-bot-token" {
		t.Errorf("expected override-bot-token, got %s", cfg.Notifications.Telegram.BotToken)
	}
	if cfg.Notifications.Telegram.ChatID != "override-chat-id" {
		t.Errorf("expected override-chat-id, got %s", cfg.Notifications.Telegram.ChatID)
	}
	if cfg.Notifications.Discord.WebhookURL != "https://discord.example/webhook" {
		t.Errorf("expected discord webhook override, got %s", cfg.Notifications.Discord.WebhookURL)
	}
	if cfg.Notifications.Slack.WebhookURL != "https://slack.example/webhook" {
		t.Errorf("expected slack webhook override, got %s", cfg.Notifications.Slack.WebhookURL)
	}
	if cfg.Heartbeat.URL != "https://heartbeat.example/ping" {
		t.Errorf("expected heartbeat url override, got %s", cfg.Heartbeat.URL)
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/non/existent/path/config.yaml")
	if err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}
}

func TestLoadConfigInvalidYaml(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(cfgPath, []byte("server: [invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Errorf("expected error for invalid yaml, got nil")
	}
}

func TestDefaultConfigWithEnv(t *testing.T) {
	t.Setenv("SERVER_NAME", "env-server")
	t.Setenv("BOT_TOKEN", "my-bot-token")
	t.Setenv("DEFAULT_CHAT_ID", "987654")
	t.Setenv("DISCORD_WEBHOOK_URL", "https://discord.gg/webhook")

	cfg := DefaultConfigWithEnv()
	if cfg.Server.Name != "env-server" {
		t.Errorf("expected env-server, got %s", cfg.Server.Name)
	}
	if !cfg.Notifications.Telegram.Enabled {
		t.Errorf("expected telegram to be enabled when BOT_TOKEN is set")
	}
	if cfg.Notifications.Telegram.BotToken != "my-bot-token" {
		t.Errorf("expected my-bot-token, got %s", cfg.Notifications.Telegram.BotToken)
	}
	if cfg.Notifications.Telegram.ChatID != "987654" {
		t.Errorf("expected 987654, got %s", cfg.Notifications.Telegram.ChatID)
	}
	if !cfg.Notifications.Discord.Enabled {
		t.Errorf("expected discord to be enabled when webhook URL is set")
	}
	if cfg.Notifications.Discord.WebhookURL != "https://discord.gg/webhook" {
		t.Errorf("expected https://discord.gg/webhook, got %s", cfg.Notifications.Discord.WebhookURL)
	}
	if cfg.Server.CheckIntervalSeconds != 5 {
		t.Errorf("expected default interval 5, got %d", cfg.Server.CheckIntervalSeconds)
	}
}

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := `# Comment line
SERVER_NAME="envfile-server"
BOT_TOKEN='envfile-token'
DEFAULT_CHAT_ID=123456
EMPTY_LINE=
`
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SERVER_NAME", "")
	t.Setenv("BOT_TOKEN", "")
	t.Setenv("DEFAULT_CHAT_ID", "")

	LoadEnvFile(envPath)

	if val := os.Getenv("SERVER_NAME"); val != "envfile-server" {
		t.Errorf("expected envfile-server, got %s", val)
	}
	if val := os.Getenv("BOT_TOKEN"); val != "envfile-token" {
		t.Errorf("expected envfile-token, got %s", val)
	}
	if val := os.Getenv("DEFAULT_CHAT_ID"); val != "123456" {
		t.Errorf("expected 123456, got %s", val)
	}
}

