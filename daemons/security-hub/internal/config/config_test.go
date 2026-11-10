package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigAndEnvOverrides(t *testing.T) {
	defCfg := DefaultConfig()
	if defCfg.Web.Port != 10311 {
		t.Fatalf("expected default port 10311, got %d", defCfg.Web.Port)
	}

	t.Setenv("SECURITY_HUB_PORT", "10311")
	t.Setenv("AUTHENTIK_ISSUER", "https://auth.jaewook.dev/application/o/security-hub/")
	t.Setenv("AUTHENTIK_CLIENT_ID", "security-hub")
	t.Setenv("SECURITY_HUB_DB_NAME", "security_hub_custom")
	t.Setenv("EMAIL_TO", "admin@jaewook.dev")

	cfg := DefaultConfigWithEnv()
	if cfg.Web.Port != 10311 {
		t.Fatalf("expected port 10311, got %d", cfg.Web.Port)
	}
	if cfg.Auth.OIDCIssuer != "https://auth.jaewook.dev/application/o/security-hub/" {
		t.Fatalf("unexpected issuer: %s", cfg.Auth.OIDCIssuer)
	}
	if cfg.Database.DBName != "security_hub_custom" {
		t.Fatalf("expected DBName security_hub_custom, got %s", cfg.Database.DBName)
	}
	if cfg.Scanner.EoLWarningDays != 30 {
		t.Fatalf("expected default EoLWarningDays=30, got %d", cfg.Scanner.EoLWarningDays)
	}
	if len(cfg.Updater.CriticalServices) == 0 {
		t.Fatal("expected default critical services list")
	}

	tmp := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(tmp, []byte("scanner:\n  eol_warning_days: 45\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(tmp)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.Scanner.EoLWarningDays != 45 {
		t.Fatalf("expected 45, got %d", loaded.Scanner.EoLWarningDays)
	}
	if loaded.NodeName == "" {
		t.Fatalf("expected non-empty default NodeName from hostname, got %q", loaded.NodeName)
	}
}

func TestGitBotConfigDefaultsAndEnvOverrides(t *testing.T) {
	def := DefaultConfig()
	if !def.Updater.Git.Enabled {
		t.Fatal("expected default Updater.Git.Enabled to be true")
	}
	if def.Updater.Git.BotName != "NAL Bot" {
		t.Fatalf("expected default BotName 'NAL Bot', got %q", def.Updater.Git.BotName)
	}
	if def.Updater.Git.BotEmail != "nal-git-system@jaewook.me" {
		t.Fatalf("expected default BotEmail 'nal-git-system@jaewook.me', got %q", def.Updater.Git.BotEmail)
	}
	if !def.Updater.Git.GPGSign {
		t.Fatal("expected default Updater.Git.GPGSign to be true")
	}
	if def.Updater.Git.GPGKey != "024D4017DFF5360A" {
		t.Fatalf("expected default GPGKey '024D4017DFF5360A', got %q", def.Updater.Git.GPGKey)
	}

	// Verify environment variable overrides including turning off GPG signing and commit
	t.Setenv("SECURITY_HUB_GIT_BOT_NAME", "Custom Bot")
	t.Setenv("SECURITY_HUB_GIT_BOT_EMAIL", "bot@example.com")
	t.Setenv("SECURITY_HUB_GIT_GPG_SIGN", "false")
	t.Setenv("SECURITY_HUB_GIT_GPG_KEY", "AABBCCDD11223344")

	cfg := DefaultConfigWithEnv()
	if cfg.Updater.Git.BotName != "Custom Bot" {
		t.Fatalf("expected overridden BotName 'Custom Bot', got %q", cfg.Updater.Git.BotName)
	}
	if cfg.Updater.Git.BotEmail != "bot@example.com" {
		t.Fatalf("expected overridden BotEmail 'bot@example.com', got %q", cfg.Updater.Git.BotEmail)
	}
	if cfg.Updater.Git.GPGSign {
		t.Fatal("expected SECURITY_HUB_GIT_GPG_SIGN=false to disable GPGSign")
	}
	if cfg.Updater.Git.GPGKey != "AABBCCDD11223344" {
		t.Fatalf("expected overridden GPGKey 'AABBCCDD11223344', got %q", cfg.Updater.Git.GPGKey)
	}

	t.Setenv("SECURITY_HUB_GIT_COMMIT_ENABLED", "0")
	cfgDisabled := DefaultConfigWithEnv()
	if cfgDisabled.Updater.Git.Enabled {
		t.Fatal("expected SECURITY_HUB_GIT_COMMIT_ENABLED=0 to disable Git auto-commit")
	}
}

func TestHubAndAgentAdvertiseURLConfig(t *testing.T) {
	t.Setenv("SECURITY_HUB_URL", "http://hub.lan:10311")
	t.Setenv("SECURITY_HUB_ADVERTISE_URL", "http://agent.lan:10247")

	cfg := DefaultConfigWithEnv()
	if cfg.HubURL != "http://hub.lan:10311" {
		t.Fatalf("expected HubURL 'http://hub.lan:10311', got %q", cfg.HubURL)
	}
	if cfg.AgentAdvertiseURL != "http://agent.lan:10247" {
		t.Fatalf("expected AgentAdvertiseURL 'http://agent.lan:10247', got %q", cfg.AgentAdvertiseURL)
	}

	tmp := filepath.Join(t.TempDir(), "agent-config.yml")
	content := "hub_url: http://hub-yaml.lan:10311\nagent_advertise_url: http://agent-yaml.lan:10247\n"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_HUB_URL", "")
	t.Setenv("SECURITY_HUB_ADVERTISE_URL", "")
	loaded, err := LoadConfig(tmp)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.HubURL != "http://hub-yaml.lan:10311" {
		t.Fatalf("expected loaded HubURL 'http://hub-yaml.lan:10311', got %q", loaded.HubURL)
	}
	if loaded.AgentAdvertiseURL != "http://agent-yaml.lan:10247" {
		t.Fatalf("expected loaded AgentAdvertiseURL 'http://agent-yaml.lan:10247', got %q", loaded.AgentAdvertiseURL)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"   ", ""},
		{"192.168.1.100:10311", "http://192.168.1.100:10311"},
		{"192.168.1.100:10311/", "http://192.168.1.100:10311"},
		{"http://192.168.1.100:10311///", "http://192.168.1.100:10311"},
		{"https://agent.corp.internal:10247", "https://agent.corp.internal:10247"},
		{"agent.corp.internal:10247/", "http://agent.corp.internal:10247"},
		{"  http://localhost:8080/  ", "http://localhost:8080"},
	}
	for _, tc := range cases {
		got := NormalizeURL(tc.input)
		if got != tc.expected {
			t.Errorf("NormalizeURL(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}
