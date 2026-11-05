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
