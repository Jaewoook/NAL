package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigAndEnvOverrides(t *testing.T) {
	t.Setenv("UPDATER_PORT", "10246")
	t.Setenv("AUTHENTIK_ISSUER", "https://auth.jaewook.dev/application/o/system-updater/")
	t.Setenv("AUTHENTIK_CLIENT_ID", "system-updater")
	t.Setenv("PG_DSN", "postgres://system_updater:secret@127.0.0.1:5432/system_updater?sslmode=disable")
	t.Setenv("EMAIL_TO", "admin@jaewook.dev")

	cfg := DefaultConfigWithEnv()
	if cfg.Web.Port != 10246 {
		t.Fatalf("expected port 10246, got %d", cfg.Web.Port)
	}
	if cfg.Auth.OIDCIssuer != "https://auth.jaewook.dev/application/o/system-updater/" {
		t.Fatalf("unexpected issuer: %s", cfg.Auth.OIDCIssuer)
	}
	if cfg.Database.DSN == "" {
		t.Fatal("expected non-empty DSN")
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
	if loaded.NodeName != "Axis" {
		t.Fatalf("expected default NodeName='Axis', got %q", loaded.NodeName)
	}
}
