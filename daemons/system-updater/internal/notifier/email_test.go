package notifier

import (
	"context"
	"net/smtp"
	"strings"
	"testing"

	"github.com/jaewoook/system-updater/internal/config"
	"github.com/jaewoook/system-updater/internal/db"
	"github.com/jaewoook/system-updater/internal/models"
)

func TestAlerter_NotifyScanFindingsDeduplicationAndRollback(t *testing.T) {
	ctx := context.Background()
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var sentMessages []string
	alerter := NewAlerter(config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "smtp.example.com",
		SMTPPort:  587,
		Username:  "nal@example.com",
		Password:  "secret",
		FromEmail: "nal@example.com",
		ToEmail:   "admin@jaewook.dev",
	}, store)

	alerter.sendMailFunc = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		sentMessages = append(sentMessages, string(msg))
		return nil
	}

	scan := &models.ScanResult{
		Items: []models.ManagedItem{
			{
				TargetType:     models.TargetDocker,
				Name:           "cloudflare-tunnel",
				CurrentVersion: "2026.8.0",
				LatestVersion:  "2026.10.2",
				CritCount:      1,
				Vulnerabilities: []models.Vulnerability{
					{ID: "GHSA-cf-1234", Severity: models.SeverityCritical, Summary: "Tunnel compromise", FixedVersion: "2026.10.2"},
				},
			},
			{
				TargetType:     models.TargetDocker,
				Name:           "auth",
				CurrentVersion: "2026.5.3",
				EoL: models.EoLInfo{
					Product:       "authentik",
					Cycle:         "2026.5",
					Status:        models.EoLExpiringSoon,
					EoLDate:       "2026-11-18",
					DaysRemaining: 19,
				},
			},
			{
				TargetType:     models.TargetBrew,
				Name:           "node@22",
				CurrentVersion: "22.23.2_2",
				BrokenLinkage:  true,
				LinkageDetails: "Missing libsimdjson.33.dylib",
			},
		},
	}

	count, err := alerter.NotifyScanFindings(ctx, scan)
	if err != nil {
		t.Fatalf("NotifyScanFindings failed: %v", err)
	}
	if count != 3 || len(sentMessages) != 1 {
		t.Fatalf("expected 3 findings in 1 email, got count=%d emails=%d", count, len(sentMessages))
	}
	if !strings.Contains(sentMessages[0], "GHSA-cf-1234") || !strings.Contains(sentMessages[0], "authentik") || !strings.Contains(sentMessages[0], "node@22") {
		t.Fatalf("email body missing expected findings: %s", sentMessages[0])
	}

	// Second call with identical scan findings should send 0 emails (deduplicated)
	count2, err := alerter.NotifyScanFindings(ctx, scan)
	if err != nil {
		t.Fatalf("second NotifyScanFindings failed: %v", err)
	}
	if count2 != 0 || len(sentMessages) != 1 {
		t.Fatalf("expected 0 new findings and no extra email on duplicate scan, got count=%d emails=%d", count2, len(sentMessages))
	}

	// Rollback alert
	if err := alerter.NotifyDeadManRollback(ctx, "cloudflare-tunnel", "2026.8.0", "2026.10.2", "external probe failed"); err != nil {
		t.Fatalf("NotifyDeadManRollback failed: %v", err)
	}
	if len(sentMessages) != 2 || !strings.Contains(sentMessages[1], "ROLLBACK") {
		t.Fatalf("expected rollback email to be sent, got %d messages", len(sentMessages))
	}
}
