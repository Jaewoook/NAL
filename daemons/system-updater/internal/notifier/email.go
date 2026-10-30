package notifier

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/config"
	"github.com/jaewoook/system-updater/internal/db"
	"github.com/jaewoook/system-updater/internal/models"
)

type sendMailFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

type Alerter struct {
	cfg          config.EmailConfig
	store        db.Store
	sendMailFunc sendMailFunc
	timeout      time.Duration
}

func NewAlerter(cfg config.EmailConfig, store db.Store) *Alerter {
	return &Alerter{
		cfg:          cfg,
		store:        store,
		sendMailFunc: smtp.SendMail,
		timeout:      10 * time.Second,
	}
}

type pendingFinding struct {
	fingerprint string
	alertType   string
	line        string
}

func (a *Alerter) NotifyScanFindings(ctx context.Context, scan *models.ScanResult) (int, error) {
	if scan == nil {
		return 0, nil
	}
	var findings []pendingFinding

	for _, item := range scan.Items {
		for _, v := range item.Vulnerabilities {
			if v.Severity != models.SeverityCritical && v.Severity != models.SeverityHigh {
				continue
			}
			fp := fmt.Sprintf("cve:%s:%s:%s", item.TargetType, item.Name, v.ID)
			if a.store != nil {
				if sent, _ := a.store.HasAlertBeenSent(ctx, fp); sent {
					continue
				}
			}
			fix := ""
			if v.FixedVersion != "" {
				fix = fmt.Sprintf(" (Fixed in %s)", v.FixedVersion)
			}
			findings = append(findings, pendingFinding{
				fingerprint: fp,
				alertType:   "cve",
				line:        fmt.Sprintf("- [VULNERABILITY - %s] %s (%s): %s — %s%s", v.Severity, item.Name, item.CurrentVersion, v.ID, v.Summary, fix),
			})
		}

		if item.EoL.Status == models.EoLExpired || item.EoL.Status == models.EoLExpiringSoon {
			fp := fmt.Sprintf("eol:%s:%s:%s:%s", item.TargetType, item.Name, item.EoL.Cycle, item.EoL.Status)
			if a.store != nil {
				if sent, _ := a.store.HasAlertBeenSent(ctx, fp); sent {
					continue
				}
			}
			findings = append(findings, pendingFinding{
				fingerprint: fp,
				alertType:   "eol",
				line:        fmt.Sprintf("- [LTS/EoL - %s] %s (%s %s): EoL date %s (%d days remaining)", strings.ToUpper(string(item.EoL.Status)), item.Name, item.EoL.Product, item.EoL.Cycle, item.EoL.EoLDate, item.EoL.DaysRemaining),
			})
		}

		if item.BrokenLinkage {
			fp := fmt.Sprintf("linkage:%s:%s:%s", item.TargetType, item.Name, item.CurrentVersion)
			if a.store != nil {
				if sent, _ := a.store.HasAlertBeenSent(ctx, fp); sent {
					continue
				}
			}
			findings = append(findings, pendingFinding{
				fingerprint: fp,
				alertType:   "linkage",
				line:        fmt.Sprintf("- [HOMEBREW BROKEN LINKAGE] %s (%s): %s", item.Name, item.CurrentVersion, item.LinkageDetails),
			})
		}
	}

	if len(findings) == 0 {
		return 0, nil
	}

	var body strings.Builder
	body.WriteString("NAL System Updater — Security & Lifecycle Alert\n")
	body.WriteString(strings.Repeat("=", 52) + "\n\n")
	body.WriteString(fmt.Sprintf("Detected %d new security/lifecycle finding(s) requiring attention:\n\n", len(findings)))
	for _, f := range findings {
		body.WriteString(f.line + "\n")
	}
	body.WriteString("\nOpen your NAL System Updater web dashboard to review and trigger controlled updates.\n")

	subject := fmt.Sprintf("[NAL Security Alert] %d New Vulnerability / EoL Finding(s)", len(findings))
	if a.cfg.Enabled {
		if err := a.sendEmail(subject, body.String()); err != nil {
			return 0, err
		}
	}

	if a.store != nil {
		for _, f := range findings {
			_ = a.store.RecordAlertSent(ctx, f.fingerprint, f.alertType)
		}
	}

	return len(findings), nil
}

func (a *Alerter) NotifyDeadManRollback(ctx context.Context, serviceName, fromVer, toVer, reason string) error {
	if !a.cfg.Enabled {
		return nil
	}
	subject := fmt.Sprintf("[NAL ROLLBACK ALERT] %s automatically rolled back to %s", serviceName, fromVer)
	body := fmt.Sprintf("NAL System Updater — Automatic 60s Dead-Man's Rollback Executed\n"+
		"===============================================================\n"+
		"Service:          %s\n"+
		"Attempted Target: %s\n"+
		"Reverted To:      %s\n"+
		"Reason:           %s\n"+
		"Timestamp:        %s\n",
		serviceName, toVer, fromVer, reason, time.Now().UTC().Format(time.RFC1123Z))
	return a.sendEmail(subject, body)
}

func (a *Alerter) SendTestEmail(ctx context.Context) error {
	subject := "[NAL System Updater] Test Notification"
	body := "This is a test email from NAL System Updater (daemons/system-updater)."
	return a.sendEmail(subject, body)
}

func (a *Alerter) sendEmail(subject, body string) error {
	if a.cfg.SMTPHost == "" {
		return errors.New("smtp_host is not configured")
	}
	if a.cfg.ToEmail == "" {
		return errors.New("to_email is not configured")
	}
	from := a.cfg.FromEmail
	if from == "" {
		from = a.cfg.Username
	}
	if from == "" {
		from = "system-updater@localhost"
	}
	addr := fmt.Sprintf("%s:%d", a.cfg.SMTPHost, a.cfg.SMTPPort)
	var auth smtp.Auth
	if a.cfg.Username != "" && a.cfg.Password != "" {
		auth = smtp.PlainAuth("", a.cfg.Username, a.cfg.Password, a.cfg.SMTPHost)
	}
	now := time.Now().UTC().Format(time.RFC1123Z)
	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"Date: %s\r\n\r\n%s",
		from, a.cfg.ToEmail, subject, now, body))

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- a.sendMailFunc(addr, auth, from, []string{a.cfg.ToEmail}, msg)
	}()
	select {
	case <-ctx.Done():
		return fmt.Errorf("smtp send timed out: %w", ctx.Err())
	case err := <-done:
		return err
	}
}
