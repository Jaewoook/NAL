package notifier

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

type Alerter struct {
	cfg          config.EmailConfig
	store        db.AlertStore
	sendMailFunc sendMailFunc
	dialer       dialerFunc
	timeout      time.Duration
}

func NewAlerter(cfg config.EmailConfig, store db.AlertStore) *Alerter {
	return &Alerter{
		cfg:          cfg,
		store:        store,
		sendMailFunc: nil, // set to nil so sendEmail uses sendMailWithDialer
		dialer:       defaultDial,
		timeout:      25 * time.Second,
	}
}

type pendingFinding struct {
	fingerprint string
	alertType   string
	line        string
}

func sanitizeEmailHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(strings.TrimSpace(s))
}

func (a *Alerter) appendFindingIfUnsent(ctx context.Context, findings []pendingFinding, fp, alertType, line string) []pendingFinding {
	if a.store != nil {
		if sent, _ := a.store.HasAlertBeenSent(ctx, fp); sent {
			return findings
		}
	}
	return append(findings, pendingFinding{
		fingerprint: fp,
		alertType:   alertType,
		line:        line,
	})
}

func (a *Alerter) NotifyScanFindings(ctx context.Context, scan *models.ScanResult) (int, error) {
	if scan == nil || !a.cfg.Enabled {
		return 0, nil
	}
	var findings []pendingFinding

	for _, item := range scan.Items {
		nodePrefix := ""
		nodeLabel := ""
		if item.Node != "" {
			nodePrefix = item.Node + ":"
			nodeLabel = "[" + item.Node + "] "
		}

		for _, v := range item.Vulnerabilities {
			if v.Severity != models.SeverityCritical && v.Severity != models.SeverityHigh {
				continue
			}
			fp := fmt.Sprintf("%scve:%s:%s:%s", nodePrefix, item.TargetType, item.Name, v.ID)
			fix := ""
			if v.FixedVersion != "" {
				fix = fmt.Sprintf(" (Fixed in %s)", v.FixedVersion)
			}
			line := fmt.Sprintf("- [VULNERABILITY - %s] %s%s (%s): %s — %s%s", v.Severity, nodeLabel, item.Name, item.CurrentVersion, v.ID, v.Summary, fix)
			findings = a.appendFindingIfUnsent(ctx, findings, fp, "cve", line)
		}

		if item.EoL.Status == models.EoLExpired || item.EoL.Status == models.EoLExpiringSoon {
			fp := fmt.Sprintf("%seol:%s:%s:%s:%s", nodePrefix, item.TargetType, item.Name, item.EoL.Cycle, item.EoL.Status)
			line := fmt.Sprintf("- [LTS/EoL - %s] %s%s (%s %s): EoL date %s (%d days remaining)", strings.ToUpper(string(item.EoL.Status)), nodeLabel, item.Name, item.EoL.Product, item.EoL.Cycle, item.EoL.EoLDate, item.EoL.DaysRemaining)
			findings = a.appendFindingIfUnsent(ctx, findings, fp, "eol", line)
		}

		if item.BrokenLinkage {
			fp := fmt.Sprintf("%slinkage:%s:%s:%s", nodePrefix, item.TargetType, item.Name, item.CurrentVersion)
			label := "HOMEBREW BROKEN LINKAGE"
			if item.TargetType == models.TargetApt {
				label = "APT BROKEN DEPENDENCY"
			}
			line := fmt.Sprintf("- [%s] %s%s (%s): %s", label, nodeLabel, item.Name, item.CurrentVersion, item.LinkageDetails)
			findings = a.appendFindingIfUnsent(ctx, findings, fp, "linkage", line)
		}
	}

	if len(findings) == 0 {
		return 0, nil
	}

	var body strings.Builder
	body.WriteString("NAL Security Hub — Security & Lifecycle Alert\n")
	body.WriteString(strings.Repeat("=", 52) + "\n\n")
	fmt.Fprintf(&body, "Detected %d new security/lifecycle finding(s) requiring attention:\n\n", len(findings))
	for _, f := range findings {
		body.WriteString(f.line + "\n")
	}
	body.WriteString("\nOpen your NAL Security Hub web dashboard to review and trigger controlled updates.\n")

	subject := fmt.Sprintf("[NAL Security Alert] %d New Vulnerability / EoL Finding(s)", len(findings))
	if err := a.sendEmail(ctx, subject, body.String()); err != nil {
		return 0, err
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
	subject := fmt.Sprintf("[NAL ROLLBACK ALERT] %s automatically rolled back to %s", sanitizeEmailHeader(serviceName), sanitizeEmailHeader(fromVer))
	body := fmt.Sprintf("NAL Security Hub — Automatic 60s Dead-Man's Rollback Executed\n"+
		"===============================================================\n"+
		"Service:          %s\n"+
		"Attempted Target: %s\n"+
		"Reverted To:      %s\n"+
		"Reason:           %s\n"+
		"Timestamp:        %s\n",
		serviceName, toVer, fromVer, reason, time.Now().UTC().Format(time.RFC1123Z))
	return a.sendEmail(ctx, subject, body)
}

func (a *Alerter) SendTestEmail(ctx context.Context) error {
	subject := "[NAL Security Hub] Test Notification"
	body := "This is a test email from NAL Security Hub (daemons/security-hub)."
	return a.sendEmail(ctx, subject, body)
}

func (a *Alerter) sendEmail(ctx context.Context, subject, body string) error {
	if a.cfg.SMTPHost == "" {
		return errors.New("smtp_host is not configured")
	}
	if strings.ContainsAny(a.cfg.ToEmail, "\r\n\x00") || strings.ContainsAny(a.cfg.FromEmail, "\r\n\x00") || strings.ContainsAny(a.cfg.SMTPHost, "\r\n\x00") {
		return errors.New("invalid email configuration containing control characters")
	}
	toEmail := sanitizeEmailHeader(a.cfg.ToEmail)
	if toEmail == "" {
		return errors.New("to_email is not configured")
	}
	from := sanitizeEmailHeader(a.cfg.FromEmail)
	if from == "" {
		from = sanitizeEmailHeader(a.cfg.Username)
	}
	if from == "" {
		from = "security-hub@localhost"
	}
	cleanSubject := sanitizeEmailHeader(subject)
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
		from, toEmail, cleanSubject, now, body))

	timeout := a.timeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	done := make(chan error, 1)
	go func() {
		if a.sendMailFunc != nil {
			done <- a.sendMailFunc(ctx, a.cfg, addr, auth, from, []string{toEmail}, msg)
		} else {
			dialer := a.dialer
			if dialer == nil {
				dialer = defaultDial
			}
			done <- sendMailWithDialer(ctx, dialer, a.cfg, addr, auth, from, []string{toEmail}, msg)
		}
	}()
	select {
	case <-ctx.Done():
		return fmt.Errorf("smtp send timed out after %v: %w", timeout, ctx.Err())
	case err := <-done:
		return err
	}
}
