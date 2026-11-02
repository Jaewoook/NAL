package notifier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/config"
	"github.com/jaewoook/system-updater/internal/db"
	"github.com/jaewoook/system-updater/internal/models"
)

type sendMailFunc func(ctx context.Context, cfg config.EmailConfig, addr string, a smtp.Auth, from string, to []string, msg []byte) error

type dialerFunc func(ctx context.Context, addr string, isImplicit bool, tlsConfig *tls.Config) (net.Conn, error)

type Alerter struct {
	cfg          config.EmailConfig
	store        db.Store
	sendMailFunc sendMailFunc
	dialer       dialerFunc
	timeout      time.Duration
}

func defaultDial(ctx context.Context, addr string, isImplicit bool, tlsConfig *tls.Config) (net.Conn, error) {
	if isImplicit {
		tlsDialer := &tls.Dialer{
			Config: tlsConfig,
		}
		return tlsDialer.DialContext(ctx, "tcp", addr)
	}
	netDialer := &net.Dialer{}
	return netDialer.DialContext(ctx, "tcp", addr)
}

func NewAlerter(cfg config.EmailConfig, store db.Store) *Alerter {
	return &Alerter{
		cfg:          cfg,
		store:        store,
		sendMailFunc: nil, // set to nil so sendEmail uses a.sendWithDialer
		dialer:       defaultDial,
		timeout:      25 * time.Second,
	}
}

type forcedTLSAuth struct {
	auth smtp.Auth
}

func (f forcedTLSAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	s := *server
	s.TLS = true
	return f.auth.Start(&s)
}

func (f forcedTLSAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	return f.auth.Next(fromServer, more)
}

type loginAuth struct {
	username string
	password string
	host     string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return []byte(a.password), nil
	}
	return nil, nil
}

func sendMailWithDialer(ctx context.Context, dialer dialerFunc, cfg config.EmailConfig, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	host := cfg.SMTPHost
	isImplicit := cfg.SMTPPort == 465 || (cfg.UseTLS && cfg.SMTPPort != 587 && cfg.SMTPPort != 25 && cfg.SMTPPort != 2525 && cfg.SMTPPort != 2587)

	tlsConfig := &tls.Config{
		ServerName: host,
	}
	if host == "127.0.0.1" || host == "localhost" {
		tlsConfig.InsecureSkipVerify = true
	}

	if dialer == nil {
		dialer = defaultDial
	}

	conn, err := dialer(ctx, addr, isImplicit, tlsConfig)
	if err != nil {
		if isImplicit {
			return fmt.Errorf("tls dial failed for %s: %w", addr, err)
		}
		return fmt.Errorf("dial failed for %s: %w", addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp handshake failed for %s: %w", addr, err)
	}
	defer client.Close()

	if !isImplicit && (cfg.UseTLS || cfg.SMTPPort == 587) {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("smtp starttls failed for %s: %w", addr, err)
			}
		}
	}

	if a != nil {
		authToSend := a
		if isImplicit {
			authToSend = forcedTLSAuth{auth: a}
		}
		if ok, authMechanisms := client.Extension("AUTH"); ok {
			upper := strings.ToUpper(authMechanisms)
			if !strings.Contains(upper, "PLAIN") && strings.Contains(upper, "LOGIN") && cfg.Username != "" {
				authToSend = &loginAuth{
					username: cfg.Username,
					password: cfg.Password,
					host:     host,
				}
			}
			if err := client.Auth(authToSend); err != nil {
				return fmt.Errorf("smtp auth failed: %w", err)
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from failed: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt to failed for %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write message failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data writer failed: %w", err)
	}

	_ = client.Quit()
	return nil
}

func defaultSendMail(ctx context.Context, cfg config.EmailConfig, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return sendMailWithDialer(ctx, defaultDial, cfg, addr, a, from, to, msg)
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
	body.WriteString("NAL Security Hub — Security & Lifecycle Alert\n")
	body.WriteString(strings.Repeat("=", 52) + "\n\n")
	body.WriteString(fmt.Sprintf("Detected %d new security/lifecycle finding(s) requiring attention:\n\n", len(findings)))
	for _, f := range findings {
		body.WriteString(f.line + "\n")
	}
	body.WriteString("\nOpen your NAL Security Hub web dashboard to review and trigger controlled updates.\n")

	subject := fmt.Sprintf("[NAL Security Alert] %d New Vulnerability / EoL Finding(s)", len(findings))
	if a.cfg.Enabled {
		if err := a.sendEmail(ctx, subject, body.String()); err != nil {
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
	body := "This is a test email from NAL Security Hub (daemons/system-updater)."
	return a.sendEmail(ctx, subject, body)
}

func (a *Alerter) sendEmail(ctx context.Context, subject, body string) error {
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
			done <- a.sendMailFunc(ctx, a.cfg, addr, auth, from, []string{a.cfg.ToEmail}, msg)
		} else {
			dialer := a.dialer
			if dialer == nil {
				dialer = defaultDial
			}
			done <- sendMailWithDialer(ctx, dialer, a.cfg, addr, auth, from, []string{a.cfg.ToEmail}, msg)
		}
	}()
	select {
	case <-ctx.Done():
		return fmt.Errorf("smtp send timed out after %v: %w", timeout, ctx.Err())
	case err := <-done:
		return err
	}
}
