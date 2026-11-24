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

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/models"
)

// sendMailFunc defines the signature matching smtp.SendMail.
type sendMailFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

// EmailChannel dispatches alerts via SMTP email.
type EmailChannel struct {
	cfg          config.EmailConfig
	sendMailFunc sendMailFunc
	timeout      time.Duration
}

// NewEmailChannel creates a new EmailChannel from configuration.
func NewEmailChannel(cfg config.EmailConfig) *EmailChannel {
	return &EmailChannel{
		cfg:     cfg,
		timeout: defaultHTTPTimeout,
	}
}

// Name returns the channel identifier.
func (e *EmailChannel) Name() string {
	return "email"
}

// Send formats the alert into an RFC 822 email message and sends it via SMTP.
func (e *EmailChannel) Send(alert *models.Alert) error {
	return e.SendContext(context.Background(), alert)
}

// SendContext formats the alert into an RFC 822 email message and sends it via SMTP, honoring ctx.
func (e *EmailChannel) SendContext(ctx context.Context, alert *models.Alert) error {
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if e.cfg.SMTPHost == "" {
		return errors.New("smtp host is not configured")
	}
	if e.cfg.ToEmail == "" {
		return errors.New("destination email address is not configured")
	}

	from := e.cfg.FromEmail
	if from == "" {
		from = e.cfg.Username
	}
	if from == "" {
		from = "server-monitor@localhost"
	}

	addr := fmt.Sprintf("%s:%d", e.cfg.SMTPHost, e.cfg.SMTPPort)

	var auth smtp.Auth
	if e.cfg.Username != "" && e.cfg.Password != "" {
		auth = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.SMTPHost)
	}

	subject := fmt.Sprintf("[%s] %s - %s", alert.Level, alert.Hostname, alert.Title)

	var body strings.Builder
	body.WriteString(fmt.Sprintf("Server Monitor Alert: %s\n", alert.Title))
	body.WriteString(strings.Repeat("=", 40) + "\n")
	body.WriteString(fmt.Sprintf("Level:           %s\n", alert.Level))
	body.WriteString(fmt.Sprintf("Hostname:        %s\n", alert.Hostname))
	body.WriteString(fmt.Sprintf("Metric:          %s\n", alert.MetricName))
	body.WriteString(fmt.Sprintf("Current Value:   %s\n", alert.FormatValue(alert.CurrentValue)))
	if alert.ThresholdValue > 0 {
		body.WriteString(fmt.Sprintf("Threshold Value: %s\n", alert.FormatValue(alert.ThresholdValue)))
	}
	body.WriteString(fmt.Sprintf("Timestamp:       %s\n", alert.Timestamp.UTC().Format(time.RFC1123Z)))
	body.WriteString(fmt.Sprintf("Message:         %s\n", alert.Message))

	if len(alert.TopProcesses) > 0 {
		table := models.FormatProcessesTable(alert.TopProcesses)
		if table != "" {
			body.WriteString("\nTop Processes:\n")
			body.WriteString(table + "\n")
		}
	}

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"Date: %s\r\n\r\n%s",
		from, e.cfg.ToEmail, subject, alert.Timestamp.UTC().Format(time.RFC1123Z), body.String()))

	timeout := e.timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Support test override via sendMailFunc while honoring timeout/ctx.
	if e.sendMailFunc != nil {
		done := make(chan error, 1)
		go func() {
			done <- e.sendMailFunc(addr, auth, from, []string{e.cfg.ToEmail}, msg)
		}()
		select {
		case <-ctx.Done():
			return fmt.Errorf("smtp send timed out after %v: %w", timeout, ctx.Err())
		case err := <-done:
			if err != nil {
				return fmt.Errorf("smtp send failed: %w", err)
			}
			return nil
		}
	}

	if err := e.sendWithDialContext(ctx, addr, auth, from, []string{e.cfg.ToEmail}, msg); err != nil {
		return fmt.Errorf("smtp send failed: %w", err)
	}
	return nil
}

func (e *EmailChannel) sendWithDialContext(ctx context.Context, addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, e.cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()

	if e.cfg.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: e.cfg.SMTPHost}); err != nil {
				return err
			}
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
