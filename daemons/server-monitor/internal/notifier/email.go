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

	"github.com/jaewoook/server-monitor/internal/models"
)

// EmailOptions configures SMTP delivery for EmailChannel without coupling to internal/config.
type EmailOptions struct {
	SMTPHost  string
	SMTPPort  int
	UseTLS    bool
	Username  string
	Password  string
	FromEmail string
	ToEmail   string
}

// sendMailFunc defines the signature matching smtp.SendMail.
type sendMailFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

// EmailChannel dispatches alerts via SMTP email.
type EmailChannel struct {
	opts         EmailOptions
	sendMailFunc sendMailFunc
	timeout      time.Duration
}

// NewEmailChannel creates a new EmailChannel from SMTP options.
func NewEmailChannel(opts EmailOptions) *EmailChannel {
	return &EmailChannel{
		opts:    opts,
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
	if e.opts.SMTPHost == "" {
		return errors.New("smtp host is not configured")
	}
	if e.opts.ToEmail == "" {
		return errors.New("destination email address is not configured")
	}

	from := e.resolveFrom()
	addr := fmt.Sprintf("%s:%d", e.opts.SMTPHost, e.opts.SMTPPort)

	var auth smtp.Auth
	if e.opts.Username != "" && e.opts.Password != "" {
		auth = smtp.PlainAuth("", e.opts.Username, e.opts.Password, e.opts.SMTPHost)
	}

	msg := buildEmailMessage(from, e.opts.ToEmail, alert)

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
			done <- e.sendMailFunc(addr, auth, from, []string{e.opts.ToEmail}, msg)
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

	if err := e.sendWithDialContext(ctx, addr, auth, from, []string{e.opts.ToEmail}, msg); err != nil {
		return fmt.Errorf("smtp send failed: %w", err)
	}
	return nil
}

func (e *EmailChannel) resolveFrom() string {
	if e.opts.FromEmail != "" {
		return e.opts.FromEmail
	}
	if e.opts.Username != "" {
		return e.opts.Username
	}
	return "server-monitor@localhost"
}

func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func buildEmailMessage(from, to string, alert *models.Alert) []byte {
	from = sanitizeHeader(from)
	to = sanitizeHeader(to)
	subject := sanitizeHeader(fmt.Sprintf("[%s] %s - %s", alert.Level, alert.Hostname, alert.Title))
	dateStr := alert.Timestamp.UTC().Format(time.RFC1123Z)

	var body strings.Builder
	fmt.Fprintf(&body, "Server Monitor Alert: %s\n", alert.Title)
	body.WriteString(strings.Repeat("=", 40) + "\n")
	fmt.Fprintf(&body, "Level:           %s\n", alert.Level)
	fmt.Fprintf(&body, "Hostname:        %s\n", alert.Hostname)
	fmt.Fprintf(&body, "Metric:          %s\n", alert.MetricName)
	fmt.Fprintf(&body, "Current Value:   %s\n", alert.FormatValue(alert.CurrentValue))
	if alert.ThresholdValue > 0 {
		fmt.Fprintf(&body, "Threshold Value: %s\n", alert.FormatValue(alert.ThresholdValue))
	}
	if tempSummary := alert.FormatTemperatures(); tempSummary != "" {
		fmt.Fprintf(&body, "Temperature:     %s\n", tempSummary)
	}
	fmt.Fprintf(&body, "Timestamp:       %s\n", dateStr)
	fmt.Fprintf(&body, "Message:         %s\n", alert.Message)

	if table := models.FormatProcessesTable(alert.TopProcesses); table != "" {
		body.WriteString("\nTop Processes:\n")
		body.WriteString(table + "\n")
	}

	return []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"Date: %s\r\n\r\n%s",
		from, to, subject, dateStr, body.String()))
}

func (e *EmailChannel) sendWithDialContext(ctx context.Context, addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: e.opts.SMTPHost}

	var (
		conn net.Conn
		err  error
	)
	if e.opts.UseTLS && e.opts.SMTPPort == 465 {
		// Implicit TLS (SMTPS on port 465)
		dialer := &tls.Dialer{Config: tlsCfg}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	} else {
		var dialer net.Dialer
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, e.opts.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()

	if e.opts.UseTLS && e.opts.SMTPPort != 465 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
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
