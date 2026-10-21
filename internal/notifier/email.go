package notifier

import (
	"context"
	"errors"
	"fmt"
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
		cfg:          cfg,
		sendMailFunc: smtp.SendMail,
		timeout:      5 * time.Second,
	}
}

// Name returns the channel identifier.
func (e *EmailChannel) Name() string {
	return "email"
}

// Send formats the alert into an RFC 822 email message and sends it via SMTP.
func (e *EmailChannel) Send(alert *models.Alert) error {
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if e.cfg.SMTPHost == "" {
		return errors.New("smtp host is not configured")
	}
	if e.cfg.ToEmail == "" {
		return errors.New("destination email address is not configured")
	}

	from := e.cfg.Username
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
	body.WriteString(fmt.Sprintf("Current Value:   %.2f%%\n", alert.CurrentValue))
	if alert.ThresholdValue > 0 {
		body.WriteString(fmt.Sprintf("Threshold Value: %.2f%%\n", alert.ThresholdValue))
	}
	body.WriteString(fmt.Sprintf("Timestamp:       %s\n", alert.Timestamp.UTC().Format(time.RFC1123Z)))
	body.WriteString(fmt.Sprintf("Message:         %s\n", alert.Message))

	if len(alert.TopProcesses) > 0 {
		table := formatProcessesTable(alert.TopProcesses)
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
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

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
	}

	return nil
}
