package notifier

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/models"
)

func TestDiscordChannel(t *testing.T) {
	tests := []struct {
		name          string
		level         models.AlertLevel
		expectedColor int
	}{
		{"critical", models.AlertLevelCritical, 16711680}, // Red
		{"warning", models.AlertLevelWarning, 16776960},   // Yellow
		{"resolved", models.AlertLevelResolved, 65280},    // Green
		{"info", models.AlertLevelInfo, 3447003},          // Blue
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPayload discordPayload
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(body, &receivedPayload); err != nil {
					t.Errorf("failed to unmarshal discord body: %v", err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer ts.Close()

			ch := NewDiscordChannel(ts.URL)
			if ch.Name() != "discord" {
				t.Errorf("expected channel name 'discord', got '%s'", ch.Name())
			}

			alert := &models.Alert{
				Title:          "Memory High",
				Message:        "Memory usage above 90%",
				Level:          tt.level,
				MetricName:     "Memory",
				CurrentValue:   91.5,
				ThresholdValue: 90.0,
				Timestamp:      time.Now(),
				Hostname:       "worker-1",
				TopProcesses: []models.ProcessInfo{
					{PID: 200, Name: "postgres", CPUPercent: 12.0, MemoryPercent: 45.0},
				},
			}

			if err := ch.Send(alert); err != nil {
				t.Fatalf("unexpected send error: %v", err)
			}

			if len(receivedPayload.Embeds) != 1 {
				t.Fatalf("expected 1 embed, got %d", len(receivedPayload.Embeds))
			}
			embed := receivedPayload.Embeds[0]
			if embed.Color != tt.expectedColor {
				t.Errorf("expected color %d, got %d", tt.expectedColor, embed.Color)
			}
			if !strings.Contains(embed.Title, "Memory High") {
				t.Errorf("expected title to contain 'Memory High', got '%s'", embed.Title)
			}
			if embed.Description != "Memory usage above 90%" {
				t.Errorf("expected description 'Memory usage above 90%%', got '%s'", embed.Description)
			}

			// Check for top processes field
			foundTopProcs := false
			for _, f := range embed.Fields {
				if f.Name == "Top Processes" && strings.Contains(f.Value, "postgres") {
					foundTopProcs = true
				}
			}
			if !foundTopProcs {
				t.Errorf("expected top processes field containing 'postgres'")
			}
		})
	}
}

func TestDiscordChannelErrors(t *testing.T) {
	// Nil alert
	ch := NewDiscordChannel("http://example.com")
	if err := ch.Send(nil); err == nil {
		t.Error("expected error for nil alert")
	}

	// Missing URL
	chEmpty := NewDiscordChannel("")
	if err := chEmpty.Send(&models.Alert{Title: "Test"}); err == nil {
		t.Error("expected error for empty webhook URL")
	}

	// HTTP error response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Invalid Webhook Token"}`))
	}))
	defer ts.Close()

	chErr := NewDiscordChannel(ts.URL)
	err := chErr.Send(&models.Alert{Title: "Test"})
	if err == nil {
		t.Error("expected error on HTTP 401 response")
	}
	if !strings.Contains(err.Error(), "Invalid Webhook Token") {
		t.Errorf("expected error message to contain 'Invalid Webhook Token', got: %v", err)
	}
}

func TestSlackChannel(t *testing.T) {
	tests := []struct {
		name          string
		level         models.AlertLevel
		expectedColor string
	}{
		{"critical", models.AlertLevelCritical, "danger"},
		{"warning", models.AlertLevelWarning, "warning"},
		{"resolved", models.AlertLevelResolved, "good"},
		{"info", models.AlertLevelInfo, "#3498DB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPayload slackPayload
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(body, &receivedPayload); err != nil {
					t.Errorf("failed to unmarshal slack body: %v", err)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))
			defer ts.Close()

			ch := NewSlackChannel(ts.URL)
			if ch.Name() != "slack" {
				t.Errorf("expected channel name 'slack', got '%s'", ch.Name())
			}

			alert := &models.Alert{
				Title:          "Disk Full",
				Message:        "Disk at 95%",
				Level:          tt.level,
				MetricName:     "Disk",
				CurrentValue:   95.0,
				ThresholdValue: 85.0,
				Timestamp:      time.Now(),
				Hostname:       "db-server",
				TopProcesses: []models.ProcessInfo{
					{PID: 12, Name: "influxd", CPUPercent: 4.2, MemoryPercent: 18.0},
				},
			}

			if err := ch.Send(alert); err != nil {
				t.Fatalf("unexpected send error: %v", err)
			}

			if len(receivedPayload.Attachments) != 1 {
				t.Fatalf("expected 1 attachment, got %d", len(receivedPayload.Attachments))
			}
			att := receivedPayload.Attachments[0]
			if att.Color != tt.expectedColor {
				t.Errorf("expected color '%s', got '%s'", tt.expectedColor, att.Color)
			}
			if !strings.Contains(att.Title, "Disk Full") {
				t.Errorf("expected title to contain 'Disk Full', got '%s'", att.Title)
			}
			if !strings.Contains(att.Text, "influxd") {
				t.Errorf("expected text to include 'influxd', got: %s", att.Text)
			}
		})
	}
}

func TestSlackChannelErrors(t *testing.T) {
	// Nil alert
	ch := NewSlackChannel("http://example.com")
	if err := ch.Send(nil); err == nil {
		t.Error("expected error for nil alert")
	}

	// Missing URL
	chEmpty := NewSlackChannel("")
	if err := chEmpty.Send(&models.Alert{Title: "Test"}); err == nil {
		t.Error("expected error for empty webhook URL")
	}

	// HTTP error response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("channel_not_found"))
	}))
	defer ts.Close()

	chErr := NewSlackChannel(ts.URL)
	err := chErr.Send(&models.Alert{Title: "Test"})
	if err == nil {
		t.Error("expected error on HTTP 404 response")
	}
	if !strings.Contains(err.Error(), "channel_not_found") {
		t.Errorf("expected error message to contain 'channel_not_found', got: %v", err)
	}
}

func TestWebhookChannel(t *testing.T) {
	var receivedAlert models.Alert
	var userAgent string
	var contentType string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &receivedAlert); err != nil {
			t.Errorf("failed to unmarshal alert payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ch := NewWebhookChannel(ts.URL)
	if ch.Name() != "webhook" {
		t.Errorf("expected channel name 'webhook', got '%s'", ch.Name())
	}

	alert := &models.Alert{
		Title:          "CPU Plunge",
		Message:        "CPU plunged 45%",
		Level:          models.AlertLevelCritical,
		MetricName:     "CPU",
		CurrentValue:   12.0,
		ThresholdValue: 40.0,
		Timestamp:      time.Now(),
		Hostname:       "node-2",
	}

	if err := ch.Send(alert); err != nil {
		t.Fatalf("unexpected send error: %v", err)
	}

	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got '%s'", contentType)
	}
	if userAgent != "server-monitor/1.0" {
		t.Errorf("expected User-Agent server-monitor/1.0, got '%s'", userAgent)
	}
	if receivedAlert.Title != "CPU Plunge" || receivedAlert.Hostname != "node-2" {
		t.Errorf("unexpected deserialized alert: %+v", receivedAlert)
	}
}

func TestWebhookChannelErrors(t *testing.T) {
	// Nil alert
	ch := NewWebhookChannel("http://example.com")
	if err := ch.Send(nil); err == nil {
		t.Error("expected error for nil alert")
	}

	// Missing URL
	chEmpty := NewWebhookChannel("")
	if err := chEmpty.Send(&models.Alert{Title: "Test"}); err == nil {
		t.Error("expected error for empty webhook URL")
	}

	// HTTP error response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal database failure"))
	}))
	defer ts.Close()

	chErr := NewWebhookChannel(ts.URL)
	err := chErr.Send(&models.Alert{Title: "Test"})
	if err == nil {
		t.Error("expected error on HTTP 500 response")
	}
	if !strings.Contains(err.Error(), "internal database failure") {
		t.Errorf("expected error message to contain 'internal database failure', got: %v", err)
	}
}

func TestEmailChannel(t *testing.T) {
	var sentAddr string
	var sentFrom string
	var sentTo []string
	var sentMsg []byte
	var capturedAuth smtp.Auth

	mockSend := func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		sentAddr = addr
		capturedAuth = a
		sentFrom = from
		sentTo = to
		sentMsg = msg
		return nil
	}

	cfg := config.EmailConfig{
		Enabled:  true,
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		UseTLS:   true,
		Username: "alert-bot@example.com",
		Password: "secretpassword",
		ToEmail:  "sysadmin@example.com",
	}

	ch := NewEmailChannel(cfg)
	ch.sendMailFunc = mockSend

	if ch.Name() != "email" {
		t.Errorf("expected channel name 'email', got '%s'", ch.Name())
	}

	alert := &models.Alert{
		Title:          "Memory Spike",
		Message:        "Memory reached 92%",
		Level:          models.AlertLevelCritical,
		MetricName:     "Memory",
		CurrentValue:   92.0,
		ThresholdValue: 90.0,
		Timestamp:      time.Now(),
		Hostname:       "prod-srv-01",
		TopProcesses: []models.ProcessInfo{
			{PID: 1001, Name: "redis-server", CPUPercent: 5.5, MemoryPercent: 78.2},
		},
	}

	if err := ch.Send(alert); err != nil {
		t.Fatalf("unexpected error sending email: %v", err)
	}

	if sentAddr != "smtp.example.com:587" {
		t.Errorf("expected addr 'smtp.example.com:587', got '%s'", sentAddr)
	}
	if sentFrom != "alert-bot@example.com" {
		t.Errorf("expected from 'alert-bot@example.com', got '%s'", sentFrom)
	}
	if len(sentTo) != 1 || sentTo[0] != "sysadmin@example.com" {
		t.Errorf("expected to ['sysadmin@example.com'], got %v", sentTo)
	}
	if capturedAuth == nil {
		t.Error("expected auth to be initialized with username/password")
	}

	msgStr := string(sentMsg)
	if !strings.Contains(msgStr, "Subject: [CRITICAL] prod-srv-01 - Memory Spike") {
		t.Errorf("missing or invalid subject header: %s", msgStr)
	}
	if !strings.Contains(msgStr, "To: sysadmin@example.com") {
		t.Errorf("missing or invalid To header: %s", msgStr)
	}
	if !strings.Contains(msgStr, "redis-server") {
		t.Errorf("missing top process in email body: %s", msgStr)
	}
}

func TestEmailChannelErrors(t *testing.T) {
	// Nil alert
	ch := NewEmailChannel(config.EmailConfig{})
	if err := ch.Send(nil); err == nil {
		t.Error("expected error for nil alert")
	}

	// Missing SMTP host
	chNoHost := NewEmailChannel(config.EmailConfig{ToEmail: "test@example.com"})
	if err := chNoHost.Send(&models.Alert{Title: "Test"}); err == nil {
		t.Error("expected error for missing SMTP host")
	}

	// Missing ToEmail
	chNoTo := NewEmailChannel(config.EmailConfig{SMTPHost: "smtp.example.com"})
	if err := chNoTo.Send(&models.Alert{Title: "Test"}); err == nil {
		t.Error("expected error for missing ToEmail")
	}

	// Send failure
	chFail := NewEmailChannel(config.EmailConfig{
		SMTPHost: "smtp.example.com",
		SMTPPort: 25,
		ToEmail:  "test@example.com",
	})
	chFail.sendMailFunc = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		return errors.New("connection refused")
	}

	err := chFail.Send(&models.Alert{Title: "Test"})
	if err == nil {
		t.Error("expected error when sendMailFunc fails")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected connection refused error, got: %v", err)
	}
}
