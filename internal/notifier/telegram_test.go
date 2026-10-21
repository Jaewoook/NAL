package notifier

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTelegramChannelSend(t *testing.T) {
	var receivedBody string
	var receivedContentType string

	ch := NewTelegramChannelWithEndpoint("test-token", "12345", "http://localhost/test")
	ch.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		receivedContentType = req.Header.Get("Content-Type")
		body, _ := io.ReadAll(req.Body)
		receivedBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok": true}`)),
			Header:     make(http.Header),
		}, nil
	})

	if ch.Name() != "telegram" {
		t.Errorf("expected channel name 'telegram', got '%s'", ch.Name())
	}

	alert := &models.Alert{
		Title:          "CPU Spike Alert",
		Message:        "CPU reached 95%",
		Level:          models.AlertLevelCritical,
		MetricName:     "CPU",
		CurrentValue:   95.0,
		ThresholdValue: 85.0,
		Timestamp:      time.Now(),
		Hostname:       "my-server",
		TopProcesses: []models.ProcessInfo{
			{PID: 101, Name: "stress", CPUPercent: 88.5, MemoryPercent: 2.1},
		},
	}

	err := ch.Send(alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(receivedContentType, "application/json") {
		t.Errorf("expected Content-Type application/json, got: %s", receivedContentType)
	}

	var parsedPayload map[string]interface{}
	if err := json.Unmarshal([]byte(receivedBody), &parsedPayload); err != nil {
		t.Fatalf("failed to unmarshal received body as JSON: %v", err)
	}

	if parsedPayload["chat_id"] != "12345" {
		t.Errorf("expected chat_id '12345', got '%v'", parsedPayload["chat_id"])
	}
	if parsedPayload["parse_mode"] != "HTML" {
		t.Errorf("expected parse_mode 'HTML', got '%v'", parsedPayload["parse_mode"])
	}

	if !strings.Contains(receivedBody, "stress") {
		t.Errorf("payload did not contain top process 'stress': %s", receivedBody)
	}
}

func TestTelegramChannelHTTPError(t *testing.T) {
	ch := NewTelegramChannelWithEndpoint("test-token", "invalid-chat", "http://localhost/test")
	ch.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(`{"ok": false, "description": "Bad Request: chat not found"}`)),
			Header:     make(http.Header),
		}, nil
	})

	alert := &models.Alert{
		Title:   "Alert",
		Message: "Test",
		Level:   models.AlertLevelWarning,
	}

	err := ch.Send(alert)
	if err == nil {
		t.Fatal("expected error on HTTP 400 response, got nil")
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("expected error to mention 'chat not found', got: %v", err)
	}
}

func TestTelegramChannelNilAlert(t *testing.T) {
	ch := NewTelegramChannelWithEndpoint("test-token", "12345", "http://localhost:9999")
	err := ch.Send(nil)
	if err == nil {
		t.Fatal("expected error for nil alert, got nil")
	}
}

func TestTelegramChannelConfigValidation(t *testing.T) {
	chNoToken := NewTelegramChannel("", "12345")
	if err := chNoToken.Send(&models.Alert{Title: "Test"}); err == nil {
		t.Error("expected error for empty bot token")
	}

	chNoChatID := NewTelegramChannel("token", "")
	if err := chNoChatID.Send(&models.Alert{Title: "Test"}); err == nil {
		t.Error("expected error for empty chat ID")
	}
}

func TestTelegramChannelDefaultEndpoint(t *testing.T) {
	ch := NewTelegramChannel("test-token", "12345")
	if ch.Name() != "telegram" {
		t.Errorf("expected channel name 'telegram', got '%s'", ch.Name())
	}
	expectedURL := "https://api.telegram.org/bottest-token/sendMessage"
	if ch.endpoint != expectedURL {
		t.Errorf("expected default endpoint '%s', got '%s'", expectedURL, ch.endpoint)
	}
}

func TestTelegramChannelHTMLEscaping(t *testing.T) {
	var receivedBody string
	ch := NewTelegramChannelWithEndpoint("test-token", "12345", "http://localhost/test")
	ch.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		receivedBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok": true}`)),
			Header:     make(http.Header),
		}, nil
	})

	alert := &models.Alert{
		Title:   "CPU <Critical> & Warning",
		Message: "Value > 90% && status <fail>",
		Level:   models.AlertLevelCritical,
	}

	if err := ch.Send(alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload telegramPayload
	if err := json.Unmarshal([]byte(receivedBody), &payload); err != nil {
		t.Fatalf("failed to unmarshal received body: %v", err)
	}

	// Should contain HTML escaped strings &lt;, &gt;, &amp;
	if !strings.Contains(payload.Text, "&lt;Critical&gt;") || !strings.Contains(payload.Text, "&amp;") {
		t.Errorf("expected HTML escaped content in received text: %s", payload.Text)
	}
}

func TestTelegramChannelOKFalse200(t *testing.T) {
	ch := NewTelegramChannelWithEndpoint("test-token", "12345", "http://localhost/test")
	ch.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok": false, "description": "bot was blocked by user"}`)),
			Header:     make(http.Header),
		}, nil
	})

	err := ch.Send(&models.Alert{Title: "Test"})
	if err == nil {
		t.Fatal("expected error when ok=false, got nil")
	}
	if !strings.Contains(err.Error(), "bot was blocked by user") {
		t.Errorf("expected error to contain description, got: %v", err)
	}
}

func TestTelegramChannelMessageLengthCap(t *testing.T) {
	var capturedPayload telegramPayload
	ch := NewTelegramChannelWithEndpoint("test-token", "12345", "http://localhost/test")
	ch.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(body, &capturedPayload)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok": true}`)),
			Header:     make(http.Header),
		}, nil
	})

	longMsg := strings.Repeat("A", 5000)
	alert := &models.Alert{
		Title:   "Long message",
		Message: longMsg,
		Level:   models.AlertLevelCritical,
	}

	if err := ch.Send(alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len([]rune(capturedPayload.Text)) > 4096 {
		t.Errorf("expected text length <= 4096, got %d", len([]rune(capturedPayload.Text)))
	}
	if !strings.HasSuffix(capturedPayload.Text, "...") {
		t.Errorf("expected truncated text to end with '...', got: %s", capturedPayload.Text[len(capturedPayload.Text)-10:])
	}
}
