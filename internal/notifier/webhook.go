package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

// WebhookChannel dispatches alerts to any generic HTTP webhook via JSON POST.
type WebhookChannel struct {
	url    string
	client *http.Client
}

// NewWebhookChannel creates a new WebhookChannel.
func NewWebhookChannel(url string) *WebhookChannel {
	return &WebhookChannel{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Name returns the channel identifier.
func (w *WebhookChannel) Name() string {
	return "webhook"
}

// Send dispatches the alert as a JSON payload to the configured webhook URL.
func (w *WebhookChannel) Send(alert *models.Alert) error {
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if w.url == "" {
		return errors.New("webhook URL is not configured")
	}

	bodyBytes, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "server-monitor/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
