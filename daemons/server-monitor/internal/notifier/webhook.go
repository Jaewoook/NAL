package notifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/jaewoook/server-monitor/internal/models"
)

// WebhookChannel dispatches alerts to any generic HTTP webhook via JSON POST.
type WebhookChannel struct {
	httpPoster
	url string
}

// NewWebhookChannel creates a new WebhookChannel.
func NewWebhookChannel(url string) *WebhookChannel {
	return &WebhookChannel{
		httpPoster: newHTTPPoster(),
		url:        url,
	}
}

// Name returns the channel identifier.
func (w *WebhookChannel) Name() string {
	return "webhook"
}

// Send dispatches the alert as a JSON payload to the configured webhook URL.
func (w *WebhookChannel) Send(alert *models.Alert) error {
	return w.SendContext(context.Background(), alert)
}

// SendContext dispatches the alert as a JSON payload to the configured webhook URL, honoring ctx.
func (w *WebhookChannel) SendContext(ctx context.Context, alert *models.Alert) error {
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if w.url == "" {
		return errors.New("webhook URL is not configured")
	}

	headers := map[string]string{
		"User-Agent": "server-monitor/1.0",
	}

	status, respBody, err := w.postJSON(ctx, w.url, alert, headers)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("webhook endpoint returned status %d: %s", status, string(respBody))
	}

	return nil
}
