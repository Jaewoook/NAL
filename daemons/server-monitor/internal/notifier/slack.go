package notifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jaewoook/server-monitor/internal/models"
)

// SlackChannel dispatches alerts to Slack channels via incoming webhooks.
type SlackChannel struct {
	httpPoster
	webhookURL string
}

// NewSlackChannel creates a new SlackChannel.
func NewSlackChannel(webhookURL string) *SlackChannel {
	return &SlackChannel{
		httpPoster: newHTTPPoster(),
		webhookURL: webhookURL,
	}
}

// Name returns the channel identifier.
func (s *SlackChannel) Name() string {
	return "slack"
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type slackAttachment struct {
	Color     string       `json:"color"`
	Title     string       `json:"title"`
	Text      string       `json:"text"`
	Fields    []slackField `json:"fields,omitempty"`
	Timestamp int64        `json:"ts,omitempty"`
}

type slackPayload struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

// Send dispatches an alert to Slack via incoming webhook.
func (s *SlackChannel) Send(alert *models.Alert) error {
	return s.SendContext(context.Background(), alert)
}

// SendContext dispatches an alert to Slack via incoming webhook, honoring ctx.
func (s *SlackChannel) SendContext(ctx context.Context, alert *models.Alert) error {
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if s.webhookURL == "" {
		return errors.New("slack webhook URL is not configured")
	}

	status, respBody, err := s.postJSON(ctx, s.webhookURL, buildSlackPayload(alert), nil)
	if err != nil {
		return fmt.Errorf("slack request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("slack api error (status %d): %s", status, string(respBody))
	}

	return nil
}

func slackLevelColor(level models.AlertLevel) string {
	switch level {
	case models.AlertLevelCritical:
		return "danger"
	case models.AlertLevelWarning:
		return "warning"
	case models.AlertLevelResolved:
		return "good"
	default:
		return "#3498DB"
	}
}

func buildSlackPayload(alert *models.Alert) slackPayload {
	var fields []slackField
	if alert.Hostname != "" {
		fields = append(fields, slackField{Title: "Host", Value: alert.Hostname, Short: true})
	}
	if alert.MetricName != "" {
		fields = append(fields, slackField{Title: "Metric", Value: alert.MetricName, Short: true})
	}
	fields = append(fields, slackField{Title: "Current Value", Value: alert.FormatValue(alert.CurrentValue), Short: true})
	if alert.ThresholdValue > 0 {
		fields = append(fields, slackField{Title: "Threshold", Value: alert.FormatValue(alert.ThresholdValue), Short: true})
	}

	desc := alert.Message
	if table := models.FormatProcessesTable(alert.TopProcesses); table != "" {
		desc += "\n\n*Top Processes:*\n```\n" + table + "\n```"
	}

	return slackPayload{
		Text: fmt.Sprintf("*[%s] %s* on `%s`", alert.Level, alert.Title, alert.Hostname),
		Attachments: []slackAttachment{{
			Color:     slackLevelColor(alert.Level),
			Title:     fmt.Sprintf("[%s] %s", alert.Level, alert.Title),
			Text:      desc,
			Fields:    fields,
			Timestamp: alert.Timestamp.Unix(),
		}},
	}
}
