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

// SlackChannel dispatches alerts to Slack channels via incoming webhooks.
type SlackChannel struct {
	webhookURL string
	client     *http.Client
}

// NewSlackChannel creates a new SlackChannel.
func NewSlackChannel(webhookURL string) *SlackChannel {
	return &SlackChannel{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
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
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if s.webhookURL == "" {
		return errors.New("slack webhook URL is not configured")
	}

	color := "#3498DB"
	switch alert.Level {
	case models.AlertLevelCritical:
		color = "danger"
	case models.AlertLevelWarning:
		color = "warning"
	case models.AlertLevelResolved:
		color = "good"
	}

	var fields []slackField
	if alert.Hostname != "" {
		fields = append(fields, slackField{Title: "Host", Value: alert.Hostname, Short: true})
	}
	if alert.MetricName != "" {
		fields = append(fields, slackField{Title: "Metric", Value: alert.MetricName, Short: true})
	}
	fields = append(fields, slackField{Title: "Current Value", Value: fmt.Sprintf("%.2f%%", alert.CurrentValue), Short: true})
	if alert.ThresholdValue > 0 {
		fields = append(fields, slackField{Title: "Threshold", Value: fmt.Sprintf("%.2f%%", alert.ThresholdValue), Short: true})
	}

	desc := alert.Message
	if len(alert.TopProcesses) > 0 {
		table := formatProcessesTable(alert.TopProcesses)
		if table != "" {
			desc += "\n\n*Top Processes:*\n```\n" + table + "\n```"
		}
	}

	attachment := slackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("[%s] %s", alert.Level, alert.Title),
		Text:      desc,
		Fields:    fields,
		Timestamp: alert.Timestamp.Unix(),
	}

	payload := slackPayload{
		Text:        fmt.Sprintf("*[%s] %s* on `%s`", alert.Level, alert.Title, alert.Hostname),
		Attachments: []slackAttachment{attachment},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack api error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}
