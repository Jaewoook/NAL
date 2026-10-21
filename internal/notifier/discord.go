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

// DiscordChannel dispatches alerts to Discord channels via webhooks.
type DiscordChannel struct {
	webhookURL string
	client     *http.Client
}

// NewDiscordChannel creates a new DiscordChannel.
func NewDiscordChannel(webhookURL string) *DiscordChannel {
	return &DiscordChannel{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Name returns the channel identifier.
func (d *DiscordChannel) Name() string {
	return "discord"
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

// Send dispatches an alert to Discord as a rich embed with color coding.
func (d *DiscordChannel) Send(alert *models.Alert) error {
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if d.webhookURL == "" {
		return errors.New("discord webhook URL is not configured")
	}

	color := 3447003 // 0x3498DB (Blue/Info)
	switch alert.Level {
	case models.AlertLevelCritical:
		color = 16711680 // 0xFF0000 (Red)
	case models.AlertLevelWarning:
		color = 16776960 // 0xFFFF00 (Yellow)
	case models.AlertLevelResolved:
		color = 65280 // 0x00FF00 (Green)
	}

	var fields []discordField
	if alert.Hostname != "" {
		fields = append(fields, discordField{Name: "Host", Value: alert.Hostname, Inline: true})
	}
	if alert.MetricName != "" {
		fields = append(fields, discordField{Name: "Metric", Value: alert.MetricName, Inline: true})
	}
	fields = append(fields, discordField{Name: "Current Value", Value: fmt.Sprintf("%.2f%%", alert.CurrentValue), Inline: true})
	if alert.ThresholdValue > 0 {
		fields = append(fields, discordField{Name: "Threshold", Value: fmt.Sprintf("%.2f%%", alert.ThresholdValue), Inline: true})
	}

	if len(alert.TopProcesses) > 0 {
		table := formatProcessesTable(alert.TopProcesses)
		if table != "" {
			fields = append(fields, discordField{
				Name:   "Top Processes",
				Value:  "```\n" + table + "\n```",
				Inline: false,
			})
		}
	}

	ts := ""
	if !alert.Timestamp.IsZero() {
		ts = alert.Timestamp.UTC().Format(time.RFC3339)
	}

	embed := discordEmbed{
		Title:       fmt.Sprintf("[%s] %s", alert.Level, alert.Title),
		Description: alert.Message,
		Color:       color,
		Fields:      fields,
		Timestamp:   ts,
	}

	payload := discordPayload{
		Embeds: []discordEmbed{embed},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal discord payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("discord request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord api error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}
