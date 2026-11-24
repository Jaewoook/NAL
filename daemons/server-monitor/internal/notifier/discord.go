package notifier

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

// DiscordChannel dispatches alerts to Discord channels via webhooks.
type DiscordChannel struct {
	httpPoster
	webhookURL string
}

// NewDiscordChannel creates a new DiscordChannel.
func NewDiscordChannel(webhookURL string) *DiscordChannel {
	return &DiscordChannel{
		httpPoster: newHTTPPoster(),
		webhookURL: webhookURL,
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
	return d.SendContext(context.Background(), alert)
}

// SendContext dispatches an alert to Discord as a rich embed, honoring ctx.
func (d *DiscordChannel) SendContext(ctx context.Context, alert *models.Alert) error {
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
	fields = append(fields, discordField{Name: "Current Value", Value: alert.FormatValue(alert.CurrentValue), Inline: true})
	if alert.ThresholdValue > 0 {
		fields = append(fields, discordField{Name: "Threshold", Value: alert.FormatValue(alert.ThresholdValue), Inline: true})
	}

	if len(alert.TopProcesses) > 0 {
		table := models.FormatProcessesTable(alert.TopProcesses)
		if table != "" {
			runes := []rune(table)
			if len(runes) > 1000 {
				table = string(runes[:997]) + "..."
			}
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

	payload := discordPayload{
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("[%s] %s", alert.Level, alert.Title),
			Description: alert.Message,
			Color:       color,
			Fields:      fields,
			Timestamp:   ts,
		}},
	}

	status, respBody, err := d.postJSON(ctx, d.webhookURL, payload, nil)
	if err != nil {
		return fmt.Errorf("discord request failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("discord api error (status %d): %s", status, string(respBody))
	}

	return nil
}
