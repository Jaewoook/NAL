package notifier

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

const (
	discordColorInfo     = 0x3498DB
	discordColorCritical = 0xFF0000
	discordColorWarning  = 0xFFFF00
	discordColorResolved = 0x00FF00
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

	status, respBody, err := d.postJSON(ctx, d.webhookURL, buildDiscordPayload(alert), nil)
	if err != nil {
		return fmt.Errorf("discord request failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("discord api error (status %d): %s", status, string(respBody))
	}

	return nil
}

func discordLevelColor(level models.AlertLevel) int {
	switch level {
	case models.AlertLevelCritical:
		return discordColorCritical
	case models.AlertLevelWarning:
		return discordColorWarning
	case models.AlertLevelResolved:
		return discordColorResolved
	default:
		return discordColorInfo
	}
}

func buildDiscordPayload(alert *models.Alert) discordPayload {
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

	if table := models.FormatProcessesTable(alert.TopProcesses); table != "" {
		if runes := []rune(table); len(runes) > 1000 {
			table = string(runes[:997]) + "..."
		}
		fields = append(fields, discordField{
			Name:   "Top Processes",
			Value:  "```\n" + table + "\n```",
			Inline: false,
		})
	}

	ts := ""
	if !alert.Timestamp.IsZero() {
		ts = alert.Timestamp.UTC().Format(time.RFC3339)
	}

	return discordPayload{
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("[%s] %s", alert.Level, alert.Title),
			Description: alert.Message,
			Color:       discordLevelColor(alert.Level),
			Fields:      fields,
			Timestamp:   ts,
		}},
	}
}
