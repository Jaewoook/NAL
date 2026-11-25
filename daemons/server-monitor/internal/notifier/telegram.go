package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"

	"github.com/jaewoook/server-monitor/internal/models"
)

const maxTelegramMessageRunes = 4096

// TelegramChannel dispatches alerts to a Telegram chat via Bot API.
type TelegramChannel struct {
	httpPoster
	botToken string
	chatID   string
	endpoint string
}

// NewTelegramChannel creates a TelegramChannel pointing to the default Telegram Bot API endpoint.
func NewTelegramChannel(botToken, chatID string) *TelegramChannel {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	return NewTelegramChannelWithEndpoint(botToken, chatID, endpoint)
}

// NewTelegramChannelWithEndpoint creates a TelegramChannel with a custom endpoint URL (useful for testing).
func NewTelegramChannelWithEndpoint(botToken, chatID, endpoint string) *TelegramChannel {
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	}
	return &TelegramChannel{
		httpPoster: newHTTPPoster(),
		botToken:   botToken,
		chatID:     chatID,
		endpoint:   endpoint,
	}
}

// Name returns the channel identifier.
func (t *TelegramChannel) Name() string {
	return "telegram"
}

type telegramPayload struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

type telegramResponse struct {
	Ok          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

// Send formats the alert into an HTML message and posts it to Telegram.
func (t *TelegramChannel) Send(alert *models.Alert) error {
	return t.SendContext(context.Background(), alert)
}

// SendContext formats the alert into an HTML message and posts it to Telegram, honoring ctx.
func (t *TelegramChannel) SendContext(ctx context.Context, alert *models.Alert) error {
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if t.botToken == "" || t.chatID == "" {
		return errors.New("telegram bot token and chat ID must be configured")
	}

	payload := telegramPayload{
		ChatID:    t.chatID,
		Text:      truncateTelegramHTML(formatTelegramMessage(alert), maxTelegramMessageRunes),
		ParseMode: "HTML",
	}

	status, respBody, err := t.postJSON(ctx, t.endpoint, payload, nil)
	if err != nil {
		return fmt.Errorf("telegram request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("telegram api error (status %d): %s", status, string(respBody))
	}

	var tgResp telegramResponse
	if err := json.Unmarshal(respBody, &tgResp); err == nil && !tgResp.Ok {
		return fmt.Errorf("telegram api returned not ok: %s", tgResp.Description)
	}

	return nil
}

func telegramLevelIcon(level models.AlertLevel) string {
	switch level {
	case models.AlertLevelCritical:
		return "🚨"
	case models.AlertLevelWarning:
		return "⚠️"
	case models.AlertLevelResolved:
		return "✅"
	default:
		return "ℹ️"
	}
}

func formatTelegramMessage(alert *models.Alert) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s <b>[%s] %s</b>\n",
		telegramLevelIcon(alert.Level),
		html.EscapeString(string(alert.Level)),
		html.EscapeString(alert.Title)))

	if alert.Hostname != "" {
		buf.WriteString(fmt.Sprintf("<b>Host:</b> <code>%s</code>\n", html.EscapeString(alert.Hostname)))
	}
	if alert.MetricName != "" {
		if alert.ThresholdValue > 0 {
			buf.WriteString(fmt.Sprintf("<b>Metric:</b> %s (Current: %s, Threshold: %s)\n",
				html.EscapeString(alert.MetricName), alert.FormatValue(alert.CurrentValue), alert.FormatValue(alert.ThresholdValue)))
		} else {
			buf.WriteString(fmt.Sprintf("<b>Metric:</b> %s (Current: %s)\n",
				html.EscapeString(alert.MetricName), alert.FormatValue(alert.CurrentValue)))
		}
	}
	if !alert.Timestamp.IsZero() {
		buf.WriteString(fmt.Sprintf("<b>Time:</b> %s\n", alert.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")))
	}
	if alert.Message != "" {
		buf.WriteString(fmt.Sprintf("<b>Message:</b> %s\n", html.EscapeString(alert.Message)))
	}

	if table := models.FormatProcessesTable(alert.TopProcesses); table != "" {
		const (
			prePrefix = "\n<b>Top Processes:</b>\n<pre>"
			preSuffix = "</pre>\n"
		)
		escapedTable := html.EscapeString(table)
		baseRunes := len([]rune(buf.String()))
		budget := maxTelegramMessageRunes - baseRunes - len([]rune(prePrefix)) - len([]rune(preSuffix))
		if budget > 0 {
			tableRunes := []rune(escapedTable)
			if len(tableRunes) > budget {
				if budget > 3 {
					escapedTable = string(tableRunes[:budget-3]) + "..."
				} else {
					escapedTable = string(tableRunes[:budget])
				}
			}
			buf.WriteString(prePrefix)
			buf.WriteString(escapedTable)
			buf.WriteString(preSuffix)
		}
	}

	return buf.String()
}

func truncateTelegramHTML(msgText string, maxLen int) string {
	runes := []rune(msgText)
	if len(runes) <= maxLen {
		return msgText
	}

	const suffix = "..."
	cutoff := maxLen - len([]rune(suffix))
	truncated := string(runes[:cutoff]) + suffix

	// Ensure any open <pre> tag is balanced after truncation.
	if strings.Count(truncated, "<pre>") > strings.Count(truncated, "</pre>") {
		const closeTag = "\n</pre>"
		cutoff = maxLen - len([]rune(suffix)) - len([]rune(closeTag))
		truncated = string(runes[:cutoff]) + suffix + closeTag
	}

	return truncated
}
