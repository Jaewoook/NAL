package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

// TelegramChannel dispatches alerts to a Telegram chat via Bot API.
type TelegramChannel struct {
	botToken string
	chatID   string
	endpoint string
	client   *http.Client
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
		botToken: botToken,
		chatID:   chatID,
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// SetTransport configures a custom HTTP transport (useful for tests or proxies).
func (t *TelegramChannel) SetTransport(rt http.RoundTripper) {
	t.client.Transport = rt
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
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if t.botToken == "" || t.chatID == "" {
		return errors.New("telegram bot token and chat ID must be configured")
	}

	icon := "ℹ️"
	switch alert.Level {
	case models.AlertLevelCritical:
		icon = "🚨"
	case models.AlertLevelWarning:
		icon = "⚠️"
	case models.AlertLevelResolved:
		icon = "✅"
	}

	var textBuilder bytes.Buffer
	textBuilder.WriteString(fmt.Sprintf("%s <b>[%s] %s</b>\n", icon, html.EscapeString(string(alert.Level)), html.EscapeString(alert.Title)))
	if alert.Hostname != "" {
		textBuilder.WriteString(fmt.Sprintf("<b>Host:</b> <code>%s</code>\n", html.EscapeString(alert.Hostname)))
	}
	if alert.MetricName != "" {
		if alert.ThresholdValue > 0 {
			textBuilder.WriteString(fmt.Sprintf("<b>Metric:</b> %s (Current: %.2f%%, Threshold: %.2f%%)\n",
				html.EscapeString(alert.MetricName), alert.CurrentValue, alert.ThresholdValue))
		} else {
			textBuilder.WriteString(fmt.Sprintf("<b>Metric:</b> %s (Current: %.2f%%)\n",
				html.EscapeString(alert.MetricName), alert.CurrentValue))
		}
	}
	if !alert.Timestamp.IsZero() {
		textBuilder.WriteString(fmt.Sprintf("<b>Time:</b> %s\n", alert.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")))
	}
	if alert.Message != "" {
		textBuilder.WriteString(fmt.Sprintf("<b>Message:</b> %s\n", html.EscapeString(alert.Message)))
	}

	if len(alert.TopProcesses) > 0 {
		table := formatProcessesTable(alert.TopProcesses)
		if table != "" {
			escapedTable := html.EscapeString(table)
			const (
				prePrefix = "\n<b>Top Processes:</b>\n<pre>"
				preSuffix = "</pre>\n"
				maxLen    = 4096
			)
			baseRunes := len([]rune(textBuilder.String()))
			budget := maxLen - baseRunes - len([]rune(prePrefix)) - len([]rune(preSuffix))
			if budget > 0 {
				tableRunes := []rune(escapedTable)
				if len(tableRunes) > budget {
					if budget > 3 {
						escapedTable = string(tableRunes[:budget-3]) + "..."
					} else {
						escapedTable = string(tableRunes[:budget])
					}
				}
				textBuilder.WriteString(prePrefix)
				textBuilder.WriteString(escapedTable)
				textBuilder.WriteString(preSuffix)
			}
		}
	}

	msgText := textBuilder.String()
	const maxTelegramLength = 4096
	if len([]rune(msgText)) > maxTelegramLength {
		runes := []rune(msgText)
		const suffix = "..."
		cutoff := maxTelegramLength - len([]rune(suffix))
		truncated := string(runes[:cutoff]) + suffix

		// If <pre> is open in truncated slice without matching </pre>, close it
		if strings.Count(truncated, "<pre>") > strings.Count(truncated, "</pre>") {
			closeTag := "\n</pre>"
			cutoff = maxTelegramLength - len([]rune(suffix)) - len([]rune(closeTag))
			truncated = string(runes[:cutoff]) + suffix + closeTag
		}

		msgText = truncated
	}

	payload := telegramPayload{
		ChatID:    t.chatID,
		Text:      msgText,
		ParseMode: "HTML",
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram api error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var tgResp telegramResponse
	if err := json.Unmarshal(respBody, &tgResp); err == nil && !tgResp.Ok {
		return fmt.Errorf("telegram api returned not ok: %s", tgResp.Description)
	}

	return nil
}
