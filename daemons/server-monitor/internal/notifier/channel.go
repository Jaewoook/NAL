package notifier

import (
	"context"

	"github.com/jaewoook/server-monitor/internal/models"
)

// Channel represents an alert delivery medium (Telegram, Discord, Slack, etc.).
type Channel interface {
	// Name returns the identifier of the notification channel.
	Name() string
	// Send delivers an alert payload to the destination.
	Send(alert *models.Alert) error
}

// ContextChannel is an optional extension of Channel that honors context cancellation and deadlines.
type ContextChannel interface {
	Channel
	SendContext(ctx context.Context, alert *models.Alert) error
}

// formatProcessesTable delegates to models.FormatProcessesTable.
func formatProcessesTable(processes []models.ProcessInfo) string {
	return models.FormatProcessesTable(processes)
}
