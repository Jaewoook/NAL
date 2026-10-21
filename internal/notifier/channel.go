package notifier

import (
	"fmt"
	"strings"

	"github.com/jaewoook/server-monitor/internal/models"
)

// Channel represents an alert delivery medium (Telegram, Discord, Slack, etc.).
type Channel interface {
	// Name returns the identifier of the notification channel.
	Name() string
	// Send delivers an alert payload to the destination.
	Send(alert *models.Alert) error
}

// formatProcessesTable formats top processes into an aligned plaintext table.
func formatProcessesTable(processes []models.ProcessInfo) string {
	if len(processes) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-7s %-16s %-8s %-8s\n", "PID", "NAME", "CPU%", "MEM%"))
	for _, p := range processes {
		name := p.Name
		runes := []rune(name)
		if len(runes) > 16 {
			name = string(runes[:13]) + "..."
		}
		sb.WriteString(fmt.Sprintf("%-7d %-16s %-7.1f%% %-7.1f%%\n", p.PID, name, p.CPUPercent, p.MemoryPercent))
	}
	return strings.TrimRight(sb.String(), "\n")
}
