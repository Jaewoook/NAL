package models

import (
	"fmt"
	"strings"
)

// FormatUptime formats seconds into a human-readable duration string.
func FormatUptime(seconds uint64) string {
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	mins := (seconds % 3600) / 60
	secs := seconds % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, mins, secs)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

// FormatProcessesTable formats top processes into an aligned, rune-safe plaintext table.
func FormatProcessesTable(processes []ProcessInfo) string {
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
		cpuStr := fmt.Sprintf("%.1f%%", p.CPUPercent)
		memStr := fmt.Sprintf("%.1f%%", p.MemoryPercent)
		sb.WriteString(fmt.Sprintf("%-7d %-16s %-8s %-8s\n", p.PID, name, cpuStr, memStr))
	}
	return strings.TrimRight(sb.String(), "\n")
}

// FormatValue formats a numeric alert value with its effective unit.
func (a *Alert) FormatValue(val float64) string {
	return fmt.Sprintf("%.2f%s", val, a.EffectiveUnit())
}

// FormatTemperatures returns a concise summary of available CPU/GPU temperatures
// attached to the alert (e.g. "CPU 68.5°C, GPU 54.0°C"), or "" if none are present.
func (a *Alert) FormatTemperatures() string {
	if a == nil {
		return ""
	}
	var parts []string
	if a.HasCPUTemp {
		parts = append(parts, fmt.Sprintf("CPU %.1f°C", a.CPUTempCelsius))
	}
	if a.HasGPUTemp {
		parts = append(parts, fmt.Sprintf("GPU %.1f°C", a.GPUTempCelsius))
	}
	return strings.Join(parts, ", ")
}
