package digest

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

// Engine generates periodic aliveness health summary alerts.
type Engine struct {
	mu       sync.Mutex
	hostname string
	interval time.Duration
	lastTick time.Time
}

// New creates a new digest Engine with the specified hostname and interval.
func New(hostname string, interval time.Duration) *Engine {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &Engine{
		hostname: hostname,
		interval: interval,
	}
}

// Hostname returns the engine's configured hostname.
func (e *Engine) Hostname() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hostname
}

// Interval returns the engine's digest interval.
func (e *Engine) Interval() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.interval
}

// LastTick returns the timestamp of the last generated digest.
func (e *Engine) LastTick() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastTick
}

// SetLastTick sets the last digest timestamp (e.g. to suppress startup digest).
func (e *Engine) SetLastTick(t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastTick = t
}

// Reset clears the last tick timestamp.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastTick = time.Time{}
}

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

// BuildDigest formats a clean health summary Alert without updating internal tick state.
func (e *Engine) BuildDigest(now time.Time, m *models.SystemMetrics) (*models.Alert, error) {
	if m == nil {
		return nil, errors.New("metrics cannot be nil")
	}
	if now.IsZero() {
		now = time.Now()
	}

	e.mu.Lock()
	hostname := e.hostname
	e.mu.Unlock()

	msg := fmt.Sprintf(
		"Periodic System Health Digest\n"+
			"• CPU: %.1f%%\n"+
			"• Memory: %.1f%%\n"+
			"• Disk: %.1f%%\n"+
			"• Load Averages: %.2f (1m), %.2f (5m), %.2f (15m)\n"+
			"• Uptime: %s\n"+
			"• Status: All systems operational",
		m.CPUPercent,
		m.MemoryPercent,
		m.DiskPercent,
		m.Load1,
		m.Load5,
		m.Load15,
		FormatUptime(m.UptimeSeconds),
	)

	alert := &models.Alert{
		Title:        "System Health Digest",
		Message:      msg,
		Level:        models.AlertLevelInfo,
		MetricName:   "System",
		CurrentValue: m.CPUPercent,
		Timestamp:    now,
		Hostname:     hostname,
		TopProcesses: m.TopProcesses,
	}

	return alert, nil
}

// Tick evaluates whether the digest interval has elapsed.
// If elapsed (or on first tick), it updates lastTick and returns the formatted Alert.
// If before the interval, it returns (nil, nil).
func (e *Engine) Tick(now time.Time, m *models.SystemMetrics) (*models.Alert, error) {
	if m == nil {
		return nil, errors.New("metrics cannot be nil")
	}
	if now.IsZero() {
		now = time.Now()
	}

	e.mu.Lock()
	if !e.lastTick.IsZero() && now.Sub(e.lastTick) < e.interval {
		e.mu.Unlock()
		return nil, nil
	}
	e.lastTick = now
	e.mu.Unlock()

	return e.BuildDigest(now, m)
}
