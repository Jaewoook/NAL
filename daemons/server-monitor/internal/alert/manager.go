package alert

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

// alertTrack tracks the state machine and cooldown timers for a specific rule.
type alertTrack struct {
	ruleName      string
	active        bool
	lastAlertTime time.Time
	cooldown      time.Duration
}

// Manager manages independent alert tracks, enforces debouncing/cooldowns,
// and emits actionable alerts and recovery notifications.
type Manager struct {
	mu               sync.Mutex
	hostname         string
	cooldowns        map[string]time.Duration
	notifyOnRecovery bool
	eventRules       map[string]bool
	tracks           map[string]*alertTrack
}

// NewManager creates a new alert manager with the specified server hostname,
// per-rule cooldown durations, and recovery notification preference.
func NewManager(hostname string, cooldowns map[string]time.Duration, notifyOnRecovery bool) *Manager {
	cooldownsCopy := make(map[string]time.Duration)
	for k, v := range cooldowns {
		cooldownsCopy[k] = v
	}

	eventRules := map[string]bool{
		"cpu_plunge": true,
	}

	return &Manager{
		hostname:         hostname,
		cooldowns:        cooldownsCopy,
		notifyOnRecovery: notifyOnRecovery,
		eventRules:       eventRules,
		tracks:           make(map[string]*alertTrack),
	}
}

// RegisterEventRule marks a rule as event-based (fires once per incident,
// does not expect or emit recovery notifications).
func (m *Manager) RegisterEventRule(ruleName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventRules[ruleName] = true
}

// IsActive returns whether a given rule track is currently in an active alerting state.
func (m *Manager) IsActive(ruleName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if track, exists := m.tracks[ruleName]; exists {
		return track.active
	}
	return false
}

// LastAlertTime returns the timestamp when an alert last fired for the rule.
func (m *Manager) LastAlertTime(ruleName string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if track, exists := m.tracks[ruleName]; exists {
		return track.lastAlertTime
	}
	return time.Time{}
}

// Reset clears the alerting state and last alert timestamp for the specified rule.
// If ruleName is empty, all tracks are reset.
func (m *Manager) Reset(ruleName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ruleName == "" {
		m.tracks = make(map[string]*alertTrack)
		return
	}
	delete(m.tracks, ruleName)
}

// ProcessEvents processes a batch of raw condition events against independent subsystem
// tracks, enforcing cooldowns and generating alerts / recoveries.
func (m *Manager) ProcessEvents(events []models.RawConditionEvent, metrics *models.SystemMetrics) []models.Alert {
	if len(events) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if metrics != nil && !metrics.Timestamp.IsZero() {
		now = metrics.Timestamp
	}

	var alerts []models.Alert

	for _, ev := range events {
		ruleName := ev.RuleName
		if ruleName == "" {
			ruleName = "unknown"
		}

		track, exists := m.tracks[ruleName]
		if !exists {
			track = &alertTrack{
				ruleName: ruleName,
				cooldown: m.getCooldown(ruleName),
			}
			m.tracks[ruleName] = track
		}

		isEvent := m.eventRules[ruleName]

		if isEvent {
			// Event-based rules (e.g. cpu_plunge)
			if !ev.IsActive || ev.Level == models.AlertLevelResolved {
				// Event-based alerts do not emit recovery alerts
				continue
			}

			// Active event: check cooldown against repeated occurrences
			if track.cooldown > 0 && !track.lastAlertTime.IsZero() && now.Sub(track.lastAlertTime) < track.cooldown {
				// Throttled during cooldown
				continue
			}

			track.lastAlertTime = now
			track.active = false

			level := ev.Level
			if level == "" {
				level = models.AlertLevelWarning
			}

			alerts = append(alerts, m.createAlert(ev, now, level, metrics))
		} else {
			// Stateful rules (e.g. cpu_spike, memory, disk, cpu_floor)
			if !ev.IsActive || ev.Level == models.AlertLevelResolved {
				// Condition resolved or inactive
				if track.active {
					track.active = false
					if m.notifyOnRecovery {
						alerts = append(alerts, m.createAlert(ev, now, models.AlertLevelResolved, metrics))
					}
				}
			} else {
				// Condition active
				if !track.active {
					// Initial breach -> alert
					track.active = true
					track.lastAlertTime = now

					level := ev.Level
					if level == "" {
						level = models.AlertLevelCritical
					}
					alerts = append(alerts, m.createAlert(ev, now, level, metrics))
				} else {
					// Ongoing active breach: check if cooldown has elapsed to re-alert
					if track.cooldown > 0 && !now.Before(track.lastAlertTime.Add(track.cooldown)) {
						track.lastAlertTime = now

						level := ev.Level
						if level == "" {
							level = models.AlertLevelCritical
						}
						alerts = append(alerts, m.createAlert(ev, now, level, metrics))
					}
					// Otherwise throttled during cooldown
				}
			}
		}
	}

	return alerts
}

func (m *Manager) getCooldown(ruleName string) time.Duration {
	if m.cooldowns != nil {
		if cd, ok := m.cooldowns[ruleName]; ok {
			return cd
		}
	}

	// Default fallback cooldowns if not explicitly mapped
	switch ruleName {
	case "cpu_plunge":
		return 15 * time.Minute
	case "cpu_spike", "cpu_floor", "memory":
		return 30 * time.Minute
	case "disk":
		return 60 * time.Minute
	default:
		return 15 * time.Minute
	}
}

func (m *Manager) createAlert(ev models.RawConditionEvent, now time.Time, level models.AlertLevel, metrics *models.SystemMetrics) models.Alert {
	metricName := ev.RuleName
	if metricName == "" {
		metricName = "system"
	}

	topProcs := ev.TopProcesses
	if len(topProcs) == 0 && metrics != nil && len(metrics.TopProcesses) > 0 {
		topProcs = metrics.TopProcesses
	}

	msg := ev.Message
	if msg == "" {
		if level == models.AlertLevelResolved {
			msg = fmt.Sprintf("%s recovered to normal (current: %.1f)", formatRuleName(ev.RuleName), ev.CurrentValue)
		} else {
			msg = fmt.Sprintf("%s threshold breached (current: %.1f, threshold: %.1f)", formatRuleName(ev.RuleName), ev.CurrentValue, ev.ThresholdValue)
		}
	}

	return models.Alert{
		Title:          m.formatTitle(ev.RuleName, level),
		Message:        msg,
		Level:          level,
		MetricName:     metricName,
		CurrentValue:   ev.CurrentValue,
		ThresholdValue: ev.ThresholdValue,
		Timestamp:      now,
		Hostname:       m.hostname,
		TopProcesses:   topProcs,
	}
}

func (m *Manager) formatTitle(ruleName string, level models.AlertLevel) string {
	name := formatRuleName(ruleName)
	var title string
	if level == models.AlertLevelResolved {
		title = fmt.Sprintf("%s Resolved", name)
	} else {
		title = fmt.Sprintf("%s Alert", name)
	}

	if m.hostname != "" {
		return fmt.Sprintf("[%s] %s", m.hostname, title)
	}
	return title
}

func formatRuleName(rule string) string {
	switch rule {
	case "cpu_spike":
		return "CPU Spike"
	case "cpu_plunge":
		return "CPU Plunge"
	case "cpu_floor":
		return "CPU Floor"
	case "memory":
		return "Memory"
	case "disk":
		return "Disk"
	default:
		words := strings.Split(rule, "_")
		for i, w := range words {
			if len(w) > 0 {
				words[i] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		return strings.Join(words, " ")
	}
}
