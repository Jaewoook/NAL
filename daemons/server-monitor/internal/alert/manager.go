package alert

import (
	"fmt"
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
	cooldownsCopy := make(map[string]time.Duration, len(cooldowns))
	for k, v := range cooldowns {
		cooldownsCopy[k] = v
	}

	return &Manager{
		hostname:         hostname,
		cooldowns:        cooldownsCopy,
		notifyOnRecovery: notifyOnRecovery,
		eventRules:       make(map[string]bool),
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

func (m *Manager) isEventRule(ruleName string) bool {
	if m.eventRules[ruleName] {
		return true
	}
	if meta, ok := models.LookupRuleMeta(ruleName); ok {
		return meta.IsEvent
	}
	return false
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

// ScheduleRetry shortens a rule's cooldown window after a total delivery failure so
// the alert is retried after retryAfter instead of waiting the full cooldown duration
// or thrashing on every tick.
func (m *Manager) ScheduleRetry(ruleName string, retryAfter time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	track, exists := m.tracks[ruleName]
	if !exists || track.lastAlertTime.IsZero() {
		return
	}
	if retryAfter <= 0 {
		delete(m.tracks, ruleName)
		return
	}
	if track.cooldown > retryAfter {
		track.lastAlertTime = track.lastAlertTime.Add(retryAfter - track.cooldown)
	}
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

		track := m.getOrCreateTrack(ruleName)

		var emitted *models.Alert
		if m.isEventRule(ruleName) {
			emitted = m.processEventTrack(track, ev, now, metrics)
		} else {
			emitted = m.processStatefulTrack(track, ev, now, metrics)
		}
		if emitted != nil {
			alerts = append(alerts, *emitted)
		}
	}

	return alerts
}

func (m *Manager) getOrCreateTrack(ruleName string) *alertTrack {
	if track, exists := m.tracks[ruleName]; exists {
		return track
	}
	track := &alertTrack{
		ruleName: ruleName,
		cooldown: m.getCooldown(ruleName),
	}
	m.tracks[ruleName] = track
	return track
}

func (m *Manager) processEventTrack(track *alertTrack, ev models.RawConditionEvent, now time.Time, metrics *models.SystemMetrics) *models.Alert {
	if !ev.IsActive || ev.Level == models.AlertLevelResolved {
		return nil
	}
	if track.cooldown > 0 && !track.lastAlertTime.IsZero() && now.Sub(track.lastAlertTime) < track.cooldown {
		return nil
	}

	track.lastAlertTime = now
	track.active = false

	level := ev.Level
	if level == "" {
		level = models.AlertLevelWarning
	}
	alert := m.createAlert(ev, now, level, metrics)
	return &alert
}

func (m *Manager) processStatefulTrack(track *alertTrack, ev models.RawConditionEvent, now time.Time, metrics *models.SystemMetrics) *models.Alert {
	if !ev.IsActive || ev.Level == models.AlertLevelResolved {
		if !track.active {
			return nil
		}
		track.active = false
		if !m.notifyOnRecovery {
			return nil
		}
		alert := m.createAlert(ev, now, models.AlertLevelResolved, metrics)
		return &alert
	}

	shouldAlert := !track.active || (track.cooldown > 0 && !now.Before(track.lastAlertTime.Add(track.cooldown)))
	if !shouldAlert {
		return nil
	}

	track.active = true
	track.lastAlertTime = now

	level := ev.Level
	if level == "" {
		level = models.AlertLevelCritical
	}
	alert := m.createAlert(ev, now, level, metrics)
	return &alert
}

func (m *Manager) getCooldown(ruleName string) time.Duration {
	if m.cooldowns != nil {
		if cd, ok := m.cooldowns[ruleName]; ok {
			return cd
		}
	}
	if meta, ok := models.LookupRuleMeta(ruleName); ok && meta.DefaultCooldown > 0 {
		return meta.DefaultCooldown
	}
	return 15 * time.Minute
}

func (m *Manager) createAlert(ev models.RawConditionEvent, now time.Time, level models.AlertLevel, metrics *models.SystemMetrics) models.Alert {
	metricName := ev.RuleName
	if metricName == "" {
		metricName = "system"
	}

	unit := ev.Unit
	if unit == "" {
		if meta, ok := models.LookupRuleMeta(ev.RuleName); ok {
			unit = meta.Unit
		}
	}

	topProcs := ev.TopProcesses
	if len(topProcs) == 0 && metrics != nil && len(metrics.TopProcesses) > 0 {
		topProcs = metrics.TopProcesses
	}

	msg := ev.Message
	if msg == "" {
		if level == models.AlertLevelResolved {
			msg = fmt.Sprintf("%s recovered to normal (current: %.1f%s)", models.FormatRuleName(ev.RuleName), ev.CurrentValue, unit)
		} else {
			msg = fmt.Sprintf("%s threshold breached (current: %.1f%s, threshold: %.1f%s)", models.FormatRuleName(ev.RuleName), ev.CurrentValue, unit, ev.ThresholdValue, unit)
		}
	}

	alert := models.Alert{
		Title:          m.formatTitle(ev.RuleName, level),
		Message:        msg,
		Level:          level,
		MetricName:     metricName,
		CurrentValue:   ev.CurrentValue,
		ThresholdValue: ev.ThresholdValue,
		Unit:           unit,
		Timestamp:      now,
		Hostname:       m.hostname,
		TopProcesses:   topProcs,
	}
	if metrics != nil {
		if metrics.HasCPUTemp {
			alert.HasCPUTemp = true
			alert.CPUTempCelsius = metrics.CPUTempCelsius
		}
		if metrics.HasGPUTemp {
			alert.HasGPUTemp = true
			alert.GPUTempCelsius = metrics.GPUTempCelsius
		}
	}
	return alert
}

func (m *Manager) formatTitle(ruleName string, level models.AlertLevel) string {
	name := models.FormatRuleName(ruleName)
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
