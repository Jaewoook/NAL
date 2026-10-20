package alert

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

func TestAlertManagerFiresAndThrottles(t *testing.T) {
	cooldowns := map[string]time.Duration{
		"cpu_spike": 15 * time.Minute,
	}
	mgr := NewManager("server1", cooldowns, true)
	t0 := time.Now()

	ev := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       true,
		Level:          models.AlertLevelCritical,
		CurrentValue:   92.0,
		ThresholdValue: 85.0,
		Message:        "CPU Spike at 92%",
	}

	// 1. First event -> alerts
	alerts1 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts1) != 1 || alerts1[0].Level != models.AlertLevelCritical {
		t.Fatalf("expected 1 critical alert, got %v", alerts1)
	}

	// 2. Second event during cooldown (5m later) -> throttled
	alerts2 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0.Add(5 * time.Minute)})
	if len(alerts2) != 0 {
		t.Fatalf("expected alert to be throttled during cooldown, got %v", alerts2)
	}

	// 3. Condition resolves -> recovery alert
	clearEv := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       false,
		Level:          models.AlertLevelResolved,
		CurrentValue:   30.0,
		ThresholdValue: 85.0,
		Message:        "CPU back to normal",
	}
	alerts3 := mgr.ProcessEvents([]models.RawConditionEvent{clearEv}, &models.SystemMetrics{Timestamp: t0.Add(6 * time.Minute)})
	if len(alerts3) != 1 || alerts3[0].Level != models.AlertLevelResolved {
		t.Fatalf("expected 1 resolved alert, got %v", alerts3)
	}
}

func TestAlertManagerCooldownExpiryReAlerts(t *testing.T) {
	cooldowns := map[string]time.Duration{
		"cpu_spike": 15 * time.Minute,
	}
	mgr := NewManager("server1", cooldowns, true)
	t0 := time.Now()

	ev := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       true,
		Level:          models.AlertLevelCritical,
		CurrentValue:   95.0,
		ThresholdValue: 85.0,
		Message:        "CPU Spike sustained",
	}

	// 1. Initial breach -> fires
	alerts1 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts1) != 1 {
		t.Fatalf("expected 1 initial alert, got %v", alerts1)
	}

	// 2. Event during cooldown (10m later) -> throttled
	alerts2 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0.Add(10 * time.Minute)})
	if len(alerts2) != 0 {
		t.Fatalf("expected alert to be throttled during cooldown, got %v", alerts2)
	}

	// 3. Event after cooldown expires (15m later) -> re-alerts
	alerts3 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0.Add(15 * time.Minute)})
	if len(alerts3) != 1 || alerts3[0].Level != models.AlertLevelCritical {
		t.Fatalf("expected 1 critical alert after cooldown elapsed, got %v", alerts3)
	}

	// 4. Event right after re-alerting (18m later) -> throttled again
	alerts4 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0.Add(18 * time.Minute)})
	if len(alerts4) != 0 {
		t.Fatalf("expected alert to be throttled in new cooldown window, got %v", alerts4)
	}
}

func TestAlertManagerRecoveryDisabled(t *testing.T) {
	cooldowns := map[string]time.Duration{
		"cpu_spike": 15 * time.Minute,
	}
	// notifyOnRecovery is set to false
	mgr := NewManager("server1", cooldowns, false)
	t0 := time.Now()

	ev := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       true,
		Level:          models.AlertLevelCritical,
		CurrentValue:   90.0,
		ThresholdValue: 85.0,
	}

	alerts1 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts1) != 1 {
		t.Fatalf("expected 1 alert, got %v", alerts1)
	}

	// Resolving event should NOT emit alert when notifyOnRecovery is false
	clearEv := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       false,
		Level:          models.AlertLevelResolved,
		CurrentValue:   20.0,
		ThresholdValue: 85.0,
	}
	alerts2 := mgr.ProcessEvents([]models.RawConditionEvent{clearEv}, &models.SystemMetrics{Timestamp: t0.Add(2 * time.Minute)})
	if len(alerts2) != 0 {
		t.Fatalf("expected no recovery alert when notifyOnRecovery is false, got %v", alerts2)
	}

	// Verify track is reset: new spike fires immediately
	alerts3 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0.Add(5 * time.Minute)})
	if len(alerts3) != 1 {
		t.Fatalf("expected new breach to alert after recovery reset, got %v", alerts3)
	}
}

func TestAlertManagerNoRecoveryIfNeverAlerted(t *testing.T) {
	mgr := NewManager("server1", nil, true)
	t0 := time.Now()

	clearEv := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       false,
		Level:          models.AlertLevelResolved,
		CurrentValue:   20.0,
		ThresholdValue: 85.0,
	}

	alerts := mgr.ProcessEvents([]models.RawConditionEvent{clearEv}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts) != 0 {
		t.Fatalf("expected 0 recovery alerts for track that was never alerting, got %v", alerts)
	}
}

func TestAlertManagerEventBasedPlungeDrop(t *testing.T) {
	cooldowns := map[string]time.Duration{
		"cpu_plunge": 15 * time.Minute,
	}
	mgr := NewManager("server1", cooldowns, true)
	t0 := time.Now()

	plungeEv := models.RawConditionEvent{
		RuleName:       "cpu_plunge",
		IsActive:       true,
		Level:          models.AlertLevelWarning,
		CurrentValue:   25.0,
		ThresholdValue: 40.0,
		Message:        "CPU plunge drop detected: dropped by 45%",
	}

	// 1. First event -> alerts
	alerts1 := mgr.ProcessEvents([]models.RawConditionEvent{plungeEv}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts1) != 1 || alerts1[0].Level != models.AlertLevelWarning {
		t.Fatalf("expected 1 warning alert for plunge drop, got %v", alerts1)
	}

	// 2. Second event during cooldown (5m later) -> throttled
	alerts2 := mgr.ProcessEvents([]models.RawConditionEvent{plungeEv}, &models.SystemMetrics{Timestamp: t0.Add(5 * time.Minute)})
	if len(alerts2) != 0 {
		t.Fatalf("expected plunge drop to be throttled during cooldown, got %v", alerts2)
	}

	// 3. Event-based alerts do NOT emit recovery
	clearEv := models.RawConditionEvent{
		RuleName:       "cpu_plunge",
		IsActive:       false,
		Level:          models.AlertLevelResolved,
		CurrentValue:   25.0,
		ThresholdValue: 40.0,
	}
	alerts3 := mgr.ProcessEvents([]models.RawConditionEvent{clearEv}, &models.SystemMetrics{Timestamp: t0.Add(10 * time.Minute)})
	if len(alerts3) != 0 {
		t.Fatalf("expected no recovery alert for event-based plunge drop, got %v", alerts3)
	}

	// 4. After cooldown (16m later), new plunge fires
	alerts4 := mgr.ProcessEvents([]models.RawConditionEvent{plungeEv}, &models.SystemMetrics{Timestamp: t0.Add(16 * time.Minute)})
	if len(alerts4) != 1 || alerts4[0].Level != models.AlertLevelWarning {
		t.Fatalf("expected new plunge drop alert after cooldown elapsed, got %v", alerts4)
	}
}

func TestAlertManagerMultiSubsystemIsolation(t *testing.T) {
	cooldowns := map[string]time.Duration{
		"cpu_spike": 15 * time.Minute,
		"memory":    30 * time.Minute,
		"disk":      60 * time.Minute,
	}
	mgr := NewManager("node-a", cooldowns, true)
	t0 := time.Now()

	cpuEv := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       true,
		Level:          models.AlertLevelCritical,
		CurrentValue:   95.0,
		ThresholdValue: 85.0,
		Message:        "CPU high",
	}
	memEv := models.RawConditionEvent{
		RuleName:       "memory",
		IsActive:       true,
		Level:          models.AlertLevelCritical,
		CurrentValue:   92.0,
		ThresholdValue: 90.0,
		Message:        "Memory high",
	}
	diskEv := models.RawConditionEvent{
		RuleName:       "disk",
		IsActive:       true,
		Level:          models.AlertLevelWarning,
		CurrentValue:   88.0,
		ThresholdValue: 85.0,
		Message:        "Disk high",
	}

	// 1. All three subsystems fire concurrently
	alerts1 := mgr.ProcessEvents([]models.RawConditionEvent{cpuEv, memEv, diskEv}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts1) != 3 {
		t.Fatalf("expected 3 concurrent alerts across independent tracks, got %d", len(alerts1))
	}

	// 2. 5 minutes later: CPU resolves, memory still active, disk still active
	cpuClear := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       false,
		Level:          models.AlertLevelResolved,
		CurrentValue:   40.0,
		ThresholdValue: 85.0,
		Message:        "CPU recovered",
	}
	alerts2 := mgr.ProcessEvents([]models.RawConditionEvent{cpuClear, memEv, diskEv}, &models.SystemMetrics{Timestamp: t0.Add(5 * time.Minute)})
	// CPU should recover (1 alert), while memory and disk are throttled during their cooldowns (0 alerts)
	if len(alerts2) != 1 {
		t.Fatalf("expected only CPU recovery alert (mem & disk in cooldown), got %d: %v", len(alerts2), alerts2)
	}
	if alerts2[0].MetricName != "cpu_spike" || alerts2[0].Level != models.AlertLevelResolved {
		t.Fatalf("expected CPU resolved alert, got %v", alerts2[0])
	}

	// 3. 10 minutes later: CPU spikes again!
	// Memory and Disk must NOT prevent CPU from alerting
	alerts3 := mgr.ProcessEvents([]models.RawConditionEvent{cpuEv}, &models.SystemMetrics{Timestamp: t0.Add(10 * time.Minute)})
	if len(alerts3) != 1 || alerts3[0].MetricName != "cpu_spike" || alerts3[0].Level != models.AlertLevelCritical {
		t.Fatalf("expected independent CPU alert after resolution, got %v", alerts3)
	}
}

func TestAlertManagerPayloadFieldsAndTopProcesses(t *testing.T) {
	mgr := NewManager("host-42", nil, true)
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	topProcs := []models.ProcessInfo{
		{PID: 1234, Name: "stress", CPUPercent: 88.5, MemoryPercent: 5.2},
	}
	ev := models.RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       true,
		Level:          models.AlertLevelCritical,
		CurrentValue:   94.5,
		ThresholdValue: 85.0,
		Message:        "CPU usage sustained high: 94.5% >= 85.0%",
		TopProcesses:   topProcs,
	}

	alerts := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{
		Timestamp: t0,
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	a := alerts[0]
	if a.Hostname != "host-42" {
		t.Errorf("expected hostname host-42, got %q", a.Hostname)
	}
	if !a.Timestamp.Equal(t0) {
		t.Errorf("expected timestamp %v, got %v", t0, a.Timestamp)
	}
	if a.MetricName != "cpu_spike" {
		t.Errorf("expected metric_name cpu_spike, got %q", a.MetricName)
	}
	if a.CurrentValue != 94.5 {
		t.Errorf("expected current value 94.5, got %f", a.CurrentValue)
	}
	if a.ThresholdValue != 85.0 {
		t.Errorf("expected threshold value 85.0, got %f", a.ThresholdValue)
	}
	if a.Message != "CPU usage sustained high: 94.5% >= 85.0%" {
		t.Errorf("unexpected message: %q", a.Message)
	}
	if len(a.TopProcesses) != 1 || a.TopProcesses[0].PID != 1234 {
		t.Errorf("expected top process preserved, got %v", a.TopProcesses)
	}
	if a.Title == "" {
		t.Errorf("expected non-empty title")
	}
}

func TestAlertManagerConcurrentProcessing(t *testing.T) {
	mgr := NewManager("host-test", nil, true)
	var wg sync.WaitGroup
	t0 := time.Now()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		rule := fmt.Sprintf("rule_%d", i%5)
		go func(r string, offset int) {
			defer wg.Done()
			ev := models.RawConditionEvent{
				RuleName:     r,
				IsActive:     true,
				Level:        models.AlertLevelWarning,
				CurrentValue: 50.0 + float64(offset),
			}
			_ = mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{
				Timestamp: t0.Add(time.Duration(offset) * time.Second),
			})
		}(rule, i)
	}

	wg.Wait()
}

func TestAlertManagerStateQueriesAndReset(t *testing.T) {
	mgr := NewManager("test-host", nil, true)
	t0 := time.Now()

	if mgr.IsActive("cpu_spike") {
		t.Errorf("expected track initially inactive")
	}
	if !mgr.LastAlertTime("cpu_spike").IsZero() {
		t.Errorf("expected zero last alert time initially")
	}

	ev := models.RawConditionEvent{
		RuleName:     "cpu_spike",
		IsActive:     true,
		Level:        models.AlertLevelCritical,
		CurrentValue: 95.0,
	}
	_ = mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0})

	if !mgr.IsActive("cpu_spike") {
		t.Errorf("expected track to be active")
	}
	if !mgr.LastAlertTime("cpu_spike").Equal(t0) {
		t.Errorf("expected last alert time %v, got %v", t0, mgr.LastAlertTime("cpu_spike"))
	}

	// Reset single track
	mgr.Reset("cpu_spike")
	if mgr.IsActive("cpu_spike") {
		t.Errorf("expected track to be inactive after reset")
	}

	// Reset all tracks
	_ = mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0})
	mgr.Reset("")
	if mgr.IsActive("cpu_spike") {
		t.Errorf("expected all tracks to be inactive after full reset")
	}
}

func TestAlertManagerRegisterEventRule(t *testing.T) {
	mgr := NewManager("host", map[string]time.Duration{"app_crash": 10 * time.Minute}, true)
	mgr.RegisterEventRule("app_crash")
	t0 := time.Now()

	ev := models.RawConditionEvent{
		RuleName:     "app_crash",
		IsActive:     true,
		CurrentValue: 1.0,
	}

	alerts1 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts1) != 1 {
		t.Fatalf("expected 1 alert for custom event rule, got %d", len(alerts1))
	}

	// Cooldown throttles second
	alerts2 := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0.Add(5 * time.Minute)})
	if len(alerts2) != 0 {
		t.Fatalf("expected custom event rule to be throttled during cooldown")
	}

	// Recovery ignored for custom event rule
	clearEv := models.RawConditionEvent{
		RuleName: "app_crash",
		IsActive: false,
	}
	alerts3 := mgr.ProcessEvents([]models.RawConditionEvent{clearEv}, &models.SystemMetrics{Timestamp: t0.Add(12 * time.Minute)})
	if len(alerts3) != 0 {
		t.Fatalf("expected no recovery alert for custom event rule")
	}
}

func TestAlertManagerDefaultMessagesAndTitles(t *testing.T) {
	// Empty hostname
	mgr := NewManager("", nil, true)
	t0 := time.Now()

	// Trigger without message to test default message and title without hostname
	ev := models.RawConditionEvent{
		RuleName:       "disk",
		IsActive:       true,
		CurrentValue:   92.0,
		ThresholdValue: 85.0,
	}
	alerts := mgr.ProcessEvents([]models.RawConditionEvent{ev}, &models.SystemMetrics{Timestamp: t0})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Title != "Disk Alert" {
		t.Errorf("expected title 'Disk Alert', got %q", alerts[0].Title)
	}
	if alerts[0].Message == "" {
		t.Errorf("expected generated default message")
	}

	// Recover without message
	clearEv := models.RawConditionEvent{
		RuleName:       "disk",
		IsActive:       false,
		CurrentValue:   70.0,
		ThresholdValue: 85.0,
	}
	recoverAlerts := mgr.ProcessEvents([]models.RawConditionEvent{clearEv}, &models.SystemMetrics{Timestamp: t0.Add(time.Minute)})
	if len(recoverAlerts) != 1 {
		t.Fatalf("expected 1 recovery alert, got %d", len(recoverAlerts))
	}
	if recoverAlerts[0].Title != "Disk Resolved" {
		t.Errorf("expected title 'Disk Resolved', got %q", recoverAlerts[0].Title)
	}
	if recoverAlerts[0].Message == "" {
		t.Errorf("expected generated default recovery message")
	}
}

func TestAlertManagerEmptyAndNilEvents(t *testing.T) {
	mgr := NewManager("host", nil, true)
	if alerts := mgr.ProcessEvents(nil, nil); alerts != nil {
		t.Errorf("expected nil for nil events, got %v", alerts)
	}
	if alerts := mgr.ProcessEvents([]models.RawConditionEvent{}, nil); alerts != nil {
		t.Errorf("expected nil for empty events, got %v", alerts)
	}
}
