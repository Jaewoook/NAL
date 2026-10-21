package digest

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

func sampleMetrics() *models.SystemMetrics {
	return &models.SystemMetrics{
		Timestamp:     time.Now(),
		CPUPercent:    15.5,
		MemoryPercent: 42.3,
		DiskPercent:   68.7,
		Load1:         0.85,
		Load5:         1.20,
		Load15:        0.95,
		UptimeSeconds: 90065, // 1d 1h 1m 5s
		TopProcesses: []models.ProcessInfo{
			{PID: 101, Name: "postgres", CPUPercent: 12.0, MemoryPercent: 25.0},
			{PID: 102, Name: "redis", CPUPercent: 3.5, MemoryPercent: 5.0},
		},
	}
}

func TestDigestTick(t *testing.T) {
	engine := New("prod-server-1", 24*time.Hour)
	t0 := time.Now()
	m := sampleMetrics()

	// First tick -> emits digest alert
	alert1, err := engine.Tick(t0, m)
	if err != nil {
		t.Fatalf("unexpected error on first tick: %v", err)
	}
	if alert1 == nil {
		t.Fatalf("expected digest alert on first tick, got nil")
	}
	if alert1.Hostname != "prod-server-1" {
		t.Errorf("expected hostname 'prod-server-1', got '%s'", alert1.Hostname)
	}
	if alert1.Level != models.AlertLevelInfo {
		t.Errorf("expected level INFO, got '%s'", alert1.Level)
	}

	// Before interval (12 hours later) -> returns nil, nil
	alert2, err := engine.Tick(t0.Add(12*time.Hour), m)
	if err != nil {
		t.Fatalf("unexpected error before interval: %v", err)
	}
	if alert2 != nil {
		t.Fatalf("expected nil alert before interval, got %+v", alert2)
	}

	// After interval (25 hours later) -> emits digest alert
	alert3, err := engine.Tick(t0.Add(25*time.Hour), m)
	if err != nil {
		t.Fatalf("unexpected error after interval: %v", err)
	}
	if alert3 == nil {
		t.Fatalf("expected digest alert after interval, got nil")
	}
}

func TestDigestNilMetrics(t *testing.T) {
	engine := New("server-1", 24*time.Hour)
	t0 := time.Now()

	alert, err := engine.Tick(t0, nil)
	if err == nil {
		t.Fatalf("expected error for nil metrics, got nil")
	}
	if alert != nil {
		t.Fatalf("expected nil alert for nil metrics, got %+v", alert)
	}

	alertBuild, err := engine.BuildDigest(t0, nil)
	if err == nil {
		t.Fatalf("expected error for nil metrics in BuildDigest, got nil")
	}
	if alertBuild != nil {
		t.Fatalf("expected nil alert for nil metrics in BuildDigest, got %+v", alertBuild)
	}
}

func TestDigestContentFormatting(t *testing.T) {
	engine := New("my-host", 24*time.Hour)
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	m := sampleMetrics()

	alert, err := engine.BuildDigest(t0, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert == nil {
		t.Fatalf("expected alert, got nil")
	}

	if alert.Title != "System Health Digest" {
		t.Errorf("expected title 'System Health Digest', got '%s'", alert.Title)
	}
	if alert.Level != models.AlertLevelInfo {
		t.Errorf("expected level INFO, got '%s'", alert.Level)
	}
	if alert.Hostname != "my-host" {
		t.Errorf("expected hostname 'my-host', got '%s'", alert.Hostname)
	}
	if !alert.Timestamp.Equal(t0) {
		t.Errorf("expected timestamp %v, got %v", t0, alert.Timestamp)
	}
	if alert.CurrentValue != 15.5 {
		t.Errorf("expected currentValue 15.5, got %v", alert.CurrentValue)
	}
	if alert.MetricName != "System" {
		t.Errorf("expected MetricName 'System', got '%s'", alert.MetricName)
	}
	if len(alert.TopProcesses) != 2 {
		t.Errorf("expected 2 top processes, got %d", len(alert.TopProcesses))
	}

	// Verify required content sections in message
	msg := alert.Message
	expectedFragments := []string{
		"CPU: 15.5%",
		"Memory: 42.3%",
		"Disk: 68.7%",
		"0.85 (1m), 1.20 (5m), 0.95 (15m)",
		"1d 1h 1m 5s",
		"All systems operational",
	}
	for _, frag := range expectedFragments {
		if !strings.Contains(msg, frag) {
			t.Errorf("expected message to contain '%s', message is:\n%s", frag, msg)
		}
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		seconds  uint64
		expected string
	}{
		{0, "0s"},
		{45, "45s"},
		{60, "1m 0s"},
		{125, "2m 5s"},
		{3600, "1h 0m 0s"},
		{3665, "1h 1m 5s"},
		{86400, "1d 0h 0m 0s"},
		{90065, "1d 1h 1m 5s"},
		{864000 + 7200 + 180 + 20, "10d 2h 3m 20s"},
	}

	for _, tt := range tests {
		got := FormatUptime(tt.seconds)
		if got != tt.expected {
			t.Errorf("FormatUptime(%d) = %q, expected %q", tt.seconds, got, tt.expected)
		}
	}
}

func TestDigestSetLastTickAndReset(t *testing.T) {
	engine := New("srv-1", 24*time.Hour)
	t0 := time.Now()
	m := sampleMetrics()

	// Setting LastTick simulates daemon startup where first digest is delayed until interval passes
	engine.SetLastTick(t0)

	alert, err := engine.Tick(t0.Add(5*time.Minute), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert != nil {
		t.Fatalf("expected alert to be suppressed when lastTick was set, got %+v", alert)
	}

	// After Reset(), first tick should send immediately
	engine.Reset()
	if !engine.LastTick().IsZero() {
		t.Errorf("expected lastTick to be zero after Reset()")
	}

	alertReset, err := engine.Tick(t0.Add(6*time.Minute), m)
	if err != nil {
		t.Fatalf("unexpected error after reset: %v", err)
	}
	if alertReset == nil {
		t.Fatalf("expected alert after reset, got nil")
	}
}

func TestDigestDefaultsAndGetters(t *testing.T) {
	engine := New("srv-default", 0)
	if engine.Interval() != 24*time.Hour {
		t.Errorf("expected default interval 24h, got %v", engine.Interval())
	}
	if engine.Hostname() != "srv-default" {
		t.Errorf("expected hostname 'srv-default', got '%s'", engine.Hostname())
	}

	engineNeg := New("srv-neg", -5*time.Hour)
	if engineNeg.Interval() != 24*time.Hour {
		t.Errorf("expected default interval 24h for negative interval, got %v", engineNeg.Interval())
	}

	// Zero timestamp in Tick uses time.Now()
	m := sampleMetrics()
	alert, err := engine.Tick(time.Time{}, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert == nil {
		t.Fatalf("expected alert for zero timestamp, got nil")
	}
	if alert.Timestamp.IsZero() {
		t.Errorf("expected alert timestamp to be populated, got zero time")
	}
}

func TestDigestConcurrentTicks(t *testing.T) {
	engine := New("concurrent-host", 24*time.Hour)
	m := sampleMetrics()
	t0 := time.Now()

	var wg sync.WaitGroup
	var alertCount int32

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			alert, err := engine.Tick(t0, m)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if alert != nil {
				atomic.AddInt32(&alertCount, 1)
			}
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&alertCount) != 1 {
		t.Errorf("expected exactly 1 alert from concurrent first ticks, got %d", atomic.LoadInt32(&alertCount))
	}
}
