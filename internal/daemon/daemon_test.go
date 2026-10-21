package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/alert"
	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/detector"
	"github.com/jaewoook/server-monitor/internal/digest"
	"github.com/jaewoook/server-monitor/internal/heartbeat"
	"github.com/jaewoook/server-monitor/internal/models"
	"github.com/jaewoook/server-monitor/internal/notifier"
)

type mockCollector struct {
	metrics *models.SystemMetrics
	err     error
}

func (m *mockCollector) Collect() (*models.SystemMetrics, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.metrics, nil
}

type mockChannel struct {
	name   string
	alerts []*models.Alert
}

func (m *mockChannel) Name() string { return m.name }
func (m *mockChannel) Send(a *models.Alert) error {
	m.alerts = append(m.alerts, a)
	return nil
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDaemonSingleStepSpikeAlert(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Name = "test-host"
	cfg.CPU.Spike.Enabled = true
	cfg.CPU.Spike.ThresholdPercent = 80.0
	cfg.CPU.Spike.SustainedSeconds = 1 // 1 count in detector for quick trigger

	coll := &mockCollector{
		metrics: &models.SystemMetrics{
			Timestamp:     time.Now(),
			CPUPercent:    95.0,
			MemoryPercent: 40.0,
			DiskPercent:   50.0,
		},
	}

	det := detector.New(cfg)
	cooldowns := map[string]time.Duration{
		detector.RuleCPUSpike: 10 * time.Minute,
	}
	mgr := alert.NewManager(cfg.Server.Name, cooldowns, true)
	ch := &mockChannel{name: "mock"}
	disp := notifier.NewDispatcher(ch)

	d, err := New(cfg,
		WithCollector(coll),
		WithDetector(det),
		WithAlertManager(mgr),
		WithDispatcher(disp),
	)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	ctx := context.Background()
	// Step 1: breach count 1 -> triggers spike
	if err := d.Step(ctx); err != nil {
		t.Fatalf("unexpected step error: %v", err)
	}

	if len(ch.alerts) != 1 {
		t.Fatalf("expected 1 alert dispatched, got %d", len(ch.alerts))
	}
	if ch.alerts[0].MetricName != detector.RuleCPUSpike {
		t.Errorf("expected CPU alert %s, got %s", detector.RuleCPUSpike, ch.alerts[0].MetricName)
	}
	if ch.alerts[0].Level != models.AlertLevelCritical {
		t.Errorf("expected Critical alert level, got %s", ch.alerts[0].Level)
	}
}

func TestDaemonStepCollectorErrorGraceful(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Heartbeat.Enabled = true
	cfg.Heartbeat.URL = "http://heartbeat.local/ping"

	coll := &mockCollector{
		err: errors.New("hardware sensor unavailable"),
	}

	var heartbeatCount int32
	hb := heartbeat.New(cfg.Heartbeat.URL, 60*time.Second)
	hb.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&heartbeatCount, 1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}))

	d, err := New(cfg,
		WithCollector(coll),
		WithHeartbeat(hb),
	)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	// Should not return an error or panic; collector failure should be logged and heartbeat should still tick
	err = d.Step(context.Background())
	if err != nil {
		t.Fatalf("Step() should handle collector error gracefully, got: %v", err)
	}

	if atomic.LoadInt32(&heartbeatCount) != 1 {
		t.Errorf("expected heartbeat to tick despite collector error, got %d pings", atomic.LoadInt32(&heartbeatCount))
	}
}

func TestDaemonDigestExecution(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Digest.Enabled = true
	cfg.Digest.IntervalHours = 24

	coll := &mockCollector{
		metrics: &models.SystemMetrics{
			Timestamp:     time.Now(),
			CPUPercent:    20.0,
			MemoryPercent: 30.0,
			DiskPercent:   40.0,
			UptimeSeconds: 3600,
		},
	}

	ch := &mockChannel{name: "mock"}
	disp := notifier.NewDispatcher(ch)

	dig := digest.New(cfg.Server.Name, 24*time.Hour)
	// Reset so it ticks on first step
	dig.Reset()

	d, err := New(cfg,
		WithCollector(coll),
		WithDispatcher(disp),
		WithDigest(dig),
	)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	err = d.Step(context.Background())
	if err != nil {
		t.Fatalf("unexpected step error: %v", err)
	}

	if len(ch.alerts) != 1 {
		t.Fatalf("expected 1 digest alert dispatched, got %d", len(ch.alerts))
	}
	if ch.alerts[0].Title != "System Health Digest" {
		t.Errorf("expected digest title, got %s", ch.alerts[0].Title)
	}
}

func TestDaemonRunCancellation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.CheckIntervalSeconds = 1

	coll := &mockCollector{
		metrics: &models.SystemMetrics{
			Timestamp:     time.Now(),
			CPUPercent:    10.0,
			MemoryPercent: 20.0,
			DiskPercent:   30.0,
		},
	}

	d, err := New(cfg, WithCollector(coll))
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	// override interval for rapid test
	d.interval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- d.Run(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected clean nil exit on context cancel, got: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("daemon did not terminate within timeout")
	}
}
