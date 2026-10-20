package detector

import (
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/models"
)

func makeMetrics(cpu, mem, disk float64, ts time.Time) *models.SystemMetrics {
	return &models.SystemMetrics{
		Timestamp:     ts,
		CPUPercent:    cpu,
		MemoryPercent: mem,
		DiskPercent:   disk,
	}
}

func TestSpikeDetectionSustained(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.Spike.Enabled = true
	cfg.CPU.Spike.ThresholdPercent = 85.0
	cfg.CPU.Spike.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	// Sample 1: 90% (5s) -> not yet sustained
	evs1 := d.Evaluate(makeMetrics(90.0, 20.0, 30.0, t0))
	for _, e := range evs1 {
		if e.RuleName == "cpu_spike" && e.IsActive {
			t.Fatalf("cpu_spike fired too early")
		}
	}

	// Sample 2: 90% (10s sustained) -> triggers!
	evs2 := d.Evaluate(makeMetrics(92.0, 20.0, 30.0, t0.Add(5*time.Second)))
	found := false
	for _, e := range evs2 {
		if e.RuleName == "cpu_spike" && e.IsActive {
			found = true
			if e.Level != models.AlertLevelCritical {
				t.Errorf("expected CRITICAL level for spike, got %s", e.Level)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected cpu_spike to trigger")
	}
}

func TestSpikeDetectionRecovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.Spike.Enabled = true
	cfg.CPU.Spike.ThresholdPercent = 85.0
	cfg.CPU.Spike.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	// Trigger spike (10s sustained)
	d.Evaluate(makeMetrics(90.0, 20.0, 30.0, t0))
	d.Evaluate(makeMetrics(90.0, 20.0, 30.0, t0.Add(5*time.Second)))

	// Drop below threshold: sample 1 (5s) -> not yet sustained recovery
	evs3 := d.Evaluate(makeMetrics(40.0, 20.0, 30.0, t0.Add(10*time.Second)))
	for _, e := range evs3 {
		if e.RuleName == "cpu_spike" && !e.IsActive {
			t.Fatalf("recovery fired too early at 5s")
		}
	}

	// Drop below threshold: sample 2 (10s) -> sustained recovery!
	evs4 := d.Evaluate(makeMetrics(40.0, 20.0, 30.0, t0.Add(15*time.Second)))
	recovered := false
	for _, e := range evs4 {
		if e.RuleName == "cpu_spike" && !e.IsActive && e.Level == models.AlertLevelResolved {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Fatalf("expected cpu_spike recovery event")
	}

	// Subsequent normal sample: should not re-emit recovery
	evs5 := d.Evaluate(makeMetrics(40.0, 20.0, 30.0, t0.Add(20*time.Second)))
	for _, e := range evs5 {
		if e.RuleName == "cpu_spike" {
			t.Fatalf("unexpected event after recovery: %v", e)
		}
	}
}

func TestPlungeDropDetection(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.PlungeDrop.Enabled = true
	cfg.CPU.PlungeDrop.DeltaPercent = 40.0
	cfg.CPU.PlungeDrop.FromMinPercent = 50.0

	d := New(cfg)
	t0 := time.Now()

	// High load baseline
	d.Evaluate(makeMetrics(75.0, 20.0, 30.0, t0))
	d.Evaluate(makeMetrics(80.0, 20.0, 30.0, t0.Add(5*time.Second)))

	// Plunge to 15%
	evs := d.Evaluate(makeMetrics(15.0, 20.0, 30.0, t0.Add(10*time.Second)))
	found := false
	for _, e := range evs {
		if e.RuleName == "cpu_plunge" && e.IsActive {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected cpu_plunge to trigger")
	}
}

func TestNoPlungeWhenStartingLow(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.PlungeDrop.Enabled = true
	cfg.CPU.PlungeDrop.DeltaPercent = 40.0
	cfg.CPU.PlungeDrop.FromMinPercent = 50.0

	d := New(cfg)
	t0 := time.Now()

	// Low load baseline
	d.Evaluate(makeMetrics(20.0, 20.0, 30.0, t0))
	evs := d.Evaluate(makeMetrics(2.0, 20.0, 30.0, t0.Add(5*time.Second)))
	for _, e := range evs {
		if e.RuleName == "cpu_plunge" {
			t.Fatalf("plunge should not trigger when starting below from_min_percent")
		}
	}
}

func TestPlungeDropWindowExpiry(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.PlungeDrop.Enabled = true
	cfg.CPU.PlungeDrop.DeltaPercent = 40.0
	cfg.CPU.PlungeDrop.FromMinPercent = 50.0
	cfg.CPU.PlungeDrop.WindowSeconds = 15

	d := New(cfg)
	t0 := time.Now()

	// High load baseline at t0
	d.Evaluate(makeMetrics(80.0, 20.0, 30.0, t0))

	// Drop occurs at t0 + 20s (exceeds window of 15s)
	evs := d.Evaluate(makeMetrics(15.0, 20.0, 30.0, t0.Add(20*time.Second)))
	for _, e := range evs {
		if e.RuleName == "cpu_plunge" {
			t.Fatalf("plunge should not trigger after sliding window has expired")
		}
	}
}

func TestFloorDropDetectionAndRecovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.FloorDrop.Enabled = true
	cfg.CPU.FloorDrop.ThresholdPercent = 5.0
	cfg.CPU.FloorDrop.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	// Sample 1: 2% (5s) -> not yet sustained
	evs1 := d.Evaluate(makeMetrics(2.0, 20.0, 30.0, t0))
	for _, e := range evs1 {
		if e.RuleName == "cpu_floor" && e.IsActive {
			t.Fatalf("cpu_floor fired too early")
		}
	}

	// Sample 2: 2% (10s) -> triggers!
	evs2 := d.Evaluate(makeMetrics(2.0, 20.0, 30.0, t0.Add(5*time.Second)))
	found := false
	for _, e := range evs2 {
		if e.RuleName == "cpu_floor" && e.IsActive {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected cpu_floor to trigger")
	}

	// Recovery Sample 1: 20% (5s) -> not yet sustained recovery
	evs3 := d.Evaluate(makeMetrics(20.0, 20.0, 30.0, t0.Add(10*time.Second)))
	for _, e := range evs3 {
		if e.RuleName == "cpu_floor" && !e.IsActive {
			t.Fatalf("cpu_floor recovery fired too early")
		}
	}

	// Recovery Sample 2: 20% (10s) -> sustained recovery!
	evs4 := d.Evaluate(makeMetrics(20.0, 20.0, 30.0, t0.Add(15*time.Second)))
	recovered := false
	for _, e := range evs4 {
		if e.RuleName == "cpu_floor" && !e.IsActive && e.Level == models.AlertLevelResolved {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Fatalf("expected cpu_floor recovery event")
	}
}

func TestMemoryHealthSustainedAndRecovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Health.Memory.Enabled = true
	cfg.Health.Memory.ThresholdPercent = 90.0
	cfg.Health.Memory.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	// Sample 1: 95% (5s) -> not yet sustained
	evs1 := d.Evaluate(makeMetrics(20.0, 95.0, 30.0, t0))
	for _, e := range evs1 {
		if e.RuleName == "memory" && e.IsActive {
			t.Fatalf("memory fired too early")
		}
	}

	// Sample 2: 95% (10s) -> triggers!
	evs2 := d.Evaluate(makeMetrics(20.0, 95.0, 30.0, t0.Add(5*time.Second)))
	found := false
	for _, e := range evs2 {
		if e.RuleName == "memory" && e.IsActive {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected memory alert to trigger")
	}

	// Recovery: 50% for 10s
	d.Evaluate(makeMetrics(20.0, 50.0, 30.0, t0.Add(10*time.Second)))
	evs4 := d.Evaluate(makeMetrics(20.0, 50.0, 30.0, t0.Add(15*time.Second)))
	recovered := false
	for _, e := range evs4 {
		if e.RuleName == "memory" && !e.IsActive && e.Level == models.AlertLevelResolved {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Fatalf("expected memory recovery event")
	}
}

func TestDiskHealthThresholdAndRecovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Health.Disk.Enabled = true
	cfg.Health.Disk.ThresholdPercent = 85.0
	cfg.Health.Disk.MountPoint = "/"

	d := New(cfg)
	t0 := time.Now()

	// Sample 1: 90% -> triggers immediately (disk threshold has no sustained delay)
	evs1 := d.Evaluate(makeMetrics(20.0, 30.0, 90.0, t0))
	found := false
	for _, e := range evs1 {
		if e.RuleName == "disk" && e.IsActive {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected disk alert to trigger")
	}

	// Sample 2: 70% -> recovers immediately
	evs2 := d.Evaluate(makeMetrics(20.0, 30.0, 70.0, t0.Add(5*time.Second)))
	recovered := false
	for _, e := range evs2 {
		if e.RuleName == "disk" && !e.IsActive && e.Level == models.AlertLevelResolved {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Fatalf("expected disk recovery event")
	}
}

func TestDisabledRules(t *testing.T) {
	cfg := &config.Config{} // All disabled by default

	d := New(cfg)
	t0 := time.Now()

	evs := d.Evaluate(makeMetrics(99.0, 99.0, 99.0, t0))
	if len(evs) != 0 {
		t.Fatalf("expected no events when all rules disabled, got %v", evs)
	}
}

func TestDetectorNilGuards(t *testing.T) {
	d := New(nil)
	if d == nil {
		t.Fatalf("expected non-nil detector from New(nil)")
	}
	evs := d.Evaluate(nil)
	if evs != nil {
		t.Fatalf("expected nil events for Evaluate(nil), got %v", evs)
	}
}

func TestSpikeBreachResetOnDrop(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.Spike.Enabled = true
	cfg.CPU.Spike.ThresholdPercent = 85.0
	cfg.CPU.Spike.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	// 1 sample high (5s)
	d.Evaluate(makeMetrics(90.0, 20.0, 30.0, t0))

	// Drops back down (resets breach counter)
	d.Evaluate(makeMetrics(50.0, 20.0, 30.0, t0.Add(5*time.Second)))

	// Another single sample high (5s) -> should NOT trigger because counter was reset
	evs := d.Evaluate(makeMetrics(90.0, 20.0, 30.0, t0.Add(10*time.Second)))
	for _, e := range evs {
		if e.RuleName == "cpu_spike" && e.IsActive {
			t.Fatalf("cpu_spike should not have fired after breach was reset")
		}
	}
}

func TestOngoingActiveSpikeEmitsActiveEvent(t *testing.T) {
	cfg := &config.Config{}
	cfg.CPU.Spike.Enabled = true
	cfg.CPU.Spike.ThresholdPercent = 85.0
	cfg.CPU.Spike.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	d.Evaluate(makeMetrics(90.0, 20.0, 30.0, t0))
	d.Evaluate(makeMetrics(90.0, 20.0, 30.0, t0.Add(5*time.Second)))

	// Third sample still high -> should emit active event
	evs := d.Evaluate(makeMetrics(95.0, 20.0, 30.0, t0.Add(10*time.Second)))
	found := false
	for _, e := range evs {
		if e.RuleName == "cpu_spike" && e.IsActive {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ongoing active cpu_spike event")
	}
}

