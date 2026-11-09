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

func TestCPUTemperatureDetectionSustainedAndRecovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Health.Temperature.Enabled = true
	cfg.Health.Temperature.CPUThresholdCelsius = 75.0
	cfg.Health.Temperature.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	m1 := makeMetrics(10, 10, 10, t0)
	m1.HasCPUTemp = true
	m1.CPUTempCelsius = 76.0

	// Sample 1 (5s): not yet sustained
	evs1 := d.Evaluate(m1)
	for _, e := range evs1 {
		if e.RuleName == RuleCPUTemp && e.IsActive {
			t.Fatalf("cpu_temperature fired too early at 5s")
		}
	}

	// Sample 2 (10s): sustained breach -> triggers
	m2 := makeMetrics(10, 10, 10, t0.Add(5*time.Second))
	m2.HasCPUTemp = true
	m2.CPUTempCelsius = 78.5
	m2.TopProcesses = []models.ProcessInfo{{PID: 100, Name: "stress", CPUPercent: 99.0}}

	evs2 := d.Evaluate(m2)
	found := false
	for _, e := range evs2 {
		if e.RuleName == RuleCPUTemp && e.IsActive {
			found = true
			if e.Level != models.AlertLevelCritical {
				t.Errorf("expected CRITICAL level for cpu temp alert, got %s", e.Level)
			}
			if e.CurrentValue != 78.5 {
				t.Errorf("expected current value 78.5, got %f", e.CurrentValue)
			}
			if len(e.TopProcesses) != 1 || e.TopProcesses[0].Name != "stress" {
				t.Errorf("expected top processes preserved in event, got %v", e.TopProcesses)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected cpu_temperature breach event")
	}

	// Ongoing active event
	evsOngoing := d.Evaluate(m2)
	foundOngoing := false
	for _, e := range evsOngoing {
		if e.RuleName == RuleCPUTemp && e.IsActive {
			foundOngoing = true
			break
		}
	}
	if !foundOngoing {
		t.Fatalf("expected ongoing cpu_temperature event")
	}

	// Recovery sample 1 (5s): not yet sustained recovery
	m3 := makeMetrics(10, 10, 10, t0.Add(15*time.Second))
	m3.HasCPUTemp = true
	m3.CPUTempCelsius = 70.0
	evs3 := d.Evaluate(m3)
	for _, e := range evs3 {
		if e.RuleName == RuleCPUTemp && !e.IsActive {
			t.Fatalf("recovery fired too early at 5s")
		}
	}

	// Recovery sample 2 (10s): sustained recovery
	m4 := makeMetrics(10, 10, 10, t0.Add(20*time.Second))
	m4.HasCPUTemp = true
	m4.CPUTempCelsius = 68.0
	evs4 := d.Evaluate(m4)
	foundRecovery := false
	for _, e := range evs4 {
		if e.RuleName == RuleCPUTemp && !e.IsActive {
			foundRecovery = true
			if e.Level != models.AlertLevelResolved {
				t.Errorf("expected RESOLVED level, got %s", e.Level)
			}
			break
		}
	}
	if !foundRecovery {
		t.Fatalf("expected cpu_temperature recovery event")
	}
}

func TestGPUTemperatureDetectionSustainedAndRecovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Health.Temperature.Enabled = true
	cfg.Health.Temperature.GPUThresholdCelsius = 75.0
	cfg.Health.Temperature.SustainedSeconds = 10
	cfg.Server.CheckIntervalSeconds = 5

	d := New(cfg)
	t0 := time.Now()

	m1 := makeMetrics(10, 10, 10, t0)
	m1.HasGPUTemp = true
	m1.GPUTempCelsius = 80.0

	// 5s: not yet sustained
	d.Evaluate(m1)

	// 10s: sustained -> triggers
	m2 := makeMetrics(10, 10, 10, t0.Add(5*time.Second))
	m2.HasGPUTemp = true
	m2.GPUTempCelsius = 82.0

	evs2 := d.Evaluate(m2)
	found := false
	for _, e := range evs2 {
		if e.RuleName == RuleGPUTemp && e.IsActive {
			found = true
			if e.Level != models.AlertLevelCritical {
				t.Errorf("expected CRITICAL level, got %s", e.Level)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected gpu_temperature breach event")
	}

	// Sustained recovery
	m3 := makeMetrics(10, 10, 10, t0.Add(10*time.Second))
	m3.HasGPUTemp = true
	m3.GPUTempCelsius = 60.0
	d.Evaluate(m3)

	m4 := makeMetrics(10, 10, 10, t0.Add(15*time.Second))
	m4.HasGPUTemp = true
	m4.GPUTempCelsius = 58.0
	evs4 := d.Evaluate(m4)
	foundRecovery := false
	for _, e := range evs4 {
		if e.RuleName == RuleGPUTemp && !e.IsActive {
			foundRecovery = true
			break
		}
	}
	if !foundRecovery {
		t.Fatalf("expected gpu_temperature recovery event")
	}
}

func TestTemperatureDetection_NoSensorsOrDisabled(t *testing.T) {
	// Case 1: Disabled
	cfgDisabled := &config.Config{}
	cfgDisabled.Health.Temperature.Enabled = false
	cfgDisabled.Health.Temperature.CPUThresholdCelsius = 75.0
	d1 := New(cfgDisabled)

	m := makeMetrics(10, 10, 10, time.Now())
	m.HasCPUTemp = true
	m.CPUTempCelsius = 95.0
	evs := d1.Evaluate(m)
	if len(evs) != 0 {
		t.Fatalf("expected no events when temperature monitoring is disabled")
	}

	// Case 2: Enabled but HasCPUTemp / HasGPUTemp are false
	cfgEnabled := &config.Config{}
	cfgEnabled.Health.Temperature.Enabled = true
	cfgEnabled.Health.Temperature.CPUThresholdCelsius = 75.0
	cfgEnabled.Health.Temperature.GPUThresholdCelsius = 75.0
	d2 := New(cfgEnabled)

	mNoSensors := makeMetrics(10, 10, 10, time.Now())
	mNoSensors.HasCPUTemp = false
	mNoSensors.CPUTempCelsius = 95.0
	mNoSensors.HasGPUTemp = false
	mNoSensors.GPUTempCelsius = 95.0
	evs2 := d2.Evaluate(mNoSensors)
	if len(evs2) != 0 {
		t.Fatalf("expected no events when HasCPUTemp/HasGPUTemp are false")
	}
}

