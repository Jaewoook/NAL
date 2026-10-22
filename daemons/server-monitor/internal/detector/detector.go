package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/models"
)

// Rule name constants emitted in RawConditionEvent.
const (
	RuleCPUSpike  = "cpu_spike"
	RuleCPUPlunge = "cpu_plunge"
	RuleCPUFloor  = "cpu_floor"
	RuleMemory    = "memory"
	RuleDisk      = "disk"
)

type cpuSample struct {
	timestamp time.Time
	cpu       float64
}

// Detector evaluates system metrics and emits raw condition events.
type Detector struct {
	mu  sync.Mutex
	cfg *config.Config

	// CPU Spike state
	cpuSpikeActive        bool
	cpuSpikeBreachCount   int
	cpuSpikeRecoveryCount int

	// CPU Plunge Drop rolling window
	cpuBuffer []cpuSample

	// CPU Floor Drop state
	cpuFloorActive        bool
	cpuFloorBreachCount   int
	cpuFloorRecoveryCount int

	// Memory state
	memActive        bool
	memBreachCount   int
	memRecoveryCount int

	// Disk state
	diskActive bool
}

// New creates a new Detector with the given configuration.
func New(cfg *config.Config) *Detector {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Detector{
		cfg: cfg,
	}
}

// Evaluate analyzes point-in-time metrics against configured rules and returns any triggered events.
func (d *Detector) Evaluate(m *models.SystemMetrics) []models.RawConditionEvent {
	if m == nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	interval := d.cfg.Server.CheckIntervalSeconds
	if interval <= 0 {
		interval = 5
	}

	var events []models.RawConditionEvent

	if ev := d.checkCPUSpike(m, interval); ev != nil {
		events = append(events, *ev)
	}
	if ev := d.checkCPUPlunge(m); ev != nil {
		events = append(events, *ev)
	}
	if ev := d.checkCPUFloor(m, interval); ev != nil {
		events = append(events, *ev)
	}
	if ev := d.checkMemory(m, interval); ev != nil {
		events = append(events, *ev)
	}
	if ev := d.checkDisk(m); ev != nil {
		events = append(events, *ev)
	}

	return events
}

func (d *Detector) checkCPUSpike(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.CPU.Spike.Enabled {
		return nil
	}

	threshold := d.cfg.CPU.Spike.ThresholdPercent
	sustainedSec := d.cfg.CPU.Spike.SustainedSeconds
	if sustainedSec <= 0 {
		sustainedSec = interval
	}

	if m.CPUPercent >= threshold {
		d.cpuSpikeRecoveryCount = 0
		d.cpuSpikeBreachCount++
		if !d.cpuSpikeActive {
			if d.cpuSpikeBreachCount*interval >= sustainedSec {
				d.cpuSpikeActive = true
				return &models.RawConditionEvent{
					RuleName:       RuleCPUSpike,
					IsActive:       true,
					Level:          models.AlertLevelCritical,
					CurrentValue:   m.CPUPercent,
					ThresholdValue: threshold,
					Message:        fmt.Sprintf("CPU usage sustained high: %.1f%% >= %.1f%% for %ds", m.CPUPercent, threshold, d.cpuSpikeBreachCount*interval),
					TopProcesses:   m.TopProcesses,
				}
			}
		} else {
			return &models.RawConditionEvent{
				RuleName:       RuleCPUSpike,
				IsActive:       true,
				Level:          models.AlertLevelCritical,
				CurrentValue:   m.CPUPercent,
				ThresholdValue: threshold,
				Message:        fmt.Sprintf("CPU usage sustained high: %.1f%% >= %.1f%%", m.CPUPercent, threshold),
				TopProcesses:   m.TopProcesses,
			}
		}
	} else {
		d.cpuSpikeBreachCount = 0
		if d.cpuSpikeActive {
			d.cpuSpikeRecoveryCount++
			if d.cpuSpikeRecoveryCount*interval >= sustainedSec {
				d.cpuSpikeActive = false
				d.cpuSpikeRecoveryCount = 0
				return &models.RawConditionEvent{
					RuleName:       RuleCPUSpike,
					IsActive:       false,
					Level:          models.AlertLevelResolved,
					CurrentValue:   m.CPUPercent,
					ThresholdValue: threshold,
					Message:        fmt.Sprintf("CPU usage recovered: %.1f%% < %.1f%%", m.CPUPercent, threshold),
					TopProcesses:   m.TopProcesses,
				}
			}
		} else {
			d.cpuSpikeRecoveryCount = 0
		}
	}

	return nil
}

func (d *Detector) checkCPUPlunge(m *models.SystemMetrics) *models.RawConditionEvent {
	if !d.cfg.CPU.PlungeDrop.Enabled {
		return nil
	}

	ts := m.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	windowSec := d.cfg.CPU.PlungeDrop.WindowSeconds
	if windowSec <= 0 {
		windowSec = 15
	}
	windowDuration := time.Duration(windowSec) * time.Second

	// Prune samples older than the sliding window duration
	cutoff := ts.Add(-windowDuration)
	var validSamples []cpuSample
	for _, s := range d.cpuBuffer {
		if !s.timestamp.Before(cutoff) {
			validSamples = append(validSamples, s)
		}
	}
	d.cpuBuffer = validSamples

	// Check if any prior sample in window met the baseline threshold and dropped by >= DeltaPercent
	var maxBaseline float64
	hasEligibleBaseline := false

	for _, s := range d.cpuBuffer {
		if s.cpu >= d.cfg.CPU.PlungeDrop.FromMinPercent {
			if !hasEligibleBaseline || s.cpu > maxBaseline {
				maxBaseline = s.cpu
				hasEligibleBaseline = true
			}
		}
	}

	var event *models.RawConditionEvent
	if hasEligibleBaseline && (maxBaseline-m.CPUPercent) >= d.cfg.CPU.PlungeDrop.DeltaPercent {
		event = &models.RawConditionEvent{
			RuleName:       RuleCPUPlunge,
			IsActive:       true,
			Level:          models.AlertLevelWarning,
			CurrentValue:   m.CPUPercent,
			ThresholdValue: d.cfg.CPU.PlungeDrop.DeltaPercent,
			Message:        fmt.Sprintf("CPU plunge drop detected: dropped by %.1f%% (from %.1f%% to %.1f%%) within %ds", maxBaseline-m.CPUPercent, maxBaseline, m.CPUPercent, windowSec),
			TopProcesses:   m.TopProcesses,
		}
		// Reset buffer to only current sample so the same drop event is not repeatedly emitted
		d.cpuBuffer = []cpuSample{{timestamp: ts, cpu: m.CPUPercent}}
	} else {
		d.cpuBuffer = append(d.cpuBuffer, cpuSample{timestamp: ts, cpu: m.CPUPercent})
	}

	return event
}

func (d *Detector) checkCPUFloor(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.CPU.FloorDrop.Enabled {
		return nil
	}

	threshold := d.cfg.CPU.FloorDrop.ThresholdPercent
	sustainedSec := d.cfg.CPU.FloorDrop.SustainedSeconds
	if sustainedSec <= 0 {
		sustainedSec = interval
	}

	if m.CPUPercent <= threshold {
		d.cpuFloorRecoveryCount = 0
		d.cpuFloorBreachCount++
		if !d.cpuFloorActive {
			if d.cpuFloorBreachCount*interval >= sustainedSec {
				d.cpuFloorActive = true
				return &models.RawConditionEvent{
					RuleName:       RuleCPUFloor,
					IsActive:       true,
					Level:          models.AlertLevelWarning,
					CurrentValue:   m.CPUPercent,
					ThresholdValue: threshold,
					Message:        fmt.Sprintf("CPU floor drop detected: usage at %.1f%% <= %.1f%% for sustained period", m.CPUPercent, threshold),
					TopProcesses:   m.TopProcesses,
				}
			}
		} else {
			return &models.RawConditionEvent{
				RuleName:       RuleCPUFloor,
				IsActive:       true,
				Level:          models.AlertLevelWarning,
				CurrentValue:   m.CPUPercent,
				ThresholdValue: threshold,
				Message:        fmt.Sprintf("CPU floor drop active: usage at %.1f%% <= %.1f%%", m.CPUPercent, threshold),
				TopProcesses:   m.TopProcesses,
			}
		}
	} else {
		d.cpuFloorBreachCount = 0
		if d.cpuFloorActive {
			d.cpuFloorRecoveryCount++
			if d.cpuFloorRecoveryCount*interval >= sustainedSec {
				d.cpuFloorActive = false
				d.cpuFloorRecoveryCount = 0
				return &models.RawConditionEvent{
					RuleName:       RuleCPUFloor,
					IsActive:       false,
					Level:          models.AlertLevelResolved,
					CurrentValue:   m.CPUPercent,
					ThresholdValue: threshold,
					Message:        fmt.Sprintf("CPU floor drop recovered: usage at %.1f%% > %.1f%%", m.CPUPercent, threshold),
					TopProcesses:   m.TopProcesses,
				}
			}
		} else {
			d.cpuFloorRecoveryCount = 0
		}
	}

	return nil
}

func (d *Detector) checkMemory(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.Health.Memory.Enabled {
		return nil
	}

	threshold := d.cfg.Health.Memory.ThresholdPercent
	sustainedSec := d.cfg.Health.Memory.SustainedSeconds
	if sustainedSec <= 0 {
		sustainedSec = interval
	}

	if m.MemoryPercent >= threshold {
		d.memRecoveryCount = 0
		d.memBreachCount++
		if !d.memActive {
			if d.memBreachCount*interval >= sustainedSec {
				d.memActive = true
				return &models.RawConditionEvent{
					RuleName:       RuleMemory,
					IsActive:       true,
					Level:          models.AlertLevelCritical,
					CurrentValue:   m.MemoryPercent,
					ThresholdValue: threshold,
					Message:        fmt.Sprintf("Memory usage high: %.1f%% >= %.1f%% for %ds", m.MemoryPercent, threshold, d.memBreachCount*interval),
					TopProcesses:   m.TopProcesses,
				}
			}
		} else {
			return &models.RawConditionEvent{
				RuleName:       RuleMemory,
				IsActive:       true,
				Level:          models.AlertLevelCritical,
				CurrentValue:   m.MemoryPercent,
				ThresholdValue: threshold,
				Message:        fmt.Sprintf("Memory usage high: %.1f%% >= %.1f%%", m.MemoryPercent, threshold),
				TopProcesses:   m.TopProcesses,
			}
		}
	} else {
		d.memBreachCount = 0
		if d.memActive {
			d.memRecoveryCount++
			if d.memRecoveryCount*interval >= sustainedSec {
				d.memActive = false
				d.memRecoveryCount = 0
				return &models.RawConditionEvent{
					RuleName:       RuleMemory,
					IsActive:       false,
					Level:          models.AlertLevelResolved,
					CurrentValue:   m.MemoryPercent,
					ThresholdValue: threshold,
					Message:        fmt.Sprintf("Memory usage recovered: %.1f%% < %.1f%%", m.MemoryPercent, threshold),
					TopProcesses:   m.TopProcesses,
				}
			}
		} else {
			d.memRecoveryCount = 0
		}
	}

	return nil
}

func (d *Detector) checkDisk(m *models.SystemMetrics) *models.RawConditionEvent {
	if !d.cfg.Health.Disk.Enabled {
		return nil
	}

	threshold := d.cfg.Health.Disk.ThresholdPercent
	mount := d.cfg.Health.Disk.MountPoint
	if mount == "" {
		mount = "/"
	}

	if m.DiskPercent >= threshold {
		if !d.diskActive {
			d.diskActive = true
		}
		return &models.RawConditionEvent{
			RuleName:       RuleDisk,
			IsActive:       true,
			Level:          models.AlertLevelCritical,
			CurrentValue:   m.DiskPercent,
			ThresholdValue: threshold,
			Message:        fmt.Sprintf("Disk usage high on %s: %.1f%% >= %.1f%%", mount, m.DiskPercent, threshold),
			TopProcesses:   m.TopProcesses,
		}
	}

	// m.DiskPercent < threshold
	if d.diskActive {
		d.diskActive = false
		return &models.RawConditionEvent{
			RuleName:       RuleDisk,
			IsActive:       false,
			Level:          models.AlertLevelResolved,
			CurrentValue:   m.DiskPercent,
			ThresholdValue: threshold,
			Message:        fmt.Sprintf("Disk usage recovered on %s: %.1f%% < %.1f%%", mount, m.DiskPercent, threshold),
			TopProcesses:   m.TopProcesses,
		}
	}

	return nil
}
