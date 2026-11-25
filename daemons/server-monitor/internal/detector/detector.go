package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/models"
)

// Rule name constants aliased from models for backward compatibility.
const (
	RuleCPUSpike  = models.RuleCPUSpike
	RuleCPUPlunge = models.RuleCPUPlunge
	RuleCPUFloor  = models.RuleCPUFloor
	RuleMemory    = models.RuleMemory
	RuleDisk      = models.RuleDisk
	RuleCPUTemp   = models.RuleCPUTemp
	RuleGPUTemp   = models.RuleGPUTemp
)

type cpuSample struct {
	timestamp time.Time
	cpu       float64
}

type sustainedState int

const (
	stateNoEvent sustainedState = iota
	stateInitialBreach
	stateOngoingBreach
	stateRecovered
)

// sustainedTracker implements the shared breach/recovery state machine
// used by sustained threshold rules (CPU spike, CPU floor, memory, temperatures).
// Elapsed duration uses wall timestamps when monotonic/advancing, falling back
// to tick count so slow or delayed ticks still trigger accurately.
type sustainedTracker struct {
	active        bool
	breachCount   int
	recoveryCount int
	breachSince   time.Time
	recoverySince time.Time
}

func sustainedElapsed(count, interval int, since, now time.Time) int {
	tickElapsed := count * interval
	if !since.IsZero() && !now.IsZero() && now.After(since) {
		wallElapsed := int(now.Sub(since).Seconds()) + interval
		if wallElapsed > tickElapsed {
			return wallElapsed
		}
	}
	return tickElapsed
}

func (s *sustainedTracker) evaluate(breached bool, interval, sustainedSec int, now time.Time) (state sustainedState, elapsedSec int) {
	if sustainedSec <= 0 {
		sustainedSec = interval
	}

	if breached {
		s.recoveryCount = 0
		s.recoverySince = time.Time{}
		if s.breachCount == 0 {
			s.breachSince = now
		}
		s.breachCount++
		elapsed := sustainedElapsed(s.breachCount, interval, s.breachSince, now)
		if !s.active {
			if elapsed >= sustainedSec {
				s.active = true
				return stateInitialBreach, elapsed
			}
			return stateNoEvent, 0
		}
		return stateOngoingBreach, elapsed
	}

	s.breachCount = 0
	s.breachSince = time.Time{}
	if s.active {
		if s.recoveryCount == 0 {
			s.recoverySince = now
		}
		s.recoveryCount++
		if sustainedElapsed(s.recoveryCount, interval, s.recoverySince, now) >= sustainedSec {
			s.active = false
			s.recoveryCount = 0
			s.recoverySince = time.Time{}
			return stateRecovered, 0
		}
	} else {
		s.recoveryCount = 0
		s.recoverySince = time.Time{}
	}
	return stateNoEvent, 0
}

type sustainedRuleParams struct {
	ruleName     string
	unit         string
	level        models.AlertLevel
	value        float64
	threshold    float64
	breached     bool
	sustainedSec int
	interval     int
	timestamp    time.Time
	topProcesses []models.ProcessInfo
	initialMsg   func(val, threshold float64, elapsedSec int) string
	ongoingMsg   func(val, threshold float64) string
	recoveredMsg func(val, threshold float64) string
}

func evaluateSustainedRule(tracker *sustainedTracker, p sustainedRuleParams) *models.RawConditionEvent {
	state, elapsed := tracker.evaluate(p.breached, p.interval, p.sustainedSec, p.timestamp)
	switch state {
	case stateInitialBreach:
		return &models.RawConditionEvent{
			RuleName:       p.ruleName,
			IsActive:       true,
			Level:          p.level,
			CurrentValue:   p.value,
			ThresholdValue: p.threshold,
			Unit:           p.unit,
			Message:        p.initialMsg(p.value, p.threshold, elapsed),
			TopProcesses:   p.topProcesses,
		}
	case stateOngoingBreach:
		return &models.RawConditionEvent{
			RuleName:       p.ruleName,
			IsActive:       true,
			Level:          p.level,
			CurrentValue:   p.value,
			ThresholdValue: p.threshold,
			Unit:           p.unit,
			Message:        p.ongoingMsg(p.value, p.threshold),
			TopProcesses:   p.topProcesses,
		}
	case stateRecovered:
		return &models.RawConditionEvent{
			RuleName:       p.ruleName,
			IsActive:       false,
			Level:          models.AlertLevelResolved,
			CurrentValue:   p.value,
			ThresholdValue: p.threshold,
			Unit:           p.unit,
			Message:        p.recoveredMsg(p.value, p.threshold),
			TopProcesses:   p.topProcesses,
		}
	default:
		return nil
	}
}

// Detector evaluates system metrics and emits raw condition events.
type Detector struct {
	mu  sync.Mutex
	cfg *config.Config

	cpuSpike sustainedTracker
	cpuFloor sustainedTracker
	memory   sustainedTracker
	cpuTemp  sustainedTracker
	gpuTemp  sustainedTracker

	cpuBuffer  []cpuSample
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

// ElevatedCPUThreshold returns a conservative CPU percentage above which the
// collector should eagerly scan top processes so alert diagnostics are ready.
func (d *Detector) ElevatedCPUThreshold() float64 {
	if d.cfg == nil || d.cfg.CPU.Spike.ThresholdPercent <= 0 {
		return 0
	}
	threshold := d.cfg.CPU.Spike.ThresholdPercent * 0.7
	if d.cfg.CPU.PlungeDrop.FromMinPercent > 0 && d.cfg.CPU.PlungeDrop.FromMinPercent < threshold {
		threshold = d.cfg.CPU.PlungeDrop.FromMinPercent
	}
	return threshold
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
	appendIf := func(ev *models.RawConditionEvent) {
		if ev != nil {
			events = append(events, *ev)
		}
	}

	appendIf(d.checkCPUSpike(m, interval))
	appendIf(d.checkCPUPlunge(m))
	appendIf(d.checkCPUFloor(m, interval))
	appendIf(d.checkMemory(m, interval))
	appendIf(d.checkDisk(m))
	appendIf(d.checkCPUTemp(m, interval))
	appendIf(d.checkGPUTemp(m, interval))

	return events
}

func (d *Detector) checkCPUSpike(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.CPU.Spike.Enabled || m.CPUFailed {
		return nil
	}
	threshold := d.cfg.CPU.Spike.ThresholdPercent
	return evaluateSustainedRule(&d.cpuSpike, sustainedRuleParams{
		ruleName:     RuleCPUSpike,
		unit:         "%",
		level:        models.AlertLevelCritical,
		value:        m.CPUPercent,
		threshold:    threshold,
		breached:     m.CPUPercent >= threshold,
		sustainedSec: d.cfg.CPU.Spike.SustainedSeconds,
		interval:     interval,
		timestamp:    m.Timestamp,
		topProcesses: m.TopProcesses,
		initialMsg: func(v, t float64, sec int) string {
			return fmt.Sprintf("CPU usage sustained high: %.1f%% >= %.1f%% for %ds", v, t, sec)
		},
		ongoingMsg: func(v, t float64) string {
			return fmt.Sprintf("CPU usage sustained high: %.1f%% >= %.1f%%", v, t)
		},
		recoveredMsg: func(v, t float64) string {
			return fmt.Sprintf("CPU usage recovered: %.1f%% < %.1f%%", v, t)
		},
	})
}

func (d *Detector) checkCPUPlunge(m *models.SystemMetrics) *models.RawConditionEvent {
	if !d.cfg.CPU.PlungeDrop.Enabled || m.CPUFailed {
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
	cutoff := ts.Add(-time.Duration(windowSec) * time.Second)

	validSamples := d.cpuBuffer[:0]
	for _, s := range d.cpuBuffer {
		if !s.timestamp.Before(cutoff) {
			validSamples = append(validSamples, s)
		}
	}
	d.cpuBuffer = validSamples

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

	if hasEligibleBaseline && (maxBaseline-m.CPUPercent) >= d.cfg.CPU.PlungeDrop.DeltaPercent {
		event := &models.RawConditionEvent{
			RuleName:       RuleCPUPlunge,
			IsActive:       true,
			Level:          models.AlertLevelWarning,
			CurrentValue:   m.CPUPercent,
			ThresholdValue: d.cfg.CPU.PlungeDrop.DeltaPercent,
			Unit:           "%",
			Message:        fmt.Sprintf("CPU plunge drop detected: dropped by %.1f%% (from %.1f%% to %.1f%%) within %ds", maxBaseline-m.CPUPercent, maxBaseline, m.CPUPercent, windowSec),
			TopProcesses:   m.TopProcesses,
		}
		// Reset buffer to only current sample so the same drop event is not repeatedly emitted
		d.cpuBuffer = []cpuSample{{timestamp: ts, cpu: m.CPUPercent}}
		return event
	}

	d.cpuBuffer = append(d.cpuBuffer, cpuSample{timestamp: ts, cpu: m.CPUPercent})
	return nil
}

func (d *Detector) checkCPUFloor(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.CPU.FloorDrop.Enabled || m.CPUFailed {
		return nil
	}
	threshold := d.cfg.CPU.FloorDrop.ThresholdPercent
	return evaluateSustainedRule(&d.cpuFloor, sustainedRuleParams{
		ruleName:     RuleCPUFloor,
		unit:         "%",
		level:        models.AlertLevelWarning,
		value:        m.CPUPercent,
		threshold:    threshold,
		breached:     m.CPUPercent <= threshold,
		sustainedSec: d.cfg.CPU.FloorDrop.SustainedSeconds,
		interval:     interval,
		timestamp:    m.Timestamp,
		topProcesses: m.TopProcesses,
		initialMsg: func(v, t float64, _ int) string {
			return fmt.Sprintf("CPU floor drop detected: usage at %.1f%% <= %.1f%% for sustained period", v, t)
		},
		ongoingMsg: func(v, t float64) string {
			return fmt.Sprintf("CPU floor drop active: usage at %.1f%% <= %.1f%%", v, t)
		},
		recoveredMsg: func(v, t float64) string {
			return fmt.Sprintf("CPU floor drop recovered: usage at %.1f%% > %.1f%%", v, t)
		},
	})
}

func (d *Detector) checkMemory(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.Health.Memory.Enabled || m.MemoryFailed {
		return nil
	}
	threshold := d.cfg.Health.Memory.ThresholdPercent
	return evaluateSustainedRule(&d.memory, sustainedRuleParams{
		ruleName:     RuleMemory,
		unit:         "%",
		level:        models.AlertLevelCritical,
		value:        m.MemoryPercent,
		threshold:    threshold,
		breached:     m.MemoryPercent >= threshold,
		sustainedSec: d.cfg.Health.Memory.SustainedSeconds,
		interval:     interval,
		timestamp:    m.Timestamp,
		topProcesses: m.TopProcesses,
		initialMsg: func(v, t float64, sec int) string {
			return fmt.Sprintf("Memory usage high: %.1f%% >= %.1f%% for %ds", v, t, sec)
		},
		ongoingMsg: func(v, t float64) string {
			return fmt.Sprintf("Memory usage high: %.1f%% >= %.1f%%", v, t)
		},
		recoveredMsg: func(v, t float64) string {
			return fmt.Sprintf("Memory usage recovered: %.1f%% < %.1f%%", v, t)
		},
	})
}

func (d *Detector) checkDisk(m *models.SystemMetrics) *models.RawConditionEvent {
	if !d.cfg.Health.Disk.Enabled || m.DiskFailed {
		return nil
	}

	threshold := d.cfg.Health.Disk.ThresholdPercent
	mount := d.cfg.Health.Disk.MountPoint
	if mount == "" {
		mount = "/"
	}

	if m.DiskPercent >= threshold {
		d.diskActive = true
		return &models.RawConditionEvent{
			RuleName:       RuleDisk,
			IsActive:       true,
			Level:          models.AlertLevelCritical,
			CurrentValue:   m.DiskPercent,
			ThresholdValue: threshold,
			Unit:           "%",
			Message:        fmt.Sprintf("Disk usage high on %s: %.1f%% >= %.1f%%", mount, m.DiskPercent, threshold),
			TopProcesses:   m.TopProcesses,
		}
	}

	if d.diskActive {
		d.diskActive = false
		return &models.RawConditionEvent{
			RuleName:       RuleDisk,
			IsActive:       false,
			Level:          models.AlertLevelResolved,
			CurrentValue:   m.DiskPercent,
			ThresholdValue: threshold,
			Unit:           "%",
			Message:        fmt.Sprintf("Disk usage recovered on %s: %.1f%% < %.1f%%", mount, m.DiskPercent, threshold),
			TopProcesses:   m.TopProcesses,
		}
	}

	return nil
}

func (d *Detector) checkCPUTemp(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.Health.Temperature.Enabled || !m.HasCPUTemp {
		return nil
	}
	threshold := d.cfg.Health.Temperature.CPUThresholdCelsius
	return evaluateSustainedRule(&d.cpuTemp, sustainedRuleParams{
		ruleName:     RuleCPUTemp,
		unit:         "°C",
		level:        models.AlertLevelCritical,
		value:        m.CPUTempCelsius,
		threshold:    threshold,
		breached:     m.CPUTempCelsius >= threshold,
		sustainedSec: d.cfg.Health.Temperature.SustainedSeconds,
		interval:     interval,
		timestamp:    m.Timestamp,
		topProcesses: m.TopProcesses,
		initialMsg: func(v, t float64, sec int) string {
			return fmt.Sprintf("CPU temperature sustained high: %.1f°C >= %.1f°C for %ds", v, t, sec)
		},
		ongoingMsg: func(v, t float64) string {
			return fmt.Sprintf("CPU temperature high: %.1f°C >= %.1f°C", v, t)
		},
		recoveredMsg: func(v, t float64) string {
			return fmt.Sprintf("CPU temperature recovered: %.1f°C < %.1f°C", v, t)
		},
	})
}

func (d *Detector) checkGPUTemp(m *models.SystemMetrics, interval int) *models.RawConditionEvent {
	if !d.cfg.Health.Temperature.Enabled || !m.HasGPUTemp {
		return nil
	}
	threshold := d.cfg.Health.Temperature.GPUThresholdCelsius
	return evaluateSustainedRule(&d.gpuTemp, sustainedRuleParams{
		ruleName:     RuleGPUTemp,
		unit:         "°C",
		level:        models.AlertLevelCritical,
		value:        m.GPUTempCelsius,
		threshold:    threshold,
		breached:     m.GPUTempCelsius >= threshold,
		sustainedSec: d.cfg.Health.Temperature.SustainedSeconds,
		interval:     interval,
		timestamp:    m.Timestamp,
		topProcesses: m.TopProcesses,
		initialMsg: func(v, t float64, sec int) string {
			return fmt.Sprintf("GPU temperature sustained high: %.1f°C >= %.1f°C for %ds", v, t, sec)
		},
		ongoingMsg: func(v, t float64) string {
			return fmt.Sprintf("GPU temperature high: %.1f°C >= %.1f°C", v, t)
		},
		recoveredMsg: func(v, t float64) string {
			return fmt.Sprintf("GPU temperature recovered: %.1f°C < %.1f°C", v, t)
		},
	})
}
