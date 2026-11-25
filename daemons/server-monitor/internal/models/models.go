package models

import (
	"time"
)

// UserAgent is the HTTP User-Agent string sent by outbound requests.
const UserAgent = "server-monitor/1.0"

// AlertLevel represents the severity or state of an alert.
type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "INFO"
	AlertLevelWarning  AlertLevel = "WARNING"
	AlertLevelCritical AlertLevel = "CRITICAL"
	AlertLevelResolved AlertLevel = "RESOLVED"
)

// ProcessInfo captures information about a running process.
type ProcessInfo struct {
	PID           int32   `json:"pid" yaml:"pid"`
	Name          string  `json:"name" yaml:"name"`
	CPUPercent    float64 `json:"cpu_percent" yaml:"cpu_percent"`
	MemoryPercent float32 `json:"memory_percent" yaml:"memory_percent"`
}

// SystemMetrics captures point-in-time system resource utilization and telemetry.
type SystemMetrics struct {
	Timestamp      time.Time     `json:"timestamp" yaml:"timestamp"`
	CPUPercent     float64       `json:"cpu_percent" yaml:"cpu_percent"`
	MemoryPercent  float64       `json:"memory_percent" yaml:"memory_percent"`
	DiskPercent    float64       `json:"disk_percent" yaml:"disk_percent"`
	CPUFailed      bool          `json:"cpu_failed,omitempty" yaml:"cpu_failed,omitempty"`
	MemoryFailed   bool          `json:"memory_failed,omitempty" yaml:"memory_failed,omitempty"`
	DiskFailed     bool          `json:"disk_failed,omitempty" yaml:"disk_failed,omitempty"`
	CPUTempCelsius float64       `json:"cpu_temp_celsius" yaml:"cpu_temp_celsius"`
	GPUTempCelsius float64       `json:"gpu_temp_celsius" yaml:"gpu_temp_celsius"`
	HasCPUTemp     bool          `json:"has_cpu_temp" yaml:"has_cpu_temp"`
	HasGPUTemp     bool          `json:"has_gpu_temp" yaml:"has_gpu_temp"`
	Load1          float64       `json:"load_1" yaml:"load_1"`
	Load5          float64       `json:"load_5" yaml:"load_5"`
	Load15         float64       `json:"load_15" yaml:"load_15"`
	UptimeSeconds  uint64        `json:"uptime_seconds" yaml:"uptime_seconds"`
	TopProcesses   []ProcessInfo `json:"top_processes,omitempty" yaml:"top_processes,omitempty"`
}

// RawConditionEvent represents an evaluation outcome from the anomaly detector.
type RawConditionEvent struct {
	RuleName       string        `json:"rule_name" yaml:"rule_name"`
	IsActive       bool          `json:"is_active" yaml:"is_active"`
	Level          AlertLevel    `json:"level" yaml:"level"`
	CurrentValue   float64       `json:"current_value" yaml:"current_value"`
	ThresholdValue float64       `json:"threshold_value" yaml:"threshold_value"`
	Unit           string        `json:"unit,omitempty" yaml:"unit,omitempty"`
	Message        string        `json:"message" yaml:"message"`
	TopProcesses   []ProcessInfo `json:"top_processes,omitempty" yaml:"top_processes,omitempty"`
}

// Alert represents an actionable notification emitted by the alert manager.
type Alert struct {
	Title          string        `json:"title" yaml:"title"`
	Message        string        `json:"message" yaml:"message"`
	Level          AlertLevel    `json:"level" yaml:"level"`
	MetricName     string        `json:"metric_name" yaml:"metric_name"`
	CurrentValue   float64       `json:"current_value" yaml:"current_value"`
	ThresholdValue float64       `json:"threshold_value" yaml:"threshold_value"`
	Unit           string        `json:"unit,omitempty" yaml:"unit,omitempty"`
	Timestamp      time.Time     `json:"timestamp" yaml:"timestamp"`
	Hostname       string        `json:"hostname" yaml:"hostname"`
	TopProcesses   []ProcessInfo `json:"top_processes,omitempty" yaml:"top_processes,omitempty"`
}

// EffectiveUnit returns the alert's unit, falling back to rule metadata or "%".
func (a *Alert) EffectiveUnit() string {
	if a != nil && a.Unit != "" {
		return a.Unit
	}
	if a != nil {
		if meta, ok := LookupRuleMeta(a.MetricName); ok && meta.Unit != "" {
			return meta.Unit
		}
	}
	return "%"
}
