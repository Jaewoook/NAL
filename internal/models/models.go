package models

import (
	"time"
)

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
	Timestamp     time.Time     `json:"timestamp" yaml:"timestamp"`
	CPUPercent    float64       `json:"cpu_percent" yaml:"cpu_percent"`
	MemoryPercent float64       `json:"memory_percent" yaml:"memory_percent"`
	DiskPercent   float64       `json:"disk_percent" yaml:"disk_percent"`
	Load1         float64       `json:"load_1" yaml:"load_1"`
	Load5         float64       `json:"load_5" yaml:"load_5"`
	Load15        float64       `json:"load_15" yaml:"load_15"`
	UptimeSeconds uint64        `json:"uptime_seconds" yaml:"uptime_seconds"`
	TopProcesses  []ProcessInfo `json:"top_processes,omitempty" yaml:"top_processes,omitempty"`
}

// RawConditionEvent represents an evaluation outcome from the anomaly detector.
type RawConditionEvent struct {
	RuleName       string        `json:"rule_name" yaml:"rule_name"`
	IsActive       bool          `json:"is_active" yaml:"is_active"`
	Level          AlertLevel    `json:"level" yaml:"level"`
	CurrentValue   float64       `json:"current_value" yaml:"current_value"`
	ThresholdValue float64       `json:"threshold_value" yaml:"threshold_value"`
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
	Timestamp      time.Time     `json:"timestamp" yaml:"timestamp"`
	Hostname       string        `json:"hostname" yaml:"hostname"`
	TopProcesses   []ProcessInfo `json:"top_processes,omitempty" yaml:"top_processes,omitempty"`
}
