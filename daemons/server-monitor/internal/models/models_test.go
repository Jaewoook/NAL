package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAlertLevelConstants(t *testing.T) {
	if AlertLevelInfo != "INFO" {
		t.Errorf("expected INFO, got %s", AlertLevelInfo)
	}
	if AlertLevelWarning != "WARNING" {
		t.Errorf("expected WARNING, got %s", AlertLevelWarning)
	}
	if AlertLevelCritical != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", AlertLevelCritical)
	}
	if AlertLevelResolved != "RESOLVED" {
		t.Errorf("expected RESOLVED, got %s", AlertLevelResolved)
	}
}

func TestModelsJSONSerialization(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	metrics := &SystemMetrics{
		Timestamp:     now,
		CPUPercent:    42.5,
		MemoryPercent: 68.2,
		DiskPercent:   55.0,
		Load1:         1.2,
		Load5:         1.5,
		Load15:        1.1,
		UptimeSeconds: 86400,
		TopProcesses: []ProcessInfo{
			{
				PID:           1234,
				Name:          "stress",
				CPUPercent:    40.0,
				MemoryPercent: 2.5,
			},
		},
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		t.Fatalf("failed to marshal SystemMetrics: %v", err)
	}

	var decoded SystemMetrics
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal SystemMetrics: %v", err)
	}

	if decoded.CPUPercent != 42.5 {
		t.Errorf("expected 42.5 CPUPercent, got %f", decoded.CPUPercent)
	}
	if len(decoded.TopProcesses) != 1 || decoded.TopProcesses[0].Name != "stress" {
		t.Errorf("unexpected top processes: %v", decoded.TopProcesses)
	}

	event := &RawConditionEvent{
		RuleName:       "cpu_spike",
		IsActive:       true,
		Level:          AlertLevelCritical,
		CurrentValue:   95.0,
		ThresholdValue: 85.0,
		Message:        "CPU Spike at 95%",
		TopProcesses:   metrics.TopProcesses,
	}

	eventData, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal RawConditionEvent: %v", err)
	}

	var decodedEvent RawConditionEvent
	if err := json.Unmarshal(eventData, &decodedEvent); err != nil {
		t.Fatalf("failed to unmarshal RawConditionEvent: %v", err)
	}
	if decodedEvent.RuleName != "cpu_spike" || !decodedEvent.IsActive || decodedEvent.Level != AlertLevelCritical {
		t.Errorf("unexpected decoded event: %v", decodedEvent)
	}

	alert := &Alert{
		Title:          "CPU Alert",
		Message:        "CPU high",
		Level:          AlertLevelCritical,
		MetricName:     "CPU",
		CurrentValue:   95.0,
		ThresholdValue: 85.0,
		Timestamp:      now,
		Hostname:       "server1",
		TopProcesses:   metrics.TopProcesses,
	}

	alertData, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("failed to marshal Alert: %v", err)
	}

	var decodedAlert Alert
	if err := json.Unmarshal(alertData, &decodedAlert); err != nil {
		t.Fatalf("failed to unmarshal Alert: %v", err)
	}
	if decodedAlert.Title != "CPU Alert" || decodedAlert.Level != AlertLevelCritical {
		t.Errorf("unexpected decoded alert: %v", decodedAlert)
	}
}
