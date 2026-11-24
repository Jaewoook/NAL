package models

import (
	"strings"
	"time"
)

// Canonical rule identifiers shared across detector, alert manager, and daemon.
const (
	RuleCPUSpike  = "cpu_spike"
	RuleCPUPlunge = "cpu_plunge"
	RuleCPUFloor  = "cpu_floor"
	RuleMemory    = "memory"
	RuleDisk      = "disk"
	RuleCPUTemp   = "cpu_temperature"
	RuleGPUTemp   = "gpu_temperature"
)

// RuleMeta describes static metadata for a built-in monitoring rule.
type RuleMeta struct {
	ID              string
	DisplayName     string
	Unit            string
	IsEvent         bool
	DefaultCooldown time.Duration
}

var builtinRules = map[string]RuleMeta{
	RuleCPUSpike: {
		ID:              RuleCPUSpike,
		DisplayName:     "CPU Spike",
		Unit:            "%",
		DefaultCooldown: 30 * time.Minute,
	},
	RuleCPUPlunge: {
		ID:              RuleCPUPlunge,
		DisplayName:     "CPU Plunge",
		Unit:            "%",
		IsEvent:         true,
		DefaultCooldown: 15 * time.Minute,
	},
	RuleCPUFloor: {
		ID:              RuleCPUFloor,
		DisplayName:     "CPU Floor",
		Unit:            "%",
		DefaultCooldown: 30 * time.Minute,
	},
	RuleMemory: {
		ID:              RuleMemory,
		DisplayName:     "Memory",
		Unit:            "%",
		DefaultCooldown: 30 * time.Minute,
	},
	RuleDisk: {
		ID:              RuleDisk,
		DisplayName:     "Disk",
		Unit:            "%",
		DefaultCooldown: 60 * time.Minute,
	},
	RuleCPUTemp: {
		ID:              RuleCPUTemp,
		DisplayName:     "CPU Temperature",
		Unit:            "°C",
		DefaultCooldown: 30 * time.Minute,
	},
	RuleGPUTemp: {
		ID:              RuleGPUTemp,
		DisplayName:     "GPU Temperature",
		Unit:            "°C",
		DefaultCooldown: 30 * time.Minute,
	},
}

// LookupRuleMeta returns metadata for a built-in rule ID.
func LookupRuleMeta(ruleName string) (RuleMeta, bool) {
	meta, ok := builtinRules[ruleName]
	return meta, ok
}

// FormatRuleName returns a human-readable display name for a rule identifier.
func FormatRuleName(rule string) string {
	if meta, ok := builtinRules[rule]; ok {
		return meta.DisplayName
	}
	words := strings.Split(rule, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
