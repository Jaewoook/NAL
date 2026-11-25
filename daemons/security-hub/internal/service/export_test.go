package service

import "github.com/jaewoook/security-hub/internal/config"

// StopLaunchdServiceForTest exposes stopLaunchdService to external package tests.
func StopLaunchdServiceForTest(plist, label string) error {
	return stopLaunchdService(plist, label)
}

// SetResolveAdvertiseURLForTest overrides resolveAdvertiseURLFn for tests and returns a restore function.
func SetResolveAdvertiseURLForTest(fn func(*config.Config) string) func() {
	prev := resolveAdvertiseURLFn
	if fn != nil {
		resolveAdvertiseURLFn = fn
	}
	return func() {
		resolveAdvertiseURLFn = prev
	}
}
