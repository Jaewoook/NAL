package service

// StopLaunchdServiceForTest exposes stopLaunchdService to external package tests.
func StopLaunchdServiceForTest(plist, label string) error {
	return stopLaunchdService(plist, label)
}
