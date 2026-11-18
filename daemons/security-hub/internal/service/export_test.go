package service

// SetCmdRunner overrides command execution in service_test and returns a restore function.
func SetCmdRunner(fn func(name string, args ...string) ([]byte, error)) func() {
	orig := cmdRunner
	cmdRunner = fn
	return func() {
		cmdRunner = orig
	}
}

// StopLaunchdServiceForTest exposes stopLaunchdService to external package tests.
func StopLaunchdServiceForTest(plist, label string) error {
	return stopLaunchdService(plist, label)
}
