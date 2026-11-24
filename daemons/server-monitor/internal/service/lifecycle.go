package service

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CommandRunner executes an external OS command and returns combined stdout/stderr.
type CommandRunner func(name string, args ...string) ([]byte, error)

// Backend manages OS service lifecycle operations for a specific init system (launchd or systemd).
type Backend interface {
	Start(serviceName, targetPath string) (string, error)
	Stop(serviceName, targetPath string) (string, error)
	Restart(serviceName, targetPath string) (string, error)
	Uninstall(serviceName, targetPath string) (string, error)
	Status(serviceName, targetPath string) (string, error)
}

func defaultExecCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

var (
	runnerMu      sync.RWMutex
	defaultRunner CommandRunner = defaultExecCommand
)

// SetCommandRunner allows overriding the default command execution function for testing.
func SetCommandRunner(runner func(name string, args ...string) ([]byte, error)) {
	runnerMu.Lock()
	defer runnerMu.Unlock()
	if runner != nil {
		defaultRunner = runner
	} else {
		defaultRunner = defaultExecCommand
	}
}

func currentRunner() CommandRunner {
	runnerMu.RLock()
	defer runnerMu.RUnlock()
	return defaultRunner
}

func resolveServiceType(st string) string {
	if st != "" {
		return strings.ToLower(st)
	}
	if runtime.GOOS == "darwin" {
		return "launchd"
	}
	return "systemd"
}

func normalizeServiceName(serviceName string) string {
	if serviceName == "" {
		return "server-monitor"
	}
	return serviceName
}

// NewBackend returns a Backend for the given service type ("launchd" or "systemd").
// If runner is nil, the default OS command runner is used.
func NewBackend(serviceType string, runner CommandRunner) (Backend, error) {
	if runner == nil {
		runner = currentRunner()
	}
	switch st := resolveServiceType(serviceType); st {
	case "launchd":
		return &launchdBackend{run: runner, pollInterval: 500 * time.Millisecond}, nil
	case "systemd":
		return &systemdBackend{run: runner}, nil
	default:
		return nil, fmt.Errorf("unsupported service type: %s", st)
	}
}

// StartService starts the background service.
func StartService(serviceType, serviceName, targetPath string) (string, error) {
	b, err := NewBackend(serviceType, nil)
	if err != nil {
		return "", err
	}
	return b.Start(normalizeServiceName(serviceName), targetPath)
}

// StopService stops the background service.
func StopService(serviceType, serviceName, targetPath string) (string, error) {
	b, err := NewBackend(serviceType, nil)
	if err != nil {
		return "", err
	}
	return b.Stop(normalizeServiceName(serviceName), targetPath)
}

// RestartService restarts the background service.
func RestartService(serviceType, serviceName, targetPath string) (string, error) {
	b, err := NewBackend(serviceType, nil)
	if err != nil {
		return "", err
	}
	return b.Restart(normalizeServiceName(serviceName), targetPath)
}

// UninstallService unloads and removes the background service.
func UninstallService(serviceType, serviceName, targetPath string) (string, error) {
	b, err := NewBackend(serviceType, nil)
	if err != nil {
		return "", err
	}
	return b.Uninstall(normalizeServiceName(serviceName), targetPath)
}

// StatusService queries and formats the status of the background service.
func StatusService(serviceType, serviceName, targetPath string) (string, error) {
	b, err := NewBackend(serviceType, nil)
	if err != nil {
		return "", err
	}
	return b.Status(normalizeServiceName(serviceName), targetPath)
}
