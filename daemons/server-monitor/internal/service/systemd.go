package service

import (
	"fmt"
	"os"
	"strings"
)

type systemdBackend struct {
	run CommandRunner
}

func (b *systemdBackend) Start(serviceName, _ string) (string, error) {
	unitName := serviceName + ".service"
	out, err := b.run("systemctl", "start", unitName)
	if err != nil {
		return "", fmt.Errorf("failed to start %s: %s (%v)", unitName, strings.TrimSpace(string(out)), err)
	}
	return fmt.Sprintf("Successfully started %s.", unitName), nil
}

func (b *systemdBackend) Stop(serviceName, _ string) (string, error) {
	unitName := serviceName + ".service"
	out, err := b.run("systemctl", "stop", unitName)
	if err != nil {
		return "", fmt.Errorf("failed to stop %s: %s (%v)", unitName, strings.TrimSpace(string(out)), err)
	}
	return fmt.Sprintf("Successfully stopped %s.", unitName), nil
}

func (b *systemdBackend) Restart(serviceName, _ string) (string, error) {
	unitName := serviceName + ".service"
	out, err := b.run("systemctl", "restart", unitName)
	if err != nil {
		return "", fmt.Errorf("failed to restart %s: %s (%v)", unitName, strings.TrimSpace(string(out)), err)
	}
	return fmt.Sprintf("Successfully restarted %s.", unitName), nil
}

func (b *systemdBackend) Uninstall(serviceName, targetPath string) (string, error) {
	unitName := serviceName + ".service"
	_, _ = b.run("systemctl", "stop", unitName)
	_, _ = b.run("systemctl", "disable", unitName)

	unitPath := targetPath
	if unitPath == "" {
		unitPath = "/etc/systemd/system/" + unitName
	}
	if _, err := os.Stat(unitPath); err == nil {
		if err := os.Remove(unitPath); err != nil {
			return "", fmt.Errorf("failed to remove unit file %s: %w", unitPath, err)
		}
	}
	_, _ = b.run("systemctl", "daemon-reload")
	return fmt.Sprintf("Successfully uninstalled %s (removed %s).", unitName, unitPath), nil
}

func (b *systemdBackend) Status(serviceName, _ string) (string, error) {
	unitName := serviceName + ".service"
	out, _ := b.run("systemctl", "status", unitName)
	if len(out) > 0 {
		return string(out), nil
	}
	return fmt.Sprintf("● %s (Linux systemd)\n   State: Not active or not installed\n", unitName), nil
}
