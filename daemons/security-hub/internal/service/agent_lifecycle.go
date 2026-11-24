package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jaewoook/security-hub/internal/fsutil"
)

func systemdEnvPathForUnit(unitPath string) string {
	if strings.Contains(unitPath, ".config/systemd/user") {
		return filepath.Join(filepath.Dir(unitPath), "security-hub-agent.env")
	}
	return "/etc/security-hub/agent.env"
}

func runSystemctl(isUser bool, args ...string) ([]byte, error) {
	if isUser {
		args = append([]string{"--user"}, args...)
	}
	return cmdRunner("systemctl", args...)
}

func isSystemdNotLoaded(err error, out string) bool {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) && coded.ExitCode() == 5 {
		return true
	}
	lower := strings.ToLower(out)
	return strings.Contains(lower, "not loaded") ||
		strings.Contains(lower, "could not be found") ||
		strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "does not exist")
}

func isKnownSystemdState(st string) bool {
	switch st {
	case "inactive", "failed", "deactivating", "activating", "reloading", "unknown", "maintenance", "not-found":
		return true
	default:
		return false
	}
}

func writeSystemdTokenEnvFile(envPath, token string) error {
	if err := os.MkdirAll(filepath.Dir(envPath), 0700); err != nil {
		return err
	}
	line := formatSystemdEnvLine("SECURITY_HUB_AGENT_TOKEN", token)
	return fsutil.WriteFileAtomic(envPath, []byte(line), 0600)
}

// InstallAgent installs the agent service file for the current OS using restricted 0600 permissions.
func InstallAgent(opts AgentServiceOptions) error {
	if err := ValidateAgentServiceOptions(opts); err != nil {
		return err
	}
	opts = applyAgentDefaults(opts)

	targetOS := runtime.GOOS
	if opts.CustomPath != "" {
		if err := os.MkdirAll(filepath.Dir(opts.CustomPath), 0755); err != nil {
			return err
		}
		var content string
		if strings.HasSuffix(opts.CustomPath, ".plist") || (targetOS == "darwin" && !strings.HasSuffix(opts.CustomPath, ".service")) {
			content = GenerateAgentLaunchdPlist(opts)
		} else {
			if strings.Contains(opts.CustomPath, ".config/systemd/user") || strings.Contains(opts.CustomPath, "/user/") {
				opts.IsUser = true
			}
			if opts.Token != "" && opts.EnvironmentFile == "" {
				envPath := opts.CustomPath + ".env"
				if err := writeSystemdTokenEnvFile(envPath, opts.Token); err != nil {
					return err
				}
				opts.EnvironmentFile = envPath
			}
			content = GenerateAgentSystemdUnit(opts)
		}
		return fsutil.WriteFileAtomic(opts.CustomPath, []byte(content), 0600)
	}

	switch targetOS {
	case "darwin":
		destPath := DefaultAgentPlistPath()
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}
		content := GenerateAgentLaunchdPlist(opts)
		return fsutil.WriteFileAtomic(destPath, []byte(content), 0600)

	case "linux":
		destPath := DefaultAgentSystemdPath()
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}
		isUser := strings.Contains(destPath, ".config/systemd/user")
		opts.IsUser = isUser
		if opts.Token != "" && opts.EnvironmentFile == "" {
			envPath := systemdEnvPathForUnit(destPath)
			if err := writeSystemdTokenEnvFile(envPath, opts.Token); err != nil {
				return err
			}
			opts.EnvironmentFile = envPath
		}
		content := GenerateAgentSystemdUnit(opts)
		if err := fsutil.WriteFileAtomic(destPath, []byte(content), 0600); err != nil {
			return err
		}
		if _, lErr := exec.LookPath("systemctl"); lErr == nil {
			if out, err := runSystemctl(isUser, "daemon-reload"); err != nil {
				return fmt.Errorf("systemctl daemon-reload failed: %w (%s)", err, strings.TrimSpace(string(out)))
			}
			if out, err := runSystemctl(isUser, "enable", AgentSystemdUnit); err != nil {
				return fmt.Errorf("systemctl enable failed: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported operating system %q for agent service installation", targetOS)
	}
}

// UninstallAgent uninstalls and removes the agent daemon service.
func UninstallAgent() error {
	switch runtime.GOOS {
	case "darwin":
		plist := DefaultAgentPlistPath()
		if err := stopLaunchdService(plist, AgentLaunchdLabel); err != nil {
			return err
		}
		if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove launchd plist %s: %w", plist, err)
		}
		return nil

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		_, lookErr := exec.LookPath("systemctl")
		if lookErr == nil {
			if out, err := runSystemctl(isUser, "stop", AgentSystemdUnit); err != nil && !isSystemdNotLoaded(err, string(out)) {
				return fmt.Errorf("systemctl stop failed: %w (%s)", err, strings.TrimSpace(string(out)))
			}
			if out, err := runSystemctl(isUser, "disable", AgentSystemdUnit); err != nil && !isSystemdNotLoaded(err, string(out)) {
				return fmt.Errorf("systemctl disable failed: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove systemd unit %s: %w", unitPath, err)
		}
		envPath := systemdEnvPathForUnit(unitPath)
		if err := os.Remove(envPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove systemd env file %s: %w", envPath, err)
		}
		if lookErr == nil {
			if out, err := runSystemctl(isUser, "daemon-reload"); err != nil {
				return fmt.Errorf("systemctl daemon-reload failed: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}

// StartAgent starts the agent service via launchd (darwin) or systemd (linux).
func StartAgent() error {
	switch runtime.GOOS {
	case "darwin":
		return startLaunchdService(DefaultAgentPlistPath(), AgentLaunchdLabel, "security-hub agent service install")

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		if _, err := os.Stat(unitPath); os.IsNotExist(err) {
			return fmt.Errorf("systemd unit not found at %s; run 'security-hub agent service install' first", unitPath)
		}
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		if out, err := runSystemctl(isUser, "daemon-reload"); err != nil {
			return fmt.Errorf("failed to reload systemd daemon: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		if out, err := runSystemctl(isUser, "enable", "--now", AgentSystemdUnit); err != nil {
			return fmt.Errorf("failed to enable and start agent service: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil

	default:
		return fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}

// StopAgent stops the agent service via launchd (darwin) or systemd (linux).
func StopAgent() error {
	switch runtime.GOOS {
	case "darwin":
		return stopLaunchdService(DefaultAgentPlistPath(), AgentLaunchdLabel)

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		if out, err := runSystemctl(isUser, "stop", AgentSystemdUnit); err != nil && !isSystemdNotLoaded(err, string(out)) {
			return fmt.Errorf("systemctl stop failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil

	default:
		return fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}

// RestartAgent restarts the agent service.
func RestartAgent() error {
	if err := StopAgent(); err != nil {
		return err
	}
	return StartAgent()
}

// StatusAgent reports the current status of the agent service.
func StatusAgent() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return launchdStatus(AgentLaunchdLabel)

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		out, err := runSystemctl(isUser, "is-active", AgentSystemdUnit)
		status := strings.TrimSpace(string(out))
		if err != nil {
			if isKnownSystemdState(status) {
				return status, nil
			}
			return "", fmt.Errorf("systemctl is-active failed: %w (%s)", err, status)
		}
		return status, nil

	default:
		return "", fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}
