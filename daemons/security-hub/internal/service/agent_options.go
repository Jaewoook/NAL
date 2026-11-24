package service

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// AgentServiceOptions defines metadata used to render agent service files or plists.
type AgentServiceOptions struct {
	BinaryPath      string
	WorkingDir      string
	Name            string
	Host            string
	Port            int
	Token           string
	EnvironmentFile string
	HubURL          string
	AdvertiseURL    string
	CustomPath      string
	User            string
	IsUser          bool
}

var validPOSIXUserRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}\$?$`)

// ValidateAgentServiceOptions rejects newline/control-char directive injection and invalid service users.
func ValidateAgentServiceOptions(opts AgentServiceOptions) error {
	checks := []struct {
		name string
		val  string
	}{
		{"BinaryPath", opts.BinaryPath},
		{"WorkingDir", opts.WorkingDir},
		{"Name", opts.Name},
		{"Host", opts.Host},
		{"Token", opts.Token},
		{"EnvironmentFile", opts.EnvironmentFile},
		{"HubURL", opts.HubURL},
		{"AdvertiseURL", opts.AdvertiseURL},
		{"CustomPath", opts.CustomPath},
		{"User", opts.User},
	}
	for _, c := range checks {
		if err := validateNoControlChars(c.name, c.val); err != nil {
			return err
		}
	}
	if opts.User != "" && !validPOSIXUserRe.MatchString(opts.User) {
		return fmt.Errorf("invalid systemd User %q", opts.User)
	}
	return nil
}

// AgentServiceManager provides method-based dispatch for agent daemon service operations.
type AgentServiceManager struct{}

// AgentService is the singleton instance of AgentServiceManager.
var AgentService = AgentServiceManager{}

func (AgentServiceManager) Install(opts AgentServiceOptions) error { return InstallAgent(opts) }
func (AgentServiceManager) Uninstall() error                       { return UninstallAgent() }
func (AgentServiceManager) Start() error                           { return StartAgent() }
func (AgentServiceManager) Stop() error                            { return StopAgent() }
func (AgentServiceManager) Restart() error                         { return RestartAgent() }
func (AgentServiceManager) Status() (string, error)                { return StatusAgent() }
func (AgentServiceManager) GenerateLaunchdPlist(opts AgentServiceOptions) string {
	return GenerateAgentLaunchdPlist(opts)
}
func (AgentServiceManager) GenerateSystemdUnit(opts AgentServiceOptions) string {
	return GenerateAgentSystemdUnit(opts)
}

func resolveAbsPathOrDefault(val string, lookup func() (string, error), fallback string) string {
	if val == "" {
		resolved, err := lookup()
		if err != nil {
			return fallback
		}
		val = resolved
	}
	if abs, err := filepath.Abs(val); err == nil {
		return abs
	}
	return val
}

func applyAgentDefaults(opts AgentServiceOptions) AgentServiceOptions {
	opts.BinaryPath = resolveAbsPathOrDefault(opts.BinaryPath, os.Executable, "/usr/local/bin/security-hub")
	opts.WorkingDir = resolveAbsPathOrDefault(opts.WorkingDir, os.Getwd, "/tmp")
	if opts.Host == "" {
		opts.Host = "0.0.0.0"
	}
	if opts.Port <= 0 {
		opts.Port = 10247
	}
	return opts
}

// buildAgentArgs emits non-secret agent flags for process invocation.
// Secrets like AgentToken are deliberately kept out of CLI arguments to avoid exposure in ps / /proc/pid/cmdline.
func buildAgentArgs(opts AgentServiceOptions) []string {
	var args []string
	if opts.Host != "" {
		args = append(args, "-host", stripControlChars(opts.Host))
	}
	if opts.Port > 0 {
		args = append(args, "-port", strconv.Itoa(opts.Port))
	}
	if opts.HubURL != "" {
		args = append(args, "-hub", stripControlChars(opts.HubURL))
	}
	if opts.Name != "" {
		args = append(args, "-name", stripControlChars(opts.Name))
	}
	if opts.AdvertiseURL != "" {
		args = append(args, "-advertise-url", stripControlChars(opts.AdvertiseURL))
	}
	return args
}
