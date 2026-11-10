package service

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
)

// AgentServiceOptions defines metadata used to render agent service files or plists.
type AgentServiceOptions struct {
	BinaryPath   string
	WorkingDir   string
	Name         string
	Host         string
	Port         int
	Token        string
	HubURL       string
	AdvertiseURL string
	CustomPath   string
	User         string
	IsUser       bool
}

// AgentServiceManager provides method-based dispatch for agent daemon service operations.
type AgentServiceManager struct{}

// AgentService is the singleton instance of AgentServiceManager.
var AgentService = AgentServiceManager{}

func (AgentServiceManager) Install(opts AgentServiceOptions) error { return InstallAgent(opts) }
func (AgentServiceManager) Uninstall() error                      { return UninstallAgent() }
func (AgentServiceManager) Start() error                          { return StartAgent() }
func (AgentServiceManager) Stop() error                           { return StopAgent() }
func (AgentServiceManager) Restart() error                        { return RestartAgent() }
func (AgentServiceManager) Status() (string, error)               { return StatusAgent() }
func (AgentServiceManager) GenerateLaunchdPlist(opts AgentServiceOptions) string {
	return GenerateAgentLaunchdPlist(opts)
}
func (AgentServiceManager) GenerateSystemdUnit(opts AgentServiceOptions) string {
	return GenerateAgentSystemdUnit(opts)
}

func applyAgentDefaults(opts AgentServiceOptions) AgentServiceOptions {
	if opts.BinaryPath == "" {
		if exe, err := os.Executable(); err == nil {
			if abs, err := filepath.Abs(exe); err == nil {
				opts.BinaryPath = abs
			} else {
				opts.BinaryPath = exe
			}
		} else {
			opts.BinaryPath = "/usr/local/bin/security-hub"
		}
	} else {
		if abs, err := filepath.Abs(opts.BinaryPath); err == nil {
			opts.BinaryPath = abs
		}
	}

	if opts.WorkingDir == "" {
		if wd, err := os.Getwd(); err == nil {
			if abs, err := filepath.Abs(wd); err == nil {
				opts.WorkingDir = abs
			} else {
				opts.WorkingDir = wd
			}
		} else {
			opts.WorkingDir = "/tmp"
		}
	} else {
		if abs, err := filepath.Abs(opts.WorkingDir); err == nil {
			opts.WorkingDir = abs
		}
	}

	if opts.Host == "" {
		opts.Host = "0.0.0.0"
	}
	if opts.Port <= 0 {
		opts.Port = 10247
	}
	return opts
}

func buildAgentArgs(opts AgentServiceOptions) []string {
	var args []string
	if opts.Host != "" {
		args = append(args, "-host", opts.Host)
	}
	if opts.Port > 0 {
		args = append(args, "-port", strconv.Itoa(opts.Port))
	}
	if opts.Token != "" {
		args = append(args, "-token", opts.Token)
	}
	if opts.HubURL != "" {
		args = append(args, "-hub", opts.HubURL)
	}
	if opts.Name != "" {
		args = append(args, "-name", opts.Name)
	}
	if opts.AdvertiseURL != "" {
		args = append(args, "-advertise-url", opts.AdvertiseURL)
	}
	return args
}

const agentLaunchdTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{ .Label }}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{ .BinaryPath }}</string>
        <string>agent</string>
{{- range .Args }}
        <string>{{ . }}</string>
{{- end }}
    </array>
    <key>WorkingDirectory</key>
    <string>{{ .WorkingDir }}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{ .WorkingDir }}/security-hub-agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{{ .WorkingDir }}/security-hub-agent.stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
`

// GenerateAgentLaunchdPlist renders a launchd plist for the Security Hub agent.
func GenerateAgentLaunchdPlist(opts AgentServiceOptions) string {
	opts = applyAgentDefaults(opts)
	data := struct {
		Label      string
		BinaryPath string
		WorkingDir string
		Args       []string
	}{
		Label:      AgentLaunchdLabel,
		BinaryPath: opts.BinaryPath,
		WorkingDir: opts.WorkingDir,
		Args:       buildAgentArgs(opts),
	}

	tmpl := template.Must(template.New("agent-launchd").Parse(agentLaunchdTemplate))
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, data)
	return buf.String()
}

const agentSystemdTemplate = `[Unit]
Description=NAL Security Hub Agent Daemon
After=network.target

[Service]
Type=simple
{{- if .User }}
User={{ .User }}
{{- end }}
WorkingDirectory={{ .WorkingDir }}
ExecStart={{ .BinaryPath }} agent{{ range .Args }} {{ . }}{{ end }}
Restart=always
RestartSec=5s
Environment=PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

[Install]
{{- if .IsUser }}
WantedBy=default.target
{{- else }}
WantedBy=multi-user.target
{{- end }}
`

// quoteSystemdArg wraps an argument in double quotes and escapes backslashes and double quotes
// if it contains whitespace, quotes, or is empty, ensuring safe word splitting by systemd ExecStart.
func quoteSystemdArg(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\n\r\"'") {
		escaped := strings.ReplaceAll(s, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		return `"` + escaped + `"`
	}
	return s
}

// GenerateAgentSystemdUnit renders a systemd service unit for the Security Hub agent.
func GenerateAgentSystemdUnit(opts AgentServiceOptions) string {
	opts = applyAgentDefaults(opts)
	rawArgs := buildAgentArgs(opts)
	quotedArgs := make([]string, len(rawArgs))
	for i, arg := range rawArgs {
		quotedArgs[i] = quoteSystemdArg(arg)
	}

	data := struct {
		BinaryPath string
		WorkingDir string
		User       string
		Args       []string
		IsUser     bool
	}{
		BinaryPath: quoteSystemdArg(opts.BinaryPath),
		WorkingDir: opts.WorkingDir,
		User:       opts.User,
		Args:       quotedArgs,
		IsUser:     opts.IsUser,
	}

	tmpl := template.Must(template.New("agent-systemd").Parse(agentSystemdTemplate))
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, data)
	return buf.String()
}

// GenerateSystemdUnit is an alias to GenerateAgentSystemdUnit.
func GenerateSystemdUnit(opts AgentServiceOptions) string {
	return GenerateAgentSystemdUnit(opts)
}

// InstallAgent installs the agent service file for the current OS.
func InstallAgent(opts AgentServiceOptions) error {
	opts = applyAgentDefaults(opts)

	targetOS := runtime.GOOS
	if opts.CustomPath != "" {
		if err := os.MkdirAll(filepath.Dir(opts.CustomPath), 0755); err != nil {
			return err
		}
		var content string
		if targetOS == "darwin" || strings.HasSuffix(opts.CustomPath, ".plist") {
			content = GenerateAgentLaunchdPlist(opts)
		} else {
			if strings.Contains(opts.CustomPath, ".config/systemd/user") || strings.Contains(opts.CustomPath, "/user/") {
				opts.IsUser = true
			}
			content = GenerateAgentSystemdUnit(opts)
		}
		return os.WriteFile(opts.CustomPath, []byte(content), 0644)
	}

	switch targetOS {
	case "darwin":
		destPath := DefaultAgentPlistPath()
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}
		content := GenerateAgentLaunchdPlist(opts)
		return os.WriteFile(destPath, []byte(content), 0644)

	case "linux":
		destPath := DefaultAgentSystemdPath()
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}
		isUser := strings.Contains(destPath, ".config/systemd/user")
		opts.IsUser = isUser
		content := GenerateAgentSystemdUnit(opts)
		if err := os.WriteFile(destPath, []byte(content), 0644); err != nil {
			return err
		}
		sysArgs := []string{"systemctl"}
		if isUser {
			sysArgs = append(sysArgs, "--user")
		}
		_ = exec.Command(sysArgs[0], append(sysArgs[1:], "daemon-reload")...).Run()
		_ = exec.Command(sysArgs[0], append(sysArgs[1:], "enable", AgentSystemdUnit)...).Run()
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
		_ = exec.Command("launchctl", "unload", "-w", plist).Run()
		if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove launchd plist %s: %w", plist, err)
		}
		return nil

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		sysArgs := []string{"systemctl"}
		if isUser {
			sysArgs = append(sysArgs, "--user")
		}
		_ = exec.Command(sysArgs[0], append(sysArgs[1:], "stop", AgentSystemdUnit)...).Run()
		_ = exec.Command(sysArgs[0], append(sysArgs[1:], "disable", AgentSystemdUnit)...).Run()
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove systemd unit %s: %w", unitPath, err)
		}
		_ = exec.Command(sysArgs[0], append(sysArgs[1:], "daemon-reload")...).Run()
		return nil

	default:
		return fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}

// StartAgent starts the agent service via launchd (darwin) or systemd (linux).
func StartAgent() error {
	switch runtime.GOOS {
	case "darwin":
		plist := DefaultAgentPlistPath()
		if _, err := os.Stat(plist); os.IsNotExist(err) {
			return fmt.Errorf("launchd plist not found at %s; run 'security-hub agent service install' first", plist)
		}
		_ = exec.Command("launchctl", "unload", "-w", plist).Run()
		if err := exec.Command("launchctl", "load", "-w", plist).Run(); err != nil {
			return fmt.Errorf("failed to load launchd agent service: %w", err)
		}
		return exec.Command("launchctl", "start", AgentLaunchdLabel).Run()

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		if _, err := os.Stat(unitPath); os.IsNotExist(err) {
			return fmt.Errorf("systemd unit not found at %s; run 'security-hub agent service install' first", unitPath)
		}
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		sysArgs := []string{"systemctl"}
		if isUser {
			sysArgs = append(sysArgs, "--user")
		}
		if err := exec.Command(sysArgs[0], append(sysArgs[1:], "daemon-reload")...).Run(); err != nil {
			return fmt.Errorf("failed to reload systemd daemon: %w", err)
		}
		if err := exec.Command(sysArgs[0], append(sysArgs[1:], "enable", "--now", AgentSystemdUnit)...).Run(); err != nil {
			return fmt.Errorf("failed to enable and start agent service: %w", err)
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
		plist := DefaultAgentPlistPath()
		if _, err := os.Stat(plist); err == nil {
			_ = exec.Command("launchctl", "unload", "-w", plist).Run()
		}
		_ = exec.Command("launchctl", "stop", AgentLaunchdLabel).Run()
		return nil

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		sysArgs := []string{"systemctl"}
		if isUser {
			sysArgs = append(sysArgs, "--user")
		}
		return exec.Command(sysArgs[0], append(sysArgs[1:], "stop", AgentSystemdUnit)...).Run()

	default:
		return fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}

// RestartAgent restarts the agent service.
func RestartAgent() error {
	_ = StopAgent()
	return StartAgent()
}

// StatusAgent reports the current status of the agent service.
func StatusAgent() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("launchctl", "list").CombinedOutput()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, AgentLaunchdLabel) {
				return strings.TrimSpace(line), nil
			}
		}
		return "not running / not loaded", nil

	case "linux":
		unitPath := DefaultAgentSystemdPath()
		isUser := strings.Contains(unitPath, ".config/systemd/user")
		sysArgs := []string{"systemctl"}
		if isUser {
			sysArgs = append(sysArgs, "--user")
		}
		out, err := exec.Command(sysArgs[0], append(sysArgs[1:], "status", AgentSystemdUnit)...).CombinedOutput()
		trimmed := strings.TrimSpace(string(out))
		if err != nil {
			if trimmed == "" {
				return "inactive / not loaded", nil
			}
			return trimmed, nil
		}
		return trimmed, nil

	default:
		return "", fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}
