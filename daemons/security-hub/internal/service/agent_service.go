package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"text/template"
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
{{- if .Token }}
        <key>SECURITY_HUB_AGENT_TOKEN</key>
        <string>{{ .Token }}</string>
{{- end }}
    </dict>
</dict>
</plist>
`

func escapeXML(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// GenerateAgentLaunchdPlist renders a launchd plist for the Security Hub agent.
func GenerateAgentLaunchdPlist(opts AgentServiceOptions) string {
	opts = applyAgentDefaults(opts)
	rawArgs := buildAgentArgs(opts)
	escapedArgs := make([]string, len(rawArgs))
	for i, a := range rawArgs {
		escapedArgs[i] = escapeXML(a)
	}

	data := struct {
		Label      string
		BinaryPath string
		WorkingDir string
		Args       []string
		Token      string
	}{
		Label:      AgentLaunchdLabel,
		BinaryPath: escapeXML(stripControlChars(opts.BinaryPath)),
		WorkingDir: escapeXML(stripControlChars(opts.WorkingDir)),
		Args:       escapedArgs,
		Token:      escapeXML(stripControlChars(opts.Token)),
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
{{- if .EnvironmentFile }}
EnvironmentFile={{ .EnvironmentFile }}
{{- else if .EnvToken }}
Environment={{ .EnvToken }}
{{- end }}

[Install]
{{- if .IsUser }}
WantedBy=default.target
{{- else }}
WantedBy=multi-user.target
{{- end }}
`

// quoteSystemdArg strips control characters, escapes $ as $$, and wraps arguments
// containing whitespace, quotes, or backslashes in double quotes for systemd directives.
func quoteSystemdArg(s string) string {
	clean := stripControlChars(s)
	escaped := strings.ReplaceAll(clean, "$", "$$")
	if escaped == "" || strings.ContainsAny(escaped, " \t\"'\\") {
		escaped = strings.ReplaceAll(escaped, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		return `"` + escaped + `"`
	}
	return escaped
}

func formatSystemdEnvLine(key, val string) string {
	clean := stripControlChars(val)
	clean = strings.ReplaceAll(clean, `\`, `\\`)
	clean = strings.ReplaceAll(clean, `"`, `\"`)
	return fmt.Sprintf("%s=\"%s\"\n", key, clean)
}

// GenerateAgentSystemdUnit renders a systemd service unit for the Security Hub agent.
func GenerateAgentSystemdUnit(opts AgentServiceOptions) string {
	opts = applyAgentDefaults(opts)
	rawArgs := buildAgentArgs(opts)
	quotedArgs := make([]string, len(rawArgs))
	for i, arg := range rawArgs {
		quotedArgs[i] = quoteSystemdArg(arg)
	}

	user := ""
	if opts.User != "" && validPOSIXUserRe.MatchString(opts.User) {
		user = opts.User
	}

	envToken := ""
	if opts.EnvironmentFile == "" && opts.Token != "" {
		envToken = quoteSystemdArg("SECURITY_HUB_AGENT_TOKEN=" + opts.Token)
	}

	data := struct {
		BinaryPath      string
		WorkingDir      string
		User            string
		Args            []string
		EnvironmentFile string
		EnvToken        string
		IsUser          bool
	}{
		BinaryPath:      quoteSystemdArg(opts.BinaryPath),
		WorkingDir:      quoteSystemdArg(opts.WorkingDir),
		User:            user,
		Args:            quotedArgs,
		EnvironmentFile: quoteSystemdArgIfNonEmpty(opts.EnvironmentFile),
		EnvToken:        envToken,
		IsUser:          opts.IsUser,
	}

	tmpl := template.Must(template.New("agent-systemd").Parse(agentSystemdTemplate))
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, data)
	return buf.String()
}

func quoteSystemdArgIfNonEmpty(s string) string {
	if s == "" {
		return ""
	}
	return quoteSystemdArg(s)
}

// GenerateSystemdUnit is an alias to GenerateAgentSystemdUnit.
func GenerateSystemdUnit(opts AgentServiceOptions) string {
	return GenerateAgentSystemdUnit(opts)
}

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
	return writeFileAtomic(envPath, []byte(line), 0600)
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
		return writeFileAtomic(opts.CustomPath, []byte(content), 0600)
	}

	switch targetOS {
	case "darwin":
		destPath := DefaultAgentPlistPath()
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}
		content := GenerateAgentLaunchdPlist(opts)
		return writeFileAtomic(destPath, []byte(content), 0600)

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
		if err := writeFileAtomic(destPath, []byte(content), 0600); err != nil {
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
