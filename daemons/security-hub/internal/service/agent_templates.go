package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"text/template"
)

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

func quoteSystemdArgIfNonEmpty(s string) string {
	if s == "" {
		return ""
	}
	return quoteSystemdArg(s)
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

// GenerateSystemdUnit is an alias to GenerateAgentSystemdUnit.
func GenerateSystemdUnit(opts AgentServiceOptions) string {
	return GenerateAgentSystemdUnit(opts)
}
