package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// ServiceOptions defines metadata used to render service unit files or plists.
type ServiceOptions struct {
	BinaryPath  string
	ConfigPath  string
	User        string
	WorkingDir  string
	ServiceName string
	Description string
}

func applyDefaults(opts ServiceOptions) ServiceOptions {
	if opts.ServiceName == "" {
		opts.ServiceName = "server-monitor"
	}
	if opts.Description == "" {
		opts.Description = "Physical Server Monitor Daemon"
	}
	if opts.BinaryPath == "" {
		if exe, err := os.Executable(); err == nil {
			opts.BinaryPath = exe
		} else {
			opts.BinaryPath = "/usr/local/bin/server-monitor"
		}
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = "/etc/server-monitor/config.yaml"
	}
	if opts.User == "" {
		opts.User = "root"
	}
	return opts
}

const systemdTemplate = `[Unit]
Description={{ .Description }}
After=network.target

[Service]
Type=simple
User={{ .User }}
{{- if .WorkingDir }}
WorkingDirectory={{ .WorkingDir }}
{{- end }}
ExecStart={{ .BinaryPath }} run -config {{ .ConfigPath }}
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`

const launchdTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{ .ServiceName }}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{ .BinaryPath }}</string>
        <string>run</string>
        <string>-config</string>
        <string>{{ .ConfigPath }}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/{{ .ServiceName }}.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/{{ .ServiceName }}.log</string>
</dict>
</plist>
`

// GenerateSystemdUnit generates a systemd service unit string.
func GenerateSystemdUnit(opts ServiceOptions) string {
	opts = applyDefaults(opts)
	tmpl := template.Must(template.New("systemd").Parse(systemdTemplate))
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, opts)
	return buf.String()
}

// GenerateLaunchdPlist generates a macOS launchd plist XML string.
func GenerateLaunchdPlist(opts ServiceOptions) string {
	opts = applyDefaults(opts)
	tmpl := template.Must(template.New("launchd").Parse(launchdTemplate))
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, opts)
	return buf.String()
}

// Generate generates a service configuration string based on the service type.
// Supported types: "systemd", "launchd".
func Generate(serviceType string, opts ServiceOptions) (string, error) {
	switch strings.ToLower(serviceType) {
	case "systemd":
		return GenerateSystemdUnit(opts), nil
	case "launchd":
		return GenerateLaunchdPlist(opts), nil
	default:
		return "", fmt.Errorf("unsupported service type %q (supported: systemd, launchd)", serviceType)
	}
}

// Install writes the generated service definition to the specified target path.
func Install(serviceType string, opts ServiceOptions, targetPath string) error {
	content, err := Generate(serviceType, opts)
	if err != nil {
		return err
	}

	if targetPath == "" {
		return fmt.Errorf("target path cannot be empty")
	}

	// Ensure parent directory exists
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", dir, err)
	}

	if err := os.WriteFile(targetPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write service file %q: %w", targetPath, err)
	}

	return nil
}
