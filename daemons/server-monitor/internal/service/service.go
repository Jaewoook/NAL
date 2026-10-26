package service

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
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
	LogDir      string
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
			if absExe, err := filepath.Abs(exe); err == nil {
				opts.BinaryPath = absExe
			} else {
				opts.BinaryPath = exe
			}
		} else {
			opts.BinaryPath = "/usr/local/bin/server-monitor"
		}
	} else {
		if absExe, err := filepath.Abs(opts.BinaryPath); err == nil {
			opts.BinaryPath = absExe
		}
	}

	// 1. Resolve ConfigPath if not specified
	if opts.ConfigPath == "" {
		// Look for config.yml or config.yaml in current working directory
		for _, name := range []string{"config.yml", "config.yaml"} {
			if _, err := os.Stat(name); err == nil {
				if abs, err := filepath.Abs(name); err == nil {
					opts.ConfigPath = abs
					break
				}
			}
		}
		// If still not found, look adjacent to the binary
		if opts.ConfigPath == "" && opts.BinaryPath != "" {
			binDir := filepath.Dir(opts.BinaryPath)
			for _, name := range []string{"config.yml", "config.yaml"} {
				cand := filepath.Join(binDir, name)
				if _, err := os.Stat(cand); err == nil {
					opts.ConfigPath = cand
					break
				}
			}
		}
		// OS-specific fallbacks
		if opts.ConfigPath == "" {
			if runtime.GOOS == "darwin" {
				if home, err := os.UserHomeDir(); err == nil && home != "" {
					opts.ConfigPath = filepath.Join(home, ".config", opts.ServiceName, "config.yml")
				} else {
					opts.ConfigPath = "/etc/server-monitor/config.yml"
				}
			} else {
				opts.ConfigPath = "/etc/server-monitor/config.yml"
			}
		}
	} else {
		if abs, err := filepath.Abs(opts.ConfigPath); err == nil {
			opts.ConfigPath = abs
		}
	}

	// 2. Resolve WorkingDir
	if opts.WorkingDir == "" {
		if opts.ConfigPath != "" && filepath.IsAbs(opts.ConfigPath) {
			opts.WorkingDir = filepath.Dir(opts.ConfigPath)
		} else if opts.BinaryPath != "" && filepath.IsAbs(opts.BinaryPath) {
			opts.WorkingDir = filepath.Dir(opts.BinaryPath)
		}
	}

	// 3. Resolve User
	if opts.User == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			opts.User = u.Username
		} else {
			opts.User = "root"
		}
	}

	// 4. Resolve LogDir
	if opts.LogDir == "" {
		if runtime.GOOS == "darwin" {
			isRoot := os.Geteuid() == 0
			if isRoot {
				opts.LogDir = "/var/log"
			} else if home, err := os.UserHomeDir(); err == nil && home != "" {
				opts.LogDir = filepath.Join(home, "Library", "Logs")
			} else {
				opts.LogDir = "/tmp"
			}
		} else {
			opts.LogDir = "/var/log"
		}
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
{{- if .WorkingDir }}
    <key>WorkingDirectory</key>
    <string>{{ .WorkingDir }}</string>
{{- end }}
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>{{ .LogDir }}/{{ .ServiceName }}.err</string>
    <key>StandardOutPath</key>
    <string>{{ .LogDir }}/{{ .ServiceName }}.log</string>
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

// ExpandHome expands a leading ~/ in a path string with the user's home directory.
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~/") || path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// Install writes the generated service definition to the specified target path.
func Install(serviceType string, opts ServiceOptions, targetPath string) error {
	if targetPath == "" {
		return fmt.Errorf("target path cannot be empty")
	}

	targetPath = ExpandHome(targetPath)

	// If installing into a user LaunchAgents directory on macOS, ensure user log directory
	if strings.Contains(targetPath, "Library/LaunchAgents") && opts.LogDir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			opts.LogDir = filepath.Join(home, "Library", "Logs")
		}
	}

	content, err := Generate(serviceType, opts)
	if err != nil {
		return err
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
