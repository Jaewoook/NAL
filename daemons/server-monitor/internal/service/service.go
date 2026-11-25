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

	"github.com/jaewoook/server-monitor/internal/config"
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

var (
	systemdTmpl = template.Must(template.New("systemd").Parse(`[Unit]
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
`))

	launchdTmpl = template.Must(template.New("launchd").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
`))
)

func applyDefaults(opts ServiceOptions) ServiceOptions {
	if opts.ServiceName == "" {
		opts.ServiceName = "server-monitor"
	}
	if opts.Description == "" {
		opts.Description = "Physical Server Monitor Daemon"
	}
	opts.BinaryPath = resolveBinaryPath(opts.BinaryPath)
	opts.ConfigPath = resolveConfigPath(opts.ConfigPath, opts.BinaryPath, opts.ServiceName)
	opts.WorkingDir = resolveWorkingDir(opts.WorkingDir, opts.ConfigPath, opts.BinaryPath)
	opts.User = resolveUser(opts.User)
	opts.LogDir = resolveLogDir(opts.LogDir)
	return opts
}

func resolveBinaryPath(binPath string) string {
	if binPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return "/usr/local/bin/server-monitor"
		}
		if abs, err := filepath.Abs(exe); err == nil {
			return abs
		}
		return exe
	}
	if abs, err := filepath.Abs(binPath); err == nil {
		return abs
	}
	return binPath
}

func findExistingConfig(dir string) string {
	for _, name := range config.DefaultConfigFilenames {
		cand := name
		if dir != "" {
			cand = filepath.Join(dir, name)
		}
		if _, err := os.Stat(cand); err == nil {
			if abs, err := filepath.Abs(cand); err == nil {
				return abs
			}
			return cand
		}
	}
	return ""
}

func resolveConfigPath(cfgPath, binPath, serviceName string) string {
	if cfgPath != "" {
		if abs, err := filepath.Abs(cfgPath); err == nil {
			return abs
		}
		return cfgPath
	}
	if found := findExistingConfig(""); found != "" {
		return found
	}
	if binPath != "" {
		if found := findExistingConfig(filepath.Dir(binPath)); found != "" {
			return found
		}
	}
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, ".config", serviceName, "config.yml")
		}
	}
	return "/etc/server-monitor/config.yml"
}

func resolveWorkingDir(workDir, cfgPath, binPath string) string {
	if workDir != "" {
		return workDir
	}
	if cfgPath != "" && filepath.IsAbs(cfgPath) {
		return filepath.Dir(cfgPath)
	}
	if binPath != "" && filepath.IsAbs(binPath) {
		return filepath.Dir(binPath)
	}
	return ""
}

func resolveUser(u string) string {
	if u != "" {
		return u
	}
	if cur, err := user.Current(); err == nil && cur.Username != "" {
		return cur.Username
	}
	return "root"
}

func resolveLogDir(logDir string) string {
	if logDir != "" {
		return logDir
	}
	if runtime.GOOS == "darwin" {
		if os.Geteuid() == 0 {
			return "/var/log"
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "Library", "Logs")
		}
		return "/tmp"
	}
	return "/var/log"
}

// GenerateSystemdUnit generates a systemd service unit string.
func GenerateSystemdUnit(opts ServiceOptions) string {
	opts = applyDefaults(opts)
	var buf bytes.Buffer
	_ = systemdTmpl.Execute(&buf, opts)
	return buf.String()
}

// GenerateLaunchdPlist generates a macOS launchd plist XML string.
func GenerateLaunchdPlist(opts ServiceOptions) string {
	opts = applyDefaults(opts)
	var buf bytes.Buffer
	_ = launchdTmpl.Execute(&buf, opts)
	return buf.String()
}

// ResolveServiceType normalizes a service type or returns the OS-native default.
func ResolveServiceType(serviceType string) string {
	return resolveServiceType(serviceType)
}

// Generate generates a service configuration string based on the service type.
// Supported types: "systemd", "launchd" (empty defaults to OS native).
func Generate(serviceType string, opts ServiceOptions) (string, error) {
	switch resolveServiceType(serviceType) {
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
