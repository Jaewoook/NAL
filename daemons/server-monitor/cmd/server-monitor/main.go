package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/version"
)

const usageText = `Usage: server-monitor <command> [options]

Commands:
  check        Run a single point-in-time health check and print formatted metrics
  test-alert   Send a test notification to verify channel credentials and connectivity
  run          Start the continuous background monitoring daemon
  service      Manage OS background service lifecycle
  version      Print the build version of this binary
  help         Display this help message

Options for check:
  -config string   Path to configuration file (default "config.yml")

Options for test-alert:
  -config string   Path to configuration file (default "config.yml")
  -channel string  Specific notification channel to test (e.g. telegram, discord, webhook)

Options for run:
  -config string   Path to configuration file (default "config.yml")

Service Subcommands:
  service status       Display current running state, PID, uptime, and memory
  service start        Start the installed background service
  service stop         Stop the background service (sends graceful shutdown notification)
  service restart      Restart the background service
  service install      Generate and install service definition (systemd or launchd)
  service uninstall    Stop and remove service definition from system

Options for service install:
  -type string     Service manager type: systemd or launchd (defaults to OS native)
  -path string     File destination to write service unit/plist (defaults to stdout)
  -config string   Configuration path to embed in service definition
  -bin string      Binary path to embed in service definition
  -user string     User to run service as
  -workdir string  Working directory for service
`

func resolveConfig(configPath string) (*config.Config, error) {
	if configPath != "" {
		return config.LoadConfig(configPath)
	}
	for _, candidate := range config.DefaultConfigFilenames {
		if _, err := os.Stat(candidate); err == nil {
			return config.LoadConfig(candidate)
		}
	}
	return config.DefaultConfigWithEnv(), nil
}

// AppOption configures optional runtime parameters for runApp.
type AppOption func(*appConfig)

type appConfig struct {
	transport http.RoundTripper
	ctx       context.Context
}

// WithHTTPTransport configures a custom HTTP transport for notification dispatchers.
func WithHTTPTransport(rt http.RoundTripper) AppOption {
	return func(a *appConfig) {
		a.transport = rt
	}
}

// WithContext configures a custom context for controlling daemon lifecycle.
func WithContext(ctx context.Context) AppOption {
	return func(a *appConfig) {
		a.ctx = ctx
	}
}

func runApp(args []string, stdout, stderr io.Writer, opts ...AppOption) int {
	var appCfg appConfig
	for _, opt := range opts {
		opt(&appCfg)
	}

	if len(args) == 0 {
		fmt.Fprint(stdout, usageText)
		return 0
	}

	switch cmd := args[0]; cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, version.Current())
		return 0
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "test-alert":
		return runTestAlert(args[1:], stdout, stderr, &appCfg)
	case "run":
		return runDaemon(args[1:], stdout, stderr, &appCfg)
	case "service":
		return runService(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %q. Run 'server-monitor help' for usage.\n", cmd)
		return 1
	}
}

func main() {
	os.Exit(runApp(os.Args[1:], os.Stdout, os.Stderr))
}
