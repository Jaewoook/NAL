package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jaewoook/server-monitor/internal/collector"
	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/daemon"
	"github.com/jaewoook/server-monitor/internal/detector"
	"github.com/jaewoook/server-monitor/internal/digest"
	"github.com/jaewoook/server-monitor/internal/models"
	"github.com/jaewoook/server-monitor/internal/notifier"
	"github.com/jaewoook/server-monitor/internal/service"
)

const usageText = `Usage: server-monitor <command> [options]

Commands:
  check        Run a single point-in-time health check and print formatted metrics
  test-alert   Send a test notification to verify channel credentials and connectivity
  run          Start the continuous background monitoring daemon
  service      Manage OS background service definitions
  help         Display this help message

Options for check:
  -config string   Path to configuration file (default "config.yaml")

Options for test-alert:
  -config string   Path to configuration file (default "config.yaml")
  -channel string  Specific notification channel to test (e.g. telegram, discord, webhook)

Options for run:
  -config string   Path to configuration file (default "config.yaml")

Options for service install:
  -type string     Service manager type: systemd or launchd (defaults to OS native)
  -path string     File destination to write service unit/plist (defaults to stdout)
  -config string   Configuration path to embed in service definition
  -bin string      Binary path to embed in service definition
`

func resolveConfig(configPath string) (*config.Config, error) {
	if configPath != "" {
		return config.LoadConfig(configPath)
	}
	defaultPath := "config.yaml"
	if _, err := os.Stat(defaultPath); err == nil {
		return config.LoadConfig(defaultPath)
	}
	return config.DefaultConfigWithEnv(), nil
}

// AppOption configures optional runtime parameters for runApp.
type AppOption func(*appConfig)

type appConfig struct {
	transport http.RoundTripper
}

// WithHTTPTransport configures a custom HTTP transport for notification dispatchers.
func WithHTTPTransport(rt http.RoundTripper) AppOption {
	return func(a *appConfig) {
		a.transport = rt
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

	cmd := args[0]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0

	case "check":
		fs := flag.NewFlagSet("check", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "", "Path to configuration file")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}

		cfg, err := resolveConfig(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "failed to load configuration: %v\n", err)
			return 1
		}

		c := collector.New(cfg.CPU.TopProcessesCount, cfg.Health.Disk.MountPoint)
		metrics, err := c.Collect()
		if err != nil {
			fmt.Fprintf(stderr, "failed to collect metrics: %v\n", err)
			return 1
		}

		det := detector.New(cfg)
		events := det.Evaluate(metrics)

		fmt.Fprintln(stdout, "=== Server Monitor: System Health Check ===")
		fmt.Fprintf(stdout, "Server:    %s\n", cfg.Server.Name)
		fmt.Fprintf(stdout, "Timestamp: %s\n", metrics.Timestamp.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(stdout, "Uptime:    %s\n\n", digest.FormatUptime(metrics.UptimeSeconds))

		fmt.Fprintln(stdout, "[System Metrics]")
		fmt.Fprintf(stdout, "  CPU Utilization:    %.1f%%\n", metrics.CPUPercent)
		fmt.Fprintf(stdout, "  Memory Utilization: %.1f%%\n", metrics.MemoryPercent)
		fmt.Fprintf(stdout, "  Disk Utilization:   %.1f%% (%s)\n", metrics.DiskPercent, cfg.Health.Disk.MountPoint)
		fmt.Fprintf(stdout, "  Load Averages:      %.2f (1m), %.2f (5m), %.2f (15m)\n\n", metrics.Load1, metrics.Load5, metrics.Load15)

		if len(metrics.TopProcesses) > 0 {
			fmt.Fprintln(stdout, "[Top Processes by CPU]")
			fmt.Fprintf(stdout, "  %-7s %-16s %-8s %-8s\n", "PID", "NAME", "CPU%", "MEM%")
			for _, p := range metrics.TopProcesses {
				name := p.Name
				runes := []rune(name)
				if len(runes) > 16 {
					name = string(runes[:13]) + "..."
				}
				cpuStr := fmt.Sprintf("%.1f%%", p.CPUPercent)
				memStr := fmt.Sprintf("%.1f%%", p.MemoryPercent)
				fmt.Fprintf(stdout, "  %-7d %-16s %-8s %-8s\n", p.PID, name, cpuStr, memStr)
			}
			fmt.Fprintln(stdout)
		}

		fmt.Fprintln(stdout, "[Rule Evaluations]")
		if len(events) == 0 {
			fmt.Fprintln(stdout, "  Status: OK (no alerts triggered)")
		} else {
			for _, ev := range events {
				fmt.Fprintf(stdout, "  [TRIGGERED] %s: %s\n", ev.RuleName, ev.Message)
			}
		}
		return 0

	case "test-alert":
		fs := flag.NewFlagSet("test-alert", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "", "Path to configuration file")
		channelName := fs.String("channel", "", "Specific notification channel to test")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}

		cfg, err := resolveConfig(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "failed to load configuration: %v\n", err)
			return 1
		}

		var dispOpts []notifier.DispatcherOption
		if appCfg.transport != nil {
			dispOpts = append(dispOpts, notifier.WithTransport(appCfg.transport))
		}
		disp := notifier.NewDispatcherFromConfig(&cfg.Notifications, dispOpts...)

		if *channelName != "" {
			var matched notifier.Channel
			for _, ch := range disp.Channels() {
				if strings.EqualFold(ch.Name(), *channelName) {
					matched = ch
					break
				}
			}
			if matched == nil {
				fmt.Fprintf(stderr, "channel %q is not enabled or not recognized in configuration\n", *channelName)
				return 1
			}
			disp = notifier.NewDispatcher(matched)
		} else {
			if len(disp.Channels()) == 0 {
				fmt.Fprintln(stderr, "no notification channels are enabled in configuration")
				return 1
			}
		}

		channelNames := make([]string, 0, len(disp.Channels()))
		for _, ch := range disp.Channels() {
			channelNames = append(channelNames, ch.Name())
		}

		testAlert := &models.Alert{
			Title:        "Server Monitor: Test Alert",
			Message:      fmt.Sprintf("This is a test notification from %s to verify channel connectivity.", cfg.Server.Name),
			Level:        models.AlertLevelInfo,
			MetricName:   "Test",
			CurrentValue: 0,
			Timestamp:    time.Now(),
			Hostname:     cfg.Server.Name,
		}

		errs := disp.Dispatch(testAlert)
		if len(errs) > 0 {
			for name, dispatchErr := range errs {
				fmt.Fprintf(stderr, "failed to dispatch alert to %s: %v\n", name, dispatchErr)
			}
			return 1
		}

		fmt.Fprintf(stdout, "Test alert successfully sent to: %s\n", strings.Join(channelNames, ", "))
		return 0

	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "", "Path to configuration file")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}

		cfg, err := resolveConfig(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "failed to load configuration: %v\n", err)
			return 1
		}

		d, err := daemon.New(cfg)
		if err != nil {
			fmt.Fprintf(stderr, "failed to initialize daemon: %v\n", err)
			return 1
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		if err := d.Run(ctx); err != nil {
			fmt.Fprintf(stderr, "daemon exited with error: %v\n", err)
			return 1
		}
		return 0

	case "service":
		if len(args) < 2 || args[1] != "install" {
			fmt.Fprintln(stderr, "usage: server-monitor service install [-type systemd|launchd] [-path PATH]")
			return 1
		}

		fs := flag.NewFlagSet("service install", flag.ContinueOnError)
		fs.SetOutput(stderr)
		serviceType := fs.String("type", "", "Service manager type: systemd or launchd")
		targetPath := fs.String("path", "", "Destination path to write service file")
		cfgPath := fs.String("config", "", "Path to config file for service")
		binPath := fs.String("bin", "", "Path to executable binary for service")
		if err := fs.Parse(args[2:]); err != nil {
			return 1
		}

		resolvedType := *serviceType
		if resolvedType == "" {
			if runtime.GOOS == "darwin" {
				resolvedType = "launchd"
			} else {
				resolvedType = "systemd"
			}
		}

		opts := service.ServiceOptions{
			BinaryPath: *binPath,
			ConfigPath: *cfgPath,
		}

		if *targetPath != "" && *targetPath != "-" {
			if err := service.Install(resolvedType, opts, *targetPath); err != nil {
				fmt.Fprintf(stderr, "failed to install service: %v\n", err)
				return 1
			}
			fmt.Fprintf(stdout, "Successfully installed %s service to %s\n", resolvedType, *targetPath)
			return 0
		}

		content, err := service.Generate(resolvedType, opts)
		if err != nil {
			fmt.Fprintf(stderr, "failed to generate service: %v\n", err)
			return 1
		}
		fmt.Fprint(stdout, content)
		return 0

	default:
		fmt.Fprintf(stderr, "unknown command: %q. Run 'server-monitor help' for usage.\n", cmd)
		return 1
	}
}

func main() {
	os.Exit(runApp(os.Args[1:], os.Stdout, os.Stderr))
}
