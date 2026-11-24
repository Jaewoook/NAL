package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/jaewoook/server-monitor/internal/collector"
	"github.com/jaewoook/server-monitor/internal/detector"
	"github.com/jaewoook/server-monitor/internal/models"
)

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to configuration file")
	if err := fs.Parse(args); err != nil {
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
	fmt.Fprintf(stdout, "Uptime:    %s\n\n", models.FormatUptime(metrics.UptimeSeconds))

	fmt.Fprintln(stdout, "[System Metrics]")
	fmt.Fprintf(stdout, "  CPU Utilization:    %.1f%%\n", metrics.CPUPercent)
	if metrics.HasCPUTemp {
		fmt.Fprintf(stdout, "  CPU Temperature:    %.1f°C\n", metrics.CPUTempCelsius)
	}
	if metrics.HasGPUTemp {
		fmt.Fprintf(stdout, "  GPU Temperature:    %.1f°C\n", metrics.GPUTempCelsius)
	}
	fmt.Fprintf(stdout, "  Memory Utilization: %.1f%%\n", metrics.MemoryPercent)
	fmt.Fprintf(stdout, "  Disk Utilization:   %.1f%% (%s)\n", metrics.DiskPercent, cfg.Health.Disk.MountPoint)
	fmt.Fprintf(stdout, "  Load Averages:      %.2f (1m), %.2f (5m), %.2f (15m)\n\n", metrics.Load1, metrics.Load5, metrics.Load15)

	if table := models.FormatProcessesTable(metrics.TopProcesses); table != "" {
		fmt.Fprintln(stdout, "[Top Processes by CPU]")
		for _, line := range strings.Split(table, "\n") {
			fmt.Fprintf(stdout, "  %s\n", line)
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
}
