package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jaewoook/server-monitor/internal/collector"
	"github.com/jaewoook/server-monitor/internal/config"
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
	c.SetCPUSampleInterval(200 * time.Millisecond)
	metrics, err := c.Collect()
	if err != nil {
		fmt.Fprintf(stderr, "failed to collect metrics: %v\n", err)
		return 1
	}

	events := detector.New(cfg).Evaluate(metrics)
	printHealthReport(stdout, cfg, metrics, events)
	return 0
}

func printHealthReport(w io.Writer, cfg *config.Config, metrics *models.SystemMetrics, events []models.RawConditionEvent) {
	fmt.Fprintln(w, "=== Server Monitor: System Health Check ===")
	fmt.Fprintf(w, "Server:    %s\n", cfg.Server.Name)
	fmt.Fprintf(w, "Timestamp: %s\n", metrics.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "Uptime:    %s\n\n", models.FormatUptime(metrics.UptimeSeconds))

	fmt.Fprintln(w, "[System Metrics]")
	fmt.Fprintf(w, "  CPU Utilization:    %.1f%%\n", metrics.CPUPercent)
	if metrics.HasCPUTemp {
		fmt.Fprintf(w, "  CPU Temperature:    %.1f°C\n", metrics.CPUTempCelsius)
	}
	if metrics.HasGPUTemp {
		fmt.Fprintf(w, "  GPU Temperature:    %.1f°C\n", metrics.GPUTempCelsius)
	}
	fmt.Fprintf(w, "  Memory Utilization: %.1f%%\n", metrics.MemoryPercent)
	fmt.Fprintf(w, "  Disk Utilization:   %.1f%% (%s)\n", metrics.DiskPercent, cfg.Health.Disk.MountPoint)
	fmt.Fprintf(w, "  Load Averages:      %.2f (1m), %.2f (5m), %.2f (15m)\n\n", metrics.Load1, metrics.Load5, metrics.Load15)

	if table := models.FormatProcessesTable(metrics.TopProcesses); table != "" {
		fmt.Fprintln(w, "[Top Processes by CPU]")
		for _, line := range strings.Split(table, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "[Rule Evaluations]")
	if len(events) == 0 {
		fmt.Fprintln(w, "  Status: OK (no alerts triggered)")
		return
	}
	for _, ev := range events {
		fmt.Fprintf(w, "  [TRIGGERED] %s: %s\n", ev.RuleName, ev.Message)
	}
}
