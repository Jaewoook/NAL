package collector

import (
	"fmt"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/jaewoook/server-monitor/internal/models"
)

// Collector handles gathering point-in-time system telemetry and resource utilization.
type Collector struct {
	topProcCount          int
	diskMount             string
	lazyTopProcThreshold  float64
}

// New creates a new Collector instance.
func New(topProcCount int, diskMount string) *Collector {
	if diskMount == "" {
		diskMount = "/"
	}
	return &Collector{
		topProcCount: topProcCount,
		diskMount:    diskMount,
	}
}

// SetLazyTopProcessesThreshold configures a minimum CPU percent required before
// Collect() will perform a full process table scan. If 0 (default), top processes
// are collected eagerly whenever topProcCount > 0.
func (c *Collector) SetLazyTopProcessesThreshold(threshold float64) {
	c.lazyTopProcThreshold = threshold
}

// PopulateTopProcesses scans top processes on-demand and attaches them to m
// if not already present.
func (c *Collector) PopulateTopProcesses(m *models.SystemMetrics) {
	if m == nil || c.topProcCount <= 0 || len(m.TopProcesses) > 0 {
		return
	}
	m.TopProcesses = c.collectTopProcesses()
}

// Collect gathers current system metrics including CPU, memory, disk, load averages,
// uptime, and top CPU consuming processes.
func (c *Collector) Collect() (*models.SystemMetrics, error) {
	metrics := &models.SystemMetrics{
		Timestamp: time.Now(),
	}

	// 1. CPU Percent (aggregate across all cores)
	cpuPercents, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercents) > 0 {
		metrics.CPUPercent = cpuPercents[0]
	}

	// 2. Virtual Memory
	vmem, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to collect virtual memory: %w", err)
	}
	metrics.MemoryPercent = vmem.UsedPercent

	// 3. Disk Usage
	diskUsage, err := disk.Usage(c.diskMount)
	if err != nil {
		return nil, fmt.Errorf("failed to collect disk usage for %q: %w", c.diskMount, err)
	}
	metrics.DiskPercent = diskUsage.UsedPercent

	// 4. Load Averages (defensively handled if unsupported on platform)
	loadStat, err := load.Avg()
	if err == nil && loadStat != nil {
		metrics.Load1 = loadStat.Load1
		metrics.Load5 = loadStat.Load5
		metrics.Load15 = loadStat.Load15
	}

	// 5. Host Uptime
	uptime, err := host.Uptime()
	if err != nil {
		return nil, fmt.Errorf("failed to collect host uptime: %w", err)
	}
	metrics.UptimeSeconds = uptime

	// 6. Top Processes (by CPU utilization)
	// If lazyTopProcThreshold > 0, skip process table scan unless CPU exceeds threshold.
	if c.topProcCount > 0 && (c.lazyTopProcThreshold <= 0 || metrics.CPUPercent >= c.lazyTopProcThreshold) {
		metrics.TopProcesses = c.collectTopProcesses()
	}

	return metrics, nil
}

// collectTopProcesses scans running processes defensively and returns the top N by CPU percent.
func (c *Collector) collectTopProcesses() []models.ProcessInfo {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}

	var procList []models.ProcessInfo
	for _, p := range procs {
		// Processes may terminate or deny access at any point; handle defensively.
		name, err := p.Name()
		if err != nil {
			continue
		}
		cpuPct, err := p.CPUPercent()
		if err != nil {
			continue
		}
		memPct, err := p.MemoryPercent()
		if err != nil {
			continue
		}

		procList = append(procList, models.ProcessInfo{
			PID:           p.Pid,
			Name:          name,
			CPUPercent:    cpuPct,
			MemoryPercent: memPct,
		})
	}

	return sortAndLimitProcesses(procList, c.topProcCount)
}

// sortAndLimitProcesses sorts processes by CPU percent descending and limits to count.
func sortAndLimitProcesses(procs []models.ProcessInfo, count int) []models.ProcessInfo {
	if count <= 0 || len(procs) == 0 {
		return nil
	}

	sort.Slice(procs, func(i, j int) bool {
		return procs[i].CPUPercent > procs[j].CPUPercent
	})

	if len(procs) > count {
		procs = procs[:count]
	}
	return procs
}
