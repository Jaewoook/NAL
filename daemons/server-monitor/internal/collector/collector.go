package collector

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/jaewoook/server-monitor/internal/models"
)

const (
	minValidSensorTempCelsius = 10.0
	maxValidSensorTempCelsius = 150.0
)

var (
	gpuSensorSubstrings = []string{"gpu", "vga", "nvidia", "amdgpu", "radeon", " tg", "_tg"}
	gpuSensorPrefixes   = []string{"tg"}

	cpuSensorSubstrings = []string{"cpu", "die", "core", "package", "soc", "k10temp", "acpitz", "pacc", "eacc", " tc", "_tc"}
	cpuSensorPrefixes   = []string{"tc"}

	fallbackSensorSubstrings = []string{"thermal_zone", "thermal"}
)

// Collector handles gathering point-in-time system telemetry and resource utilization.
type Collector struct {
	topProcCount         int
	diskMount            string
	lazyTopProcThreshold float64
	cpuSampleInterval    time.Duration
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

// SetCPUSampleInterval configures the duration passed to gopsutil's cpu.Percent.
// 0 (default) computes the delta since the previous call (ideal for daemon loops);
// a short positive duration (e.g. 200ms) is recommended for one-off CLI checks.
func (c *Collector) SetCPUSampleInterval(d time.Duration) {
	c.cpuSampleInterval = d
}

// PopulateTopProcesses scans top processes on-demand with a bounded 5s timeout
// and attaches them to m if not already present.
func (c *Collector) PopulateTopProcesses(m *models.SystemMetrics) {
	if m == nil || c.topProcCount <= 0 || len(m.TopProcesses) > 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.TopProcesses = c.collectTopProcesses(ctx)
}

// Collect gathers current system metrics using a background context.
func (c *Collector) Collect() (*models.SystemMetrics, error) {
	return c.CollectContext(context.Background())
}

// CollectContext gathers current system metrics including CPU, memory, disk, load averages,
// uptime, temperatures, and top CPU-consuming processes, honoring ctx for cancellation.
// If an individual subsystem fails (e.g. disk mount unavailable), partial metrics are still
// returned alongside a joined error so healthy subsystems can continue being evaluated.
func (c *Collector) CollectContext(ctx context.Context) (*models.SystemMetrics, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	metrics := &models.SystemMetrics{
		Timestamp: time.Now(),
	}
	var errs []error

	// 1. CPU Percent (aggregate across all cores)
	if cpuPercents, err := cpu.PercentWithContext(ctx, c.cpuSampleInterval, false); err != nil {
		metrics.CPUFailed = true
		errs = append(errs, fmt.Errorf("failed to collect cpu percent: %w", err))
	} else if len(cpuPercents) == 0 {
		metrics.CPUFailed = true
	} else {
		metrics.CPUPercent = cpuPercents[0]
	}

	// 2. Virtual Memory
	if vmem, err := mem.VirtualMemoryWithContext(ctx); err != nil {
		metrics.MemoryFailed = true
		errs = append(errs, fmt.Errorf("failed to collect virtual memory: %w", err))
	} else {
		metrics.MemoryPercent = vmem.UsedPercent
	}

	// 3. Disk Usage
	if diskUsage, err := disk.UsageWithContext(ctx, c.diskMount); err != nil {
		metrics.DiskFailed = true
		errs = append(errs, fmt.Errorf("failed to collect disk usage for %q: %w", c.diskMount, err))
	} else {
		metrics.DiskPercent = diskUsage.UsedPercent
	}

	// 4. Load Averages (defensively handled if unsupported on platform)
	if loadStat, err := load.AvgWithContext(ctx); err == nil && loadStat != nil {
		metrics.Load1 = loadStat.Load1
		metrics.Load5 = loadStat.Load5
		metrics.Load15 = loadStat.Load15
	}

	// 5. Host Uptime
	if uptime, err := host.UptimeWithContext(ctx); err != nil {
		errs = append(errs, fmt.Errorf("failed to collect host uptime: %w", err))
	} else {
		metrics.UptimeSeconds = uptime
	}

	// 6. Top Processes (by CPU utilization)
	if c.topProcCount > 0 && (c.lazyTopProcThreshold <= 0 || metrics.CPUPercent >= c.lazyTopProcThreshold) {
		metrics.TopProcesses = c.collectTopProcesses(ctx)
	}

	// 7. Thermal sensors (CPU / GPU temperature)
	c.collectTemperatures(ctx, metrics)

	return metrics, errors.Join(errs...)
}

func (c *Collector) collectTemperatures(ctx context.Context, metrics *models.SystemMetrics) {
	// On Darwin platforms (including Apple Silicon), query hardware SMC keys first.
	smcCPUTemp, smcHasCPU, smcGPUTemp, smcHasGPU := readDarwinSMCTemperatures()
	if smcHasCPU {
		metrics.CPUTempCelsius = smcCPUTemp
		metrics.HasCPUTemp = true
	}
	if smcHasGPU {
		metrics.GPUTempCelsius = smcGPUTemp
		metrics.HasGPUTemp = true
	}

	// If either CPU or GPU temperature is not populated from SMC, query standard system sensors.
	if !metrics.HasCPUTemp || !metrics.HasGPUTemp {
		temps, err := sensors.TemperaturesWithContext(ctx)
		if err == nil && len(temps) > 0 {
			cpuTemp, hasCPU, gpuTemp, hasGPU := parseTemperatures(temps)
			if !metrics.HasCPUTemp && hasCPU {
				metrics.CPUTempCelsius = cpuTemp
				metrics.HasCPUTemp = true
			}
			if !metrics.HasGPUTemp && hasGPU {
				metrics.GPUTempCelsius = gpuTemp
				metrics.HasGPUTemp = true
			}
		}
	}
}

// collectTopProcesses scans running processes defensively and returns the top N by CPU percent.
func (c *Collector) collectTopProcesses(ctx context.Context) []models.ProcessInfo {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil
	}

	var procList []models.ProcessInfo
	for _, p := range procs {
		// Processes may terminate or deny access at any point; handle defensively.
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}
		cpuPct, err := p.CPUPercentWithContext(ctx)
		if err != nil {
			continue
		}
		memPct, err := p.MemoryPercentWithContext(ctx)
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

func matchesSensor(name string, prefixes, substrings []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, sub := range substrings {
		if strings.Contains(name, sub) {
			return true
		}
	}
	return false
}

func meanFloat64(vals []float64) (float64, bool) {
	if len(vals) == 0 {
		return 0, false
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals)), true
}

// parseTemperatures categorizes temperature sensor readings into CPU and GPU groups,
// filtering out invalid readings (< 10°C or > 150°C, NaN, Inf), and returns their averages.
// If no explicit CPU sensor is found, generic thermal zones are used as a fallback.
func parseTemperatures(stats []sensors.TemperatureStat) (cpuTemp float64, hasCPU bool, gpuTemp float64, hasGPU bool) {
	var cpuTemps, gpuTemps, fallbackTemps []float64

	for _, stat := range stats {
		if math.IsNaN(stat.Temperature) || math.IsInf(stat.Temperature, 0) ||
			stat.Temperature < minValidSensorTempCelsius || stat.Temperature > maxValidSensorTempCelsius {
			continue
		}
		name := strings.ToLower(stat.SensorKey)

		switch {
		// GPU sensors (check first so "gpu_core" is attributed to GPU)
		case matchesSensor(name, gpuSensorPrefixes, gpuSensorSubstrings):
			gpuTemps = append(gpuTemps, stat.Temperature)
		case matchesSensor(name, cpuSensorPrefixes, cpuSensorSubstrings):
			cpuTemps = append(cpuTemps, stat.Temperature)
		case matchesSensor(name, nil, fallbackSensorSubstrings):
			fallbackTemps = append(fallbackTemps, stat.Temperature)
		}
	}

	if len(cpuTemps) == 0 && len(fallbackTemps) > 0 {
		cpuTemps = fallbackTemps
	}

	cpuTemp, hasCPU = meanFloat64(cpuTemps)
	gpuTemp, hasGPU = meanFloat64(gpuTemps)
	return cpuTemp, hasCPU, gpuTemp, hasGPU
}
