package collector

import (
	"math"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/jaewoook/server-monitor/internal/models"
)

func TestCollectRealMetrics(t *testing.T) {
	c := New(3, "/")
	m, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil SystemMetrics")
	}
	if m.CPUPercent < 0 || m.CPUPercent > 100 {
		t.Errorf("invalid CPU percent: %f", m.CPUPercent)
	}
	if m.MemoryPercent <= 0 || m.MemoryPercent > 100 {
		t.Errorf("invalid memory percent: %f", m.MemoryPercent)
	}
	if m.DiskPercent <= 0 || m.DiskPercent > 100 {
		t.Errorf("invalid disk percent: %f", m.DiskPercent)
	}
	if m.UptimeSeconds <= 0 {
		t.Errorf("invalid uptime: %d", m.UptimeSeconds)
	}
	if m.HasCPUTemp && (m.CPUTempCelsius <= 0 || m.CPUTempCelsius > 150) {
		t.Errorf("invalid CPU temperature: %f", m.CPUTempCelsius)
	}
	if m.HasGPUTemp && (m.GPUTempCelsius <= 0 || m.GPUTempCelsius > 150) {
		t.Errorf("invalid GPU temperature: %f", m.GPUTempCelsius)
	}
	if time.Since(m.Timestamp) > 10*time.Second {
		t.Errorf("expected recent timestamp, got %v", m.Timestamp)
	}
	if len(m.TopProcesses) > 3 {
		t.Errorf("expected at most 3 top processes, got %d", len(m.TopProcesses))
	}
	for i := 0; i < len(m.TopProcesses)-1; i++ {
		if m.TopProcesses[i].CPUPercent < m.TopProcesses[i+1].CPUPercent {
			t.Errorf("top processes not sorted descending: [%d]=%f < [%d]=%f",
				i, m.TopProcesses[i].CPUPercent, i+1, m.TopProcesses[i+1].CPUPercent)
		}
	}
}

func TestNewDefaultMount(t *testing.T) {
	c := New(5, "")
	if c.diskMount != "/" {
		t.Errorf("expected default mount point '/', got %q", c.diskMount)
	}
	if c.topProcCount != 5 {
		t.Errorf("expected topProcCount 5, got %d", c.topProcCount)
	}
}

func TestCollectZeroTopProcesses(t *testing.T) {
	c := New(0, "/")
	m, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(m.TopProcesses) != 0 {
		t.Errorf("expected 0 top processes when count is 0, got %d", len(m.TopProcesses))
	}
}

func TestCollectInvalidDiskMount(t *testing.T) {
	c := New(0, "/nonexistent_path_xyz_12345")
	_, err := c.Collect()
	if err == nil {
		t.Errorf("expected error for nonexistent disk mount, got nil")
	}
}

func TestSortAndLimitProcesses(t *testing.T) {
	procs := []models.ProcessInfo{
		{PID: 1, Name: "proc1", CPUPercent: 10.5},
		{PID: 2, Name: "proc2", CPUPercent: 55.0},
		{PID: 3, Name: "proc3", CPUPercent: 25.2},
		{PID: 4, Name: "proc4", CPUPercent: 70.1},
	}
	sorted := sortAndLimitProcesses(procs, 2)
	if len(sorted) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(sorted))
	}
	if sorted[0].PID != 4 || sorted[0].CPUPercent != 70.1 {
		t.Errorf("expected top process PID 4 (70.1), got PID %d (%f)", sorted[0].PID, sorted[0].CPUPercent)
	}
	if sorted[1].PID != 2 || sorted[1].CPUPercent != 55.0 {
		t.Errorf("expected second process PID 2 (55.0), got PID %d (%f)", sorted[1].PID, sorted[1].CPUPercent)
	}

	// Edge cases: count <= 0 or empty slice
	if res := sortAndLimitProcesses(procs, 0); res != nil {
		t.Errorf("expected nil when count=0, got %v", res)
	}
	if res := sortAndLimitProcesses(nil, 5); res != nil {
		t.Errorf("expected nil for nil input, got %v", res)
	}
	// count > len(procs)
	allSorted := sortAndLimitProcesses([]models.ProcessInfo{
		{PID: 1, CPUPercent: 10},
		{PID: 2, CPUPercent: 20},
	}, 10)
	if len(allSorted) != 2 || allSorted[0].PID != 2 {
		t.Errorf("expected all elements sorted, got %v", allSorted)
	}
}

func TestCollector_LazyTopProcesses(t *testing.T) {
	c := New(3, "/")
	// Threshold higher than any idle system CPU usage
	c.SetLazyTopProcessesThreshold(99.9)

	m, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(m.TopProcesses) != 0 {
		t.Errorf("expected 0 top processes when CPU is below lazy threshold, got %d", len(m.TopProcesses))
	}

	// On-demand population
	c.PopulateTopProcesses(m)
	if len(m.TopProcesses) == 0 {
		t.Errorf("expected PopulateTopProcesses to populate top processes, got 0")
	}

	// Reset threshold to 0 (eager)
	c.SetLazyTopProcessesThreshold(0)
	m2, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(m2.TopProcesses) == 0 {
		t.Errorf("expected top processes when lazy threshold is 0, got 0")
	}
}

func TestParseTemperatures(t *testing.T) {
	stats := []sensors.TemperatureStat{
		{SensorKey: "PMU tdie1", Temperature: 40.0},
		{SensorKey: "PMU tdie2", Temperature: 44.0},
		{SensorKey: "PMU tdev4", Temperature: -19.7}, // invalid: negative
		{SensorKey: "NAND CH0", Temperature: 30.0},   // ignored
		{SensorKey: "gpu_core", Temperature: 55.0},
		{SensorKey: "gpu_mem", Temperature: 65.0},
		{SensorKey: "glitch_hot", Temperature: 200.0},               // invalid: > 150
		{SensorKey: "glitch_zero", Temperature: 0.0},                // invalid: zero
		{SensorKey: "cpu_nan", Temperature: math.NaN()},             // invalid: NaN
		{SensorKey: "gpu_inf", Temperature: math.Inf(1)},            // invalid: +Inf
		{SensorKey: "gpu_neg_inf", Temperature: math.Inf(-1)},       // invalid: -Inf
	}

	cpuTemp, hasCPU, gpuTemp, hasGPU := parseTemperatures(stats)
	if !hasCPU {
		t.Errorf("expected hasCPU true")
	}
	if cpuTemp != 42.0 {
		t.Errorf("expected cpuTemp 42.0, got %f", cpuTemp)
	}

	if !hasGPU {
		t.Errorf("expected hasGPU true")
	}
	if gpuTemp != 60.0 {
		t.Errorf("expected gpuTemp 60.0, got %f", gpuTemp)
	}

	// Empty input
	_, hasCPU2, _, hasGPU2 := parseTemperatures(nil)
	if hasCPU2 || hasGPU2 {
		t.Errorf("expected false for nil stats, got CPU:%v GPU:%v", hasCPU2, hasGPU2)
	}

	// Only generic thermal zone
	genericStats := []sensors.TemperatureStat{
		{SensorKey: "thermal_zone0", Temperature: 45.0},
	}
	cpuTemp3, hasCPU3, _, hasGPU3 := parseTemperatures(genericStats)
	if !hasCPU3 {
		t.Errorf("expected hasCPU3 true for generic thermal zone fallback")
	}
	if cpuTemp3 != 45.0 {
		t.Errorf("expected cpuTemp3 45.0, got %f", cpuTemp3)
	}
	if hasGPU3 {
		t.Errorf("expected hasGPU3 false when no GPU sensor exists")
	}

	// Apple Silicon M1 IOHID sensor naming (pACC / eACC / GPU MTR)
	m1Stats := []sensors.TemperatureStat{
		{SensorKey: "eACC MTR Temp Sensor0", Temperature: 38.0},
		{SensorKey: "pACC MTR Temp Sensor2", Temperature: 42.0},
		{SensorKey: "GPU MTR Temp Sensor1", Temperature: 36.5},
	}
	cpuTempM1, hasCPUM1, gpuTempM1, hasGPUM1 := parseTemperatures(m1Stats)
	if !hasCPUM1 || cpuTempM1 != 40.0 {
		t.Errorf("expected M1 CPU temp 40.0, got hasCPU=%v temp=%f", hasCPUM1, cpuTempM1)
	}
	if !hasGPUM1 || gpuTempM1 != 36.5 {
		t.Errorf("expected M1 GPU temp 36.5, got hasGPU=%v temp=%f", hasGPUM1, gpuTempM1)
	}
}

