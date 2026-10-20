package collector

import (
	"testing"
	"time"

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
