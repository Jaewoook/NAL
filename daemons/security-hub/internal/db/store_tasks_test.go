package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

func TestSpoolStore_StartupReconcilesOrphanedRunningTasks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// 1. Create a store and an active running task, then simulate daemon crash/exit
	store1, err := NewSpoolStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	task, err := store1.CreateTask(ctx, &models.Task{
		TaskType:   "daemon_scan",
		TargetType: "host",
		TargetName: "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "running" {
		t.Fatalf("expected running, got %s", task.Status)
	}

	// 2. Start new store from same data directory
	store2, err := NewSpoolStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	reconciled, _, err := store2.GetTaskWithLogs(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != "aborted" {
		t.Fatalf("expected orphaned task to be reconciled to 'aborted', got %q", reconciled.Status)
	}
	if !strings.Contains(reconciled.ErrorMsg, "daemon restarted") {
		t.Fatalf("expected error message to mention daemon restart, got %q", reconciled.ErrorMsg)
	}
}

func TestSpoolStore_CorruptState_NumericSort_LogPermissions_And_PostgresSafety(t *testing.T) {
	ctx := context.Background()

	// 1. Corrupt spool_state.json returns error instead of silently clobbering
	corruptDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(corruptDir, "spool_state.json"), []byte("{not-json"), 0600)
	if _, err := NewSpoolStore(corruptDir, nil); err == nil {
		t.Fatal("expected NewSpoolStore to fail on corrupt spool_state.json")
	}

	// 2. Numeric task ID sorting (task-100000 > task-99999) + 0600 log file + subscriber cleanup
	store, err := NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.NextTaskNum = 99999
	store.mu.Unlock()
	t99999, _ := store.CreateTask(ctx, &models.Task{TaskType: "brew_upgrade", TargetName: "a"})
	t100000, _ := store.CreateTask(ctx, &models.Task{TaskType: "brew_upgrade", TargetName: "b"})
	tasks, _ := store.ListTasks(ctx, "", 10)
	if len(tasks) != 2 || tasks[0].ID != t100000.ID || tasks[1].ID != t99999.ID {
		t.Fatalf("expected numeric sort [%s, %s], got %+v", t100000.ID, t99999.ID, tasks)
	}

	_, unsub := store.SubscribeTaskLogs(t100000.ID)
	_, _ = store.AppendTaskLog(ctx, t100000.ID, "stdout", "line1")
	unsub()
	store.mu.RLock()
	_, subsExist := store.subscribers[t100000.ID]
	store.mu.RUnlock()
	if subsExist {
		t.Fatal("expected empty subscriber map entry to be cleaned up on unsubscribe")
	}
	st, err := os.Stat(store.GetRawLogPath(t100000.ID))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 raw log file permissions, got err=%v perm=%v", err, st)
	}

	// 3. PostgresBackend sanitizes NUL / invalid UTF-8 bytes and includes node in UpsertTask concurrently without race
	var sqlQueries []string
	var sqlMu sync.Mutex
	pg := NewPostgresBackend("postgresql", "security_hub_db", "security_hub", func(name string, args ...string) ([]byte, error) {
		sqlMu.Lock()
		sqlQueries = append(sqlQueries, args[len(args)-1])
		sqlMu.Unlock()
		return []byte("ok"), nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = pg.UpsertTask(ctx, models.Task{ID: "task-00001", Node: "RPi-01", TaskType: "apt", TargetType: "apt", TargetName: "openssl", Status: "running", StartedAt: time.Now().UTC()})
			_ = pg.InsertTaskLogsBatch(ctx, []models.TaskLogLine{{TaskID: "task-00001", Seq: idx + 1, LoggedAt: time.Now().UTC(), Stream: "stdout", Line: "bad\x00bytes\xffhere"}})
		}(i)
	}
	wg.Wait()
	joined := strings.Join(sqlQueries, "\n")
	if !strings.Contains(joined, "node") {
		t.Fatalf("expected tasks SQL to include node column, got:\n%s", joined)
	}
	if !strings.Contains(joined, "WHERE tasks.finished_at IS NULL OR EXCLUDED.finished_at IS NOT NULL") {
		t.Fatalf("expected UpsertTask SQL to guard finished tasks, got:\n%s", joined)
	}
}
