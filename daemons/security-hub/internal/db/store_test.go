package db

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jaewoook/security-hub/internal/models"
)

var errPostgresDown = errors.New("postgres connection refused")

type fakePGBackend struct {
	mu        sync.Mutex
	online    bool
	tasks     map[string]models.Task
	logs      map[string]map[int]models.TaskLogLine
	snapshots map[string]models.RollbackSnapshot
	skipped   map[string]string
	alerts    map[string]string
}

func newFakePGBackend() *fakePGBackend {
	return &fakePGBackend{
		online:    true,
		tasks:     make(map[string]models.Task),
		logs:      make(map[string]map[int]models.TaskLogLine),
		snapshots: make(map[string]models.RollbackSnapshot),
		skipped:   make(map[string]string),
		alerts:    make(map[string]string),
	}
}

func (f *fakePGBackend) setOnline(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.online = v
}

func (f *fakePGBackend) UpsertTask(ctx context.Context, task models.Task) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	f.tasks[task.ID] = task
	return nil
}

func (f *fakePGBackend) InsertTaskLog(ctx context.Context, line models.TaskLogLine) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	if f.logs[line.TaskID] == nil {
		f.logs[line.TaskID] = make(map[int]models.TaskLogLine)
	}
	f.logs[line.TaskID][line.Seq] = line
	return nil
}

func (f *fakePGBackend) UpsertSnapshot(ctx context.Context, snap models.RollbackSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	f.snapshots[snap.ServiceName] = snap
	return nil
}

func (f *fakePGBackend) UpsertSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	f.skipped[targetType+":"+targetName] = version
	return nil
}

func (f *fakePGBackend) DeleteSkippedVersion(ctx context.Context, targetType, targetName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	delete(f.skipped, targetType+":"+targetName)
	return nil
}

func (f *fakePGBackend) UpsertSentAlert(ctx context.Context, fingerprint, alertType string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	f.alerts[fingerprint] = alertType
	return nil
}

func (f *fakePGBackend) GetTaskWithLogs(ctx context.Context, taskID string) (*models.Task, []models.TaskLogLine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tasks[taskID]
	if !ok {
		return nil, nil, errors.New("not found")
	}
	var out []models.TaskLogLine
	for i := 1; i <= len(f.logs[taskID]); i++ {
		if l, exists := f.logs[taskID][i]; exists {
			out = append(out, l)
		}
	}
	return &t, out, nil
}

func TestSpoolStore_OfflineDuringPostgresUpgradeAndIdempotentFlush(t *testing.T) {
	ctx := context.Background()
	memPG := newFakePGBackend()
	memPG.setOnline(false) // Postgres is down during upgrade

	store, err := NewSpoolStore(t.TempDir(), memPG)
	if err != nil {
		t.Fatal(err)
	}

	task, err := store.CreateTask(ctx, &models.Task{
		TaskType:    "docker_update",
		TargetType:  "docker",
		TargetName:  "db",
		FromVersion: "16.4-alpine",
		ToVersion:   "16.6-alpine",
		TriggeredBy: "sso:jaewook@jaewook.dev",
	})
	if err != nil {
		t.Fatal(err)
	}

	ch, unsub := store.SubscribeTaskLogs(task.ID)
	defer unsub()

	if _, err := store.AppendTaskLog(ctx, task.ID, "info", "Pulling postgres:16.6-alpine"); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-ch:
		if line.Line != "Pulling postgres:16.6-alpine" || line.Seq != 1 {
			t.Fatalf("unexpected streamed line: %+v", line)
		}
	default:
		t.Fatal("expected live log line on subscriber channel")
	}

	// Verify reads work from local spool while Postgres is still down
	tasks, err := store.ListTasks(ctx, "", 10)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("expected 1 task from local spool while offline, got len=%d err=%v", len(tasks), err)
	}

	if err := store.SetSkippedVersion(ctx, "docker", "iot", "2026.10.0", "sso:jaewook@jaewook.dev"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAlertSent(ctx, "fp-1", "cve"); err != nil {
		t.Fatal(err)
	}

	// Postgres comes online mid-task
	memPG.setOnline(true)
	if _, err := store.AppendTaskLog(ctx, task.ID, "info", "Container postgresql Healthy"); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishTask(ctx, task.ID, "succeeded", ""); err != nil {
		t.Fatal(err)
	}

	// Flush twice to verify idempotency (no duplicate seq lines)
	if err := store.FlushPending(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.FlushPending(ctx); err != nil {
		t.Fatal(err)
	}

	gotTask, logs, err := memPG.GetTaskWithLogs(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotTask.Status != "succeeded" || len(logs) != 2 {
		t.Fatalf("expected 2 synced logs and succeeded status, got status=%s len=%d", gotTask.Status, len(logs))
	}
}

func TestPostgresBackend_BatchedLogsAndBase64SafeEncoding(t *testing.T) {
	var executedSQL []string
	pg := NewPostgresBackend("postgresql", "security_hub", "security_hub", func(name string, args ...string) ([]byte, error) {
		if len(args) > 0 {
			executedSQL = append(executedSQL, args[len(args)-1])
		}
		return []byte("ok"), nil
	})

	err := pg.InsertTaskLogsBatch(context.Background(), []models.TaskLogLine{
		{TaskID: "task-00001", Seq: 1, Stream: "stdout", Line: "line with 'quotes' and $dollar$ and \n newline"},
		{TaskID: "task-00001", Seq: 2, Stream: "stderr", Line: "second line"},
	})
	if err != nil {
		t.Fatalf("InsertTaskLogsBatch failed: %v", err)
	}
	// 1 call for schema init + 1 call for batched insert
	if len(executedSQL) != 2 {
		t.Fatalf("expected 2 SQL executions (1 schema + 1 batch), got %d", len(executedSQL))
	}
	if !strings.Contains(executedSQL[1], "convert_from(decode(") {
		t.Fatalf("expected base64-decoded safe SQL in batch insert, got: %s", executedSQL[1])
	}
}

func TestSpoolStore_NodeRegistryAddListRemove(t *testing.T) {
	ctx := context.Background()
	store, err := NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = store.UpsertNode(ctx, models.NodeInfo{
		Name:  "Atlas",
		URL:   "http://192.168.1.50:10247",
		Token: "shared-secret",
		Role:  "agent",
	})
	if err != nil {
		t.Fatalf("UpsertNode failed: %v", err)
	}

	nodes, err := store.ListNodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "Atlas" {
		t.Fatalf("expected 1 node Atlas, got err=%v nodes=%+v", err, nodes)
	}

	if err := store.RemoveNode(ctx, "Atlas"); err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}
	nodesAfter, _ := store.ListNodes(ctx)
	if len(nodesAfter) != 0 {
		t.Fatalf("expected 0 nodes after RemoveNode, got %d", len(nodesAfter))
	}
}

func TestProvisionDatabase_UsesContainerPostgresUserEnv(t *testing.T) {
	var calls []string
	err := ProvisionDatabase(context.Background(), "postgresql", "security_hub", "security_hub", "s3cr3t", func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)
		if strings.Contains(cmd, "SELECT 1 FROM pg_database") {
			return []byte("0\n"), nil
		}
		return []byte("OK"), nil
	})
	if err != nil {
		t.Fatalf("ProvisionDatabase failed: %v", err)
	}
	if len(calls) < 4 {
		t.Fatalf("expected at least 4 docker exec calls (role, check db, create db, schema), got %d", len(calls))
	}
	if !strings.Contains(calls[0], "${POSTGRES_USER:-postgres}") {
		t.Fatalf("expected ProvisionDatabase to use container POSTGRES_USER env var, got: %s", calls[0])
	}
}


