package db

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

var errPostgresDown = errors.New("postgres connection refused")

type fakePGBackend struct {
	mu           sync.Mutex
	online       bool
	tasks        map[string]models.Task
	logs         map[string]map[int]models.TaskLogLine
	snapshots    map[string]models.RollbackSnapshot
	skipped      map[string]string
	alerts       map[string]string
	nodes        map[string]models.NodeInfo
	onUpsertTask func(task models.Task)
}

func newFakePGBackend() *fakePGBackend {
	return &fakePGBackend{
		online:    true,
		tasks:     make(map[string]models.Task),
		logs:      make(map[string]map[int]models.TaskLogLine),
		snapshots: make(map[string]models.RollbackSnapshot),
		skipped:   make(map[string]string),
		alerts:    make(map[string]string),
		nodes:     make(map[string]models.NodeInfo),
	}
}

func (f *fakePGBackend) setOnline(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.online = v
}

func (f *fakePGBackend) UpsertTask(ctx context.Context, task models.Task) error {
	f.mu.Lock()
	hook := f.onUpsertTask
	if !f.online {
		f.mu.Unlock()
		return errPostgresDown
	}
	f.tasks[task.ID] = task
	f.mu.Unlock()

	if hook != nil {
		hook(task)
	}
	return nil
}

func (f *fakePGBackend) InsertTaskLog(ctx context.Context, line models.TaskLogLine) error {
	return f.InsertTaskLogsBatch(ctx, []models.TaskLogLine{line})
}

func (f *fakePGBackend) InsertTaskLogsBatch(ctx context.Context, lines []models.TaskLogLine) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	for _, line := range lines {
		if f.logs[line.TaskID] == nil {
			f.logs[line.TaskID] = make(map[int]models.TaskLogLine)
		}
		f.logs[line.TaskID][line.Seq] = line
	}
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

func (f *fakePGBackend) UpsertNode(ctx context.Context, node models.NodeInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	f.nodes[node.Name] = node
	return nil
}

func (f *fakePGBackend) DeleteNode(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errPostgresDown
	}
	delete(f.nodes, name)
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

func TestSpoolStore_Round3_CLICoexistenceAndPostgresSnapshotColumns(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// 1. NewCLISpoolStore does NOT abort daemon's running tasks, and syncs mutations cleanly via flock
	daemonStore, err := NewSpoolStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	runningTask, err := daemonStore.CreateTask(ctx, &models.Task{
		TaskType:   "security_scan",
		TargetType: "system",
		TargetName: "all",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = daemonStore.AppendTaskLog(ctx, runningTask.ID, "info", "scanning packages...")

	cliStore, err := NewCLISpoolStore(dir, nil)
	if err != nil {
		t.Fatalf("NewCLISpoolStore failed: %v", err)
	}
	gotFromCLI, _, err := cliStore.GetTaskWithLogs(ctx, runningTask.ID)
	if err != nil || gotFromCLI.Status != "running" {
		t.Fatalf("expected NewCLISpoolStore to leave daemon running task intact, got status=%v err=%v", gotFromCLI, err)
	}

	// CLI adds a node; daemon sees it on ListNodes without clobbering it when finishing task
	if err := cliStore.UpsertNode(ctx, models.NodeInfo{
		Name:   "rpi-cli",
		URL:    "http://10.0.0.88:10247",
		Status: models.NodeStatusApproved,
	}); err != nil {
		t.Fatal(err)
	}
	nodesOnDaemon, err := daemonStore.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundNode := false
	for _, n := range nodesOnDaemon {
		if n.Name == "rpi-cli" {
			foundNode = true
		}
	}
	if !foundNode {
		t.Fatalf("expected daemon store to observe CLI-added node via disk sync, got %+v", nodesOnDaemon)
	}

	if err := daemonStore.FinishTask(ctx, runningTask.ID, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	// Verify daemon didn't clobber CLI's node on disk
	cliStore2, err := NewCLISpoolStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cliStore2.GetNode(ctx, "rpi-cli"); err != nil {
		t.Fatalf("expected CLI-added node to survive daemon FinishTask: %v", err)
	}

	// 2. PostgresBackend.UpsertSnapshot updates all metadata columns on conflict
	var snapSQL string
	pg := NewPostgresBackend("postgresql", "security_hub_db", "security_hub", func(name string, args ...string) ([]byte, error) {
		snapSQL = args[len(args)-1]
		return []byte("ok"), nil
	})
	if err := pg.UpsertSnapshot(ctx, models.RollbackSnapshot{
		ServiceName:     "db",
		ServiceKey:      "db",
		ImageRepo:       "postgres",
		PreviousVersion: "16.4",
		ComposePath:     "/srv/db/compose.yml",
		EnvPath:         "/srv/db/.env",
		CreatedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{
		"service_key = EXCLUDED.service_key",
		"image_repo = EXCLUDED.image_repo",
		"compose_path = EXCLUDED.compose_path",
		"env_path = EXCLUDED.env_path",
	} {
		if !strings.Contains(snapSQL, col) {
			t.Fatalf("expected UpsertSnapshot SQL to include %q, got:\n%s", col, snapSQL)
		}
	}

	// 3. CLI RemoveNode (pg=nil) persists DeletedNodes tombstone across subsequent disk reloads until daemon FlushPending runs
	tombDir := t.TempDir()
	memPG := newFakePGBackend()
	daemon2, err := NewSpoolStore(tombDir, memPG)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon2.UpsertNode(ctx, models.NodeInfo{Name: "rpi-old", URL: "http://10.0.0.10:10247", Status: models.NodeStatusApproved}); err != nil {
		t.Fatal(err)
	}
	if err := daemon2.UpsertNode(ctx, models.NodeInfo{Name: "rpi-keep", URL: "http://10.0.0.11:10247", Status: models.NodeStatusApproved}); err != nil {
		t.Fatal(err)
	}

	cliNoPG, err := NewCLISpoolStore(tombDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cliNoPG.RemoveNode(ctx, "rpi-old"); err != nil {
		t.Fatal(err)
	}
	// Reload daemon state from disk, then apply an unrelated CLI mutation before FlushPending
	if _, err := daemon2.ListNodes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cliNoPG.UpsertNode(ctx, models.NodeInfo{Name: "rpi-extra", URL: "http://10.0.0.12:10247", Status: models.NodeStatusApproved}); err != nil {
		t.Fatal(err)
	}
	if err := daemon2.FlushPending(ctx); err != nil {
		t.Fatal(err)
	}
	memPG.mu.Lock()
	_, oldStillInPG := memPG.nodes["rpi-old"]
	_, extraInPG := memPG.nodes["rpi-extra"]
	memPG.mu.Unlock()
	if oldStillInPG {
		t.Fatal("expected DeletedNodes tombstone from pg=nil CLI RemoveNode to survive disk reload and delete from Postgres on FlushPending")
	}
	if !extraInPG {
		t.Fatal("expected rpi-extra added by CLI to sync to Postgres")
	}
}
