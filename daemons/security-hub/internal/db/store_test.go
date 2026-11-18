package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestPostgresBackend_BatchedLogsAndBase64SafeEncoding(t *testing.T) {
	var executedSQL []string
	pg := NewPostgresBackend("postgresql", "security_hub_db", "security_hub", func(name string, args ...string) ([]byte, error) {
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

func TestPostgresBackend_NodeUpsertAndDelete(t *testing.T) {
	var executedSQL []string
	pg := NewPostgresBackend("postgresql", "security_hub_db", "security_hub", func(name string, args ...string) ([]byte, error) {
		if len(args) > 0 {
			executedSQL = append(executedSQL, args[len(args)-1])
		}
		return []byte("ok"), nil
	})

	err := pg.UpsertNode(context.Background(), models.NodeInfo{
		Name:       "Atlas",
		URL:        "http://192.168.1.50:10247",
		Token:      "secret-token",
		Role:       "agent",
		Status:     models.NodeStatusPending,
		Online:     true,
		LastSeenAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC),
		LastError:  "",
		OSVersion:  "darwin/arm64",
	})
	if err != nil {
		t.Fatalf("UpsertNode failed: %v", err)
	}

	err = pg.DeleteNode(context.Background(), "Atlas")
	if err != nil {
		t.Fatalf("DeleteNode failed: %v", err)
	}

	if len(executedSQL) != 3 {
		t.Fatalf("expected 3 SQL executions, got %d", len(executedSQL))
	}
	if !strings.Contains(executedSQL[1], "INSERT INTO nodes") || !strings.Contains(executedSQL[1], "'pending'") {
		t.Fatalf("expected node upsert SQL with pending status, got: %s", executedSQL[1])
	}
	if !strings.Contains(executedSQL[2], "DELETE FROM nodes WHERE name = 'Atlas'") {
		t.Fatalf("expected node delete SQL, got: %s", executedSQL[2])
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
	err := ProvisionDatabase(context.Background(), "postgresql", "security_hub_db", "security_hub", "s3cr3t", func(name string, args ...string) ([]byte, error) {
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

func TestSpoolStore_FlushPending_ConcurrentFinishTaskNotClobbered(t *testing.T) {
	ctx := context.Background()
	memPG := newFakePGBackend()
	memPG.setOnline(false) // Start offline so task is created as SyncedToDB=false

	store, err := NewSpoolStore(t.TempDir(), memPG)
	if err != nil {
		t.Fatal(err)
	}

	task, err := store.CreateTask(ctx, &models.Task{
		TaskType:    "docker_update",
		TargetType:  "docker",
		TargetName:  "web",
		FromVersion: "1.0",
		ToVersion:   "1.1",
		TriggeredBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Bring PG online
	memPG.setOnline(true)

	// When FlushPending upserts the running task, simulate FinishTask completing concurrently
	memPG.onUpsertTask = func(upserted models.Task) {
		if upserted.Status == "running" {
			// FinishTask finishes task concurrently
			_ = store.FinishTask(ctx, task.ID, "succeeded", "")
		}
	}

	if err := store.FlushPending(ctx); err != nil {
		t.Fatal(err)
	}

	// Local spool task MUST NOT be clobbered back to "running"
	localTask, _, err := store.GetTaskWithLogs(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if localTask.Status != "succeeded" {
		t.Fatalf("expected local task status 'succeeded', got %q (was clobbered by FlushPending)", localTask.Status)
	}

	// Second flush should sync "succeeded" to Postgres
	memPG.onUpsertTask = nil
	if err := store.FlushPending(ctx); err != nil {
		t.Fatal(err)
	}
	pgTask, _, _ := memPG.GetTaskWithLogs(ctx, task.ID)
	if pgTask.Status != "succeeded" {
		t.Fatalf("expected PG task status 'succeeded', got %q", pgTask.Status)
	}
}

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

func TestSpoolStore_PendingApprovalAndDynamicOffline(t *testing.T) {
	ctx := context.Background()
	store, err := NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Upsert a node with Status: models.NodeStatusPending
	node := models.NodeInfo{
		Name:       "Atlas",
		URL:        "http://192.168.1.50:10247",
		Token:      "secret-token",
		Role:       "agent",
		Status:     models.NodeStatusPending,
		Online:     true,
		LastSeenAt: time.Now().UTC(),
	}
	if err := store.UpsertNode(ctx, node); err != nil {
		t.Fatalf("UpsertNode failed: %v", err)
	}

	// 2. List nodes and assert status is preserved
	nodes, err := store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Status != models.NodeStatusPending {
		t.Fatalf("expected status %q, got %q", models.NodeStatusPending, nodes[0].Status)
	}

	// 3. Call ApproveNode("Atlas") and assert status transitions to models.NodeStatusApproved
	if err := store.ApproveNode(ctx, "Atlas"); err != nil {
		t.Fatalf("ApproveNode failed: %v", err)
	}
	n, err := store.GetNode(ctx, "Atlas")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if n.Status != models.NodeStatusApproved {
		t.Fatalf("expected status %q after ApproveNode, got %q", models.NodeStatusApproved, n.Status)
	}

	// 4. Call RejectNode("Atlas") and assert node status transitions to models.NodeStatusRejected
	if err := store.RejectNode(ctx, "Atlas"); err != nil {
		t.Fatalf("RejectNode failed: %v", err)
	}
	n, err = store.GetNode(ctx, "Atlas")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if n.Status != models.NodeStatusRejected {
		t.Fatalf("expected status %q after RejectNode, got %q", models.NodeStatusRejected, n.Status)
	}

	// 5. Upsert an approved agent with LastSeenAt: time.Now().Add(-5 * time.Minute)
	// and assert ListNodes() reports Online: false
	staleNode := models.NodeInfo{
		Name:       "StaleAgent",
		URL:        "http://192.168.1.51:10247",
		Role:       "agent",
		Status:     models.NodeStatusApproved,
		Online:     true,
		LastSeenAt: time.Now().UTC().Add(-5 * time.Minute),
	}
	if err := store.UpsertNode(ctx, staleNode); err != nil {
		t.Fatalf("UpsertNode staleNode failed: %v", err)
	}

	nodes, err = store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes failed: %v", err)
	}
	var foundStale bool
	for _, item := range nodes {
		if item.Name == "StaleAgent" {
			foundStale = true
			if item.Online {
				t.Fatalf("expected StaleAgent Online to be false, got true")
			}
		}
	}
	if !foundStale {
		t.Fatalf("expected to find StaleAgent in ListNodes")
	}

	// Verify that a freshly seen agent (< 3 minutes) remains Online: true
	freshNode := models.NodeInfo{
		Name:       "FreshAgent",
		URL:        "http://192.168.1.52:10247",
		Role:       "agent",
		Status:     models.NodeStatusApproved,
		Online:     true,
		LastSeenAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	if err := store.UpsertNode(ctx, freshNode); err != nil {
		t.Fatalf("UpsertNode freshNode failed: %v", err)
	}
	nodes, err = store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes failed: %v", err)
	}
	for _, item := range nodes {
		if item.Name == "FreshAgent" {
			if !item.Online {
				t.Fatalf("expected FreshAgent Online to be true, got false")
			}
		}
	}

	// Verify node with unspecified status defaults to approved
	defaultNode := models.NodeInfo{
		Name: "DefaultNode",
		URL:  "http://192.168.1.53:10247",
		Role: "agent",
	}
	if err := store.UpsertNode(ctx, defaultNode); err != nil {
		t.Fatalf("UpsertNode defaultNode failed: %v", err)
	}
	dn, err := store.GetNode(ctx, "DefaultNode")
	if err != nil {
		t.Fatalf("GetNode defaultNode failed: %v", err)
	}
	if dn.Status != models.NodeStatusApproved {
		t.Fatalf("expected DefaultNode status %q, got %q", models.NodeStatusApproved, dn.Status)
	}

	// Non-existent node errors
	if err := store.ApproveNode(ctx, "NonExistent"); err == nil {
		t.Fatalf("expected error approving non-existent node")
	}
	if err := store.RejectNode(ctx, "NonExistent"); err == nil {
		t.Fatalf("expected error rejecting non-existent node")
	}
}

func TestSpoolStore_LegacyNodesDefaultToApprovedAndPersistOnStartup(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "spool_state.json")

	// Pre-create a spool_state.json with a legacy node that has no status, and NO running tasks
	rawJSON := `{
		"next_task_num": 1,
		"tasks": {},
		"nodes": {
			"LegacyNode": {
				"name": "LegacyNode",
				"url": "http://192.168.1.99:10247",
				"role": "agent",
				"status": ""
			}
		}
	}`
	if err := os.WriteFile(stateFile, []byte(rawJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Starting SpoolStore should reconcile legacy node to approved AND persist to disk
	store, err := NewSpoolStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	node, err := store.GetNode(context.Background(), "LegacyNode")
	if err != nil || node.Status != models.NodeStatusApproved {
		t.Fatalf("expected LegacyNode to be approved in memory, got %+v, err=%v", node, err)
	}

	// Verify file on disk was persisted with approved status
	diskBytes, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diskBytes), `"approved"`) {
		t.Fatalf("expected spool_state.json on disk to be saved with status 'approved', got:\n%s", string(diskBytes))
	}
}

func TestSpoolStore_NodeZeroLastSeenAndMetadataPreservation(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSpoolStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// 1. Node with zero LastSeenAt should be reported as Online: false by GetNode and ListNodes
	zeroNode := models.NodeInfo{
		Name:   "ZeroSeenAgent",
		URL:    "http://10.0.0.5:10247",
		Role:   "agent",
		Status: models.NodeStatusApproved,
		Online: true, // caller passes true, but LastSeenAt is zero
	}
	if err := store.UpsertNode(ctx, zeroNode); err != nil {
		t.Fatalf("UpsertNode failed: %v", err)
	}

	gotZero, err := store.GetNode(ctx, "ZeroSeenAgent")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if gotZero.Online {
		t.Errorf("expected GetNode for agent with zero LastSeenAt to report Online: false")
	}

	nodes, err := store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes failed: %v", err)
	}
	for _, n := range nodes {
		if n.Name == "ZeroSeenAgent" && n.Online {
			t.Errorf("expected ListNodes for agent with zero LastSeenAt to report Online: false")
		}
	}

	// 2. Metadata preservation: existing metadata should not be clobbered by empty fields
	now := time.Now().UTC()
	richNode := models.NodeInfo{
		Name:       "RichNode",
		URL:        "http://10.0.0.6:10247",
		Role:       "agent",
		Status:     models.NodeStatusApproved,
		Token:      "auth-token-123",
		OSVersion:  "linux/amd64/synology",
		Online:     true,
		LastSeenAt: now,
	}
	if err := store.UpsertNode(ctx, richNode); err != nil {
		t.Fatalf("UpsertNode failed: %v", err)
	}

	// Update node with empty token, empty os_version, zero last seen, online=false
	sparseUpdate := models.NodeInfo{
		Name: "RichNode",
		URL:  "http://10.0.0.6:10248",
	}
	if err := store.UpsertNode(ctx, sparseUpdate); err != nil {
		t.Fatalf("UpsertNode sparseUpdate failed: %v", err)
	}

	updated, err := store.GetNode(ctx, "RichNode")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if updated.URL != "http://10.0.0.6:10248" {
		t.Errorf("expected updated URL, got %s", updated.URL)
	}
	if updated.Token != "auth-token-123" {
		t.Errorf("expected preserved token 'auth-token-123', got %q", updated.Token)
	}
	if updated.OSVersion != "linux/amd64/synology" {
		t.Errorf("expected preserved OSVersion 'linux/amd64/synology', got %q", updated.OSVersion)
	}
	if updated.Status != models.NodeStatusApproved {
		t.Errorf("expected preserved Status 'approved', got %q", updated.Status)
	}
	if updated.LastSeenAt.IsZero() || !updated.LastSeenAt.Equal(now) {
		t.Errorf("expected preserved LastSeenAt %v, got %v", now, updated.LastSeenAt)
	}
	if !updated.Online {
		t.Errorf("expected preserved Online=true since LastSeenAt is fresh")
	}

	// 3. Explicit scan error: node with LastError and Online: false must NOT be overwritten by existing fresh LastSeenAt
	scanFailUpdate := models.NodeInfo{
		Name:      "RichNode",
		Online:    false,
		LastError: "connection refused: 10.0.0.6:10248",
	}
	if err := store.UpsertNode(ctx, scanFailUpdate); err != nil {
		t.Fatalf("UpsertNode scanFailUpdate failed: %v", err)
	}
	failedNode, err := store.GetNode(ctx, "RichNode")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if failedNode.Online {
		t.Errorf("expected failedNode.Online to remain false when LastError is present")
	}
	if failedNode.LastError != "connection refused: 10.0.0.6:10248" {
		t.Errorf("expected LastError to be recorded, got %q", failedNode.LastError)
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

func TestSpoolStore_AtomicNodeHealth_Announce_And_RemoveTombstones(t *testing.T) {
	ctx := context.Background()
	memPG := newFakePGBackend()
	store, err := NewSpoolStore(t.TempDir(), memPG)
	if err != nil {
		t.Fatal(err)
	}

	// 1. AnnounceNode: new node starts pending, approved URL change demotes to pending, rejected rejects
	st, err := store.AnnounceNode(ctx, models.NodeInfo{
		Name:      "edge-1",
		URL:       "http://10.0.0.21:10248",
		Token:     "tok-1",
		OSVersion: "debian/12",
	})
	if err != nil || st != models.NodeStatusPending {
		t.Fatalf("expected initial announce status pending, got %q err=%v", st, err)
	}
	if err := store.ApproveNode(ctx, "edge-1"); err != nil {
		t.Fatal(err)
	}

	// UpdateNodeHealth preserves approved Status, URL, Token while updating online/lastError
	seenAt := time.Now().UTC().Truncate(time.Second)
	if err := store.UpdateNodeHealth(ctx, "edge-1", false, seenAt, "dial tcp timeout"); err != nil {
		t.Fatal(err)
	}
	n, err := store.GetNode(ctx, "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	if n.Status != models.NodeStatusApproved || n.URL != "http://10.0.0.21:10248" || n.Token != "tok-1" {
		t.Fatalf("UpdateNodeHealth clobbered operator fields: %+v", n)
	}
	if n.Online || n.LastError != "dial tcp timeout" || !n.LastSeenAt.Equal(seenAt) {
		t.Fatalf("UpdateNodeHealth did not persist health fields: %+v", n)
	}

	// Announcing from a new URL demotes approved -> pending
	st, err = store.AnnounceNode(ctx, models.NodeInfo{
		Name: "edge-1",
		URL:  "http://10.0.0.99:10248",
	})
	if err != nil || st != models.NodeStatusPending {
		t.Fatalf("expected URL change to demote to pending, got %q err=%v", st, err)
	}
	if err := store.RejectNode(ctx, "edge-1"); err != nil {
		t.Fatal(err)
	}
	st, err = store.AnnounceNode(ctx, models.NodeInfo{
		Name: "edge-1",
		URL:  "http://10.0.0.99:10248",
	})
	if err != nil || st != models.NodeStatusRejected {
		t.Fatalf("expected rejected node to stay rejected on announce, got %q err=%v", st, err)
	}

	// 2. RemoveNode while PG is offline records tombstone and FlushPending deletes from PG when online;
	// UpdateNodeHealth on removed node is a no-op (must NOT resurrect deleted node).
	memPG.setOnline(false)
	if err := store.RemoveNode(ctx, "edge-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateNodeHealth(ctx, "edge-1", true, time.Now().UTC(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetNode(ctx, "edge-1"); err == nil {
		t.Fatal("expected UpdateNodeHealth on removed node to remain a no-op")
	}
	memPG.setOnline(true)
	if err := store.FlushPending(ctx); err != nil {
		t.Fatal(err)
	}
	memPG.mu.Lock()
	_, stillInPG := memPG.nodes["edge-1"]
	memPG.mu.Unlock()
	if stillInPG {
		t.Fatal("expected FlushPending to flush node deletion tombstone to Postgres")
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






