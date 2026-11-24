package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

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
