package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

func TestManager_RollbackServiceOnNode_RemoteFailureHandled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":"failed","error_msg":"internal agent failure"}`))
	}))
	defer ts.Close()

	root := t.TempDir()
	store, err := db.NewSpoolStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name: "remote-atlas",
		URL:  ts.URL,
		Role: "agent",
	})

	cfg := config.DefaultConfig()
	cfg.NodeName = "hub-local"
	mgr := NewManager(cfg, store, &recordingRunner{}, nil)

	_, err = mgr.RollbackServiceOnNode(ctx, "remote-atlas", "db", "admin")
	if err == nil {
		t.Fatal("expected RollbackServiceOnNode to fail when remote agent returns HTTP 500")
	}
	if !strings.Contains(err.Error(), "internal agent failure") {
		t.Fatalf("expected error message to mention agent failure, got: %v", err)
	}
}

func TestManager_RejectsUpdateAndRollbackOnUnapprovedNode(t *testing.T) {
	ctx := context.Background()
	store, _ := db.NewSpoolStore(t.TempDir(), nil)
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "pending-node",
		URL:    "http://127.0.0.1:9999",
		Role:   "agent",
		Status: models.NodeStatusPending,
	})
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "rejected-node",
		URL:    "http://127.0.0.1:9999",
		Role:   "agent",
		Status: models.NodeStatusRejected,
	})

	cfg := config.DefaultConfig()
	cfg.NodeName = "hub-local"
	mgr := NewManager(cfg, store, &recordingRunner{}, nil)

	// 1. Rollback on pending node
	_, err := mgr.RollbackServiceOnNode(ctx, "pending-node", "dns", "admin")
	if err == nil || !strings.Contains(err.Error(), "cannot rollback unapproved node") {
		t.Fatalf("expected rollback on pending node to be rejected, got: %v", err)
	}

	// 2. Rollback on rejected node
	_, err = mgr.RollbackServiceOnNode(ctx, "rejected-node", "dns", "admin")
	if err == nil || !strings.Contains(err.Error(), "cannot rollback unapproved node") {
		t.Fatalf("expected rollback on rejected node to be rejected, got: %v", err)
	}

	// 3. Update forwarding on pending node
	t1, _ := store.CreateTask(ctx, &models.Task{
		Node:     "pending-node",
		TaskType: "agent_update",
		Status:   "running",
	})
	err = mgr.RunUpdateSync(ctx, t1.ID, UpdateRequest{
		Node:          "pending-node",
		TargetType:    "docker",
		TargetName:    "dns",
		TargetVersion: "v1.0.0",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot update unapproved node") {
		t.Fatalf("expected update on pending node to be rejected, got: %v", err)
	}
}

func TestManager_RemoteForward_TokenFallbackAndLocalRouting(t *testing.T) {
	ctx := context.Background()
	var updateToken, rollbackToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/agent/update":
			updateToken = r.Header.Get("X-NAL-Node-Token")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "succeeded",
			})
		case "/api/agent/rollback":
			rollbackToken = r.Header.Get("X-NAL-Node-Token")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "succeeded",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store, _ := db.NewSpoolStore(t.TempDir(), nil)
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "agent-no-tok",
		URL:    srv.URL,
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})

	cfg := config.DefaultConfig()
	cfg.NodeName = "Hub-Primary"
	cfg.AgentToken = "shared-cluster-agent-secret"

	mgr := NewManager(cfg, store, &recordingRunner{}, nil)
	mgr.SetHTTPClient(srv.Client())

	// 1. Verify forwardUpdateToAgent falls back to cfg.AgentToken
	t1, _ := store.CreateTask(ctx, &models.Task{
		Node:     "agent-no-tok",
		TaskType: "agent_update",
		Status:   "running",
	})
	err := mgr.RunUpdateSync(ctx, t1.ID, UpdateRequest{
		Node:          "agent-no-tok",
		TargetType:    "docker",
		TargetName:    "dns",
		TargetVersion: "1.2.0",
	})
	if err != nil {
		t.Fatalf("RunUpdateSync failed on remote node: %v", err)
	}
	if updateToken != "shared-cluster-agent-secret" {
		t.Fatalf("expected update token fallback to 'shared-cluster-agent-secret', got %q", updateToken)
	}

	// 2. Verify RollbackServiceOnNode falls back to cfg.AgentToken
	_, err = mgr.RollbackServiceOnNode(ctx, "agent-no-tok", "dns", "admin")
	if err != nil {
		t.Fatalf("RollbackServiceOnNode failed on remote node: %v", err)
	}
	if rollbackToken != "shared-cluster-agent-secret" {
		t.Fatalf("expected rollback token fallback to 'shared-cluster-agent-secret', got %q", rollbackToken)
	}

	// 3. Verify local node routing: 'local' and case-insensitive 'hub-primary' route locally
	tLocal, _ := store.CreateTask(ctx, &models.Task{
		Node:     "local",
		TaskType: "docker_update",
		Status:   "running",
	})
	err = mgr.RunUpdateSync(ctx, tLocal.ID, UpdateRequest{
		Node:          "local",
		TargetType:    "docker",
		TargetName:    "nonexistent",
		TargetVersion: "1.0.0",
	})
	if err != nil && strings.Contains(err.Error(), "unknown remote node") {
		t.Fatalf("expected 'local' to route locally, but attempted remote forward: %v", err)
	}

	tLocalCase, _ := store.CreateTask(ctx, &models.Task{
		Node:     "hub-primary",
		TaskType: "docker_update",
		Status:   "running",
	})
	err = mgr.RunUpdateSync(ctx, tLocalCase.ID, UpdateRequest{
		Node:          "hub-primary",
		TargetType:    "docker",
		TargetName:    "nonexistent",
		TargetVersion: "1.0.0",
	})
	if err != nil && strings.Contains(err.Error(), "unknown remote node") {
		t.Fatalf("expected 'hub-primary' to route locally via EqualFold, but attempted remote forward: %v", err)
	}

	// 4. Verify RollbackServiceOnNode with 'local' routes locally
	_, err = mgr.RollbackServiceOnNode(ctx, "local", "dns", "admin")
	if err != nil && strings.Contains(err.Error(), "node \"local\" not found") {
		t.Fatalf("expected rollback with 'local' to route locally, but attempted remote lookup: %v", err)
	}
}
