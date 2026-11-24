package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

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
