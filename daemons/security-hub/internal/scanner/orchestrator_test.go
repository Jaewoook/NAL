package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

func TestOrchestrator_ScanMutex(t *testing.T) {
	orch := &Orchestrator{}

	scanning, active := orch.IsScanning()
	if scanning || active != "" {
		t.Fatalf("expected idle orchestrator, got scanning=%v active=%q", scanning, active)
	}

	started, active := orch.StartScan("task-123")
	if !started || active != "" {
		t.Fatalf("expected successful StartScan, got started=%v active=%q", started, active)
	}

	scanning, active = orch.IsScanning()
	if !scanning || active != "task-123" {
		t.Fatalf("expected scanning=true active=task-123, got scanning=%v active=%q", scanning, active)
	}

	// Attempt second scan while active
	started2, active2 := orch.StartScan("task-456")
	if started2 || active2 != "task-123" {
		t.Fatalf("expected second StartScan to fail with active task-123, got started=%v active=%q", started2, active2)
	}

	orch.FinishScan()

	scanning, active = orch.IsScanning()
	if scanning || active != "" {
		t.Fatalf("expected idle orchestrator after FinishScan, got scanning=%v active=%q", scanning, active)
	}

	// Default task ID when taskID == ""
	started3, _ := orch.StartScan("")
	if !started3 || !strings.HasPrefix(orch.activeTaskID, "scan_") {
		t.Fatalf("expected default scan_ task ID, got started=%v activeTaskID=%q", started3, orch.activeTaskID)
	}
	orch.FinishScan()
}

func TestOrchestrator_FetchRemoteAgentScan_TokenFallback(t *testing.T) {
	var receivedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-NAL-Node-Token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node":  "remote-node",
			"items": []models.ManagedItem{},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentToken: "shared-cluster-secret",
	}
	orch := &Orchestrator{
		cfg:        cfg,
		httpClient: srv.Client(),
	}

	// 1. Node without token should fall back to cfg.AgentToken
	_, err := orch.fetchRemoteAgentScan(context.Background(), models.NodeInfo{
		Name: "remote-node",
		URL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("fetchRemoteAgentScan failed: %v", err)
	}
	if receivedToken != "shared-cluster-secret" {
		t.Fatalf("expected fallback token 'shared-cluster-secret', got %q", receivedToken)
	}

	// 2. Node with explicit token should override cfg.AgentToken
	_, err = orch.fetchRemoteAgentScan(context.Background(), models.NodeInfo{
		Name:  "remote-node",
		URL:   srv.URL,
		Token: "node-specific-secret",
	})
	if err != nil {
		t.Fatalf("fetchRemoteAgentScan failed: %v", err)
	}
	if receivedToken != "node-specific-secret" {
		t.Fatalf("expected explicit token 'node-specific-secret', got %q", receivedToken)
	}
}

func TestOrchestrator_RunFullScanWithTask_ContextCancelled(t *testing.T) {
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSpoolStore failed: %v", err)
	}
	task, err := store.CreateTask(context.Background(), &models.Task{
		TaskType:    "scan",
		TriggeredBy: "manual",
	})
	if err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	cfg := &config.Config{}
	orch := &Orchestrator{
		cfg:   cfg,
		store: store,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	res, err := orch.RunFullScanWithTask(ctx, task.ID)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if res != nil {
		t.Fatalf("expected nil result on cancelled context, got %+v", res)
	}

	finishedTask, _, err := store.GetTaskWithLogs(context.Background(), task.ID)
	if err != nil {
		t.Fatalf("GetTaskWithLogs failed: %v", err)
	}
	if finishedTask.Status != "failed" {
		t.Fatalf("expected task status 'failed', got %q", finishedTask.Status)
	}
}

func TestOrchestrator_ScanLocalNode_NilCfg(t *testing.T) {
	orch := &Orchestrator{}
	items, err := orch.ScanLocalNode(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on nil cfg, got: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items on nil scanners, got %d", len(items))
	}
}

func TestRegistryAndOrchestrator_Round2Regressions(t *testing.T) {
	ctx := context.Background()

	// 1. CheckImageUpdates preserves currentTag when latest candidate has equal semver (e.g. v1.2.3 vs 1.2.3),
	// and always includes same-major latestVersion in availableTags even when >=12 newer-major tags exist.
	reg := NewRegistryClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u := req.URL.String()
			switch {
			case strings.Contains(u, "/v2/org/vprefix/tags/list"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["1.2.3","v1.1.0"]}`)),
					Header:     make(http.Header),
				}, nil
			case strings.Contains(u, "/v2/org/manymajor/tags/list"):
				tags := []string{
					"2.0.12", "2.0.11", "2.0.10", "2.0.9", "2.0.8", "2.0.7",
					"2.0.6", "2.0.5", "2.0.4", "2.0.3", "2.0.2", "2.0.1", "2.0.0",
					"1.5.0", "1.0.0",
				}
				b, _ := json.Marshal(map[string][]string{"tags": tags})
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader(b)),
					Header:     make(http.Header),
				}, nil
			default:
				return &http.Response{StatusCode: 404, Body: http.NoBody, Header: make(http.Header)}, nil
			}
		}),
	})

	latest, _, _, outdated, err := reg.CheckImageUpdates(ctx, "quay.io/org/vprefix:v1.2.3", "")
	if err != nil {
		t.Fatalf("vprefix CheckImageUpdates error: %v", err)
	}
	if outdated || latest != "v1.2.3" {
		t.Fatalf("expected equal semver v1.2.3 vs 1.2.3 to stay latestVersion='v1.2.3' outdated=false, got latest=%q outdated=%v", latest, outdated)
	}

	latest2, avail2, _, outdated2, err := reg.CheckImageUpdates(ctx, "quay.io/org/manymajor:1.0.0", "")
	if err != nil {
		t.Fatalf("manymajor CheckImageUpdates error: %v", err)
	}
	if !outdated2 || latest2 != "1.5.0" {
		t.Fatalf("expected latestVersion='1.5.0' outdated=true, got latest=%q outdated=%v", latest2, outdated2)
	}
	foundInAvail := false
	for _, tg := range avail2 {
		if tg == "1.5.0" {
			foundInAvail = true
			break
		}
	}
	if !foundInAvail {
		t.Fatalf("expected availableTags to include same-major target '1.5.0', got %v", avail2)
	}

	// 2. Orchestrator.RunFullScanWithTask uses UpdateNodeHealth so concurrent RemoveNode or RejectNode
	// during remote scan is neither resurrected nor overwritten back to approved.
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var agentDelSrv, agentRejSrv *httptest.Server
	agentDelSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = store.RemoveNode(ctx, "node-del")
		_, _ = w.Write([]byte(`{"node":"node-del","items":[{"target_type":"apt","name":"curl","current_version":"1.0"}]}`))
	}))
	defer agentDelSrv.Close()

	agentRejSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = store.RejectNode(ctx, "node-rej")
		_, _ = w.Write([]byte(`{"node":"node-rej","items":[]}`))
	}))
	defer agentRejSrv.Close()

	_ = store.UpsertNode(ctx, models.NodeInfo{Name: "node-del", URL: agentDelSrv.URL, Status: models.NodeStatusApproved, Online: true})
	_ = store.UpsertNode(ctx, models.NodeInfo{Name: "node-rej", URL: agentRejSrv.URL, Status: models.NodeStatusApproved, Online: true})

	cfg := config.DefaultConfig()
	cfg.NodeName = "hub"
	cfg.Scanner.ServicesDir = t.TempDir()
	cfg.Scanner.DaemonsDir = t.TempDir()
	cfg.Scanner.EoLAPIURL = "http://127.0.0.1:0"
	cfg.Scanner.OSVAPIURL = "http://127.0.0.1:0"

	runner := &fakeRunner{handler: func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("not installed in unit test")
	}}
	orch := NewOrchestrator(cfg, store, runner, agentDelSrv.Client())
	res, err := orch.RunFullScanWithTask(ctx, "")
	if err != nil {
		t.Fatalf("RunFullScanWithTask error: %v", err)
	}
	if _, err := store.GetNode(ctx, "node-del"); err == nil {
		t.Fatal("expected deleted node-del not to be resurrected by scan completion")
	}
	rejNode, err := store.GetNode(ctx, "node-rej")
	if err != nil {
		t.Fatalf("expected node-rej to still exist: %v", err)
	}
	if rejNode.Status != models.NodeStatusRejected {
		t.Fatalf("expected node-rej status to remain rejected, got %q", rejNode.Status)
	}
	for _, n := range res.Nodes {
		if n.Name == "node-del" {
			t.Fatalf("expected deleted node-del omitted from scan Nodes, got %+v", res.Nodes)
		}
		if n.Name == "node-rej" && n.Status != models.NodeStatusRejected {
			t.Fatalf("expected res.Nodes entry for node-rej to have rejected status, got %q", n.Status)
		}
	}
}

func TestOrchestrator_ScanningNodesTracking(t *testing.T) {
	orch := &Orchestrator{}

	started, active := orch.StartScanWithNodes("task-abc", []string{"Hub", "Node1", "Node1", ""})
	if !started || active != "" {
		t.Fatalf("StartScanWithNodes failed: started=%v active=%q", started, active)
	}

	scanning, activeID, nodes := orch.GetScanState()
	if !scanning || activeID != "task-abc" || len(nodes) != 2 || nodes[0] != "Hub" || nodes[1] != "Node1" {
		t.Fatalf("unexpected scan state: scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	orch.removeScanningNodeIfMultiple("Hub")
	nodes = orch.ScanningNodes()
	if len(nodes) != 1 || nodes[0] != "Node1" {
		t.Fatalf("expected only Node1 left after removing Hub, got %v", nodes)
	}

	// Removing last remaining node must be a no-op so chip indicator stays visible until FinishScan
	orch.removeScanningNodeIfMultiple("Node1")
	nodes = orch.ScanningNodes()
	if len(nodes) != 1 || nodes[0] != "Node1" {
		t.Fatalf("expected final node Node1 to be preserved until FinishScan, got %v", nodes)
	}

	// FinishScanTask with mismatched ID must not clear active task
	orch.FinishScanTask("wrong-task-id")
	if scanning, _, _ := orch.GetScanState(); !scanning {
		t.Fatal("expected FinishScanTask(wrong-task-id) not to clear active scan")
	}

	orch.FinishScan()
	scanning, activeID, nodes = orch.GetScanState()
	if scanning || activeID != "" || len(nodes) != 0 {
		t.Fatalf("expected clean idle state after FinishScan, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	// Verify FinishScanTask("wrong-id") also does not clear placeholder "scan_..." active task
	if started, _ := orch.StartScan(""); !started {
		t.Fatal("StartScan(\"\") failed")
	}
	orch.FinishScanTask("other-id")
	if scanning, _, _ := orch.GetScanState(); !scanning {
		t.Fatal("expected FinishScanTask(other-id) not to clear scan_ active task")
	}
	orch.FinishScan()
}

func TestOrchestrator_ResolveTargetNode(t *testing.T) {
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "ApprovedAgent",
		URL:    "http://approved.lan:10247",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "PendingAgent",
		URL:    "http://pending.lan:10247",
		Role:   "agent",
		Status: models.NodeStatusPending,
	})

	cfg := &config.Config{NodeName: "Axis"}
	orch := NewOrchestrator(cfg, store, nil, nil)

	// 1. Hub by empty name and explicit name (case-insensitive)
	hub1, err := orch.ResolveTargetNode(ctx, "")
	if err != nil || hub1.Name != "Axis" || hub1.Role != "hub" {
		t.Fatalf("expected Axis hub by empty name, got %+v, err=%v", hub1, err)
	}
	hub2, err := orch.ResolveTargetNode(ctx, "axis")
	if err != nil || hub2.Name != "Axis" || hub2.Role != "hub" {
		t.Fatalf("expected Axis hub by lowercase name, got %+v, err=%v", hub2, err)
	}

	// 2. Approved agent
	ag, err := orch.ResolveTargetNode(ctx, "ApprovedAgent")
	if err != nil || ag.Name != "ApprovedAgent" || ag.Role != "agent" {
		t.Fatalf("expected ApprovedAgent, got %+v, err=%v", ag, err)
	}

	// 3. Pending agent -> ErrScanNodeNotApproved
	_, err = orch.ResolveTargetNode(ctx, "PendingAgent")
	if !errors.Is(err, ErrScanNodeNotApproved) {
		t.Fatalf("expected ErrScanNodeNotApproved for pending agent, got: %v", err)
	}

	// 4. Unknown node -> ErrScanNodeNotFound
	_, err = orch.ResolveTargetNode(ctx, "GhostNode")
	if !errors.Is(err, ErrScanNodeNotFound) {
		t.Fatalf("expected ErrScanNodeNotFound for unknown node, got: %v", err)
	}
}

func TestOrchestrator_RunNodeScan_SingleNodeAndCacheMerge(t *testing.T) {
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Seed previous scan result with items from Hub (Axis), Atlas, and lowercase "aegis" to verify case-insensitive canonicalization
	_ = store.SaveScanResult(ctx, &models.ScanResult{
		ScannedAt: time.Now().UTC().Add(-1 * time.Hour),
		Items: []models.ManagedItem{
			{Node: "Axis", TargetType: models.TargetDocker, Name: "hub-auth", CurrentVersion: "1.0"},
			{Node: "Atlas", TargetType: models.TargetDocker, Name: "old-atlas-service", CurrentVersion: "0.9"},
			{Node: "aegis", TargetType: models.TargetDocker, Name: "aegis-worker", CurrentVersion: "2.5"},
		},
	})

	var atlasContacted, aegisContacted bool
	var orch *Orchestrator
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.Host, "atlas"):
			atlasContacted = true
			if orch != nil {
				scanning, activeTaskID, scanningNodes := orch.GetScanState()
				if !scanning || activeTaskID == "" || len(scanningNodes) != 1 || scanningNodes[0] != "Atlas" {
					t.Errorf("expected live GetScanState(true, non-empty, [Atlas]) during direct RunNodeScan, got scanning=%v taskID=%q nodes=%v", scanning, activeTaskID, scanningNodes)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node": "Atlas",
				"items": []models.ManagedItem{
					{
						Node:           "Atlas",
						TargetType:     models.TargetDocker,
						Name:           "new-atlas-service",
						CurrentVersion: "1.0",
						LatestVersion:  "1.1",
						Outdated:       true,
					},
				},
			})
		case strings.Contains(r.Host, "aegis"):
			aegisContacted = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node":  "Aegis",
				"items": []models.ManagedItem{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "Atlas",
		URL:    "http://atlas.local",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "Aegis",
		URL:    "http://aegis.local",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})

	cfg := &config.Config{NodeName: "Axis"}
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			// Redirect host calls to test server
			r2 := req.Clone(req.Context())
			r2.URL.Scheme = "http"
			r2.URL.Host = server.Listener.Addr().String()
			return server.Client().Transport.RoundTrip(r2)
		}),
	}
	orch = NewOrchestrator(cfg, store, nil, client)

	// Execute single node scan for Atlas
	res, err := orch.RunNodeScan(ctx, "Atlas")
	if err != nil {
		t.Fatalf("RunNodeScan(Atlas) failed: %v", err)
	}
	if scanning, activeID, nodes := orch.GetScanState(); scanning || activeID != "" || len(nodes) != 0 {
		t.Fatalf("expected clean idle scan state after RunNodeScan, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	if !atlasContacted {
		t.Fatal("expected Atlas agent to be contacted")
	}
	if aegisContacted {
		t.Fatal("expected Aegis agent NOT to be contacted during Atlas single-node scan")
	}

	// Verify items: old Atlas item replaced with new Atlas item, Axis and Aegis items preserved
	itemsByNodeAndName := make(map[string]models.ManagedItem)
	for _, it := range res.Items {
		itemsByNodeAndName[it.Node+":"+it.Name] = it
	}

	if _, hasOld := itemsByNodeAndName["Atlas:old-atlas-service"]; hasOld {
		t.Fatal("expected old-atlas-service to be removed/replaced for Atlas")
	}
	if newAtlas, hasNew := itemsByNodeAndName["Atlas:new-atlas-service"]; !hasNew || !newAtlas.Outdated {
		t.Fatalf("expected new-atlas-service with Outdated=true, got %+v", newAtlas)
	}
	if hubItem, hasHub := itemsByNodeAndName["Axis:hub-auth"]; !hasHub || hubItem.CurrentVersion != "1.0" {
		t.Fatalf("expected Axis:hub-auth preserved, got %+v", hubItem)
	}
	if aegisItem, hasAegis := itemsByNodeAndName["Aegis:aegis-worker"]; !hasAegis || aegisItem.CurrentVersion != "2.5" {
		t.Fatalf("expected Aegis:aegis-worker preserved, got %+v", aegisItem)
	}

	// Verify Atlas node health was updated online
	atlasNode, _ := store.GetNode(ctx, "Atlas")
	if !atlasNode.Online || !atlasNode.LastSeenAt.After(time.Now().UTC().Add(-10*time.Second)) {
		t.Fatalf("expected Atlas node health updated, got %+v", atlasNode)
	}

	// Verify Hub context cancellation during remote scan does NOT mark healthy Atlas node offline
	cancelCtx, cancelFunc := context.WithCancel(ctx)
	cancelOrch := NewOrchestrator(cfg, store, nil, &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cancelFunc()
			return nil, context.Canceled
		}),
	})
	if _, cancelErr := cancelOrch.RunNodeScan(cancelCtx, "Atlas"); cancelErr == nil {
		t.Fatal("expected error on cancelled RunNodeScan")
	}
	atlasAfterCancel, _ := store.GetNode(ctx, "Atlas")
	if !atlasAfterCancel.Online {
		t.Fatalf("expected healthy Atlas node NOT to be marked offline on Hub context cancellation, got %+v", atlasAfterCancel)
	}
}

func TestOrchestrator_DirectScanRejectsWhenScanInProgress(t *testing.T) {
	ctx := context.Background()
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.NodeName = "Axis"
	cfg.Scanner.ServicesDir = t.TempDir()
	cfg.Scanner.DaemonsDir = t.TempDir()
	orch := NewOrchestrator(cfg, store, nil, nil)

	orch.LockScanStart()
	started, existingID := orch.StartScanWithNodes("active-task", []string{"Atlas"})
	orch.UnlockScanStart()
	if !started || existingID != "" {
		t.Fatalf("expected active-task to acquire scan lock, got started=%v existingID=%q", started, existingID)
	}

	if _, err := orch.RunFullScan(ctx); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunFullScan, got: %v", err)
	}
	if _, err := orch.RunFullScanWithTask(ctx, "other-task"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunFullScanWithTask(other-task), got: %v", err)
	}
	if _, err := orch.RunNodeScan(ctx, "Axis"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunNodeScan, got: %v", err)
	}
	if _, err := orch.RunNodeScanWithTask(ctx, "Axis", "other-task"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress from RunNodeScanWithTask(other-task), got: %v", err)
	}

	scanning, activeID, nodes := orch.GetScanState()
	if !scanning || activeID != "active-task" || len(nodes) != 1 || nodes[0] != "Atlas" {
		t.Fatalf("expected active scan state preserved after rejected calls, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}

	orch.FinishScan()
	scanning, activeID, nodes = orch.GetScanState()
	if scanning || activeID != "" || len(nodes) != 0 {
		t.Fatalf("expected clean idle scan state after FinishScan, got scanning=%v activeID=%q nodes=%v", scanning, activeID, nodes)
	}
}
