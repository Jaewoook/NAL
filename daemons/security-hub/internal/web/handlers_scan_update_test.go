package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/notifier"
	"github.com/jaewoook/security-hub/internal/scanner"
	"github.com/jaewoook/security-hub/internal/updater"
)

func TestServer_AuthDashboardSkipAndSSELogs(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Database.DataDir = filepath.Join(root, "data")
	cfg.Scanner.ServicesDir = filepath.Join(root, "services")

	store, err := db.NewSpoolStore(cfg.Database.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.SaveScanResult(context.Background(), &models.ScanResult{
		ScannedAt: time.Now().UTC(),
		Items: []models.ManagedItem{
			{TargetType: models.TargetDocker, Name: "auth", CurrentVersion: "2026.5.3", LatestVersion: "2026.5.5", Outdated: true},
		},
		TotalOutdated: 1,
	})

	authMgr, err := auth.NewManager(cfg.Auth, filepath.Join(cfg.Database.DataDir, "auth_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &noopRunner{}
	alerter := notifier.NewAlerter(cfg.Notifications.Email, store)
	orch := scanner.NewOrchestrator(cfg, store, runner, nil)
	updMgr := updater.NewManager(cfg, store, runner, alerter)

	srv := NewServer(cfg, store, orch, updMgr, authMgr, alerter)
	h := srv.Handler()

	// 1. Unauthenticated request returns 401
	unauthW := httptest.NewRecorder()
	h.ServeHTTP(unauthW, httptest.NewRequest(http.MethodGet, "/api/dashboard", nil))
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /api/dashboard, got %d", unauthW.Code)
	}

	// 2. Break-glass token login sets session cookie
	tok, err := authMgr.GenerateBreakGlassToken(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, httptest.NewRequest(http.MethodGet, "/api/auth/token-login?token="+tok, nil))
	if loginW.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect on token-login, got %d", loginW.Code)
	}
	cookies := loginW.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie on token-login")
	}
	sessionCookie := cookies[0]

	// 3. Authenticated /api/dashboard returns 200
	dashReq := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	dashReq.AddCookie(sessionCookie)
	dashW := httptest.NewRecorder()
	h.ServeHTTP(dashW, dashReq)
	if dashW.Code != http.StatusOK || !strings.Contains(dashW.Body.String(), `"auth"`) {
		t.Fatalf("expected 200 with auth item, got %d: %s", dashW.Code, dashW.Body.String())
	}

	// 4. POST /api/skip & DELETE /api/skip
	skipBody, _ := json.Marshal(map[string]string{
		"target_type": "docker",
		"target_name": "auth",
		"version":     "2026.5.5",
	})
	skipReq := httptest.NewRequest(http.MethodPost, "/api/skip", bytes.NewReader(skipBody))
	addAuthAndCSRF(skipReq, sessionCookie, authMgr)
	skipW := httptest.NewRecorder()
	h.ServeHTTP(skipW, skipReq)
	if skipW.Code != http.StatusOK {
		t.Fatalf("POST /api/skip returned %d", skipW.Code)
	}
	skippedMap, _ := store.ListSkippedVersions(context.Background())
	if skippedMap["docker:auth"] != "2026.5.5" {
		t.Fatalf("expected docker:auth skipped=2026.5.5, got %v", skippedMap)
	}

	unskipReq := httptest.NewRequest(http.MethodDelete, "/api/skip?target_type=docker&target_name=auth", nil)
	addAuthAndCSRF(unskipReq, sessionCookie, authMgr)
	unskipW := httptest.NewRecorder()
	h.ServeHTTP(unskipW, unskipReq)
	if unskipW.Code != http.StatusOK {
		t.Fatalf("DELETE /api/skip returned %d", unskipW.Code)
	}

	// 5. Task creation + SSE stream (/api/tasks/{id}/stream)
	task, _ := store.CreateTask(context.Background(), &models.Task{
		TaskType:   "brew_upgrade",
		TargetType: "brew",
		TargetName: "openssl@3",
		Status:     "running",
	})
	_, _ = store.AppendTaskLog(context.Background(), task.ID, "info", "Upgrading openssl@3...")
	_ = store.FinishTask(context.Background(), task.ID, "succeeded", "")

	sseReq := httptest.NewRequest(http.MethodGet, "/api/tasks/"+task.ID+"/stream", nil)
	sseReq.AddCookie(sessionCookie)
	sseW := httptest.NewRecorder()
	h.ServeHTTP(sseW, sseReq)
	if sseW.Code != http.StatusOK || !strings.Contains(sseW.Body.String(), "Upgrading openssl@3...") {
		t.Fatalf("expected SSE stream to contain task log line, got %d: %s", sseW.Code, sseW.Body.String())
	}

	// 6. Live SSE stream when task is still running and finishes AFTER the last AppendTaskLog
	liveTask, _ := store.CreateTask(context.Background(), &models.Task{
		TaskType:   "docker_update",
		TargetType: "docker",
		TargetName: "cloudflare-tunnel",
		Status:     "running",
	})
	go func() {
		time.Sleep(25 * time.Millisecond)
		_, _ = store.AppendTaskLog(context.Background(), liveTask.ID, "info", "Live log line 1")
		time.Sleep(15 * time.Millisecond)
		_ = store.FinishTask(context.Background(), liveTask.ID, "succeeded", "")
	}()

	liveReq := httptest.NewRequest(http.MethodGet, "/api/tasks/"+liveTask.ID+"/stream", nil)
	liveReq.AddCookie(sessionCookie)
	liveW := httptest.NewRecorder()
	doneCh := make(chan struct{})
	go func() {
		h.ServeHTTP(liveW, liveReq)
		close(doneCh)
	}()
	select {
	case <-doneCh:
		if !strings.Contains(liveW.Body.String(), "Live log line 1") || !strings.Contains(liveW.Body.String(), "event: done") {
			t.Fatalf("expected live SSE stream to include log line and event: done, got: %s", liveW.Body.String())
		}
	case <-time.After(1 * time.Second):
		t.Fatal("SSE live stream deadlocked after FinishTask was called")
	}

	// 7. Multi-Node Registry API (/api/nodes) & Agent Endpoint (/api/agent/scan)
	nodeBody, _ := json.Marshal(map[string]string{
		"name":  "Atlas",
		"url":   "http://192.168.1.50:10247",
		"token": "atlas-secret-token",
	})
	nodeAddReq := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(nodeBody))
	addAuthAndCSRF(nodeAddReq, sessionCookie, authMgr)
	nodeAddW := httptest.NewRecorder()
	h.ServeHTTP(nodeAddW, nodeAddReq)
	if nodeAddW.Code != http.StatusOK {
		t.Fatalf("POST /api/nodes returned %d: %s", nodeAddW.Code, nodeAddW.Body.String())
	}

	nodeListReq := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	nodeListReq.AddCookie(sessionCookie)
	nodeListW := httptest.NewRecorder()
	h.ServeHTTP(nodeListW, nodeListReq)
	if nodeListW.Code != http.StatusOK || !strings.Contains(nodeListW.Body.String(), `"Atlas"`) {
		t.Fatalf("expected Atlas in GET /api/nodes, got %d: %s", nodeListW.Code, nodeListW.Body.String())
	}

	// Verify Agent mode endpoint rejects missing/wrong X-NAL-Node-Token and accepts valid token
	cfg.AgentToken = "atlas-secret-token"
	cfg.NodeName = "Atlas"
	agentUnauthW := httptest.NewRecorder()
	h.ServeHTTP(agentUnauthW, httptest.NewRequest(http.MethodGet, "/api/agent/info", nil))
	if agentUnauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /api/agent/info without token, got %d", agentUnauthW.Code)
	}

	agentAuthReq := httptest.NewRequest(http.MethodGet, "/api/agent/info", nil)
	agentAuthReq.Header.Set("X-NAL-Node-Token", "atlas-secret-token")
	agentAuthW := httptest.NewRecorder()
	h.ServeHTTP(agentAuthW, agentAuthReq)
	expectedOS := runtime.GOOS + "/" + runtime.GOARCH
	if agentAuthW.Code != http.StatusOK || !strings.Contains(agentAuthW.Body.String(), `"Atlas"`) || !strings.Contains(agentAuthW.Body.String(), expectedOS) {
		t.Fatalf("expected 200 with Atlas and os_version %s on /api/agent/info, got %d: %s", expectedOS, agentAuthW.Code, agentAuthW.Body.String())
	}
}

func TestServer_AsyncScanAndConcurrencyMutex(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.NodeName = "Axis"
	cfg.AgentToken = "shared-cluster-token"
	cfg.Database.DataDir = filepath.Join(root, "data")
	cfg.Scanner.ServicesDir = filepath.Join(root, "services")

	store, err := db.NewSpoolStore(cfg.Database.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewManager(cfg.Auth, filepath.Join(cfg.Database.DataDir, "auth_state.json"))
	if err != nil {
		t.Fatal(err)
	}

	scanBlocker := make(chan struct{})
	defer func() {
		select {
		case <-scanBlocker:
		default:
			close(scanBlocker)
		}
	}()

	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-scanBlocker
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node": "Atlas",
			"items": []models.ManagedItem{
				{
					Node:           "Atlas",
					TargetType:     models.TargetDaemon,
					Name:           "ollama",
					CurrentVersion: "0.4.2",
				},
			},
		})
	}))
	defer agentServer.Close()

	_ = store.UpsertNode(context.Background(), models.NodeInfo{
		Name:   "Atlas",
		URL:    agentServer.URL,
		Token:  cfg.AgentToken,
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})

	runner := &noopRunner{}
	alerter := notifier.NewAlerter(cfg.Notifications.Email, store)
	orch := scanner.NewOrchestrator(cfg, store, runner, agentServer.Client())
	updMgr := updater.NewManager(cfg, store, runner, alerter)

	srv := NewServer(cfg, store, orch, updMgr, authMgr, alerter)
	srv.SetHTTPClient(agentServer.Client())

	tok, err := authMgr.GenerateBreakGlassToken(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loginW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginW, httptest.NewRequest(http.MethodGet, "/api/auth/token-login?token="+tok, nil))
	cookies := loginW.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie on token-login")
	}
	sessionCookie := cookies[0]
	h := srv.Handler()

	// 1. Trigger POST /api/scan: assert HTTP 202 with task_id
	scanReq1 := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	addAuthAndCSRF(scanReq1, sessionCookie, authMgr)
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, scanReq1)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 Accepted on first scan trigger, got %d: %s", w1.Code, w1.Body.String())
	}
	var resp1 struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("failed to parse scan response: %v", err)
	}
	if resp1.TaskID == "" {
		t.Fatal("expected non-empty task_id in scan response")
	}
	if resp1.Status != "running" {
		t.Fatalf("expected status 'running', got %q", resp1.Status)
	}

	// 2. Immediately trigger second POST /api/scan: assert HTTP 409 Conflict while first scan is running
	scanReq2 := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	addAuthAndCSRF(scanReq2, sessionCookie, authMgr)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, scanReq2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 Conflict on simultaneous scan trigger, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp2 struct {
		Error  string `json:"error"`
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to parse conflict response: %v", err)
	}
	if resp2.Error != "scan already running" {
		t.Fatalf("expected error 'scan already running', got %q", resp2.Error)
	}
	if resp2.TaskID != resp1.TaskID {
		t.Fatalf("expected conflict task_id %q, got %q", resp1.TaskID, resp2.TaskID)
	}

	// 3. Connect to /api/tasks/<task_id>/stream and assert SSE events receive step logs and terminate with event: done
	streamReq := httptest.NewRequest(http.MethodGet, "/api/tasks/"+resp1.TaskID+"/stream", nil)
	streamReq.AddCookie(sessionCookie)
	streamW := httptest.NewRecorder()

	streamDone := make(chan struct{})
	go func() {
		h.ServeHTTP(streamW, streamReq)
		close(streamDone)
	}()

	// Allow subscriber to register before unblocking agent
	time.Sleep(30 * time.Millisecond)
	close(scanBlocker)

	select {
	case <-streamDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSE stream to complete")
	}

	if streamW.Code != http.StatusOK {
		t.Fatalf("expected 200 from stream endpoint, got %d", streamW.Code)
	}

	streamBody := streamW.Body.String()
	if !strings.Contains(streamBody, "event: done") {
		t.Fatalf("expected SSE stream to contain 'event: done', got:\n%s", streamBody)
	}

	// Verify step logs are delivered in the SSE stream
	expectedSteps := []string{
		"Starting full scan on Hub (Axis)...",
		"[Hub] Scanned",
		"[Atlas] Querying remote agent",
		"[Atlas] Scanned 1 remote components...",
		"Analyzing CVEs against vulnerability feeds...",
		"Scan complete:",
	}
	for _, step := range expectedSteps {
		if !strings.Contains(streamBody, step) {
			t.Fatalf("expected stream to contain step log %q, got body:\n%s", step, streamBody)
		}
	}

	// 4. After first scan completes, triggering POST /api/scan again succeeds (HTTP 202)
	scanReq3 := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	addAuthAndCSRF(scanReq3, sessionCookie, authMgr)
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, scanReq3)
	if w3.Code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 on scan after completion, got %d: %s", w3.Code, w3.Body.String())
	}

	srv.NotifyShutdown()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := srv.Wait(waitCtx); err != nil {
		t.Fatalf("expected srv.Wait to finish cleanly after second scan trigger, got: %v", err)
	}
}

func TestOrchestrator_ScheduledAndManualScanCoordination(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.NodeName = "Axis"

	store, err := db.NewSpoolStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewManager(cfg.Auth, filepath.Join(root, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	srv := NewServer(cfg, store, orch, nil, authMgr, nil)

	tok, err := authMgr.GenerateBreakGlassToken(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loginW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginW, httptest.NewRequest(http.MethodGet, "/api/auth/token-login?token="+tok, nil))
	sessionCookie := loginW.Result().Cookies()[0]

	// Simulate background daemon starting a scheduled scan
	started, _ := orch.StartScan("scheduled_task_99")
	if !started {
		t.Fatal("failed to start simulated scheduled scan")
	}

	// Manual scan request from UI should receive HTTP 409 Conflict with the active task ID
	req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	addAuthAndCSRF(req, sessionCookie, authMgr)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 Conflict while scheduled scan is active, got %d: %s", w.Code, w.Body.String())
	}
	var conflictResp struct {
		Error  string `json:"error"`
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &conflictResp)
	if conflictResp.Error != "scan already running" {
		t.Fatalf("expected error 'scan already running', got %q", conflictResp.Error)
	}
	if conflictResp.TaskID != "scheduled_task_99" {
		t.Fatalf("expected task_id 'scheduled_task_99', got %q", conflictResp.TaskID)
	}

	// Finish the scheduled scan
	orch.FinishScan()

	// Now manual scan should succeed
	req2 := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	addAuthAndCSRF(req2, sessionCookie, authMgr)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 after scheduled scan finished, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestServer_SingleNodeScanAndDashboardScanningNodes(t *testing.T) {
	srv, sessionCookie, store, cfg := setupTestHubServer(t)
	ctx := context.Background()

	// 1. Add approved node Atlas and pending node PendingNode
	var blockerMu sync.Mutex
	scanBlocker := make(chan struct{})
	activeBlocker := scanBlocker
	closeChannelSafe := func(ch chan struct{}) {
		if ch == nil {
			return
		}
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
	defer func() {
		blockerMu.Lock()
		ch := activeBlocker
		blockerMu.Unlock()
		closeChannelSafe(ch)
	}()

	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blockerMu.Lock()
		ch := activeBlocker
		blockerMu.Unlock()
		if ch != nil {
			select {
			case <-ch:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node": "Atlas",
			"items": []models.ManagedItem{
				{
					Node:           "Atlas",
					TargetType:     models.TargetDaemon,
					Name:           "ollama",
					CurrentVersion: "0.5.1",
				},
			},
		})
	}))
	defer agentSrv.Close()

	srv.SetHTTPClient(agentSrv.Client())
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "Atlas",
		URL:    agentSrv.URL,
		Token:  cfg.AgentToken,
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "PendingNode",
		URL:    "http://pending.lan:10247",
		Token:  cfg.AgentToken,
		Role:   "agent",
		Status: models.NodeStatusPending,
	})

	h := srv.Handler()

	// 2. Reject unknown node with 404
	badNodeReq := httptest.NewRequest(http.MethodPost, "/api/scan?node=NonExistent", nil)
	addAuthAndCSRF(badNodeReq, sessionCookie, srv.authMgr)
	badNodeW := httptest.NewRecorder()
	h.ServeHTTP(badNodeW, badNodeReq)
	if badNodeW.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown node scan, got %d: %s", badNodeW.Code, badNodeW.Body.String())
	}

	// 3. Reject pending node with 400
	pendingNodeBody, _ := json.Marshal(map[string]string{"node": "PendingNode"})
	pendingNodeReq := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewReader(pendingNodeBody))
	addAuthAndCSRF(pendingNodeReq, sessionCookie, srv.authMgr)
	pendingNodeW := httptest.NewRecorder()
	h.ServeHTTP(pendingNodeW, pendingNodeReq)
	if pendingNodeW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for pending node scan, got %d: %s", pendingNodeW.Code, pendingNodeW.Body.String())
	}

	// 3b. Reject malformed JSON bodies and conflicting query/body node params with 400
	for _, badBody := range []string{`{bad`, `{"node": 123}`, `{"unknown": "Atlas"}`, `{"node": "Atlas"} extra`} {
		badReq := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(badBody))
		addAuthAndCSRF(badReq, sessionCookie, srv.authMgr)
		badW := httptest.NewRecorder()
		h.ServeHTTP(badW, badReq)
		if badW.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for malformed scan body %q, got %d: %s", badBody, badW.Code, badW.Body.String())
		}
	}
	conflictParamReq := httptest.NewRequest(http.MethodPost, "/api/scan?node=Axis", strings.NewReader(`{"node":"Atlas"}`))
	addAuthAndCSRF(conflictParamReq, sessionCookie, srv.authMgr)
	conflictParamW := httptest.NewRecorder()
	h.ServeHTTP(conflictParamW, conflictParamReq)
	if conflictParamW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for conflicting query & body node params, got %d: %s", conflictParamW.Code, conflictParamW.Body.String())
	}

	// 4. Trigger single-node scan for Atlas -> returns 202 with scanning_nodes: ["Atlas"]
	atlasScanBody, _ := json.Marshal(map[string]string{"node": "Atlas"})
	scanReq := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewReader(atlasScanBody))
	addAuthAndCSRF(scanReq, sessionCookie, srv.authMgr)
	scanW := httptest.NewRecorder()
	h.ServeHTTP(scanW, scanReq)
	if scanW.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on single node scan trigger, got %d: %s", scanW.Code, scanW.Body.String())
	}
	var scanResp struct {
		TaskID        string   `json:"task_id"`
		Status        string   `json:"status"`
		Node          string   `json:"node"`
		ScanningNodes []string `json:"scanning_nodes"`
	}
	if err := json.Unmarshal(scanW.Body.Bytes(), &scanResp); err != nil {
		t.Fatalf("failed to decode scan response: %v", err)
	}
	if scanResp.Node != "Atlas" || len(scanResp.ScanningNodes) != 1 || scanResp.ScanningNodes[0] != "Atlas" {
		t.Fatalf("unexpected scan response: %+v", scanResp)
	}

	// 5. Query /api/dashboard while scan is running -> returns scanning: true and scanning_nodes: ["Atlas"]
	dashReq := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	dashReq.AddCookie(sessionCookie)
	dashW := httptest.NewRecorder()
	h.ServeHTTP(dashW, dashReq)
	if dashW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/dashboard, got %d", dashW.Code)
	}
	var dashResp struct {
		Scanning         bool     `json:"scanning"`
		ActiveScanTaskID string   `json:"active_scan_task_id"`
		ScanningNodes    []string `json:"scanning_nodes"`
	}
	if err := json.Unmarshal(dashW.Body.Bytes(), &dashResp); err != nil {
		t.Fatalf("failed to decode dashboard response: %v", err)
	}
	if !dashResp.Scanning || dashResp.ActiveScanTaskID != scanResp.TaskID || len(dashResp.ScanningNodes) != 1 || dashResp.ScanningNodes[0] != "Atlas" {
		t.Fatalf("unexpected dashboard scanning state: %+v", dashResp)
	}

	// 6. Attempt concurrent scan while Atlas is scanning -> 409 Conflict with scanning_nodes: ["Atlas"]
	conflictReq := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	addAuthAndCSRF(conflictReq, sessionCookie, srv.authMgr)
	conflictW := httptest.NewRecorder()
	h.ServeHTTP(conflictW, conflictReq)
	if conflictW.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for concurrent scan trigger, got %d: %s", conflictW.Code, conflictW.Body.String())
	}
	var conflictResp struct {
		Error         string   `json:"error"`
		TaskID        string   `json:"task_id"`
		ScanningNodes []string `json:"scanning_nodes"`
	}
	if err := json.Unmarshal(conflictW.Body.Bytes(), &conflictResp); err != nil {
		t.Fatalf("failed to decode conflict response: %v", err)
	}
	if conflictResp.TaskID != scanResp.TaskID || len(conflictResp.ScanningNodes) != 1 || conflictResp.ScanningNodes[0] != "Atlas" {
		t.Fatalf("unexpected conflict response payload: %+v", conflictResp)
	}

	// 7. Unblock Atlas and wait for scan to complete
	closeChannelSafe(scanBlocker)
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if err := srv.Wait(waitCtx); err != nil {
		t.Fatalf("srv.Wait failed: %v", err)
	}

	// 8. Final dashboard check: scanning=false, scanning_nodes=[]
	dashReq2 := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	dashReq2.AddCookie(sessionCookie)
	dashW2 := httptest.NewRecorder()
	h.ServeHTTP(dashW2, dashReq2)
	var dashResp2 struct {
		Scanning      bool     `json:"scanning"`
		ScanningNodes []string `json:"scanning_nodes"`
	}
	_ = json.Unmarshal(dashW2.Body.Bytes(), &dashResp2)
	if dashResp2.Scanning || len(dashResp2.ScanningNodes) != 0 {
		t.Fatalf("expected idle dashboard state after scan completion, got: %+v", dashResp2)
	}

	// 9. Verify concurrent scan-start requests create zero phantom aborted tasks
	concBlocker := make(chan struct{})
	blockerMu.Lock()
	activeBlocker = concBlocker
	blockerMu.Unlock()
	defer closeChannelSafe(concBlocker)

	var concWG sync.WaitGroup
	acceptedCount := 0
	conflictCount := 0
	var countMu sync.Mutex
	for i := 0; i < 5; i++ {
		concWG.Add(1)
		go func() {
			defer concWG.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"node":"Atlas"}`))
			addAuthAndCSRF(req, sessionCookie, srv.authMgr)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			countMu.Lock()
			switch rec.Code {
			case http.StatusAccepted:
				acceptedCount++
			case http.StatusConflict:
				conflictCount++
			default:
				t.Errorf("unexpected status code in concurrent scan test: %d (%s)", rec.Code, rec.Body.String())
			}
			countMu.Unlock()
		}()
	}
	concWG.Wait()
	closeChannelSafe(concBlocker)
	waitCtx2, waitCancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel2()
	if err := srv.Wait(waitCtx2); err != nil {
		t.Fatalf("srv.Wait after concurrent test failed: %v", err)
	}
	if acceptedCount != 1 || conflictCount != 4 {
		t.Fatalf("expected exactly 1 Accepted and 4 Conflict in concurrent start, got accepted=%d conflict=%d", acceptedCount, conflictCount)
	}
	allTasks, err := store.ListTasks(ctx, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range allTasks {
		if tk.Status == "aborted" {
			t.Fatalf("found unexpected phantom aborted task: %+v", tk)
		}
	}
}
