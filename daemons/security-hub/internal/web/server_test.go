package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type noopRunner struct{}

func (n *noopRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return []byte("running"), nil
}

func addAuthAndCSRF(req *http.Request, sessionCookie *http.Cookie, mgr *auth.Manager) {
	req.AddCookie(sessionCookie)
	if tok := mgr.CSRFTokenForRequest(req); tok != "" {
		req.Header.Set(auth.CSRFHeaderName, tok)
	}
}

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

type handlerRoundTripper struct {
	handler http.Handler
}

func (rt *handlerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Host, "atlas.lan") {
		w := httptest.NewRecorder()
		rt.handler.ServeHTTP(w, req)
		return w.Result(), nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}, nil
}

type mockCmdRunner struct {
	fn func(name string, args ...string) ([]byte, error)
}

func (m *mockCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return m.fn(name, args...)
}

func TestHubToAgent_MultiNodeScanAndRemoteUpdate(t *testing.T) {
	// 1. Setup Atlas Agent (no Docker installed, only Ollama & Brew)
	atlasDir := t.TempDir()
	atlasCfg := config.DefaultConfig()
	atlasCfg.NodeName = "Atlas"
	atlasCfg.AgentToken = "shared-secret-xyz"
	atlasCfg.Database.DataDir = atlasDir
	atlasCfg.Scanner.ServicesDir = filepath.Join(atlasDir, "no-services")

	var upgradedOnAtlas bool
	atlasRunner := &mockCmdRunner{
		fn: func(name string, args ...string) ([]byte, error) {
			if name == "docker" {
				return []byte("docker not installed"), errors.New("exit status 127")
			}
			if name == "ollama" && len(args) > 0 && args[0] == "--version" {
				return []byte("ollama version is 0.4.2"), nil
			}
			if name == "brew" && len(args) >= 2 && args[0] == "upgrade" && args[1] == "ollama" {
				upgradedOnAtlas = true
				return []byte("==> Upgrading ollama 0.4.2 -> 0.5.1 on Atlas"), nil
			}
			if name == "brew" && len(args) >= 2 && args[0] == "linkage" {
				return []byte(""), nil
			}
			return []byte(`{"formulae":[],"casks":[]}`), nil
		},
	}
	atlasStore, _ := db.NewSpoolStore(atlasDir, nil)
	atlasAuth, _ := auth.NewManager(atlasCfg.Auth, filepath.Join(atlasDir, "auth.json"))
	atlasOrch := scanner.NewOrchestrator(atlasCfg, atlasStore, atlasRunner, &http.Client{Transport: &handlerRoundTripper{}})
	atlasUpd := updater.NewManager(atlasCfg, atlasStore, atlasRunner, nil)
	atlasSrv := NewServer(atlasCfg, atlasStore, atlasOrch, atlasUpd, atlasAuth, nil)

	// 2. Setup Axis Hub connected to Atlas via in-memory LAN HTTP transport
	axisDir := t.TempDir()
	axisCfg := config.DefaultConfig()
	axisCfg.NodeName = "Axis"
	axisCfg.Database.DataDir = axisDir
	axisCfg.Scanner.ServicesDir = filepath.Join(axisDir, "services")
	axisStore, _ := db.NewSpoolStore(axisDir, nil)
	_ = axisStore.UpsertNode(context.Background(), models.NodeInfo{
		Name:  "Atlas",
		URL:   "http://atlas.lan:10247",
		Token: "shared-secret-xyz",
		Role:  "agent",
	})

	lanHTTP := &http.Client{Transport: &handlerRoundTripper{handler: atlasSrv.Handler()}}
	axisRunner := &mockCmdRunner{
		fn: func(name string, args ...string) ([]byte, error) {
			return []byte(`{"formulae":[],"casks":[]}`), nil
		},
	}
	axisOrch := scanner.NewOrchestrator(axisCfg, axisStore, axisRunner, lanHTTP)

	// 3. Run multi-node scan from Axis Hub -> verifies Atlas items are aggregated and Docker on Atlas is skipped gracefully
	scanRes, err := axisOrch.RunFullScan(context.Background())
	if err != nil {
		t.Fatalf("RunFullScan failed: %v", err)
	}
	var foundAtlasOllama bool
	for _, it := range scanRes.Items {
		if it.Node == "Atlas" && it.Name == "ollama" && it.CurrentVersion == "0.4.2" {
			foundAtlasOllama = true
		}
	}
	if !foundAtlasOllama {
		t.Fatalf("expected Axis multi-node scan to discover ollama 0.4.2 on Atlas, got items=%+v", scanRes.Items)
	}

	// 4. Trigger update for Atlas's ollama from Axis Hub -> verifies remote execution & log aggregation in Axis SpoolStore
	axisUpd := updater.NewManager(axisCfg, axisStore, axisRunner, nil)
	axisUpd.SetHTTPClient(lanHTTP)
	hubTask, _ := axisStore.CreateTask(context.Background(), &models.Task{
		Node:       "Atlas",
		TaskType:   "daemon_upgrade",
		TargetType: "daemon",
		TargetName: "ollama",
		ToVersion:  "0.5.1",
	})
	if err := axisUpd.RunUpdateSync(context.Background(), hubTask.ID, updater.UpdateRequest{
		Node:          "Atlas",
		TargetType:    "daemon",
		TargetName:    "ollama",
		TargetVersion: "0.5.1",
		TriggeredBy:   "oidc:admin",
	}); err != nil {
		t.Fatalf("remote update on Atlas failed: %v", err)
	}
	if !upgradedOnAtlas {
		t.Fatal("expected brew upgrade ollama to have executed on Atlas agent")
	}
	finalTask, logs, _ := axisStore.GetTaskWithLogs(context.Background(), hubTask.ID)
	if finalTask.Status != "succeeded" || len(logs) == 0 {
		t.Fatalf("expected succeeded task with logs from Atlas, got task=%+v logs=%+v", finalTask, logs)
	}
}

func setupTestHubServer(t *testing.T) (*Server, *http.Cookie, db.Store, *config.Config) {
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
	runner := &noopRunner{}
	alerter := notifier.NewAlerter(cfg.Notifications.Email, store)
	orch := scanner.NewOrchestrator(cfg, store, runner, nil)
	updMgr := updater.NewManager(cfg, store, runner, alerter)

	srv := NewServer(cfg, store, orch, updMgr, authMgr, alerter)

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
	return srv, cookies[0], store, cfg
}

type testRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (rt *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.fn(req)
}

func TestServer_NodeAnnounce_PendingAndApprovedTransitions(t *testing.T) {
	srv, sessionCookie, store, cfg := setupTestHubServer(t)
	h := srv.Handler()

	// 1. Announce with invalid token -> 401 Unauthorized
	badPayload, _ := json.Marshal(map[string]string{
		"name":       "MacStudio",
		"url":        "http://192.168.1.120:10247",
		"token":      "wrong-token",
		"os_version": "darwin/arm64",
	})
	badReq := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(badPayload))
	badW := httptest.NewRecorder()
	h.ServeHTTP(badW, badReq)
	if badW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid announce token, got %d", badW.Code)
	}

	// 2. Announce with valid token -> 200 OK with status: "pending"
	validPayload, _ := json.Marshal(map[string]string{
		"name":       "MacStudio",
		"url":        "http://192.168.1.120:10247",
		"token":      cfg.AgentToken,
		"os_version": "darwin/arm64",
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(validPayload))
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 on initial announce, got %d: %s", w1.Code, w1.Body.String())
	}
	var res1 map[string]any
	if err := json.Unmarshal(w1.Body.Bytes(), &res1); err != nil {
		t.Fatalf("failed to decode announce response: %v", err)
	}
	if res1["status"] != "pending" {
		t.Fatalf("expected status 'pending', got %v", res1["status"])
	}

	// Verify node in store has pending status
	node, err := store.GetNode(context.Background(), "MacStudio")
	if err != nil {
		t.Fatalf("node MacStudio not found in store: %v", err)
	}
	if node.Status != models.NodeStatusPending {
		t.Fatalf("expected node status 'pending', got %q", node.Status)
	}
	initialLastSeen := node.LastSeenAt

	// 3. Operator calls POST /api/nodes/approve?name=MacStudio -> 200 OK
	approveReq := httptest.NewRequest(http.MethodPost, "/api/nodes/approve?name=MacStudio", nil)
	addAuthAndCSRF(approveReq, sessionCookie, srv.authMgr)
	approveW := httptest.NewRecorder()
	h.ServeHTTP(approveW, approveReq)
	if approveW.Code != http.StatusOK {
		t.Fatalf("expected 200 on approve, got %d: %s", approveW.Code, approveW.Body.String())
	}

	nodeApproved, err := store.GetNode(context.Background(), "MacStudio")
	if err != nil || nodeApproved.Status != models.NodeStatusApproved {
		t.Fatalf("expected node to be approved, got status %q, err: %v", nodeApproved.Status, err)
	}

	// 4. Node announces again -> 200 OK with status: "approved" and updated LastSeenAt
	time.Sleep(10 * time.Millisecond) // ensure time diff
	updatedPayload, _ := json.Marshal(map[string]string{
		"name":       "MacStudio",
		"url":        "http://192.168.1.120:10247",
		"token":      cfg.AgentToken,
		"os_version": "darwin/arm64",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(updatedPayload))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 on re-announce, got %d: %s", w2.Code, w2.Body.String())
	}
	var res2 map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &res2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res2["status"] != "approved" {
		t.Fatalf("expected status 'approved', got %v", res2["status"])
	}

	nodeUpdated, _ := store.GetNode(context.Background(), "MacStudio")
	if nodeUpdated.URL != "http://192.168.1.120:10247" {
		t.Fatalf("expected URL, got %s", nodeUpdated.URL)
	}
	if !nodeUpdated.LastSeenAt.After(initialLastSeen) {
		t.Fatalf("expected LastSeenAt to advance, initial=%v new=%v", initialLastSeen, nodeUpdated.LastSeenAt)
	}

	// 4b. Security test: Approved node changes URL -> automatically demoted to "pending"
	relocatePayload, _ := json.Marshal(map[string]string{
		"name":       "MacStudio",
		"url":        "http://192.168.1.125:10247",
		"token":      cfg.AgentToken,
		"os_version": "darwin/arm64",
	})
	reqRelocate := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(relocatePayload))
	wRelocate := httptest.NewRecorder()
	h.ServeHTTP(wRelocate, reqRelocate)
	if wRelocate.Code != http.StatusOK {
		t.Fatalf("expected 200 on relocate announce, got %d: %s", wRelocate.Code, wRelocate.Body.String())
	}
	var resRelocate map[string]any
	if err := json.Unmarshal(wRelocate.Body.Bytes(), &resRelocate); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resRelocate["status"] != "pending" {
		t.Fatalf("expected status 'pending' on URL change, got %v", resRelocate["status"])
	}
	nodeRelocated, _ := store.GetNode(context.Background(), "MacStudio")
	if nodeRelocated.Status != models.NodeStatusPending {
		t.Fatalf("expected node status to be demoted to pending, got %q", nodeRelocated.Status)
	}
	if nodeRelocated.URL != "http://192.168.1.125:10247" {
		t.Fatalf("expected updated URL, got %s", nodeRelocated.URL)
	}

	// Re-approve before testing rejection
	_ = store.ApproveNode(context.Background(), "MacStudio")

	// 5. Operator calls POST /api/nodes/reject?name=MacStudio -> 200 OK
	rejectReq := httptest.NewRequest(http.MethodPost, "/api/nodes/reject?name=MacStudio", nil)
	addAuthAndCSRF(rejectReq, sessionCookie, srv.authMgr)
	rejectW := httptest.NewRecorder()
	h.ServeHTTP(rejectW, rejectReq)
	if rejectW.Code != http.StatusOK {
		t.Fatalf("expected 200 on reject, got %d: %s", rejectW.Code, rejectW.Body.String())
	}

	// 6. Rejected node announces again -> 403 Forbidden
	req3 := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(validPayload))
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, req3)
	if w3.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on announce after rejection, got %d", w3.Code)
	}
}

func TestServer_NodeTest_SuccessAndTimeout(t *testing.T) {
	srv, sessionCookie, _, _ := setupTestHubServer(t)
	h := srv.Handler()

	// 1. Mock HTTP agent returning 200 OK
	okAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-NAL-Node-Token") != "valid-agent-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.NodeInfo{
			Name:      "Atlas",
			Role:      "agent",
			Online:    true,
			OSVersion: "linux/amd64",
		})
	}))
	defer okAgent.Close()

	// 1a. Successful test with valid token
	testBody1, _ := json.Marshal(map[string]string{
		"url":   okAgent.URL,
		"token": "valid-agent-token",
	})
	testReq1 := httptest.NewRequest(http.MethodPost, "/api/nodes/test", bytes.NewReader(testBody1))
	addAuthAndCSRF(testReq1, sessionCookie, srv.authMgr)
	testW1 := httptest.NewRecorder()
	h.ServeHTTP(testW1, testReq1)
	if testW1.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/nodes/test, got %d: %s", testW1.Code, testW1.Body.String())
	}
	var res1 struct {
		OK        bool             `json:"ok"`
		LatencyMs int64            `json:"latency_ms"`
		OSVersion string           `json:"os_version"`
		Info      *models.NodeInfo `json:"info"`
		Error     string           `json:"error"`
	}
	if err := json.Unmarshal(testW1.Body.Bytes(), &res1); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !res1.OK || res1.OSVersion != "linux/amd64" || res1.Info == nil || res1.Info.Name != "Atlas" {
		t.Fatalf("unexpected success payload: %+v", res1)
	}

	// 2. Mock HTTP agent returning 401 Unauthorized
	testBody2, _ := json.Marshal(map[string]string{
		"url":   okAgent.URL,
		"token": "wrong-token",
	})
	testReq2 := httptest.NewRequest(http.MethodPost, "/api/nodes/test", bytes.NewReader(testBody2))
	addAuthAndCSRF(testReq2, sessionCookie, srv.authMgr)
	testW2 := httptest.NewRecorder()
	h.ServeHTTP(testW2, testReq2)
	if testW2.Code != http.StatusOK {
		t.Fatalf("expected 200 with ok:false on unauthorized probe, got %d", testW2.Code)
	}
	var res2 struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(testW2.Body.Bytes(), &res2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res2.OK || !strings.Contains(res2.Error, "invalid token") {
		t.Fatalf("expected ok:false and 'invalid token' error, got %+v", res2)
	}

	// 3. Non-responsive server aborts within 3s returning ok: false
	slowAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowAgent.Close()

	start := time.Now()
	testBody3, _ := json.Marshal(map[string]string{
		"url":   slowAgent.URL,
		"token": "valid-agent-token",
	})
	testReq3 := httptest.NewRequest(http.MethodPost, "/api/nodes/test", bytes.NewReader(testBody3))
	addAuthAndCSRF(testReq3, sessionCookie, srv.authMgr)
	testW3 := httptest.NewRecorder()
	h.ServeHTTP(testW3, testReq3)
	elapsed := time.Since(start)

	if testW3.Code != http.StatusOK {
		t.Fatalf("expected 200 HTTP code with JSON ok:false on timeout, got %d", testW3.Code)
	}
	var res3 struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(testW3.Body.Bytes(), &res3)
	if res3.OK {
		t.Fatalf("expected ok:false for timed out agent, got %+v", res3)
	}
	if elapsed > 3800*time.Millisecond {
		t.Fatalf("timeout took too long: %v (expected ~3s)", elapsed)
	}
	if elapsed < 2800*time.Millisecond {
		t.Fatalf("timeout was triggered too early: %v", elapsed)
	}
}

func TestOrchestrator_ExcludesPendingNodesFromFullScan(t *testing.T) {
	axisDir := t.TempDir()
	axisCfg := config.DefaultConfig()
	axisCfg.NodeName = "Axis"
	axisCfg.Database.DataDir = axisDir
	axisCfg.Scanner.ServicesDir = filepath.Join(axisDir, "services")
	axisStore, _ := db.NewSpoolStore(axisDir, nil)

	// Add an approved agent
	_ = axisStore.UpsertNode(context.Background(), models.NodeInfo{
		Name:   "ApprovedAgent",
		URL:    "http://approved.lan:10247",
		Token:  "token-1",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})

	// Add a pending agent
	_ = axisStore.UpsertNode(context.Background(), models.NodeInfo{
		Name:   "PendingAgent",
		URL:    "http://pending.lan:10247",
		Token:  "token-2",
		Role:   "agent",
		Status: models.NodeStatusPending,
	})

	var mu sync.Mutex
	requestedHosts := make([]string, 0)

	mockClient := &http.Client{
		Transport: &testRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				mu.Lock()
				requestedHosts = append(requestedHosts, req.URL.Host)
				mu.Unlock()

				respBody := `{"node":"ApprovedAgent","items":[]}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(respBody)),
					Header:     make(http.Header),
				}, nil
			},
		},
	}

	runner := &noopRunner{}
	axisOrch := scanner.NewOrchestrator(axisCfg, axisStore, runner, mockClient)

	scanRes, err := axisOrch.RunFullScan(context.Background())
	if err != nil {
		t.Fatalf("RunFullScan failed: %v", err)
	}

	mu.Lock()
	hosts := append([]string(nil), requestedHosts...)
	mu.Unlock()

	for _, h := range hosts {
		if strings.Contains(h, "pending") {
			t.Fatalf("pending node was contacted by RunFullScan: %s", h)
		}
	}
	var contactedApproved bool
	for _, h := range hosts {
		if strings.Contains(h, "approved") {
			contactedApproved = true
		}
	}
	if !contactedApproved {
		t.Fatal("expected approved node to be contacted by RunFullScan")
	}

	// Verify scanRes.Nodes strictly contains Hub and ApprovedAgent, not PendingAgent
	for _, n := range scanRes.Nodes {
		if n.Name == "PendingAgent" || n.Status == models.NodeStatusPending {
			t.Fatalf("scanRes.Nodes contains pending node: %+v", n)
		}
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

func TestWebAssets_PendingNodesAndScanProgress(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Database.DataDir = filepath.Join(root, "data")
	store, err := db.NewSpoolStore(cfg.Database.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewManager(cfg.Auth, filepath.Join(cfg.Database.DataDir, "auth_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(cfg, store, nil, nil, authMgr, nil)
	h := srv.Handler()

	// 1. Verify index.html via direct embed and via HTTP server
	indexBytes, err := staticEmbedFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("failed to read embedded index.html: %v", err)
	}
	indexHTML := string(indexBytes)

	reqIndex := httptest.NewRequest(http.MethodGet, "/", nil)
	wIndex := httptest.NewRecorder()
	h.ServeHTTP(wIndex, reqIndex)
	if wIndex.Code != http.StatusOK {
		t.Fatalf("expected 200 for /, got %d", wIndex.Code)
	}

	for _, elem := range []string{
		`id="root"`,
		"/app.js",
		"/styles.css",
	} {
		if !strings.Contains(indexHTML, elem) {
			t.Errorf("expected embedded index.html to contain %q", elem)
		}
		if !strings.Contains(wIndex.Body.String(), elem) {
			t.Errorf("expected served /index.html to contain %q", elem)
		}
	}

	// 2. Verify styles.css via direct embed and via HTTP server
	cssBytes, err := staticEmbedFS.ReadFile("static/styles.css")
	if err != nil {
		t.Fatalf("failed to read embedded styles.css: %v", err)
	}
	cssText := string(cssBytes)

	reqCSS := httptest.NewRequest(http.MethodGet, "/styles.css", nil)
	wCSS := httptest.NewRecorder()
	h.ServeHTTP(wCSS, reqCSS)
	if wCSS.Code != http.StatusOK {
		t.Fatalf("expected 200 for /styles.css, got %d", wCSS.Code)
	}

	for _, selector := range []string{
		".node-pill.scanning",
		".dot.scanning",
		".node-scan-status",
		".scan-node-option",
	} {
		if !strings.Contains(cssText, selector) {
			t.Errorf("expected embedded styles.css to contain %q", selector)
		}
		if !strings.Contains(wCSS.Body.String(), selector) {
			t.Errorf("expected served /styles.css to contain %q", selector)
		}
	}

	// 3. Verify compiled React app.js via direct embed and via HTTP server
	appBytes, err := staticEmbedFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("failed to read embedded app.js: %v", err)
	}
	appJS := string(appBytes)

	reqApp := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	wApp := httptest.NewRecorder()
	h.ServeHTTP(wApp, reqApp)
	if wApp.Code != http.StatusOK {
		t.Fatalf("expected 200 for /app.js, got %d", wApp.Code)
	}

	for _, token := range []string{
		"btn-test-node",
		"pending-nodes-banner",
		"scan-progress-pill",
		"pending-nodes-container",
		"scan-progress-box",
		"test-node-result",
		"pending-nodes-section",
		"pending-nodes-list",
		"btn-scan-node",
		"btn-scan-now",
		"modal-scan-node",
		"scan-node-modal-list",
		"btn-confirm-scan-node",
		"node-scan-status",
		"/api/nodes/approve",
		"/api/nodes/reject",
		"/api/nodes/test",
		"/api/tasks/",
		"/api/scan",
		"/api/dashboard",
		"EventSource",
	} {
		if !strings.Contains(appJS, token) {
			t.Errorf("expected embedded app.js to contain %q", token)
		}
		if !strings.Contains(wApp.Body.String(), token) {
			t.Errorf("expected served /app.js to contain %q", token)
		}
	}
}

func TestNodeAnnounce_RejectsHubNodeNameConflict(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.NodeName = "Axis"
	cfg.AgentToken = "secret-token-123"

	store, err := db.NewSpoolStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewManager(cfg.Auth, filepath.Join(root, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(cfg, store, nil, nil, authMgr, nil)
	h := srv.Handler()

	// 1. Conflict with exact hub node name
	body1 := `{"name":"Axis","url":"http://192.168.1.50:10247","token":"secret-token-123"}`
	req1 := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", strings.NewReader(body1))
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, req1)
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for exact hub node name conflict, got %d: %s", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), "agent node name conflicts with hub node name") {
		t.Fatalf("unexpected error response: %s", w1.Body.String())
	}

	// 2. Conflict with case-insensitive hub node name
	body2 := `{"name":"axis","url":"http://192.168.1.50:10247","token":"secret-token-123"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", strings.NewReader(body2))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for case-insensitive hub node name conflict, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "agent node name conflicts with hub node name") {
		t.Fatalf("unexpected error response: %s", w2.Body.String())
	}

	// 3. Different name succeeds with 200 OK
	body3 := `{"name":"Atlas","url":"http://192.168.1.50:10247","token":"secret-token-123"}`
	req3 := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", strings.NewReader(body3))
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-conflicting node announcement, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestNodeTest_ProbeClientSafety_NoRedirectAndLimitReader(t *testing.T) {
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
	srv := NewServer(cfg, store, nil, nil, authMgr, nil)

	tok, err := authMgr.GenerateBreakGlassToken(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loginW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginW, httptest.NewRequest(http.MethodGet, "/api/auth/token-login?token="+tok, nil))
	sessionCookie := loginW.Result().Cookies()[0]

	// 1. Redirect safety: target server returns a redirect (HTTP 302)
	redirectReceived := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer agentServer.Close()

	srv.SetHTTPClient(agentServer.Client())

	reqBody := fmt.Sprintf(`{"url":%q,"token":"secret"}`, agentServer.URL)
	testReq := httptest.NewRequest(http.MethodPost, "/api/nodes/test", strings.NewReader(reqBody))
	addAuthAndCSRF(testReq, sessionCookie, authMgr)
	testW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(testW, testReq)

	if redirectReceived {
		t.Fatal("probe client followed redirect, leaking probe token or request to redirect target!")
	}
	var testResp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(testW.Body.Bytes(), &testResp)
	if testResp.OK {
		t.Fatal("expected test to report error due to redirect 302, got OK=true")
	}
	if !strings.Contains(testResp.Error, "HTTP 302") {
		t.Fatalf("expected error to mention HTTP 302, got %q", testResp.Error)
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

func TestServer_AgentTokenPreHashedAndTrailingSlashNormalization(t *testing.T) {
	srv, sessionCookie, store, cfg := setupTestHubServer(t)
	h := srv.Handler()

	// 1. requireAgentToken with various token lengths (leaks length if not pre-hashed)
	for _, badToken := range []string{"", "short", "longer-than-the-actual-agent-token-123456789"} {
		req := httptest.NewRequest(http.MethodGet, "/api/agent/info", nil)
		req.Header.Set("X-NAL-Node-Token", badToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for bad token %q, got %d", badToken, w.Code)
		}
	}
	// Valid agent token succeeds
	reqValid := httptest.NewRequest(http.MethodGet, "/api/agent/info", nil)
	reqValid.Header.Set("X-NAL-Node-Token", cfg.AgentToken)
	wValid := httptest.NewRecorder()
	h.ServeHTTP(wValid, reqValid)
	if wValid.Code != http.StatusOK {
		t.Errorf("expected 200 for valid token, got %d", wValid.Code)
	}

	// 2. Trailing slash normalization in node announcement
	annPayload, _ := json.Marshal(map[string]string{
		"name":  "SlashNode",
		"url":   "http://192.168.1.130:10247/",
		"token": cfg.AgentToken,
	})
	annReq := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(annPayload))
	annW := httptest.NewRecorder()
	h.ServeHTTP(annW, annReq)
	if annW.Code != http.StatusOK {
		t.Fatalf("expected 200 on initial announce, got %d", annW.Code)
	}
	_ = store.ApproveNode(context.Background(), "SlashNode")

	// Re-announce WITHOUT trailing slash: should remain approved (not demoted)
	reAnnPayload, _ := json.Marshal(map[string]string{
		"name":  "SlashNode",
		"url":   "http://192.168.1.130:10247",
		"token": cfg.AgentToken,
	})
	reAnnReq := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(reAnnPayload))
	reAnnW := httptest.NewRecorder()
	h.ServeHTTP(reAnnW, reAnnReq)
	if reAnnW.Code != http.StatusOK {
		t.Fatalf("expected 200 on re-announce, got %d", reAnnW.Code)
	}
	var reAnnRes map[string]any
	_ = json.Unmarshal(reAnnW.Body.Bytes(), &reAnnRes)
	if reAnnRes["status"] != "approved" {
		t.Errorf("expected status 'approved' despite trailing slash difference, got %v", reAnnRes["status"])
	}

	// 3. POST /api/nodes manual node addition
	// 3a. Reject node with Hub's name
	hubConflictBody, _ := json.Marshal(map[string]string{
		"name": cfg.NodeName,
		"url":  "http://192.168.1.140:10247",
	})
	conflictReq := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(hubConflictBody))
	addAuthAndCSRF(conflictReq, sessionCookie, srv.authMgr)
	conflictW := httptest.NewRecorder()
	h.ServeHTTP(conflictW, conflictReq)
	if conflictW.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when manually adding node with Hub name, got %d", conflictW.Code)
	}

	// 3b. Normalizes trailing slash on valid manual add
	manualAddBody, _ := json.Marshal(map[string]string{
		"name": "ManualSlashNode",
		"url":  "http://192.168.1.141:10247/",
	})
	manReq := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(manualAddBody))
	addAuthAndCSRF(manReq, sessionCookie, srv.authMgr)
	manW := httptest.NewRecorder()
	h.ServeHTTP(manW, manReq)
	if manW.Code != http.StatusOK {
		t.Fatalf("expected 200 on manual add, got %d", manW.Code)
	}
	manNode, err := store.GetNode(context.Background(), "ManualSlashNode")
	if err != nil {
		t.Fatalf("failed to get ManualSlashNode: %v", err)
	}
	if manNode.URL != "http://192.168.1.141:10247" {
		t.Errorf("expected trailing slash to be trimmed on manual add, got %q", manNode.URL)
	}
}

func TestNodeTest_TokenFallbackAndSchemeNormalization(t *testing.T) {
	srv, sessionCookie, _, _ := setupTestHubServer(t)
	h := srv.Handler()

	var receivedToken string
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/info" {
			receivedToken = r.Header.Get("X-NAL-Node-Token")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node":       "test-agent",
				"version":    "1.0.0",
				"os_version": "darwin/arm64",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer agentSrv.Close()

	// 1. Without token in test request: falls back to cfg.AgentToken ("shared-cluster-token")
	// 2. URL provided without scheme: should normalize to http://
	rawTarget := strings.TrimPrefix(agentSrv.URL, "http://")
	testBody, _ := json.Marshal(map[string]string{
		"url": rawTarget,
	})
	testReq := httptest.NewRequest(http.MethodPost, "/api/nodes/test", bytes.NewReader(testBody))
	addAuthAndCSRF(testReq, sessionCookie, srv.authMgr)
	testW := httptest.NewRecorder()
	h.ServeHTTP(testW, testReq)

	if testW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", testW.Code, testW.Body.String())
	}
	var res map[string]any
	_ = json.Unmarshal(testW.Body.Bytes(), &res)
	if res["ok"] != true {
		t.Fatalf("expected ok=true for normalized test url, got %+v", res)
	}
	if receivedToken != "shared-cluster-token" {
		t.Fatalf("expected fallback token 'shared-cluster-token', got %q", receivedToken)
	}
}

func TestNodeAnnounce_BodyLimitAndSchemeNormalization(t *testing.T) {
	cfg := &config.Config{
		NodeName:   "HubCentral",
		AgentToken: "cluster-secret",
	}
	store, _ := db.NewSpoolStore(t.TempDir(), nil)
	authMgr, _ := auth.NewManager(cfg.Auth, "")

	srv := NewServer(cfg, store, nil, nil, authMgr, nil)
	h := srv.Handler()

	// 1. Scheme normalization on announce URL
	body, _ := json.Marshal(map[string]string{
		"name":  "NoSchemeAgent",
		"url":   "192.168.1.180:10247",
		"token": "cluster-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	node, err := store.GetNode(context.Background(), "NoSchemeAgent")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if node.URL != "http://192.168.1.180:10247" {
		t.Errorf("expected normalized http scheme, got %q", node.URL)
	}

	// 2. Body limit protection on /api/nodes/announce: > 1MB should be rejected
	largeBody := bytes.Repeat([]byte("a"), (1<<20)+1024)
	largeReq := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(largeBody))
	largeW := httptest.NewRecorder()
	h.ServeHTTP(largeW, largeReq)
	if largeW.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for body exceeding 1MB limit, got %d", largeW.Code)
	}
}

func TestRaspberryPiAgent_AptScanAndRemoteUpgrade(t *testing.T) {
	// 1. Setup Raspberry Pi Agent node running APT only (no Docker or Homebrew)
	rpiDir := t.TempDir()
	rpiCfg := config.DefaultConfig()
	rpiCfg.NodeName = "RPi-01"
	rpiCfg.AgentToken = "rpi-secret-token"
	rpiCfg.Database.DataDir = rpiDir
	rpiCfg.Scanner.ServicesDir = filepath.Join(rpiDir, "no-services")

	var upgradedAptPkg bool
	rpiRunner := &mockCmdRunner{
		fn: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case name == "docker" || name == "brew" || name == "ollama" || name == "sw_vers" || name == "softwareupdate":
				return nil, errors.New("not installed")
			case name == "dpkg-query":
				return []byte("openssl\t3.0.11-1~deb12u2\tinstalled\n"), nil
			case strings.Contains(cmdLine, "apt-get update"):
				return []byte(""), nil
			case strings.Contains(cmdLine, "apt list --upgradable"):
				return []byte("Listing...\nopenssl/stable-security 3.0.14-1~deb12u1 arm64 [upgradable from: 3.0.11-1~deb12u2]\n"), nil
			case strings.Contains(cmdLine, "apt-mark showmanual"):
				return []byte("openssl\n"), nil
			case strings.Contains(cmdLine, "dpkg --audit") || strings.Contains(cmdLine, "apt-get -o Debug::NoLocking=true check"):
				return []byte(""), nil
			case strings.Contains(cmdLine, "apt-get install --only-upgrade -y") && strings.HasSuffix(cmdLine, " openssl"):
				upgradedAptPkg = true
				return []byte("Unpacking openssl (3.0.14-1~deb12u1) ...\nSetting up openssl (3.0.14-1~deb12u1) ..."), nil
			case strings.Contains(cmdLine, "dpkg -s -- openssl"):
				return []byte("Package: openssl\nStatus: install ok installed\n"), nil
			default:
				return nil, nil
			}
		},
	}

	rpiStore, _ := db.NewSpoolStore(rpiDir, nil)
	rpiAuth, _ := auth.NewManager(rpiCfg.Auth, filepath.Join(rpiDir, "auth.json"))
	rpiOrch := scanner.NewOrchestrator(rpiCfg, rpiStore, rpiRunner, &http.Client{Transport: &handlerRoundTripper{}})
	rpiUpd := updater.NewManager(rpiCfg, rpiStore, rpiRunner, nil)
	rpiSrv := NewServer(rpiCfg, rpiStore, rpiOrch, rpiUpd, rpiAuth, nil)

	// 2. Setup Hub connected to Raspberry Pi Agent
	hubDir := t.TempDir()
	hubCfg := config.DefaultConfig()
	hubCfg.NodeName = "Axis"
	hubCfg.Database.DataDir = hubDir
	hubCfg.Scanner.ServicesDir = filepath.Join(hubDir, "services")
	hubStore, _ := db.NewSpoolStore(hubDir, nil)
	_ = hubStore.UpsertNode(context.Background(), models.NodeInfo{
		Name:   "RPi-01",
		URL:    "http://atlas.lan:10247",
		Token:  "rpi-secret-token",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})

	lanHTTP := &http.Client{Transport: &handlerRoundTripper{handler: rpiSrv.Handler()}}
	hubRunner := &mockCmdRunner{
		fn: func(name string, args ...string) ([]byte, error) {
			return nil, errors.New("not installed")
		},
	}
	hubOrch := scanner.NewOrchestrator(hubCfg, hubStore, hubRunner, lanHTTP)

	// 3. Multi-node scan discovers outdated apt package on RPi-01
	scanRes, err := hubOrch.RunFullScan(context.Background())
	if err != nil {
		t.Fatalf("RunFullScan failed: %v", err)
	}
	var foundApt bool
	for _, it := range scanRes.Items {
		if it.Node == "RPi-01" && it.TargetType == models.TargetApt && it.Name == "openssl" && it.Outdated && it.LatestVersion == "3.0.14-1~deb12u1" {
			foundApt = true
		}
	}
	if !foundApt {
		t.Fatalf("expected Hub scan to discover outdated apt openssl on RPi-01, got items=%+v", scanRes.Items)
	}

	// 4. Remote upgrade for RPi-01 apt package executes via agent and aggregates logs
	hubUpd := updater.NewManager(hubCfg, hubStore, hubRunner, nil)
	hubUpd.SetHTTPClient(lanHTTP)
	hubTask, _ := hubStore.CreateTask(context.Background(), &models.Task{
		Node:       "RPi-01",
		TaskType:   "apt_upgrade",
		TargetType: string(models.TargetApt),
		TargetName: "openssl",
		ToVersion:  "3.0.14-1~deb12u1",
	})
	if err := hubUpd.RunUpdateSync(context.Background(), hubTask.ID, updater.UpdateRequest{
		Node:          "RPi-01",
		TargetType:    string(models.TargetApt),
		TargetName:    "openssl",
		TargetVersion: "3.0.14-1~deb12u1",
		TriggeredBy:   "web:admin",
	}); err != nil {
		t.Fatalf("remote apt upgrade on RPi-01 failed: %v", err)
	}
	if !upgradedAptPkg {
		t.Fatal("expected apt-get install --only-upgrade -y openssl to execute on RPi-01 agent")
	}
	finalTask, logs, _ := hubStore.GetTaskWithLogs(context.Background(), hubTask.ID)
	if finalTask.Status != "succeeded" || len(logs) == 0 {
		t.Fatalf("expected succeeded task with logs from RPi-01, got task=%+v logs=%+v", finalTask, logs)
	}

	// 5. Verify Web UI assets include shared System Packages tab, security checks, and node-scoped skip
	appBytes, _ := staticEmbedFS.ReadFile("static/app.js")
	appText := string(appBytes)
	if !strings.Contains(appText, "System Packages (`brew` / `apt`)") {
		t.Error("expected app.js bundle to display shared System Packages (`brew` / `apt`) tab")
	}
	if !strings.Contains(appText, `target_type==="apt"`) || !strings.Contains(appText, `/^https?:\/\//i`) {
		t.Error("expected app.js bundle to handle item.target_type === 'apt' and validate safe HTTP URLs")
	}

	// 6. Verify node-scoped POST/DELETE /api/skip isolates RPi-01 from RPi-02
	hubAuthMgr, _ := auth.NewManager(hubCfg.Auth, filepath.Join(hubDir, "auth.json"))
	hubSrv := NewServer(hubCfg, hubStore, hubOrch, hubUpd, hubAuthMgr, nil)
	hubH := hubSrv.Handler()
	tok, _ := hubAuthMgr.GenerateBreakGlassToken(5 * time.Minute)
	loginW := httptest.NewRecorder()
	hubH.ServeHTTP(loginW, httptest.NewRequest(http.MethodGet, "/api/auth/token-login?token="+tok, nil))
	cookie := loginW.Result().Cookies()[0]

	skipBody, _ := json.Marshal(map[string]string{
		"node":        "RPi-01",
		"target_type": "apt",
		"target_name": "openssl",
		"version":     "3.0.14-1~deb12u1",
	})
	skipReq := httptest.NewRequest(http.MethodPost, "/api/skip", bytes.NewReader(skipBody))
	addAuthAndCSRF(skipReq, cookie, hubAuthMgr)
	skipW := httptest.NewRecorder()
	hubH.ServeHTTP(skipW, skipReq)
	if skipW.Code != http.StatusOK {
		t.Fatalf("POST /api/skip returned %d", skipW.Code)
	}

	skippedMap, _ := hubStore.ListSkippedVersions(context.Background())
	multiItems := []models.ManagedItem{
		{Node: "RPi-01", TargetType: models.TargetApt, Name: "openssl", LatestVersion: "3.0.14-1~deb12u1", Outdated: true},
		{Node: "RPi-02", TargetType: models.TargetApt, Name: "openssl", LatestVersion: "3.0.14-1~deb12u1", Outdated: true},
	}
	summarized := scanner.ApplySkippedAndSummarize(multiItems, skippedMap)
	if !summarized.Items[0].Skipped || summarized.Items[0].Outdated {
		t.Fatalf("expected RPi-01 openssl skipped, got %+v", summarized.Items[0])
	}
	if summarized.Items[1].Skipped || !summarized.Items[1].Outdated {
		t.Fatalf("expected RPi-02 openssl NOT skipped when only RPi-01 skipped, got %+v", summarized.Items[1])
	}

	unskipReq := httptest.NewRequest(http.MethodDelete, "/api/skip?node=RPi-01&target_type=apt&target_name=openssl", nil)
	addAuthAndCSRF(unskipReq, cookie, hubAuthMgr)
	unskipW := httptest.NewRecorder()
	hubH.ServeHTTP(unskipW, unskipReq)
	if unskipW.Code != http.StatusOK {
		t.Fatalf("DELETE /api/skip returned %d", unskipW.Code)
	}
	skippedAfter, _ := hubStore.ListSkippedVersions(context.Background())
	if _, stillExists := skippedAfter["RPi-01:apt:openssl"]; stillExists {
		t.Fatalf("expected RPi-01:apt:openssl to be removed after DELETE /api/skip, got %v", skippedAfter)
	}
}

func TestServer_SecurityHardening_CSRF_SyncValidation_SSE404_AgentHandler(t *testing.T) {
	srv, sessionCookie, store, cfg := setupTestHubServer(t)
	h := srv.Handler()

	// 1. Logout rejects GET and blocks CSRF without X-CSRF-Token
	getLogoutW := httptest.NewRecorder()
	h.ServeHTTP(getLogoutW, httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil))
	if getLogoutW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /api/auth/logout, got %d", getLogoutW.Code)
	}

	noCsrfReq := httptest.NewRequest(http.MethodPost, "/api/skip", strings.NewReader(`{"target_type":"docker","target_name":"db","version":"17"}`))
	noCsrfReq.AddCookie(sessionCookie)
	noCsrfW := httptest.NewRecorder()
	h.ServeHTTP(noCsrfW, noCsrfReq)
	if noCsrfW.Code != http.StatusForbidden || !strings.Contains(noCsrfW.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected 403 JSON on POST /api/skip without X-CSRF-Token, got %d ct=%q", noCsrfW.Code, noCsrfW.Header().Get("Content-Type"))
	}

	sameSiteReq := httptest.NewRequest(http.MethodPost, "/api/skip", strings.NewReader(`{"target_type":"docker","target_name":"db","version":"17"}`))
	addAuthAndCSRF(sameSiteReq, sessionCookie, srv.authMgr)
	sameSiteReq.Header.Set("Sec-Fetch-Site", "same-site")
	sameSiteW := httptest.NewRecorder()
	h.ServeHTTP(sameSiteW, sameSiteReq)
	if sameSiteW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on Sec-Fetch-Site=same-site, got %d", sameSiteW.Code)
	}

	// 2. Synchronous /api/update validation rejects invalid tag before creating background task
	badUpdateReq := httptest.NewRequest(http.MethodPost, "/api/update", strings.NewReader(`{"target_type":"docker","target_name":"db","target_version":"16.0\nprivileged: true"}`))
	addAuthAndCSRF(badUpdateReq, sessionCookie, srv.authMgr)
	badUpdateW := httptest.NewRecorder()
	h.ServeHTTP(badUpdateW, badUpdateReq)
	if badUpdateW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on invalid /api/update tag, got %d: %s", badUpdateW.Code, badUpdateW.Body.String())
	}

	// 3. SSE stream returns 404 JSON error on unknown taskID before setting text/event-stream headers
	sse404Req := httptest.NewRequest(http.MethodGet, "/api/tasks/nonexistent-task/stream", nil)
	sse404Req.AddCookie(sessionCookie)
	sse404W := httptest.NewRecorder()
	h.ServeHTTP(sse404W, sse404Req)
	if sse404W.Code != http.StatusNotFound || !strings.Contains(sse404W.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected 404 JSON on unknown task stream, got %d ct=%q", sse404W.Code, sse404W.Header().Get("Content-Type"))
	}

	// 4. AgentHandler restricts routes exclusively to /api/agent/* and propagates Docker HasRollback
	_ = store.SaveSnapshot(context.Background(), &models.RollbackSnapshot{
		ID:              "snap-db-1",
		ServiceName:     "db",
		PreviousVersion: "16.4-alpine",
	})
	agentH := srv.AgentHandler()
	for _, hubRoute := range []string{"/", "/api/dashboard", "/api/auth/session", "/api/update", "/api/nodes/announce"} {
		w := httptest.NewRecorder()
		agentH.ServeHTTP(w, httptest.NewRequest(http.MethodGet, hubRoute, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 on hub route %s when using AgentHandler, got %d", hubRoute, w.Code)
		}
	}

	// /api/agent/rollback nonexistent snapshot does not nil-panic
	rbReq := httptest.NewRequest(http.MethodPost, "/api/agent/rollback", strings.NewReader(`{"service_name":"db"}`))
	rbReq.Header.Set("X-NAL-Node-Token", cfg.AgentToken)
	rbW := httptest.NewRecorder()
	agentH.ServeHTTP(rbW, rbReq)
	if rbW.Code != http.StatusOK && rbW.Code != http.StatusBadRequest {
		t.Fatalf("expected clean response from /api/agent/rollback, got %d: %s", rbW.Code, rbW.Body.String())
	}
}

func TestServer_Round2_AuthNil503_SSEShutdownWakeup_And_AtomicAnnounce(t *testing.T) {
	ctx := context.Background()

	// 1. Server with nil authMgr serves Handler() cleanly and returns 503 JSON on protected/auth routes
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.AgentToken = "announce-secret"
	nilAuthSrv := NewServer(cfg, store, nil, nil, nil, nil)
	nilH := nilAuthSrv.Handler()

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/auth/oidc/login"},
		{http.MethodGet, "/api/auth/oidc/callback"},
		{http.MethodGet, "/api/auth/token-login?token=abc"},
		{http.MethodPost, "/api/auth/passkey/login/begin"},
		{http.MethodGet, "/api/dashboard"},
		{http.MethodPost, "/api/update"},
		{http.MethodPost, "/api/rollback"},
		{http.MethodPost, "/api/skip"},
	} {
		w := httptest.NewRecorder()
		nilH.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 on %s %s with nil authMgr, got %d (%s)", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	// Direct calls with nil authMgr do not panic either
	for _, fn := range []http.HandlerFunc{
		nilAuthSrv.handleUpdate,
		nilAuthSrv.handleRollback,
		nilAuthSrv.handleSkip,
	} {
		w := httptest.NewRecorder()
		fn(w, httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("{}")))
	}

	// 2. handleNodeAnnounce uses atomic AnnounceNode (URL change demotes approved -> pending, rejected -> 403)
	announceReq := func(payload string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", strings.NewReader(payload))
		nilH.ServeHTTP(w, r)
		return w
	}
	w1 := announceReq(`{"name":"rpi-edge","url":"http://10.0.0.50:10247","token":"announce-secret","os_version":"debian/12"}`)
	if w1.Code != http.StatusOK || !strings.Contains(w1.Body.String(), `"pending"`) {
		t.Fatalf("expected initial announce 200 pending, got %d: %s", w1.Code, w1.Body.String())
	}
	if err := store.ApproveNode(ctx, "rpi-edge"); err != nil {
		t.Fatal(err)
	}
	w2 := announceReq(`{"name":"rpi-edge","url":"http://10.0.0.99:10247","token":"announce-secret"}`)
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), `"pending"`) {
		t.Fatalf("expected URL change announce 200 demoted to pending, got %d: %s", w2.Code, w2.Body.String())
	}
	if err := store.RejectNode(ctx, "rpi-edge"); err != nil {
		t.Fatal(err)
	}
	w3 := announceReq(`{"name":"rpi-edge","url":"http://10.0.0.99:10247","token":"announce-secret"}`)
	if w3.Code != http.StatusForbidden {
		t.Fatalf("expected rejected node announce 403 Forbidden, got %d: %s", w3.Code, w3.Body.String())
	}

	// 3. NotifyShutdown registered on http.Server unblocks active SSE task log stream immediately
	srv, sessionCookie, hubStore, _ := setupTestHubServer(t)
	runningTask, err := hubStore.CreateTask(ctx, &models.Task{
		Node:       "hub",
		TaskType:   "docker_update",
		TargetType: "docker",
		TargetName: "db",
		Status:     "running",
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Config.RegisterOnShutdown(srv.NotifyShutdown)
	ts.Start()
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/tasks/"+runningTask.ID+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(sessionCookie)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("SSE GET failed: %v", err)
	}
	defer resp.Body.Close()

	shutCtx, shutCancel := context.WithTimeout(ctx, 2*time.Second)
	defer shutCancel()
	if err := ts.Config.Shutdown(shutCtx); err != nil {
		t.Fatalf("expected HTTP server Shutdown to complete promptly after NotifyShutdown unblocked SSE stream, got: %v", err)
	}
}

type blockingScanRunner struct {
	startedOnce sync.Once
	started     chan struct{}
}

func (b *blockingScanRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	b.startedOnce.Do(func() {
		close(b.started)
	})
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestServer_Round3_AgentURLValidation_And_ManualScanShutdownWait(t *testing.T) {
	srv, sessionCookie, _, cfg := setupTestHubServer(t)
	h := srv.Handler()

	// 1. POST /api/nodes and POST /api/nodes/announce reject non-HTTP/hostless agent URLs
	for _, badURL := range []string{"ftp://files.internal/pkg", "http://:10247", "://bad"} {
		body := fmt.Sprintf(`{"name":"bad-node","url":%q,"token":%q}`, badURL, cfg.AgentToken)
		reqAdd := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(body))
		addAuthAndCSRF(reqAdd, sessionCookie, srv.authMgr)
		wAdd := httptest.NewRecorder()
		h.ServeHTTP(wAdd, reqAdd)
		if wAdd.Code != http.StatusBadRequest {
			t.Fatalf("expected POST /api/nodes to reject %q with 400, got %d (%s)", badURL, wAdd.Code, wAdd.Body.String())
		}

		reqAnn := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", strings.NewReader(body))
		wAnn := httptest.NewRecorder()
		h.ServeHTTP(wAnn, reqAnn)
		if wAnn.Code != http.StatusBadRequest {
			t.Fatalf("expected POST /api/nodes/announce to reject %q with 400, got %d (%s)", badURL, wAnn.Code, wAnn.Body.String())
		}
	}

	// 2. Manual POST /api/scan goroutine cancels on NotifyShutdown and Wait completes cleanly
	ctx := context.Background()
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scanCfg := config.DefaultConfig()
	scanCfg.Auth.SessionSecret = cfg.Auth.SessionSecret
	authMgr, err := auth.NewManager(scanCfg.Auth, filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	blockRunner := &blockingScanRunner{started: make(chan struct{})}
	scanCfg.Scanner.ServicesDir = t.TempDir()
	scanCfg.Scanner.DaemonsDir = t.TempDir()
	orch := scanner.NewOrchestrator(scanCfg, store, blockRunner, nil)
	scanSrv := NewServer(scanCfg, store, orch, nil, authMgr, nil)

	recLogin := httptest.NewRecorder()
	_ = authMgr.IssueSessionCookie(recLogin, "admin@example.com", "oidc")
	var cookie *http.Cookie
	for _, c := range recLogin.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			cookie = c
			break
		}
	}

	scanReq := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	addAuthAndCSRF(scanReq, cookie, authMgr)
	scanW := httptest.NewRecorder()
	scanSrv.Handler().ServeHTTP(scanW, scanReq)
	if scanW.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for POST /api/scan, got %d: %s", scanW.Code, scanW.Body.String())
	}

	select {
	case <-blockRunner.started:
	case <-time.After(3 * time.Second):
		t.Fatal("manual scan goroutine did not start runner")
	}

	scanSrv.NotifyShutdown()
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	if err := scanSrv.Wait(waitCtx); err != nil {
		t.Fatalf("expected Server.Wait to complete after NotifyShutdown cancelled manual scan, got: %v", err)
	}

	// 3. POST /api/nodes/test rejects hostless URL http://:10247 without probing loopback
	badTestReq := httptest.NewRequest(http.MethodPost, "/api/nodes/test", strings.NewReader(`{"url":"http://:10247"}`))
	addAuthAndCSRF(badTestReq, sessionCookie, srv.authMgr)
	badTestW := httptest.NewRecorder()
	h.ServeHTTP(badTestW, badTestReq)
	if badTestW.Code != http.StatusOK {
		t.Fatalf("expected 200 JSON nodeTestResponse, got %d", badTestW.Code)
	}
	var testResp nodeTestResponse
	if err := json.Unmarshal(badTestW.Body.Bytes(), &testResp); err != nil || testResp.OK || !strings.Contains(testResp.Error, "invalid url") {
		t.Fatalf("expected hostless URL rejected with OK=false invalid url, got %+v err=%v", testResp, err)
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
			if rec.Code == http.StatusAccepted {
				acceptedCount++
			} else if rec.Code == http.StatusConflict {
				conflictCount++
			} else {
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
