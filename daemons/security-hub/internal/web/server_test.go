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
	skipReq.AddCookie(sessionCookie)
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
	unskipReq.AddCookie(sessionCookie)
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
	nodeAddReq.AddCookie(sessionCookie)
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
	approveReq.AddCookie(sessionCookie)
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
	rejectReq.AddCookie(sessionCookie)
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
	testReq1.AddCookie(sessionCookie)
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
	testReq2.AddCookie(sessionCookie)
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
	testReq3.AddCookie(sessionCookie)
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
	scanReq1.AddCookie(sessionCookie)
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
	scanReq2.AddCookie(sessionCookie)
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
	scanReq3.AddCookie(sessionCookie)
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, scanReq3)
	if w3.Code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 on scan after completion, got %d: %s", w3.Code, w3.Body.String())
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
		"btn-test-node",
		"pending-nodes-banner",
		"scan-progress-pill",
		"pending-nodes-container",
		"scan-progress-box",
		"test-node-result",
		"pending-nodes-section",
		"pending-nodes-list",
	} {
		if !strings.Contains(indexHTML, elem) {
			t.Errorf("expected embedded index.html to contain element %q", elem)
		}
		if !strings.Contains(wIndex.Body.String(), elem) {
			t.Errorf("expected served /index.html to contain element %q", elem)
		}
	}

	// 2. Verify app.js via direct embed and via HTTP server
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
		"testRemoteNodeConnection",
		"approveNode",
		"rejectNode",
		"triggerScan",
		"renderPendingNodesBanner",
		"renderNodesModalList",
		"/api/nodes/approve",
		"/api/nodes/reject",
		"/api/nodes/test",
		"/api/tasks/",
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
	testReq.AddCookie(sessionCookie)
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
	req.AddCookie(sessionCookie)
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
	req2.AddCookie(sessionCookie)
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
	conflictReq.AddCookie(sessionCookie)
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
	manReq.AddCookie(sessionCookie)
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



