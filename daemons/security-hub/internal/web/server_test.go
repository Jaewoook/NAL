package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	if agentAuthW.Code != http.StatusOK || !strings.Contains(agentAuthW.Body.String(), `"Atlas"`) {
		t.Fatalf("expected 200 with Atlas info on /api/agent/info, got %d: %s", agentAuthW.Code, agentAuthW.Body.String())
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
