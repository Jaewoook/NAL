package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

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
