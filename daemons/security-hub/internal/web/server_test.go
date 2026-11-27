package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
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
	if !HasEmbeddedUI {
		t.Skip("skipping embedded UI asset verification in agent-only build")
	}
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
