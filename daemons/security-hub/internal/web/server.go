package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/broker"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/notifier"
	"github.com/jaewoook/security-hub/internal/scanner"
	"github.com/jaewoook/security-hub/internal/updater"
)

//go:embed static/*
var staticEmbedFS embed.FS

type Server struct {
	cfg          *config.Config
	store        db.Store
	broker       *broker.Broker
	orch         *scanner.Orchestrator
	updMgr       *updater.Manager
	authMgr      *auth.Manager
	alerter      *notifier.Alerter
	httpClient   *http.Client
	shutdownOnce sync.Once
	shutdownCh   chan struct{}
	scanWG       sync.WaitGroup
}

func NewServer(cfg *config.Config, store db.Store, orch *scanner.Orchestrator, updMgr *updater.Manager, authMgr *auth.Manager, alerter *notifier.Alerter) *Server {
	return &Server{
		cfg:        cfg,
		store:      store,
		orch:       orch,
		updMgr:     updMgr,
		authMgr:    authMgr,
		alerter:    alerter,
		shutdownCh: make(chan struct{}),
	}
}

// Wait blocks until all background manual scans started by Server finish or ctx expires.
func (s *Server) Wait(ctx context.Context) error {
	if s == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		s.scanWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsValidAgentHTTPURL validates that a normalized agent URL uses http or https with a non-empty host.
func IsValidAgentHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) && u.Hostname() != ""
}

// NotifyShutdown closes the server shutdown channel so active SSE streams exit immediately.
func (s *Server) NotifyShutdown() {
	if s == nil {
		return
	}
	s.shutdownOnce.Do(func() {
		if s.shutdownCh != nil {
			close(s.shutdownCh)
		}
	})
}

func (s *Server) shutdownChan() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.shutdownCh
}

func (s *Server) SetHTTPClient(client *http.Client) {
	s.httpClient = client
}

func (s *Server) SetBroker(b *broker.Broker) {
	s.broker = b
}

func (s *Server) localNodeName() string {
	if s.cfg != nil && s.cfg.NodeName != "" {
		return s.cfg.NodeName
	}
	return config.DefaultNodeName()
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authMgr == nil {
			auth.WriteJSONError(w, http.StatusServiceUnavailable, "authentication manager is not configured")
			return
		}
		s.authMgr.RequireAuth(next)(w, r)
	}
}

func (s *Server) requireAuthCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authMgr == nil {
			auth.WriteJSONError(w, http.StatusServiceUnavailable, "authentication manager is not configured")
			return
		}
		s.authMgr.RequireAuthCSRF(next)(w, r)
	}
}

func (s *Server) requireAuthMgr(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authMgr == nil {
			auth.WriteJSONError(w, http.StatusServiceUnavailable, "authentication manager is not configured")
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAgentToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := ""
		if s.cfg != nil {
			expected = s.cfg.AgentToken
		}
		got := r.Header.Get("X-NAL-Node-Token")
		hGot := sha256.Sum256([]byte(got))
		hExp := sha256.Sum256([]byte(expected))
		if expected == "" || got == "" || subtle.ConstantTimeCompare(hGot[:], hExp[:]) != 1 {
			auth.WriteJSONError(w, http.StatusUnauthorized, "invalid or missing X-NAL-Node-Token")
			return
		}
		next(w, r)
	}
}

func (s *Server) sessionClaims(r *http.Request) *auth.SessionClaims {
	if s.authMgr == nil {
		return nil
	}
	claims, err := s.authMgr.VerifyRequest(r)
	if err != nil {
		return nil
	}
	return claims
}

func (s *Server) requestActor(r *http.Request) string {
	if claims := s.sessionClaims(r); claims != nil {
		return claims.Method + ":" + claims.Subject
	}
	return "web"
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public / Auth endpoints
	mux.HandleFunc("/api/auth/session", s.handleSession)
	mux.HandleFunc("/api/auth/oidc/login", s.requireAuthMgr(func(w http.ResponseWriter, r *http.Request) { s.authMgr.StartOIDCLogin(w, r) }))
	mux.HandleFunc("/api/auth/oidc/callback", s.requireAuthMgr(func(w http.ResponseWriter, r *http.Request) { s.authMgr.HandleOIDCCallback(w, r) }))
	mux.HandleFunc("/api/auth/token-login", s.handleTokenLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/passkey/register/begin", s.requireAuthMgr(func(w http.ResponseWriter, r *http.Request) { s.authMgr.BeginPasskeyRegistration(w, r) }))
	mux.HandleFunc("/api/auth/passkey/register/finish", s.requireAuthMgr(func(w http.ResponseWriter, r *http.Request) { s.authMgr.FinishPasskeyRegistration(w, r) }))
	mux.HandleFunc("/api/auth/passkey/login/begin", s.requireAuthMgr(func(w http.ResponseWriter, r *http.Request) { s.authMgr.BeginPasskeyLogin(w, r) }))
	mux.HandleFunc("/api/auth/passkey/login/finish", s.requireAuthMgr(func(w http.ResponseWriter, r *http.Request) { s.authMgr.FinishPasskeyLogin(w, r) }))

	// Agent announcement & reverse-poll endpoints (authenticated via AgentToken / X-NAL-Node-Token)
	mux.HandleFunc("/api/nodes/announce", s.handleNodeAnnounce)
	mux.HandleFunc("/api/nodes/poll", s.requireAgentToken(s.handleNodePoll))
	mux.HandleFunc("/api/nodes/log", s.requireAgentToken(s.handleNodeLog))
	mux.HandleFunc("/api/nodes/result", s.requireAgentToken(s.handleNodeResult))

	// Protected API endpoints (read routes require session; mutations also enforce CSRF)
	mux.HandleFunc("/api/dashboard", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/api/nodes", s.requireAuthCSRF(s.handleNodes))
	mux.HandleFunc("/api/nodes/approve", s.requireAuthCSRF(s.handleNodeApprove))
	mux.HandleFunc("/api/nodes/reject", s.requireAuthCSRF(s.handleNodeReject))
	mux.HandleFunc("/api/nodes/test", s.requireAuthCSRF(s.handleNodeTest))
	mux.HandleFunc("/api/scan", s.requireAuthCSRF(s.handleScan))
	mux.HandleFunc("/api/update", s.requireAuthCSRF(s.handleUpdate))
	mux.HandleFunc("/api/rollback", s.requireAuthCSRF(s.handleRollback))
	mux.HandleFunc("/api/skip", s.requireAuthCSRF(s.handleSkip))
	mux.HandleFunc("/api/tasks", s.requireAuth(s.handleTasksList))
	mux.HandleFunc("/api/tasks/", s.requireAuth(s.handleTaskDetailOrStream))

	// Remote Agent LAN endpoints (authenticated via X-NAL-Node-Token)
	mux.HandleFunc("/api/agent/info", s.requireAgentToken(s.handleAgentInfo))
	mux.HandleFunc("/api/agent/scan", s.requireAgentToken(s.handleAgentScan))
	mux.HandleFunc("/api/agent/update", s.requireAgentToken(s.handleAgentUpdate))
	mux.HandleFunc("/api/agent/rollback", s.requireAgentToken(s.handleAgentRollback))

	// Static dashboard files (prevent stale Cloudflare/browser caching of embedded assets)
	subFS, _ := fs.Sub(staticEmbedFS, "static")
	fileSrv := http.FileServer(http.FS(subFS))
	assetVersion := embeddedAssetVersion()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			if raw, err := staticEmbedFS.ReadFile("static/index.html"); err == nil {
				html := strings.ReplaceAll(string(raw), `"/app.js"`, `"/app.js?v=`+assetVersion+`"`)
				html = strings.ReplaceAll(html, `"/styles.css"`, `"/styles.css?v=`+assetVersion+`"`)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(html))
				return
			}
		}
		fileSrv.ServeHTTP(w, r)
	})

	return mux
}

func embeddedAssetVersion() string {
	h := sha256.New()
	if b, err := staticEmbedFS.ReadFile("static/app.js"); err == nil {
		h.Write(b)
	}
	if b, err := staticEmbedFS.ReadFile("static/styles.css"); err == nil {
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:10]
}

// AgentHandler returns a restricted HTTP handler exposing only authenticated remote agent endpoints.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/info", s.requireAgentToken(s.handleAgentInfo))
	mux.HandleFunc("/api/agent/scan", s.requireAgentToken(s.handleAgentScan))
	mux.HandleFunc("/api/agent/update", s.requireAgentToken(s.handleAgentUpdate))
	mux.HandleFunc("/api/agent/rollback", s.requireAgentToken(s.handleAgentRollback))
	return mux
}
