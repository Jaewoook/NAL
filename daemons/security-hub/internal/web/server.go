package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/notifier"
	"github.com/jaewoook/security-hub/internal/scanner"
	"github.com/jaewoook/security-hub/internal/updater"
)

//go:embed static/*
var staticEmbedFS embed.FS

type Server struct {
	cfg          *config.Config
	store        db.Store
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

	// Agent announcement (authenticated via AgentToken in payload)
	mux.HandleFunc("/api/nodes/announce", s.handleNodeAnnounce)

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

	// Static dashboard files
	subFS, _ := fs.Sub(staticEmbedFS, "static")
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	return mux
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

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	oidcConfigured := s.cfg != nil && s.cfg.Auth.OIDCIssuer != ""
	hasPasskeys := s.authMgr != nil && s.authMgr.HasRegisteredPasskeys()
	if s.authMgr == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authenticated":   false,
			"oidc_configured": oidcConfigured,
			"has_passkeys":    hasPasskeys,
		})
		return
	}
	claims, err := s.authMgr.VerifyRequest(r)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authenticated":   false,
			"oidc_configured": oidcConfigured,
			"has_passkeys":    hasPasskeys,
		})
		return
	}
	username := claims.Subject
	if atIdx := strings.Index(username, "@"); atIdx != -1 {
		username = username[:atIdx]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authenticated":   true,
		"subject":         claims.Subject,
		"username":        username,
		"method":          claims.Method,
		"has_passkeys":    hasPasskeys,
		"oidc_configured": oidcConfigured,
		"csrf_token":      s.authMgr.CSRFTokenForRequest(r),
	})
}

func (s *Server) handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	if s.authMgr == nil {
		auth.WriteJSONError(w, http.StatusServiceUnavailable, "authentication manager is not configured")
		return
	}
	tok := r.URL.Query().Get("token")
	ok, err := s.authMgr.ConsumeBreakGlassToken(tok)
	if err != nil || !ok {
		http.Error(w, "Invalid or expired break-glass login token", http.StatusUnauthorized)
		return
	}
	if err := s.authMgr.IssueSessionCookie(w, "cli-break-glass-admin", "cli"); err != nil {
		http.Error(w, "Failed to issue session cookie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.authMgr != nil {
		if _, err := s.authMgr.VerifyRequest(r); err == nil {
			if err := s.authMgr.VerifyCSRF(r); err != nil {
				auth.WriteJSONError(w, http.StatusForbidden, "csrf validation failed")
				return
			}
		} else if err := s.authMgr.VerifyOriginAndFetchSite(r); err != nil {
			auth.WriteJSONError(w, http.StatusForbidden, "origin check failed")
			return
		}
		s.authMgr.ClearSessionCookie(w)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

func (s *Server) buildNodesOverview(ctx context.Context) []models.NodeInfo {
	hubName := s.localNodeName()
	out := []models.NodeInfo{
		{
			Name:       hubName,
			Role:       "hub",
			Status:     models.NodeStatusApproved,
			Online:     true,
			LastSeenAt: time.Now().UTC(),
		},
	}
	if s.store != nil {
		registered, _ := s.store.ListNodes(ctx)
		for _, n := range registered {
			if n.Name == hubName {
				continue
			}
			n.Token = ""
			out = append(out, n)
		}
	}
	return out
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.buildNodesOverview(ctx))
	case http.MethodPost:
		var req models.NodeInfo
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.URL) == "" {
			auth.WriteJSONError(w, http.StatusBadRequest, "name and url are required")
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.URL = config.NormalizeURL(req.URL)
		if !IsValidAgentHTTPURL(req.URL) {
			auth.WriteJSONError(w, http.StatusBadRequest, "invalid agent url: must use http:// or https:// with a valid host")
			return
		}
		hubName := s.localNodeName()
		if strings.EqualFold(req.Name, hubName) {
			auth.WriteJSONError(w, http.StatusBadRequest, "agent node name conflicts with hub node name")
			return
		}
		req.Role = "agent"
		if err := s.store.UpsertNode(ctx, req); err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "saved",
			"nodes":  s.buildNodesOverview(ctx),
		})
	case http.MethodDelete:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			auth.WriteJSONError(w, http.StatusBadRequest, "name query parameter required")
			return
		}
		if err := s.store.RemoveNode(ctx, name); err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "removed",
			"nodes":  s.buildNodesOverview(ctx),
		})
	default:
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type nodeAnnounceRequest struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Token     string `json:"token"`
	OSVersion string `json:"os_version"`
}

func (s *Server) handleNodeAnnounce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}

	var req nodeAnnounceRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}

	expected := ""
	if s.cfg != nil {
		expected = s.cfg.AgentToken
	}
	h1 := sha256.Sum256([]byte(req.Token))
	h2 := sha256.Sum256([]byte(expected))
	if expected == "" || req.Token == "" || subtle.ConstantTimeCompare(h1[:], h2[:]) != 1 {
		auth.WriteJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.URL = config.NormalizeURL(req.URL)
	if req.Name == "" || req.URL == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "name and url required")
		return
	}
	if !IsValidAgentHTTPURL(req.URL) {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid agent url: must use http:// or https:// with a valid host")
		return
	}

	hubName := s.localNodeName()
	if strings.EqualFold(req.Name, hubName) {
		auth.WriteJSONError(w, http.StatusBadRequest, "agent node name conflicts with hub node name")
		return
	}

	status, err := s.store.AnnounceNode(r.Context(), models.NodeInfo{
		Name:      req.Name,
		URL:       req.URL,
		Token:     req.Token,
		OSVersion: req.OSVersion,
	})
	if err != nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if status == models.NodeStatusRejected {
		auth.WriteJSONError(w, http.StatusForbidden, "node rejected")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": string(status)})
}

func (s *Server) handleNodeApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var req struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
		name = strings.TrimSpace(req.Name)
	}
	if name == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "name parameter required")
		return
	}

	ctx := r.Context()
	if err := s.store.ApproveNode(ctx, name); err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "approved",
		"name":   name,
		"nodes":  s.buildNodesOverview(ctx),
	})
}

func (s *Server) handleNodeReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var req struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
		name = strings.TrimSpace(req.Name)
	}
	if name == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "name parameter required")
		return
	}

	ctx := r.Context()
	if err := s.store.RejectNode(ctx, name); err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "rejected",
		"name":   name,
		"nodes":  s.buildNodesOverview(ctx),
	})
}

type nodeTestRequest struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

type nodeTestResponse struct {
	OK        bool             `json:"ok"`
	LatencyMs int64            `json:"latency_ms,omitempty"`
	OSVersion string           `json:"os_version,omitempty"`
	Info      *models.NodeInfo `json:"info,omitempty"`
	Error     string           `json:"error,omitempty"`
}

func (s *Server) handleNodeTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req nodeTestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || strings.TrimSpace(req.URL) == "" {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: "url is required",
		})
		return
	}

	targetURL := config.NormalizeURL(req.URL)
	if !IsValidAgentHTTPURL(targetURL) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: "invalid url scheme: must be http or https",
		})
		return
	}
	parsedURL, _ := url.Parse(targetURL)
	parsedURL.Path = path.Join(parsedURL.Path, "/api/agent/info")
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	endpoint := parsedURL.String()

	testCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(testCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: err.Error(),
		})
		return
	}
	tok := req.Token
	if tok == "" && s.cfg != nil {
		tok = s.cfg.AgentToken
	}
	if tok != "" {
		httpReq.Header.Set("X-NAL-Node-Token", tok)
	}

	probeClient := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if s.httpClient != nil {
		probeClient.Transport = s.httpClient.Transport
		if s.httpClient.Timeout > 0 {
			probeClient.Timeout = s.httpClient.Timeout
		}
	}

	start := time.Now()
	resp, err := probeClient.Do(httpReq)
	elapsed := time.Since(start)

	if err != nil {
		errMsg := err.Error()
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errMsg, "deadline exceeded") {
			errMsg = "connection timed out"
		}
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: errMsg,
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: "invalid token",
		})
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: fmt.Sprintf("agent returned HTTP %d", resp.StatusCode),
		})
		return
	}

	var info models.NodeInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: fmt.Sprintf("invalid agent response: %v", err),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(nodeTestResponse{
		OK:        true,
		LatencyMs: elapsed.Milliseconds(),
		OSVersion: info.OSVersion,
		Info:      &info,
	})
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

func (s *Server) handleAgentInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(models.NodeInfo{
		Name:       s.localNodeName(),
		Role:       "agent",
		Online:     true,
		LastSeenAt: time.Now().UTC(),
		OSVersion:  runtime.GOOS + "/" + runtime.GOARCH,
	})
}

func (s *Server) handleAgentScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.orch == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "orchestrator not configured")
		return
	}
	items, err := s.orch.ScanLocalNode(r.Context())
	if err != nil && len(items) == 0 {
		auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodeName := s.localNodeName()
	if s.store != nil {
		if snapshots, sErr := s.store.ListSnapshots(r.Context()); sErr == nil {
			for i := range items {
				if items[i].TargetType != models.TargetDocker {
					continue
				}
				if snap, ok := snapshots[items[i].Name]; ok {
					items[i].HasRollback = true
					items[i].RollbackVersion = snap.PreviousVersion
				} else if snap, ok := snapshots[nodeName+":"+items[i].Name]; ok {
					items[i].HasRollback = true
					items[i].RollbackVersion = snap.PreviousVersion
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node":  nodeName,
		"items": items,
	})
}

func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.store == nil || s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	var req updater.UpdateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	nodeName := s.localNodeName()
	req.Node = nodeName
	req.TargetType = strings.TrimSpace(req.TargetType)
	if req.TargetType == "" {
		req.TargetType = string(models.TargetDocker)
	}
	req.TargetName = strings.TrimSpace(req.TargetName)
	req.TargetVersion = strings.TrimSpace(req.TargetVersion)
	if err := updater.ValidateUpdateRequest(req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	updCtx, updCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Minute)
	defer updCancel()
	task, err := s.store.CreateTask(updCtx, &models.Task{
		Node:        nodeName,
		TaskType:    "agent_update",
		TargetType:  req.TargetType,
		TargetName:  req.TargetName,
		ToVersion:   req.TargetVersion,
		TriggeredBy: req.TriggeredBy,
		Status:      "running",
	})
	if err != nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.updMgr.RunUpdateSync(updCtx, task.ID, req)
	finalTask, logs, _ := s.store.GetTaskWithLogs(updCtx, task.ID)
	status := "succeeded"
	errMsg := ""
	if finalTask != nil {
		status = finalTask.Status
		errMsg = finalTask.ErrorMsg
	} else {
		status = task.Status
		errMsg = task.ErrorMsg
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    status,
		"error_msg": errMsg,
		"logs":      logs,
	})
}

func (s *Server) handleAgentRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.store == nil || s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	var req struct {
		ServiceName string `json:"service_name"`
		TriggeredBy string `json:"triggered_by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.ServiceName == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "service_name required")
		return
	}
	rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Minute)
	defer rbCancel()
	task, err := s.updMgr.RollbackService(rbCtx, req.ServiceName, req.TriggeredBy)
	if err != nil && task == nil {
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	finalTask, logs, _ := s.store.GetTaskWithLogs(rbCtx, task.ID)
	status := task.Status
	errMsg := task.ErrorMsg
	if finalTask != nil {
		status = finalTask.Status
		errMsg = finalTask.ErrorMsg
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    status,
		"error_msg": errMsg,
		"logs":      logs,
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	ctx := r.Context()
	scan, err := s.store.LoadLatestScanResult(ctx)
	if err != nil || scan == nil {
		scan = &models.ScanResult{Items: []models.ManagedItem{}}
	}
	skipped, _ := s.store.ListSkippedVersions(ctx)
	snapshots, _ := s.store.ListSnapshots(ctx)
	hubName := s.localNodeName()
	for i := range scan.Items {
		if scan.Items[i].Node == "" {
			scan.Items[i].Node = hubName
		}
		if scan.Items[i].TargetType != models.TargetDocker || scan.Items[i].HasRollback {
			continue
		}
		if snap, ok := snapshots[scan.Items[i].Node+":"+scan.Items[i].Name]; ok {
			scan.Items[i].HasRollback = true
			scan.Items[i].RollbackVersion = snap.PreviousVersion
		} else if snap, ok := snapshots[scan.Items[i].Name]; ok && scan.Items[i].Node == hubName {
			scan.Items[i].HasRollback = true
			scan.Items[i].RollbackVersion = snap.PreviousVersion
		}
	}
	nodes := s.buildNodesOverview(ctx)
	summarized := scanner.ApplySkippedAndSummarize(scan.Items, skipped)
	summarized.ScannedAt = scan.ScannedAt
	summarized.Nodes = nodes

	tasks, _ := s.store.ListTasks(ctx, "", 25)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"hub_node":        hubName,
		"nodes":           nodes,
		"scan":            summarized,
		"recent_tasks":    tasks,
		"snapshots_count": len(snapshots),
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.orch == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "orchestrator not configured")
		return
	}

	if scanning, activeID := s.orch.IsScanning(); scanning {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "scan already running",
			"task_id": activeID,
		})
		return
	}

	hubName := s.localNodeName()
	actor := "web"
	if claims := s.sessionClaims(r); claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}

	var taskID string
	if s.store != nil {
		task, err := s.store.CreateTask(r.Context(), &models.Task{
			Node:        hubName,
			TaskType:    "security_scan",
			TargetType:  "system",
			TargetName:  "all",
			TriggeredBy: actor,
			Status:      "running",
		})
		if err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		taskID = task.ID
	} else {
		taskID = fmt.Sprintf("task_%d", time.Now().UnixNano())
	}

	started, activeID := s.orch.StartScan(taskID)
	if !started {
		if s.store != nil {
			abortCtx, abortCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer abortCancel()
			_ = s.store.FinishTask(abortCtx, taskID, "aborted", "scan already running")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "scan already running",
			"task_id": activeID,
		})
		return
	}

	s.scanWG.Add(1)
	go func(tid string) {
		defer s.scanWG.Done()
		defer s.orch.FinishScan()

		scanCtx, scanCancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer scanCancel()
		if shutCh := s.shutdownChan(); shutCh != nil {
			go func() {
				select {
				case <-shutCh:
					scanCancel()
				case <-scanCtx.Done():
				}
			}()
		}

		scan, err := s.orch.RunFullScanWithTask(scanCtx, tid)
		if err != nil {
			if s.store != nil {
				finishCtx, finishCancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer finishCancel()
				_ = s.store.FinishTask(finishCtx, tid, "failed", err.Error())
			}
			return
		}
		if s.store != nil {
			curTask, _, _ := s.store.GetTaskWithLogs(scanCtx, tid)
			if curTask != nil && curTask.Status == "running" {
				_ = s.store.FinishTask(scanCtx, tid, "succeeded", "")
			}
		}
		if s.alerter != nil {
			_, _ = s.alerter.NotifyScanFindings(scanCtx, scan)
		}
	}(taskID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"task_id": taskID,
		"status":  "running",
	})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	claims := s.sessionClaims(r)
	var req updater.UpdateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := updater.ValidateUpdateRequest(req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if claims != nil {
		req.TriggeredBy = claims.Method + ":" + claims.Subject
	}
	task, err := s.updMgr.TriggerUpdate(r.Context(), req)
	if err != nil {
		if errors.Is(err, updater.ErrUpdateInProgress) {
			auth.WriteJSONError(w, http.StatusConflict, err.Error())
			return
		}
		auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(task)
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	claims := s.sessionClaims(r)
	var req struct {
		Node        string `json:"node"`
		ServiceName string `json:"service_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.ServiceName == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "service_name required")
		return
	}
	actor := "web"
	if claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}
	task, err := s.updMgr.RollbackServiceOnNode(r.Context(), req.Node, req.ServiceName, actor)
	if err != nil {
		if errors.Is(err, updater.ErrUpdateInProgress) {
			auth.WriteJSONError(w, http.StatusConflict, err.Error())
			return
		}
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(task)
}

func (s *Server) handleSkip(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	claims := s.sessionClaims(r)
	actor := "web"
	if claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Node       string `json:"node"`
			TargetType string `json:"target_type"`
			TargetName string `json:"target_name"`
			Version    string `json:"version"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			auth.WriteJSONError(w, http.StatusBadRequest, "invalid request")
			return
		}
		tt := strings.TrimSpace(req.TargetType)
		if n := strings.TrimSpace(req.Node); n != "" {
			tt = n + ":" + tt
		}
		if err := s.store.SetSkippedVersion(r.Context(), tt, req.TargetName, req.Version, actor); err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "skipped"})
	case http.MethodDelete:
		node := strings.TrimSpace(r.URL.Query().Get("node"))
		tt := strings.TrimSpace(r.URL.Query().Get("target_type"))
		tn := r.URL.Query().Get("target_name")
		if node != "" {
			if err := s.store.RemoveSkippedVersion(r.Context(), node+":"+tt, tn); err != nil {
				auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		if err := s.store.RemoveSkippedVersion(r.Context(), tt, tn); err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unskipped"})
	default:
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleTasksList(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	filter := r.URL.Query().Get("type")
	tasks, err := s.store.ListTasks(r.Context(), filter, 50)
	if err != nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "failed to list tasks")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tasks)
}

func (s *Server) handleTaskDetailOrStream(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	parts := strings.Split(trimmed, "/")
	taskID := parts[0]
	if taskID == "" || taskID == "." || taskID == ".." || strings.ContainsAny(taskID, `/\`) {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}

	if len(parts) == 2 && parts[1] == "download" {
		logPath := s.store.GetRawLogPath(taskID)
		raw, err := os.ReadFile(logPath)
		if err != nil {
			auth.WriteJSONError(w, http.StatusNotFound, "Log file not found")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", taskID+".log"))
		_, _ = w.Write(raw)
		return
	}

	if len(parts) == 2 && parts[1] == "stream" {
		s.streamTaskLogsSSE(w, r, taskID)
		return
	}

	task, logs, err := s.store.GetTaskWithLogs(r.Context(), taskID)
	if err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"task": task,
		"logs": logs,
	})
}

func (s *Server) streamTaskLogsSSE(w http.ResponseWriter, r *http.Request, taskID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		auth.WriteJSONError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	if _, _, err := s.store.GetTaskWithLogs(r.Context(), taskID); err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}

	ch, unsub := s.store.SubscribeTaskLogs(taskID)
	defer unsub()

	task, existingLogs, err := s.store.GetTaskWithLogs(r.Context(), taskID)
	if err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	lastSentSeq := 0
	for _, line := range existingLogs {
		raw, _ := json.Marshal(line)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", string(raw))
		if line.Seq > lastSentSeq {
			lastSentSeq = line.Seq
		}
	}
	flusher.Flush()

	if task.Status != "running" {
		_, _ = fmt.Fprintf(w, "event: done\ndata: %q\n\n", task.Status)
		flusher.Flush()
		return
	}

	shutCh := s.shutdownChan()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-shutCh:
			return
		case line, ok := <-ch:
			if !ok {
				curTask, _, _ := s.store.GetTaskWithLogs(r.Context(), taskID)
				status := "succeeded"
				if curTask != nil {
					status = curTask.Status
				}
				_, _ = fmt.Fprintf(w, "event: done\ndata: %q\n\n", status)
				flusher.Flush()
				return
			}
			if line.Seq <= lastSentSeq {
				continue
			}
			lastSentSeq = line.Seq
			raw, _ := json.Marshal(line)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(raw))
			flusher.Flush()
		}
	}
}
