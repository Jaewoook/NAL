package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/jaewoook/system-updater/internal/auth"
	"github.com/jaewoook/system-updater/internal/config"
	"github.com/jaewoook/system-updater/internal/db"
	"github.com/jaewoook/system-updater/internal/models"
	"github.com/jaewoook/system-updater/internal/notifier"
	"github.com/jaewoook/system-updater/internal/scanner"
	"github.com/jaewoook/system-updater/internal/updater"
)

//go:embed static/*
var staticEmbedFS embed.FS

type Server struct {
	cfg     *config.Config
	store   db.Store
	orch    *scanner.Orchestrator
	updMgr  *updater.Manager
	authMgr *auth.Manager
	alerter *notifier.Alerter
}

func NewServer(cfg *config.Config, store db.Store, orch *scanner.Orchestrator, updMgr *updater.Manager, authMgr *auth.Manager, alerter *notifier.Alerter) *Server {
	return &Server{
		cfg:     cfg,
		store:   store,
		orch:    orch,
		updMgr:  updMgr,
		authMgr: authMgr,
		alerter: alerter,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public / Auth endpoints
	mux.HandleFunc("/api/auth/session", s.handleSession)
	mux.HandleFunc("/api/auth/oidc/login", s.authMgr.StartOIDCLogin)
	mux.HandleFunc("/api/auth/oidc/callback", s.authMgr.HandleOIDCCallback)
	mux.HandleFunc("/api/auth/token-login", s.handleTokenLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/passkey/register/begin", s.authMgr.BeginPasskeyRegistration)
	mux.HandleFunc("/api/auth/passkey/register/finish", s.authMgr.FinishPasskeyRegistration)
	mux.HandleFunc("/api/auth/passkey/login/begin", s.authMgr.BeginPasskeyLogin)
	mux.HandleFunc("/api/auth/passkey/login/finish", s.authMgr.FinishPasskeyLogin)

	// Protected API endpoints
	mux.HandleFunc("/api/dashboard", s.authMgr.RequireAuth(s.handleDashboard))
	mux.HandleFunc("/api/scan", s.authMgr.RequireAuth(s.handleScan))
	mux.HandleFunc("/api/update", s.authMgr.RequireAuth(s.handleUpdate))
	mux.HandleFunc("/api/rollback", s.authMgr.RequireAuth(s.handleRollback))
	mux.HandleFunc("/api/skip", s.authMgr.RequireAuth(s.handleSkip))
	mux.HandleFunc("/api/tasks", s.authMgr.RequireAuth(s.handleTasksList))
	mux.HandleFunc("/api/tasks/", s.authMgr.RequireAuth(s.handleTaskDetailOrStream))

	// Static dashboard files
	subFS, _ := fs.Sub(staticEmbedFS, "static")
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	return mux
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims, err := s.authMgr.VerifyRequest(r)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authenticated":   false,
			"oidc_configured": s.cfg.Auth.OIDCIssuer != "",
			"has_passkeys":    s.authMgr.HasRegisteredPasskeys(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authenticated":   true,
		"subject":         claims.Subject,
		"method":          claims.Method,
		"has_passkeys":    s.authMgr.HasRegisteredPasskeys(),
		"oidc_configured": s.cfg.Auth.OIDCIssuer != "",
	})
}

func (s *Server) handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	ok, err := s.authMgr.ConsumeBreakGlassToken(tok)
	if err != nil || !ok {
		http.Error(w, "Invalid or expired break-glass login token", http.StatusUnauthorized)
		return
	}
	_ = s.authMgr.IssueSessionCookie(w, "cli-break-glass-admin", "cli")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.authMgr.ClearSessionCookie(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	scan, err := s.store.LoadLatestScanResult(ctx)
	if err != nil || scan == nil {
		scan = &models.ScanResult{Items: []models.ManagedItem{}}
	}
	skipped, _ := s.store.ListSkippedVersions(ctx)
	snapshots, _ := s.store.ListSnapshots(ctx)
	for i := range scan.Items {
		if snap, ok := snapshots[scan.Items[i].Name]; ok {
			scan.Items[i].HasRollback = true
			scan.Items[i].RollbackVersion = snap.PreviousVersion
		}
	}
	summarized := scanner.ApplySkippedAndSummarize(scan.Items, skipped)
	summarized.ScannedAt = scan.ScannedAt

	tasks, _ := s.store.ListTasks(ctx, "", 25)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"scan":            summarized,
		"recent_tasks":    tasks,
		"snapshots_count": len(snapshots),
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scan, err := s.orch.RunFullScan(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if s.alerter != nil {
		_, _ = s.alerter.NotifyScanFindings(r.Context(), scan)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scan)
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, _ := s.authMgr.VerifyRequest(r)
	var req updater.UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if claims != nil {
		req.TriggeredBy = claims.Method + ":" + claims.Subject
	}
	task, err := s.updMgr.TriggerUpdate(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(task)
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, _ := s.authMgr.VerifyRequest(r)
	var req struct {
		ServiceName string `json:"service_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServiceName == "" {
		http.Error(w, `{"error":"service_name required"}`, http.StatusBadRequest)
		return
	}
	actor := "web"
	if claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}
	task, err := s.updMgr.RollbackService(r.Context(), req.ServiceName, actor)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(task)
}

func (s *Server) handleSkip(w http.ResponseWriter, r *http.Request) {
	claims, _ := s.authMgr.VerifyRequest(r)
	actor := "web"
	if claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}
	switch r.Method {
	case http.MethodPost:
		var req struct {
			TargetType string `json:"target_type"`
			TargetName string `json:"target_name"`
			Version    string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		_ = s.store.SetSkippedVersion(r.Context(), req.TargetType, req.TargetName, req.Version, actor)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "skipped"})
	case http.MethodDelete:
		tt := r.URL.Query().Get("target_type")
		tn := r.URL.Query().Get("target_name")
		_ = s.store.RemoveSkippedVersion(r.Context(), tt, tn)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unskipped"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTasksList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("type")
	tasks, err := s.store.ListTasks(r.Context(), filter, 50)
	if err != nil {
		http.Error(w, `{"error":"failed to list tasks"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tasks)
}

func (s *Server) handleTaskDetailOrStream(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	parts := strings.Split(trimmed, "/")
	taskID := parts[0]
	if taskID == "" {
		http.NotFound(w, r)
		return
	}

	if len(parts) == 2 && parts[1] == "download" {
		logPath := s.store.GetRawLogPath(taskID)
		raw, err := os.ReadFile(logPath)
		if err != nil {
			http.Error(w, "Log file not found", http.StatusNotFound)
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
		http.Error(w, `{"error":"task not found"}`, http.StatusNotFound)
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
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := s.store.SubscribeTaskLogs(taskID)
	defer unsub()

	task, existingLogs, err := s.store.GetTaskWithLogs(r.Context(), taskID)
	if err != nil {
		return
	}
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

	for {
		select {
		case <-r.Context().Done():
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
