package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/broker"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/httputil"
	"github.com/jaewoook/security-hub/internal/models"
)

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
			if strings.EqualFold(n.Name, hubName) {
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
		writeJSON(w, http.StatusOK, s.buildNodesOverview(ctx))
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
		writeJSON(w, http.StatusOK, map[string]any{
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
		writeJSON(w, http.StatusOK, map[string]any{
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

func isReversePollURL(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return lower == "reverse-poll" || strings.HasPrefix(lower, "reverse-poll ") || strings.HasPrefix(lower, "reverse-poll(")
}

func clientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip := net.ParseIP(first); ip != nil {
			return ip.String()
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func formatReversePollURL(r *http.Request) string {
	if ip := clientIPFromRequest(r); ip != "" {
		return fmt.Sprintf("reverse-poll (%s)", ip)
	}
	return "reverse-poll"
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
	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" || isReversePollURL(rawURL) {
		req.URL = formatReversePollURL(r)
	} else {
		req.URL = config.NormalizeURL(rawURL)
		if !IsValidAgentHTTPURL(req.URL) {
			auth.WriteJSONError(w, http.StatusBadRequest, "invalid agent url: must use http:// or https:// with a valid host")
			return
		}
	}
	if req.Name == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "name required")
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
	writeJSON(w, http.StatusOK, map[string]string{"status": string(status)})
}

func (s *Server) handleNodePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.broker == nil {
		auth.WriteJSONError(w, http.StatusServiceUnavailable, "agent broker is not configured")
		return
	}
	nodeName := strings.TrimSpace(r.URL.Query().Get("name"))
	if nodeName == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "name query parameter required")
		return
	}
	if s.store != nil {
		if node, err := s.store.GetNode(r.Context(), nodeName); err == nil {
			if node.Status == models.NodeStatusRejected {
				auth.WriteJSONError(w, http.StatusForbidden, "node rejected")
				return
			}
			if node.Status == models.NodeStatusApproved {
				_ = s.store.UpdateNodeHealth(r.Context(), node.Name, true, time.Now().UTC(), "")
			}
		}
	}

	pollCtx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if ch := s.shutdownChan(); ch != nil {
		go func() {
			select {
			case <-ch:
				cancel()
			case <-pollCtx.Done():
			}
		}()
	}

	job, ok := s.broker.Poll(pollCtx, nodeName, broker.DefaultPollWait)
	if !ok || job == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleNodeLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.broker == nil {
		auth.WriteJSONError(w, http.StatusServiceUnavailable, "agent broker is not configured")
		return
	}
	var entry broker.JobLogLine
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&entry); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(entry.JobID) == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "job_id required")
		return
	}
	if !s.broker.EmitLog(entry) {
		auth.WriteJSONError(w, http.StatusNotFound, "unknown or expired job_id")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

func (s *Server) handleNodeResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.broker == nil {
		auth.WriteJSONError(w, http.StatusServiceUnavailable, "agent broker is not configured")
		return
	}
	var res broker.JobResult
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&res); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(res.JobID) == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "job_id required")
		return
	}
	if !s.broker.Complete(res) {
		auth.WriteJSONError(w, http.StatusNotFound, "unknown or expired job_id")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

func parseNodeNameParam(r *http.Request) string {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var req struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
		name = strings.TrimSpace(req.Name)
	}
	return name
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
	name := parseNodeNameParam(r)
	if name == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "name parameter required")
		return
	}

	ctx := r.Context()
	if err := s.store.ApproveNode(ctx, name); err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
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
	name := parseNodeNameParam(r)
	if name == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "name parameter required")
		return
	}

	ctx := r.Context()
	if err := s.store.RejectNode(ctx, name); err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "rejected",
		"name":   name,
		"nodes":  s.buildNodesOverview(ctx),
	})
}

type nodeTestRequest struct {
	Name  string `json:"name,omitempty"`
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
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || (strings.TrimSpace(req.URL) == "" && strings.TrimSpace(req.Name) == "") {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: "url or name is required",
		})
		return
	}

	if isReversePollURL(req.URL) || (strings.TrimSpace(req.URL) == "" && strings.TrimSpace(req.Name) != "") {
		nodeName := strings.TrimSpace(req.Name)
		if s.broker != nil && nodeName != "" && s.broker.IsConnected(nodeName) {
			var info *models.NodeInfo
			osVer := ""
			if s.store != nil {
				if n, nErr := s.store.GetNode(r.Context(), nodeName); nErr == nil {
					n.Token = ""
					info = n
					osVer = n.OSVersion
				}
			}
			_ = json.NewEncoder(w).Encode(nodeTestResponse{
				OK:        true,
				OSVersion: osVer,
				Info:      info,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(nodeTestResponse{
			OK:    false,
			Error: "reverse-poll agent is not currently connected",
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

	probeClient := httputil.NoRedirectClient(s.httpClient, 3*time.Second)

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
