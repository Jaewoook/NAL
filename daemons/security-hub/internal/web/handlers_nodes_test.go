package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/scanner"
)

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

func TestServer_NodeVersionReportingAndDashboardHubVersion(t *testing.T) {
	srv, sessionCookie, store, cfg := setupTestHubServer(t)
	h := srv.Handler()

	// 1. Agent announces with build version
	payload, _ := json.Marshal(map[string]string{
		"name":       "VersionedAgent",
		"url":        "reverse-poll",
		"token":      cfg.AgentToken,
		"os_version": "linux/arm64",
		"version":    "2026-11-27.16.17",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/nodes/announce", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on announce, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := store.GetNode(context.Background(), "VersionedAgent")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if stored.Version != "2026-11-27.16.17" {
		t.Fatalf("expected stored agent version '2026-11-27.16.17', got %q", stored.Version)
	}

	// 2. Dashboard response includes hub_version and node versions
	dashReq := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	dashReq.AddCookie(sessionCookie)
	dashW := httptest.NewRecorder()
	h.ServeHTTP(dashW, dashReq)
	if dashW.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/dashboard, got %d: %s", dashW.Code, dashW.Body.String())
	}
	var dash struct {
		HubVersion string            `json:"hub_version"`
		Nodes      []models.NodeInfo `json:"nodes"`
	}
	if err := json.Unmarshal(dashW.Body.Bytes(), &dash); err != nil {
		t.Fatalf("failed to decode /api/dashboard: %v", err)
	}
	if dash.HubVersion == "" {
		t.Fatal("expected non-empty hub_version in /api/dashboard")
	}
	var foundHub, foundAgent bool
	for _, n := range dash.Nodes {
		if n.Role == "hub" && n.Version == dash.HubVersion {
			foundHub = true
		}
		if n.Name == "VersionedAgent" && n.Version == "2026-11-27.16.17" {
			foundAgent = true
		}
	}
	if !foundHub || !foundAgent {
		t.Fatalf("expected hub and agent versions in dashboard nodes, got %+v", dash.Nodes)
	}
}
