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
	"github.com/jaewoook/security-hub/internal/scanner"
	"github.com/jaewoook/security-hub/internal/updater"
)

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
	if HasEmbeddedUI {
		appBytes, _ := staticEmbedFS.ReadFile("static/app.js")
		appText := string(appBytes)
		if !strings.Contains(appText, "System Packages (`brew` / `apt`)") {
			t.Error("expected app.js bundle to display shared System Packages (`brew` / `apt`) tab")
		}
		if !strings.Contains(appText, `target_type==="apt"`) || !strings.Contains(appText, `/^https?:\/\//i`) {
			t.Error("expected app.js bundle to handle item.target_type === 'apt' and validate safe HTTP URLs")
		}
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
