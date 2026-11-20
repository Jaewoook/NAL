package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/service"
)

func TestCLI_LoginLinkAndServicePlist(t *testing.T) {
	plist := service.GenerateLaunchdPlist("/Users/jaewookahn/repos/NAL/daemons/security-hub/security-hub", "/Users/jaewookahn/repos/NAL/daemons/security-hub")
	if !strings.Contains(plist, "me.jaewook.nal.security-hub") || !strings.Contains(plist, "<string>run</string>") {
		t.Fatalf("unexpected launchd plist: %s", plist)
	}

	tmpDir := t.TempDir()
	t.Setenv("SECURITY_HUB_DATA_DIR", tmpDir)
	t.Setenv("SECURITY_HUB_PUBLIC_URL", "http://localhost:10311")
	isoCfgDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(isoCfgDir, "config.yml"), []byte("database:\n  container_name: nonexistent-unit-test-pg\n"), 0600)
	startWD, _ := os.Getwd()
	_ = os.Chdir(isoCfgDir)
	defer func() { _ = os.Chdir(startWD) }()

	var out bytes.Buffer
	code := runCLI([]string{"auth", "login-link"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for auth login-link, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "http://localhost:10311/api/auth/token-login?token=") {
		t.Fatalf("expected break-glass login URL in output, got: %s", out.String())
	}

	// Verify plist install to file
	plistPath := filepath.Join(tmpDir, "me.jaewook.nal.security-hub.plist")
	out.Reset()
	code = runCLI([]string{"service", "install", "-path", plistPath}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for service install, got %d (%s)", code, out.String())
	}

	// Verify CLI node add / list / remove
	out.Reset()
	if code := runCLI([]string{"node", "add", "Atlas", "http://192.168.1.50:10247/", "-token", "sec"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for node add, got %d (%s)", code, out.String())
	}
	out.Reset()
	if code := runCLI([]string{"node", "list"}, &out); code != 0 || !strings.Contains(out.String(), "Atlas") {
		t.Fatalf("expected Atlas in node list output, got code=%d out=%s", code, out.String())
	}
	// Verify trailing slash was trimmed in node list
	if strings.Contains(out.String(), "http://192.168.1.50:10247/") {
		t.Fatalf("expected trailing slash to be trimmed from node URL, got: %s", out.String())
	}
	// Verify node add conflicts with hub name
	hubName := config.DefaultNodeName()
	out.Reset()
	if code := runCLI([]string{"node", "add", hubName, "http://192.168.1.50:10247"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 when node name matches hub name, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "conflicts with hub node name") {
		t.Fatalf("expected conflict error message, got: %s", out.String())
	}
	out.Reset()
	if code := runCLI([]string{"node", "remove", "Atlas"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for node remove, got %d (%s)", code, out.String())
	}

	// Verify CLI node add with un-schemed URL normalizes to http://
	out.Reset()
	if code := runCLI([]string{"node", "add", "SchemelessNode", "192.168.1.188:10247", "-token", "sec"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for schemeless node add, got %d (%s)", code, out.String())
	}
	out.Reset()
	if code := runCLI([]string{"node", "list"}, &out); code != 0 || !strings.Contains(out.String(), "http://192.168.1.188:10247") {
		t.Fatalf("expected http://192.168.1.188:10247 in node list output, got code=%d out=%s", code, out.String())
	}
	out.Reset()
	_ = runCLI([]string{"node", "remove", "SchemelessNode"}, &out)

	// Verify agent requires token
	out.Reset()
	if code := runCLI([]string{"agent", "-hub", "http://hub.lan:10311", "-advertise-url", "http://192.168.1.100:10247"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 when token missing, got %d", code)
	}
	if !strings.Contains(out.String(), "agent_token") {
		t.Fatalf("expected error mentioning agent_token, got: %s", out.String())
	}

	// Verify agent service unknown returns error code
	out.Reset()
	if code := runCLI([]string{"agent", "service", "unknown"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 for agent service unknown, got %d", code)
	}
	if !strings.Contains(out.String(), "Unknown agent service action") {
		t.Fatalf("expected unknown action message, got: %s", out.String())
	}

	// Verify agent service without action returns error code
	out.Reset()
	if code := runCLI([]string{"agent", "service"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 for bare agent service, got %d", code)
	}

	// Verify agent service install with -path works cleanly
	agentPlistPath := filepath.Join(tmpDir, "me.jaewook.nal.security-hub-agent.plist")
	out.Reset()
	code = runCLI([]string{"agent", "service", "install", "-path", agentPlistPath, "-token", "sec123", "-hub", "http://hub.lan:10311"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for agent service install, got %d (%s)", code, out.String())
	}
	content, err := os.ReadFile(agentPlistPath)
	if err != nil {
		t.Fatalf("failed to read installed agent plist: %v", err)
	}
	if !strings.Contains(string(content), "me.jaewook.nal.security-hub-agent") || !strings.Contains(string(content), "sec123") {
		t.Fatalf("agent plist missing expected content: %s", string(content))
	}
	if strings.Contains(string(content), "<string>-token</string>") {
		t.Fatalf("expected agent plist not to pass -token in ProgramArguments:\n%s", string(content))
	}
	if st, sErr := os.Stat(agentPlistPath); sErr != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on agent plist, got err=%v perm=%v", sErr, st)
	}

	// Verify corrupt config.yml in CWD fails loudly
	cfgDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yml"), []byte("web: [broken\n"), 0600)
	origWD, _ := os.Getwd()
	_ = os.Chdir(cfgDir)
	defer func() { _ = os.Chdir(origWD) }()
	if _, lErr := loadAppConfig(""); lErr == nil {
		t.Fatal("expected loadAppConfig to fail on corrupt config.yml")
	}
	_ = os.Chdir(origWD)

	// Verify unknown CLI flags return non-zero
	out.Reset()
	if code := runCLI([]string{"service", "install", "-unknown-flag"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 on unknown service install flag, got %d", code)
	}

	// Verify agent service status runs cleanly (stubbing host service manager for headless CI runners)
	restoreCmd := service.SetCmdRunner(func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("inactive\n"), nil
		}
		return []byte("PID\tStatus\tLabel\n"), nil
	})
	defer restoreCmd()
	out.Reset()
	code = runCLI([]string{"agent", "service", "status"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for agent service status, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "Agent service") {
		t.Fatalf("expected agent service status in output, got: %s", out.String())
	}

	// Verify CLI node add rejects non-HTTP URLs and CLI node list does not abort running daemon tasks
	out.Reset()
	if code := runCLI([]string{"node", "add", "BadNode", "ftp://files.internal/pkg"}, &out); code != 1 {
		t.Fatalf("expected exit code 1 for non-HTTP node URL, got %d (%s)", code, out.String())
	}

	cliCoexDir := t.TempDir()
	t.Setenv("SECURITY_HUB_DATA_DIR", cliCoexDir)
	daemonStore, err := db.NewSpoolStore(cliCoexDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	task, err := daemonStore.CreateTask(context.Background(), &models.Task{
		TaskType:   "security_scan",
		TargetType: "system",
		TargetName: "all",
	})
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := runCLI([]string{"node", "list"}, &out); code != 0 {
		t.Fatalf("expected exit code 0 for node list, got %d (%s)", code, out.String())
	}
	stillRunning, _, err := daemonStore.GetTaskWithLogs(context.Background(), task.ID)
	if err != nil || stillRunning.Status != "running" {
		t.Fatalf("expected CLI node list not to abort daemon task, got status=%v err=%v", stillRunning, err)
	}
}

func TestCLI_ScanCommand(t *testing.T) {
	tmpDir := t.TempDir()
	emptyBin := t.TempDir()
	emptyServices := t.TempDir()
	emptyDaemons := t.TempDir()

	t.Setenv("PATH", emptyBin)
	t.Setenv("SECURITY_HUB_DATA_DIR", tmpDir)

	isoCfgDir := t.TempDir()
	cfgYAML := "node_name: AxisHub\ndatabase:\n  container_name: nonexistent-unit-test-pg\nscanner:\n  services_dir: " + emptyServices + "\n  daemons_dir: " + emptyDaemons + "\n  osv_api_url: http://127.0.0.1:0\n  eol_api_url: http://127.0.0.1:0\n"
	_ = os.WriteFile(filepath.Join(isoCfgDir, "config.yml"), []byte(cfgYAML), 0600)
	startWD, _ := os.Getwd()
	_ = os.Chdir(isoCfgDir)
	defer func() { _ = os.Chdir(startWD) }()

	// Seed a remote approved node (Atlas) with 1 outdated item and another node (Aegis) with cached items
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node": "Atlas",
			"items": []models.ManagedItem{
				{
					Node:           "Atlas",
					TargetType:     models.TargetDocker,
					Name:           "atlas-app",
					CurrentVersion: "1.0.0",
					LatestVersion:  "1.1.0",
					Outdated:       true,
				},
			},
		})
	}))
	defer agentSrv.Close()

	store, err := db.NewCLISpoolStore(tmpDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.UpsertNode(context.Background(), models.NodeInfo{
		Name:   "Atlas",
		URL:    agentSrv.URL,
		Token:  "tok",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	_ = store.UpsertNode(context.Background(), models.NodeInfo{
		Name:   "Aegis",
		URL:    "http://127.0.0.1:19999",
		Token:  "tok",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	_ = store.SaveScanResult(context.Background(), &models.ScanResult{
		Items: []models.ManagedItem{
			{Node: "Aegis", TargetType: models.TargetDocker, Name: "aegis-web", CurrentVersion: "1.0", Outdated: true, CritCount: 2},
			{Node: "Aegis", TargetType: models.TargetDocker, Name: "aegis-db", CurrentVersion: "2.0"},
		},
	})

	// 1. Positional arg rejected
	var out bytes.Buffer
	code := runCLI([]string{"scan", "Atlas"}, &out)
	if code != 1 {
		t.Fatalf("expected exit code 1 for positional arg on scan, got %d (%s)", code, out.String())
	}

	// 2. Single node scan CLI for local Hub -> prints only AxisHub summary (0 items), not Aegis's 2 items
	out.Reset()
	code = runCLI([]string{"scan", "-node", "AxisHub"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for scan -node AxisHub, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "=== NAL Security Hub Scan Summary (Node AxisHub) ===") {
		t.Fatalf("expected Node AxisHub scan summary, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "Items Scanned:     0") || !strings.Contains(out.String(), "Critical CVEs:     0") {
		t.Fatalf("expected node-specific counts (0 items, 0 crit CVEs) rather than Aegis cached counts, got:\n%s", out.String())
	}

	// 3. Single node scan CLI for remote Atlas agent -> prints Atlas summary (1 item) while preserving Aegis in store
	out.Reset()
	code = runCLI([]string{"scan", "-node", "atlas"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for scan -node atlas, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "=== NAL Security Hub Scan Summary (Node Atlas) ===") {
		t.Fatalf("expected canonical Node Atlas scan summary, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "Items Scanned:     1") || !strings.Contains(out.String(), "Outdated Packages: 1") {
		t.Fatalf("expected Atlas counts (1 item, 1 outdated), got:\n%s", out.String())
	}

	// 4. Full scan CLI
	_ = store.RemoveNode(context.Background(), "Aegis")
	out.Reset()
	code = runCLI([]string{"scan"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0 for full scan, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "=== NAL Security Hub Scan Summary (All Nodes) ===") {
		t.Fatalf("expected All Nodes scan summary, got: %s", out.String())
	}

	// 5. Unknown node -> exits 1 with Scan failed
	out.Reset()
	code = runCLI([]string{"scan", "-node", "UnknownNodeXYZ"}, &out)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unknown node scan, got %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "Scan failed") {
		t.Fatalf("expected Scan failed error message, got: %s", out.String())
	}
}
