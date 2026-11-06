package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/notifier"
)

type recordingRunner struct {
	cmds    []string
	handler func(cmdLine string) ([]byte, error)
}

func (r *recordingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	r.cmds = append(r.cmds, line)
	if r.handler != nil {
		return r.handler(line)
	}
	return []byte("ok"), nil
}

func TestUpdateFileTag_PreservesCommentsAndEnvVars(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yml")
	envPath := filepath.Join(dir, ".env")

	composeOriginal := `services:
  server:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
    volumes:
      # Git-managed branding assets.
      - data:/data
  worker:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
`
	envOriginal := `# Authentik Env
AUTHENTIK_SECRET_KEY=supersecret
AUTHENTIK_TAG=2026.5.3
`
	_ = os.WriteFile(composePath, []byte(composeOriginal), 0644)
	_ = os.WriteFile(envPath, []byte(envOriginal), 0644)

	newC, newE, err := UpdateFileTag(composePath, envPath, "server", "2026.10.1")
	if err != nil {
		t.Fatalf("UpdateFileTag failed: %v", err)
	}
	if !strings.Contains(string(newC), "# Git-managed branding assets.") {
		t.Fatalf("expected comments preserved in compose.yml: %s", string(newC))
	}
	if !strings.Contains(string(newC), "${AUTHENTIK_TAG:-2026.10.1}") {
		t.Fatalf("expected default tag updated in compose.yml: %s", string(newC))
	}
	if !strings.Contains(string(newE), "AUTHENTIK_TAG=2026.10.1") || !strings.Contains(string(newE), "# Authentik Env") {
		t.Fatalf("expected AUTHENTIK_TAG updated in .env with comments preserved: %s", string(newE))
	}

	// Test direct quoted image tag like 'jc21/nginx-proxy-manager:latest'
	npmCompose := filepath.Join(dir, "docker-compose.yml")
	_ = os.WriteFile(npmCompose, []byte("services:\n  proxy:\n    image: 'jc21/nginx-proxy-manager:latest'\n"), 0644)
	npmOut, _, err := UpdateFileTag(npmCompose, "", "proxy", "2.11.3")
	if err != nil {
		t.Fatalf("UpdateFileTag(npm) failed: %v", err)
	}
	if !strings.Contains(string(npmOut), "'jc21/nginx-proxy-manager:2.11.3'") {
		t.Fatalf("expected quoted tag updated to 2.11.3, got: %s", string(npmOut))
	}

	// Test multi-service compose file (like services/iot/compose.yml) updates ONLY the targeted serviceKey
	iotCompose := filepath.Join(dir, "iot-compose.yml")
	iotOriginal := `services:
  homeassistant:
    image: homeassistant/home-assistant:2026.9.4
    container_name: homeassistant
  matter-hub:
    image: ghcr.io/riddix/home-assistant-matter-hub:2.0.57
    container_name: matter-hub
`
	_ = os.WriteFile(iotCompose, []byte(iotOriginal), 0644)
	iotOut, _, err := UpdateFileTag(iotCompose, "", "matter-hub", "2.0.60")
	if err != nil {
		t.Fatalf("UpdateFileTag(iot) failed: %v", err)
	}
	if !strings.Contains(string(iotOut), "homeassistant/home-assistant:2026.9.4") {
		t.Fatalf("expected homeassistant tag to remain 2026.9.4 when updating matter-hub, got:\n%s", string(iotOut))
	}
	if !strings.Contains(string(iotOut), "ghcr.io/riddix/home-assistant-matter-hub:2.0.60") {
		t.Fatalf("expected matter-hub tag updated to 2.0.60, got:\n%s", string(iotOut))
	}

	// Test 4-space indentation and digest-pinned images: 'image: repo/app:v1.0@sha256:abcd...'
	pinnedCompose := filepath.Join(dir, "pinned-compose.yml")
	pinnedOriginal := "services:\n    app:\n        image: \"cloudflare/cloudflared:2024.1.0@sha256:4a91f8c0e123456789\"\n"
	_ = os.WriteFile(pinnedCompose, []byte(pinnedOriginal), 0644)
	pinnedOut, _, err := UpdateFileTag(pinnedCompose, "", "app", "2026.10.2")
	if err != nil {
		t.Fatalf("UpdateFileTag(pinned) failed: %v", err)
	}
	if !strings.Contains(string(pinnedOut), "\"cloudflare/cloudflared:2026.10.2\"") {
		t.Fatalf("expected digest stripped and tag replaced cleanly, got:\n%s", string(pinnedOut))
	}
}

func TestManager_RunUpdateSync_DeadManRollbackOnFailure(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	servicesDir := filepath.Join(root, "services")
	cfDir := filepath.Join(servicesDir, "cloudflare-tunnel")
	_ = os.MkdirAll(cfDir, 0755)

	origCompose := `services:
  cloudflare-tunnel:
    image: cloudflare/cloudflared:latest
    container_name: cloudflare-tunnel-daemon
`
	composeFile := filepath.Join(cfDir, "compose.yml")
	_ = os.WriteFile(composeFile, []byte(origCompose), 0644)

	store, err := db.NewSpoolStore(filepath.Join(root, "data"), nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Scanner.ServicesDir = servicesDir
	cfg.Updater.BatchDir = filepath.Join(root, "batch")
	cfg.Updater.DeadManTimeoutSeconds = 1

	runner := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			switch {
			case strings.Contains(cmdLine, "docker inspect --format {{json .Image}}"):
				return []byte(`"sha256:img111"`), nil
			case strings.Contains(cmdLine, "docker image inspect --format {{json .RepoDigests}}"):
				return []byte(`["cloudflare/cloudflared@sha256:4a91f8c0"]`), nil
			case strings.Contains(cmdLine, "docker inspect --format {{json .State}}"):
				// Simulate new container exiting/crashing!
				return []byte(`{"Status":"exited","Restarting":false}`), nil
			default:
				return []byte("ok"), nil
			}
		},
	}

	alerter := notifier.NewAlerter(config.EmailConfig{Enabled: false}, store)
	mgr := NewManager(cfg, store, runner, alerter)

	req := UpdateRequest{
		TargetType:    "docker",
		TargetName:    "cloudflare-tunnel",
		TargetVersion: "2026.10.2",
		EnableDeadMan: true,
		TriggeredBy:   "sso:jaewook@jaewook.dev",
	}
	task, err := store.CreateTask(ctx, mgr.newTaskModel(req, "latest"))
	if err != nil {
		t.Fatal(err)
	}

	err = mgr.RunUpdateSync(ctx, task.ID, req)
	if err == nil {
		t.Fatal("expected RunUpdateSync to return error when container crashes and triggers rollback")
	}

	gotTask, _, err := store.GetTaskWithLogs(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotTask.Status != "rolled_back" {
		t.Fatalf("expected task status 'rolled_back', got %s", gotTask.Status)
	}

	// Verify compose.yml was restored to original bytes
	restoredBytes, _ := os.ReadFile(composeFile)
	if string(restoredBytes) != origCompose {
		t.Fatalf("expected compose.yml restored to original, got: %s", string(restoredBytes))
	}

	// Verify docker tag of saved digest was executed before rollback compose up
	foundRetag := false
	for _, c := range runner.cmds {
		if strings.Contains(c, "docker tag cloudflare/cloudflared@sha256:4a91f8c0 cloudflare/cloudflared:latest") {
			foundRetag = true
		}
	}
	if !foundRetag {
		t.Fatalf("expected rollback to re-tag previous digest sha256:4a91f8c0, commands were: %v", runner.cmds)
	}
}

func TestManager_VerifyContainerHealthy_PollsUntilHealthyAndChecksUnhealthy(t *testing.T) {
	ctx := context.Background()
	cfg := config.DefaultConfig()
	cfg.Updater.DeadManTimeoutSeconds = 2

	attempts := 0
	runner := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.Contains(cmdLine, "docker inspect") {
				attempts++
				if attempts < 3 {
					return []byte(`{"Status":"running","Restarting":false,"HealthStatus":"starting"}`), nil
				}
				return []byte(`{"Status":"running","Restarting":false,"HealthStatus":"healthy"}`), nil
			}
			return []byte("ok"), nil
		},
	}

	mgr := NewManager(cfg, nil, runner, nil)
	mgr.pollInterval = 10 * time.Millisecond
	if err := mgr.verifyContainerHealthy(ctx, "postgresql", "db"); err != nil {
		t.Fatalf("expected polling to succeed once container transitions starting->healthy, got: %v", err)
	}
	if attempts < 3 {
		t.Fatalf("expected at least 3 poll attempts, got %d", attempts)
	}
}

func TestManager_RollbackServiceOnNode_RemoteFailureHandled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":"failed","error_msg":"internal agent failure"}`))
	}))
	defer ts.Close()

	root := t.TempDir()
	store, err := db.NewSpoolStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name: "remote-atlas",
		URL:  ts.URL,
		Role: "agent",
	})

	cfg := config.DefaultConfig()
	cfg.NodeName = "hub-local"
	mgr := NewManager(cfg, store, &recordingRunner{}, nil)

	_, err = mgr.RollbackServiceOnNode(ctx, "remote-atlas", "db", "admin")
	if err == nil {
		t.Fatal("expected RollbackServiceOnNode to fail when remote agent returns HTTP 500")
	}
	if !strings.Contains(err.Error(), "internal agent failure") {
		t.Fatalf("expected error message to mention agent failure, got: %v", err)
	}
}

