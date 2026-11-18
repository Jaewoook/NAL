package updater

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

	// Test nested keys (environment/volumes) defined before image line
	nestedCompose := filepath.Join(dir, "nested-compose.yml")
	nestedOriginal := `services:
  myapp:
    container_name: myapp
    environment:
      - NODE_ENV=production
      - PORT=8080
    volumes:
      - /data:/data
    image: myrepo/myapp:1.0.0
    restart: unless-stopped
`
	_ = os.WriteFile(nestedCompose, []byte(nestedOriginal), 0644)
	nestedOut, _, err := UpdateFileTag(nestedCompose, "", "myapp", "1.1.0")
	if err != nil {
		t.Fatalf("UpdateFileTag(nested) failed: %v", err)
	}
	if !strings.Contains(string(nestedOut), "myrepo/myapp:1.1.0") {
		t.Fatalf("expected myapp image updated to 1.1.0 even with nested keys preceding image line, got:\n%s", string(nestedOut))
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
	for _, c := range runner.cmds {
		if strings.HasPrefix(c, "git ") {
			t.Fatalf("expected no git commands when update fails health check and rolls back, got: %s", c)
		}
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
	if err := mgr.verifyContainerHealthy(ctx, "", "", "postgresql", "db"); err != nil {
		t.Fatalf("expected polling to succeed once container transitions starting->healthy, got: %v", err)
	}
	if attempts < 3 {
		t.Fatalf("expected at least 3 poll attempts, got %d", attempts)
	}
}

func TestManager_VerifyContainerHealthy_TransientInspectErrorAndCreatedStatus_RetriesUntilHealthy(t *testing.T) {
	ctx := context.Background()
	cfg := config.DefaultConfig()
	cfg.Updater.DeadManTimeoutSeconds = 2

	attempts := 0
	runner := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.Contains(cmdLine, "docker inspect") {
				attempts++
				if attempts == 1 {
					return nil, errors.New("daemon connection reset")
				}
				if attempts == 2 {
					return []byte(`{"Status":"created","Restarting":false}`), nil
				}
				return []byte(`{"Status":"running","Restarting":false,"HealthStatus":"healthy"}`), nil
			}
			return []byte("ok"), nil
		},
	}

	mgr := NewManager(cfg, nil, runner, nil)
	mgr.pollInterval = 10 * time.Millisecond
	if err := mgr.verifyContainerHealthy(ctx, "", "", "postgresql", "db"); err != nil {
		t.Fatalf("expected transient inspect error and 'created' status to retry until healthy, got: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 poll attempts, got %d", attempts)
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

func TestManager_RejectsUpdateAndRollbackOnUnapprovedNode(t *testing.T) {
	ctx := context.Background()
	store, _ := db.NewSpoolStore(t.TempDir(), nil)
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "pending-node",
		URL:    "http://127.0.0.1:9999",
		Role:   "agent",
		Status: models.NodeStatusPending,
	})
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "rejected-node",
		URL:    "http://127.0.0.1:9999",
		Role:   "agent",
		Status: models.NodeStatusRejected,
	})

	cfg := config.DefaultConfig()
	cfg.NodeName = "hub-local"
	mgr := NewManager(cfg, store, &recordingRunner{}, nil)

	// 1. Rollback on pending node
	_, err := mgr.RollbackServiceOnNode(ctx, "pending-node", "dns", "admin")
	if err == nil || !strings.Contains(err.Error(), "cannot rollback unapproved node") {
		t.Fatalf("expected rollback on pending node to be rejected, got: %v", err)
	}

	// 2. Rollback on rejected node
	_, err = mgr.RollbackServiceOnNode(ctx, "rejected-node", "dns", "admin")
	if err == nil || !strings.Contains(err.Error(), "cannot rollback unapproved node") {
		t.Fatalf("expected rollback on rejected node to be rejected, got: %v", err)
	}

	// 3. Update forwarding on pending node
	t1, _ := store.CreateTask(ctx, &models.Task{
		Node:     "pending-node",
		TaskType: "agent_update",
		Status:   "running",
	})
	err = mgr.RunUpdateSync(ctx, t1.ID, UpdateRequest{
		Node:          "pending-node",
		TargetType:    "docker",
		TargetName:    "dns",
		TargetVersion: "v1.0.0",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot update unapproved node") {
		t.Fatalf("expected update on pending node to be rejected, got: %v", err)
	}
}

func TestManager_RunUpdateSync_HealthyCommitsComposeToRealGitRepoAsNALBot(t *testing.T) {
	ctx := context.Background()
	repoRoot := t.TempDir()
	servicesDir := filepath.Join(repoRoot, "services")
	svcDir := filepath.Join(servicesDir, "cloudflare-tunnel")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}

	composeFile := filepath.Join(svcDir, "compose.yml")
	origCompose := "services:\n  cloudflare-tunnel:\n    image: cloudflare/cloudflared:2026.5.0\n    container_name: cloudflare-tunnel-daemon\n"
	if err := os.WriteFile(composeFile, []byte(origCompose), 0644); err != nil {
		t.Fatal(err)
	}
	// Write a .env file and an unrelated staged file to ensure neither gets swept into NAL Bot's commit
	if err := os.WriteFile(filepath.Join(svcDir, ".env"), []byte("TUNNEL_TOKEN=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelatedFile := filepath.Join(repoRoot, "unrelated.txt")
	if err := os.WriteFile(unrelatedFile, []byte("v1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Initialize a real git repository with personal git config (to prove bot overrides personal config)
	mustGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoRoot}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}
	mustGit("init")
	mustGit("config", "user.name", "Personal User")
	mustGit("config", "user.email", "personal@example.com")
	mustGit("config", "commit.gpgsign", "false")
	mustGit("add", "services/cloudflare-tunnel/compose.yml", "unrelated.txt")
	mustGit("commit", "-m", "initial commit")

	// Pre-stage an unrelated change so we prove --only isolates the compose commit
	if err := os.WriteFile(unrelatedFile, []byte("v2-staged\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mustGit("add", "unrelated.txt")

	store, err := db.NewSpoolStore(filepath.Join(t.TempDir(), "data"), nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECURITY_HUB_GIT_GPG_SIGN", "false")
	cfg := config.DefaultConfigWithEnv()
	cfg.Scanner.ServicesDir = servicesDir
	cfg.Updater.BatchDir = filepath.Join(repoRoot, "batch")
	cfg.Updater.DeadManTimeoutSeconds = 2

	// Delegate git commands to real git binary, mock docker commands as healthy
	runner := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.HasPrefix(cmdLine, "git ") {
				return nil, errors.New("unexpected fallback")
			}
			if strings.Contains(cmdLine, "docker inspect --format {{json .State}}") {
				return []byte(`{"Status":"running","Restarting":false,"HealthStatus":"healthy"}`), nil
			}
			return []byte("ok"), nil
		},
	}
	hybridRunner := &funcRunner{
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "git" {
				return exec.CommandContext(ctx, name, args...).CombinedOutput()
			}
			return runner.Run(ctx, name, args...)
		},
	}

	mgr := NewManager(cfg, store, hybridRunner, nil)
	req := UpdateRequest{
		TargetType:    "docker",
		TargetName:    "cloudflare-tunnel",
		TargetVersion: "2026.10.2",
		EnableDeadMan: true,
		TriggeredBy:   "sso:jaewook@jaewook.dev",
	}
	task, err := store.CreateTask(ctx, mgr.newTaskModel(req, "2026.5.0"))
	if err != nil {
		t.Fatal(err)
	}

	if err := mgr.RunUpdateSync(ctx, task.ID, req); err != nil {
		t.Fatalf("RunUpdateSync failed: %v", err)
	}

	// Verify HEAD commit was authored & committed by NAL Bot (not Personal User)
	logMeta := mustGit("log", "-1", "--format=%an|%ae|%cn|%ce|%s")
	expectedMeta := "NAL Bot|nal-git-system@jaewook.me|NAL Bot|nal-git-system@jaewook.me|chore(services): update cloudflare-tunnel image to 2026.10.2"
	if logMeta != expectedMeta {
		t.Fatalf("expected commit metadata %q, got %q", expectedMeta, logMeta)
	}

	// Verify ONLY compose.yml was committed (not .env and not pre-staged unrelated.txt)
	committedFiles := mustGit("show", "--name-only", "--format=", "HEAD")
	if committedFiles != "services/cloudflare-tunnel/compose.yml" {
		t.Fatalf("expected only compose.yml in commit, got:\n%s", committedFiles)
	}
	statusAfter := mustGit("status", "--porcelain")
	if !strings.Contains(statusAfter, "M  unrelated.txt") {
		t.Fatalf("expected pre-staged unrelated.txt to remain staged and untouched, got status:\n%s", statusAfter)
	}

	// Bug 2 regression check: manual RollbackService after a committed update commits the restored compose.yml as NAL Bot
	if _, err := mgr.RollbackService(ctx, "cloudflare-tunnel", "sso:jaewook@jaewook.dev"); err != nil {
		t.Fatalf("RollbackService failed: %v", err)
	}
	rbMeta := mustGit("log", "-1", "--format=%an|%ae|%cn|%ce|%s")
	expectedRbMeta := "NAL Bot|nal-git-system@jaewook.me|NAL Bot|nal-git-system@jaewook.me|revert(services): roll back cloudflare-tunnel image to 2026.5.0"
	if rbMeta != expectedRbMeta {
		t.Fatalf("expected rollback commit metadata %q, got %q", expectedRbMeta, rbMeta)
	}
	composeStatusAfterRb := mustGit("status", "--porcelain", "--", "services/cloudflare-tunnel/compose.yml")
	if composeStatusAfterRb != "" {
		t.Fatalf("expected compose.yml to be clean in git after committed rollback, got: %q", composeStatusAfterRb)
	}

	// Bug 1 regression check: if compose.yml already has uncommitted manual edits before update, skip committing
	headBeforeDirtyUpdate := mustGit("rev-parse", "HEAD")
	dirtyCompose := origCompose + "    environment:\n      - MANUAL_WIP=1\n"
	if err := os.WriteFile(composeFile, []byte(dirtyCompose), 0644); err != nil {
		t.Fatal(err)
	}
	reqDirty := UpdateRequest{
		TargetType:    "docker",
		TargetName:    "cloudflare-tunnel",
		TargetVersion: "2026.11.0",
		EnableDeadMan: true,
		TriggeredBy:   "sso:jaewook@jaewook.dev",
	}
	taskDirty, err := store.CreateTask(ctx, mgr.newTaskModel(reqDirty, "2026.5.0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.RunUpdateSync(ctx, taskDirty.ID, reqDirty); err != nil {
		t.Fatalf("RunUpdateSync on dirty compose failed: %v", err)
	}
	headAfterDirtyUpdate := mustGit("rev-parse", "HEAD")
	if headAfterDirtyUpdate != headBeforeDirtyUpdate {
		t.Fatalf("expected git commit to be skipped when compose.yml had pre-existing uncommitted edits, but HEAD moved from %s to %s:\n%s",
			headBeforeDirtyUpdate, headAfterDirtyUpdate, mustGit("show", "HEAD"))
	}
	updatedDirtyBytes, _ := os.ReadFile(composeFile)
	if !strings.Contains(string(updatedDirtyBytes), "2026.11.0") || !strings.Contains(string(updatedDirtyBytes), "MANUAL_WIP=1") {
		t.Fatalf("expected compose.yml on disk to have updated tag AND preserve manual edit, got:\n%s", string(updatedDirtyBytes))
	}
}

func TestManager_RunUpdateSync_GPGSigningFlagAndSkipsCommitOnUnhealthy(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	servicesDir := filepath.Join(root, "services")
	svcDir := filepath.Join(servicesDir, "dns")
	_ = os.MkdirAll(svcDir, 0755)
	composeFile := filepath.Join(svcDir, "compose.yml")
	_ = os.WriteFile(composeFile, []byte("services:\n  dns:\n    image: adguard/adguardhome:v0.107.50\n    container_name: adguard\n"), 0644)

	store, _ := db.NewSpoolStore(filepath.Join(root, "data"), nil)
	cfg := config.DefaultConfig()
	cfg.Scanner.ServicesDir = servicesDir
	cfg.Updater.DeadManTimeoutSeconds = 1

	// 1. Healthy container with default GPGSign=true -> passes -S024D4017DFF5360A and NAL Bot identity
	var gitCmdArgs [][]string
	healthyRunner := &funcRunner{
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "git" {
				gitCmdArgs = append(gitCmdArgs, append([]string{name}, args...))
				for _, a := range args {
					if a == "show" {
						return []byte("services:\n  dns:\n    image: adguard/adguardhome:v0.107.50\n    container_name: adguard\n"), nil
					}
				}
				return []byte("[main abc1234] chore(services): update dns image to v0.107.55\n"), nil
			}
			if strings.Contains(strings.Join(args, " "), "{{json .State}}") {
				return []byte(`{"Status":"running","Restarting":false}`), nil
			}
			return []byte("ok"), nil
		},
	}
	mgr := NewManager(cfg, store, healthyRunner, nil)
	req := UpdateRequest{
		TargetType:    "docker",
		TargetName:    "dns",
		TargetVersion: "v0.107.55",
		EnableDeadMan: true,
		TriggeredBy:   "admin",
	}
	t1, _ := store.CreateTask(ctx, mgr.newTaskModel(req, "v0.107.50"))
	if err := mgr.RunUpdateSync(ctx, t1.ID, req); err != nil {
		t.Fatalf("expected healthy update to succeed, got: %v", err)
	}

	var foundSignedCommit bool
	for _, argv := range gitCmdArgs {
		joined := strings.Join(argv, " ")
		if strings.Contains(joined, " commit ") {
			if !strings.Contains(joined, "-S024D4017DFF5360A") {
				t.Fatalf("expected GPG key flag -S024D4017DFF5360A in git commit, got: %v", argv)
			}
			if !strings.Contains(joined, "user.name=NAL Bot") || !strings.Contains(joined, "user.email=nal-git-system@jaewook.me") {
				t.Fatalf("expected NAL Bot identity in git commit, got: %v", argv)
			}
			foundSignedCommit = true
		}
	}
	if !foundSignedCommit {
		t.Fatalf("expected git commit command to be executed, git commands were: %v", gitCmdArgs)
	}

	// 2. Unhealthy container (even without DeadMan) -> must skip git commit completely
	var unhealthyGitCmds [][]string
	unhealthyRunner := &funcRunner{
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "git" {
				unhealthyGitCmds = append(unhealthyGitCmds, append([]string{name}, args...))
				return []byte(" M compose.yml\n"), nil
			}
			if strings.Contains(strings.Join(args, " "), "{{json .State}}") {
				return []byte(`{"Status":"exited","Restarting":false}`), nil
			}
			return []byte("ok"), nil
		},
	}
	// Use a non-critical service with EnableDeadMan=false to test plain failure path too
	webDir := filepath.Join(servicesDir, "websearch")
	_ = os.MkdirAll(webDir, 0755)
	_ = os.WriteFile(filepath.Join(webDir, "compose.yml"), []byte("services:\n  searxng:\n    image: searxng/searxng:2026.1.0\n    container_name: searxng\n"), 0644)

	mgrUnhealthy := NewManager(cfg, store, unhealthyRunner, nil)
	reqFail := UpdateRequest{
		TargetType:    "docker",
		TargetName:    "websearch",
		TargetVersion: "2026.2.0",
		EnableDeadMan: false,
		TriggeredBy:   "admin",
	}
	t2, _ := store.CreateTask(ctx, mgrUnhealthy.newTaskModel(reqFail, "2026.1.0"))
	if err := mgrUnhealthy.RunUpdateSync(ctx, t2.ID, reqFail); err == nil {
		t.Fatal("expected unhealthy update to return error")
	}
	if len(unhealthyGitCmds) != 0 {
		t.Fatalf("expected zero git commands when container is unhealthy, got: %v", unhealthyGitCmds)
	}
}

type funcRunner struct {
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (f *funcRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.run(ctx, name, args...)
}

func TestManager_RemoteForward_TokenFallbackAndLocalRouting(t *testing.T) {
	ctx := context.Background()
	var updateToken, rollbackToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/agent/update":
			updateToken = r.Header.Get("X-NAL-Node-Token")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "succeeded",
			})
		case "/api/agent/rollback":
			rollbackToken = r.Header.Get("X-NAL-Node-Token")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "succeeded",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store, _ := db.NewSpoolStore(t.TempDir(), nil)
	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "agent-no-tok",
		URL:    srv.URL,
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})

	cfg := config.DefaultConfig()
	cfg.NodeName = "Hub-Primary"
	cfg.AgentToken = "shared-cluster-agent-secret"

	mgr := NewManager(cfg, store, &recordingRunner{}, nil)
	mgr.SetHTTPClient(srv.Client())

	// 1. Verify forwardUpdateToAgent falls back to cfg.AgentToken
	t1, _ := store.CreateTask(ctx, &models.Task{
		Node:     "agent-no-tok",
		TaskType: "agent_update",
		Status:   "running",
	})
	err := mgr.RunUpdateSync(ctx, t1.ID, UpdateRequest{
		Node:          "agent-no-tok",
		TargetType:    "docker",
		TargetName:    "dns",
		TargetVersion: "1.2.0",
	})
	if err != nil {
		t.Fatalf("RunUpdateSync failed on remote node: %v", err)
	}
	if updateToken != "shared-cluster-agent-secret" {
		t.Fatalf("expected update token fallback to 'shared-cluster-agent-secret', got %q", updateToken)
	}

	// 2. Verify RollbackServiceOnNode falls back to cfg.AgentToken
	_, err = mgr.RollbackServiceOnNode(ctx, "agent-no-tok", "dns", "admin")
	if err != nil {
		t.Fatalf("RollbackServiceOnNode failed on remote node: %v", err)
	}
	if rollbackToken != "shared-cluster-agent-secret" {
		t.Fatalf("expected rollback token fallback to 'shared-cluster-agent-secret', got %q", rollbackToken)
	}

	// 3. Verify local node routing: 'local' and case-insensitive 'hub-primary' route locally
	tLocal, _ := store.CreateTask(ctx, &models.Task{
		Node:     "local",
		TaskType: "docker_update",
		Status:   "running",
	})
	err = mgr.RunUpdateSync(ctx, tLocal.ID, UpdateRequest{
		Node:          "local",
		TargetType:    "docker",
		TargetName:    "nonexistent",
		TargetVersion: "1.0.0",
	})
	if err != nil && strings.Contains(err.Error(), "unknown remote node") {
		t.Fatalf("expected 'local' to route locally, but attempted remote forward: %v", err)
	}

	tLocalCase, _ := store.CreateTask(ctx, &models.Task{
		Node:     "hub-primary",
		TaskType: "docker_update",
		Status:   "running",
	})
	err = mgr.RunUpdateSync(ctx, tLocalCase.ID, UpdateRequest{
		Node:          "hub-primary",
		TargetType:    "docker",
		TargetName:    "nonexistent",
		TargetVersion: "1.0.0",
	})
	if err != nil && strings.Contains(err.Error(), "unknown remote node") {
		t.Fatalf("expected 'hub-primary' to route locally via EqualFold, but attempted remote forward: %v", err)
	}

	// 4. Verify RollbackServiceOnNode with 'local' routes locally
	_, err = mgr.RollbackServiceOnNode(ctx, "local", "dns", "admin")
	if err != nil && strings.Contains(err.Error(), "node \"local\" not found") {
		t.Fatalf("expected rollback with 'local' to route locally, but attempted remote lookup: %v", err)
	}
}

func TestManager_RunAptUpgrade_NormalSudoFallbackAndReinstall(t *testing.T) {
	ctx := context.Background()
	store, _ := db.NewSpoolStore(t.TempDir(), nil)
	cfg := config.DefaultConfig()
	cfg.NodeName = "rpi-01"

	// 1. Normal APT upgrade (root/passwordless apt-get succeeds directly)
	rec1 := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.HasPrefix(cmdLine, "dpkg -s ") {
				return []byte("Package: openssl\nStatus: install ok installed\n"), nil
			}
			return []byte("Setting up openssl (3.0.14-1~deb12u1) ..."), nil
		},
	}
	mgr1 := NewManager(cfg, store, rec1, nil)
	req1 := UpdateRequest{
		Node:          "rpi-01",
		TargetType:    string(models.TargetApt),
		TargetName:    "openssl",
		TargetVersion: "3.0.14-1~deb12u1",
	}
	t1, _ := store.CreateTask(ctx, mgr1.newTaskModel(req1, "3.0.11-1~deb12u2"))
	if t1.TaskType != "apt_upgrade" {
		t.Fatalf("expected task type 'apt_upgrade', got %q", t1.TaskType)
	}
	if err := mgr1.RunUpdateSync(ctx, t1.ID, req1); err != nil {
		t.Fatalf("normal apt upgrade failed: %v", err)
	}
	joined1 := strings.Join(rec1.cmds, "\n")
	if !strings.Contains(joined1, "apt-get install --only-upgrade -y -o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -- openssl") || !strings.Contains(joined1, "dpkg -s -- openssl") {
		t.Fatalf("unexpected commands for normal apt upgrade:\n%s", joined1)
	}

	// 2. Broken dependency reinstall (--reinstall -f)
	rec2 := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.HasPrefix(cmdLine, "dpkg -s ") {
				return []byte("Package: nginx\nStatus: install ok installed\n"), nil
			}
			return []byte("ok"), nil
		},
	}
	mgr2 := NewManager(cfg, store, rec2, nil)
	req2 := UpdateRequest{
		Node:          "rpi-01",
		TargetType:    string(models.TargetApt),
		TargetName:    "nginx",
		TargetVersion: "1.22.1-9",
		BrokenLinkage: true,
	}
	t2, _ := store.CreateTask(ctx, mgr2.newTaskModel(req2, "1.22.1-9"))
	if err := mgr2.RunUpdateSync(ctx, t2.ID, req2); err != nil {
		t.Fatalf("apt reinstall failed: %v", err)
	}
	joined2 := strings.Join(rec2.cmds, "\n")
	if !strings.Contains(joined2, "apt-get install --reinstall -f -y -o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -- nginx") {
		t.Fatalf("expected --reinstall -f and conffile/lock flags when BrokenLinkage=true, got:\n%s", joined2)
	}

	// 3. Permission denied triggers sudo -n env DEBIAN_FRONTEND=noninteractive fallback
	rec3 := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.HasPrefix(cmdLine, "dpkg -s ") {
				return []byte("Package: curl\nStatus: hold ok installed\n"), nil
			}
			if strings.HasPrefix(cmdLine, "apt-get install ") && strings.HasSuffix(cmdLine, " -- curl") {
				return []byte("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"), errors.New("exit status 100")
			}
			return []byte("Upgraded curl via sudo"), nil
		},
	}
	mgr3 := NewManager(cfg, store, rec3, nil)
	req3 := UpdateRequest{
		Node:          "rpi-01",
		TargetType:    string(models.TargetApt),
		TargetName:    "curl",
		TargetVersion: "7.88.1-10+deb12u8",
	}
	t3, _ := store.CreateTask(ctx, mgr3.newTaskModel(req3, "7.88.1-10+deb12u6"))
	if err := mgr3.RunUpdateSync(ctx, t3.ID, req3); err != nil {
		t.Fatalf("sudo -n fallback apt upgrade failed: %v", err)
	}
	joined3 := strings.Join(rec3.cmds, "\n")
	if !strings.Contains(joined3, "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y -o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -- curl") {
		t.Fatalf("expected sudo -n env DEBIAN_FRONTEND=noninteractive retry on permission error, got:\n%s", joined3)
	}

	// 4. Multiarch package name with single :arch accepted; invalid package names rejected
	if !isValidAptPackageName("libfoo:armhf") {
		t.Fatal("expected multiarch package name libfoo:armhf to be valid")
	}
	for _, badPkg := range []string{"a", "openssl-", "a:b:c", "-badflag", "/tmp/evil.deb", "./pkg.deb", "openssl=1.0", "pkg name"} {
		reqInvalid := UpdateRequest{
			Node:       "rpi-01",
			TargetType: string(models.TargetApt),
			TargetName: badPkg,
		}
		tInvalid, _ := store.CreateTask(ctx, mgr3.newTaskModel(reqInvalid, ""))
		if err := mgr3.RunUpdateSync(ctx, tInvalid.ID, reqInvalid); err == nil {
			t.Fatalf("expected error for invalid apt package name %q", badPkg)
		}
	}

	// 5. Post-upgrade dpkg -s missing Status: or unhealthy status fails; non-permission apt error does not invoke sudo
	recBadStatus := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.HasPrefix(cmdLine, "dpkg -s ") {
				return []byte("Package: openssl\nDescription: Status: install ok installed in body only\n"), nil
			}
			return []byte("ok"), nil
		},
	}
	mgrBadStatus := NewManager(cfg, store, recBadStatus, nil)
	if err := mgrBadStatus.RunUpdateSync(ctx, t1.ID, req1); err == nil {
		t.Fatal("expected error when dpkg -s output lacks top-level Status: header")
	}

	recUnhealthy := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.HasPrefix(cmdLine, "dpkg -s ") {
				return []byte("Package: openssl\nStatus: install ok half-configured\n"), nil
			}
			return []byte("ok"), nil
		},
	}
	mgrUnhealthy := NewManager(cfg, store, recUnhealthy, nil)
	if err := mgrUnhealthy.RunUpdateSync(ctx, t1.ID, req1); err == nil {
		t.Fatal("expected error when dpkg -s Status is half-configured")
	}

	recNonPermFail := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			return []byte("E: Unable to locate package openssl"), errors.New("exit status 100")
		},
	}
	mgrNonPermFail := NewManager(cfg, store, recNonPermFail, nil)
	if err := mgrNonPermFail.RunUpdateSync(ctx, t1.ID, req1); err == nil {
		t.Fatal("expected error on missing package")
	}
	if strings.Contains(strings.Join(recNonPermFail.cmds, "\n"), "sudo") {
		t.Fatalf("did not expect sudo retry on non-permission error, cmds=%v", recNonPermFail.cmds)
	}
}

func TestManager_SecurityHardening_BrewValidationAndDockerPathTraversal(t *testing.T) {
	ctx := context.Background()
	store, _ := db.NewSpoolStore(t.TempDir(), nil)
	cfg := config.DefaultConfig()
	cfg.NodeName = "hub-local"
	cfg.Scanner.ServicesDir = t.TempDir()

	rec := &recordingRunner{}
	mgr := NewManager(cfg, store, rec, nil)

	// 1. Brew package name validation rejects flags, local formula paths, traversal, and shell characters
	for _, badBrew := range []string{"", "-v", "--HEAD", "/tmp/evil.rb", "tap//pkg", "tap/", "../tap/pkg", "pkg name", "pkg;id"} {
		req := UpdateRequest{
			Node:       "hub-local",
			TargetType: string(models.TargetBrew),
			TargetName: badBrew,
		}
		task, _ := store.CreateTask(ctx, mgr.newTaskModel(req, ""))
		if err := mgr.RunUpdateSync(ctx, task.ID, req); err == nil {
			t.Fatalf("expected error for invalid brew package name %q", badBrew)
		}
	}
	// Valid brew package with tap or @version succeeds
	reqValidBrew := UpdateRequest{
		Node:       "hub-local",
		TargetType: string(models.TargetBrew),
		TargetName: "openssl@3",
	}
	taskBrew, _ := store.CreateTask(ctx, mgr.newTaskModel(reqValidBrew, ""))
	if err := mgr.RunUpdateSync(ctx, taskBrew.ID, reqValidBrew); err != nil {
		t.Fatalf("expected valid brew package openssl@3 to succeed, got: %v", err)
	}

	// 2. Docker update & rollback reject path traversal service names and invalid target tags
	for _, badSvc := range []string{"", ".", "..", "../etc", `..\etc`, "svc/../../etc"} {
		reqDocker := UpdateRequest{
			Node:          "hub-local",
			TargetType:    string(models.TargetDocker),
			TargetName:    badSvc,
			TargetVersion: "1.0.0",
		}
		taskDoc, _ := store.CreateTask(ctx, mgr.newTaskModel(reqDocker, ""))
		if err := mgr.RunUpdateSync(ctx, taskDoc.ID, reqDocker); err == nil {
			t.Fatalf("expected error for invalid docker service name %q", badSvc)
		}
		if _, err := mgr.RollbackServiceOnNode(ctx, "hub-local", badSvc, "admin"); err == nil {
			t.Fatalf("expected rollback error for invalid service name %q", badSvc)
		}
	}
	for _, badTag := range []string{"1.0\n    privileged: true", "1.0}", "1.0'", "-bad", ".bad", "1.0@sha256:abc", "bad tag"} {
		reqTag := UpdateRequest{
			Node:          "hub-local",
			TargetType:    string(models.TargetDocker),
			TargetName:    "app",
			TargetVersion: badTag,
		}
		if err := ValidateUpdateRequest(reqTag); err == nil {
			t.Fatalf("expected ValidateUpdateRequest to reject dangerous tag %q", badTag)
		}
	}
}

func TestUpdateFileTag_FullEnvVarAndNestedLabelsSafety(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yml")
	envPath := filepath.Join(dir, ".env")

	composeContent := `x-template:
  image: should/not-touch:0.1
services:
  app:
    labels:
      meta:
        image: nested/fake:0.1
    image: ${APP_IMAGE:-ghcr.io/acme/app:1.0.0}
`
	envContent := "APP_IMAGE=ghcr.io/acme/app:1.0.0\n"
	_ = os.WriteFile(composePath, []byte(composeContent), 0640)
	_ = os.WriteFile(envPath, []byte(envContent), 0600)

	newC, newE, err := UpdateFileTag(composePath, envPath, "app", "2.0.0")
	if err != nil {
		t.Fatalf("UpdateFileTag failed: %v", err)
	}
	if !strings.Contains(string(newC), "${APP_IMAGE:-ghcr.io/acme/app:2.0.0}") {
		t.Fatalf("expected full-image env default updated preserving brace, got:\n%s", string(newC))
	}
	if !strings.Contains(string(newC), "should/not-touch:0.1") || !strings.Contains(string(newC), "nested/fake:0.1") {
		t.Fatalf("expected x-template and nested labels untouched, got:\n%s", string(newC))
	}
	if !strings.Contains(string(newE), "APP_IMAGE=ghcr.io/acme/app:2.0.0") {
		t.Fatalf("expected full-image .env value updated preserving repo, got:\n%s", string(newE))
	}
	if _, _, err := UpdateFileTag(composePath, envPath, "app", "bad\ntag"); err == nil {
		t.Fatal("expected newline tag injection in UpdateFileTag to fail")
	}
}

func TestManager_ConcurrencyAndDeadManRollbackFailureAndWrongServiceKey(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	servicesDir := filepath.Join(root, "services")
	stackDir := filepath.Join(servicesDir, "stack")
	_ = os.MkdirAll(stackDir, 0755)
	_ = os.WriteFile(filepath.Join(stackDir, "compose.yml"), []byte("services:\n  web:\n    image: nginx:1.25.0\n"), 0644)

	store, _ := db.NewSpoolStore(filepath.Join(root, "data"), nil)
	cfg := config.DefaultConfig()
	cfg.NodeName = "hub"
	cfg.Scanner.ServicesDir = servicesDir
	cfg.Updater.DeadManTimeoutSeconds = 1

	// 1. Mismatched serviceKey errors cleanly instead of falling back to refs[0]
	mgrKey := NewManager(cfg, store, &recordingRunner{}, nil)
	badKeyTask, _ := store.CreateTask(ctx, &models.Task{Node: "hub", TaskType: "docker_update", Status: "running"})
	if err := mgrKey.RunUpdateSync(ctx, badKeyTask.ID, UpdateRequest{
		Node:          "hub",
		TargetType:    "docker",
		TargetName:    "stack/missingkey",
		TargetVersion: "1.26.0",
	}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected serviceKey not found error, got: %v", err)
	}

	// 2. Dead-man's rollback restore failure marks task failed (not rolled_back)
	rbFailRunner := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			if strings.Contains(cmdLine, "up -d") && strings.Contains(cmdLine, "stack") {
				// fail both upgrade up and rollback up
				return []byte("compose error"), errors.New("exit status 1")
			}
			return []byte("ok"), nil
		},
	}
	mgrFail := NewManager(cfg, store, rbFailRunner, nil)
	failTask, _ := store.CreateTask(ctx, &models.Task{Node: "hub", TaskType: "docker_update", Status: "running"})
	err := mgrFail.RunUpdateSync(ctx, failTask.ID, UpdateRequest{
		Node:          "hub",
		TargetType:    "docker",
		TargetName:    "stack/web",
		TargetVersion: "1.26.0",
		EnableDeadMan: true,
	})
	if err == nil {
		t.Fatal("expected error when both update and rollback fail")
	}
	gotFailTask, _, _ := store.GetTaskWithLogs(ctx, failTask.ID)
	if gotFailTask.Status != "failed" {
		t.Fatalf("expected status 'failed' when rollback itself fails, got %q", gotFailTask.Status)
	}

	// 3. Concurrent TriggerUpdate on same target is rejected with ErrUpdateInProgress
	started := make(chan struct{})
	release := make(chan struct{})
	blockRunner := &recordingRunner{
		handler: func(cmdLine string) ([]byte, error) {
			select {
			case <-started:
			default:
				close(started)
			}
			<-release
			return []byte("ok"), nil
		},
	}
	mgrConc := NewManager(cfg, store, blockRunner, nil)
	if _, err := mgrConc.TriggerUpdate(ctx, UpdateRequest{
		Node:       "hub",
		TargetType: string(models.TargetBrew),
		TargetName: "curl",
	}); err != nil {
		t.Fatalf("first TriggerUpdate failed: %v", err)
	}
	<-started
	if _, err := mgrConc.TriggerUpdate(ctx, UpdateRequest{
		Node:       "hub",
		TargetType: string(models.TargetBrew),
		TargetName: "curl",
	}); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("expected ErrUpdateInProgress on overlapping update, got: %v", err)
	}
	close(release)
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := mgrConc.Wait(waitCtx); err != nil {
		t.Fatalf("Wait timed out: %v", err)
	}

	// 4. forwardUpdateToAgent blocks redirects
	redirected := false
	redirTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer redirTarget.Close()
	redirAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer redirAgent.Close()

	_ = store.UpsertNode(ctx, models.NodeInfo{
		Name:   "redir-node",
		URL:    redirAgent.URL,
		Token:  "secret",
		Role:   "agent",
		Status: models.NodeStatusApproved,
	})
	mgrRedir := NewManager(cfg, store, &recordingRunner{}, nil)
	mgrRedir.SetHTTPClient(redirAgent.Client())
	tRedir, _ := store.CreateTask(ctx, &models.Task{Node: "redir-node", TaskType: "brew_upgrade", Status: "running"})
	_ = mgrRedir.RunUpdateSync(ctx, tRedir.ID, UpdateRequest{
		Node:       "redir-node",
		TargetType: string(models.TargetBrew),
		TargetName: "curl",
	})
	if redirected {
		t.Fatal("forwardUpdateToAgent followed HTTP redirect and leaked agent token!")
	}
}

func TestUpdater_Round2Regressions(t *testing.T) {
	ctx := context.Background()

	// 1. Homebrew cask upgrade skips formula linkage error cleanly
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.NodeName = "hub"
	caskRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			joined := name + " " + strings.Join(args, " ")
			if strings.Contains(joined, "brew linkage --test") {
				return []byte("Error: No available formula with the name \"raycast\"."), errors.New("exit 1")
			}
			return []byte("Upgrading raycast"), nil
		},
	}
	mgrCask := NewManager(cfg, store, caskRunner, nil)
	tCask, _ := store.CreateTask(ctx, &models.Task{Node: "hub", TaskType: "brew_upgrade", TargetType: "brew", TargetName: "raycast", Status: "running"})
	if err := mgrCask.RunUpdateSync(ctx, tCask.ID, UpdateRequest{
		Node:       "hub",
		TargetType: string(models.TargetBrew),
		TargetName: "raycast",
	}); err != nil {
		t.Fatalf("expected cask upgrade to succeed without linkage failure, got: %v", err)
	}
	gotCask, _, _ := store.GetTaskWithLogs(ctx, tCask.ID)
	if gotCask.Status != "succeeded" {
		t.Fatalf("expected cask task status 'succeeded', got %q", gotCask.Status)
	}

	// Also verify fallback `brew list --cask --versions` detection when linkage error differs
	caskFallbackRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			joined := name + " " + strings.Join(args, " ")
			if strings.Contains(joined, "brew linkage --test") {
				return []byte("linkage unavailable"), errors.New("exit 1")
			}
			if strings.Contains(joined, "brew list --cask --versions iterm2") {
				return []byte("iterm2 3.5.0\n"), nil
			}
			return []byte("ok"), nil
		},
	}
	mgrCask2 := NewManager(cfg, store, caskFallbackRunner, nil)
	tCask2, _ := store.CreateTask(ctx, &models.Task{Node: "hub", TaskType: "brew_upgrade", TargetType: "brew", TargetName: "iterm2", Status: "running"})
	if err := mgrCask2.RunUpdateSync(ctx, tCask2.ID, UpdateRequest{
		Node:       "hub",
		TargetType: string(models.TargetBrew),
		TargetName: "iterm2",
	}); err != nil {
		t.Fatalf("expected cask fallback upgrade to succeed, got: %v", err)
	}

	// 2. Dead-Man's Rollback succeeds even when update context is cancelled during verification
	root := t.TempDir()
	servicesDir := filepath.Join(root, "services")
	svcDir := filepath.Join(servicesDir, "api")
	_ = os.MkdirAll(svcDir, 0755)
	composeFile := filepath.Join(svcDir, "compose.yml")
	_ = os.WriteFile(composeFile, []byte("services:\n  api:\n    image: nginx:1.24.0\n    container_name: api\n"), 0644)

	cfgDM := config.DefaultConfig()
	cfgDM.NodeName = "hub"
	cfgDM.Scanner.ServicesDir = servicesDir
	cfgDM.Updater.DeadManTimeoutSeconds = 5

	cancelCtx, cancelUpdate := context.WithCancel(ctx)
	rollbackUpSawActiveCtx := false
	dmRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			joined := name + " " + strings.Join(args, " ")
			if strings.Contains(joined, "{{json .State}}") {
				cancelUpdate()
				return []byte(`{"Status":"restarting","Restarting":true}`), nil
			}
			if strings.Contains(joined, "compose") && strings.Contains(joined, "up -d") {
				// First up -d is initial deploy (before cancelUpdate), second is Dead-Man rollback
				if cancelCtx.Err() != nil && c.Err() == nil {
					rollbackUpSawActiveCtx = true
				}
				return []byte("ok"), nil
			}
			return []byte("ok"), nil
		},
	}
	mgrDM := NewManager(cfgDM, store, dmRunner, nil)
	tDM, _ := store.CreateTask(ctx, &models.Task{Node: "hub", TaskType: "docker_update", TargetType: "docker", TargetName: "api", Status: "running"})
	rbErr := mgrDM.RunUpdateSync(cancelCtx, tDM.ID, UpdateRequest{
		Node:          "hub",
		TargetType:    "docker",
		TargetName:    "api",
		TargetVersion: "1.25.0",
		EnableDeadMan: true,
	})
	if rbErr == nil || !rollbackUpSawActiveCtx {
		t.Fatalf("expected Dead-Man rollback to run with fresh active context after update cancel; rbErr=%v rollbackUpSawActiveCtx=%v", rbErr, rollbackUpSawActiveCtx)
	}
	gotDM, _, _ := store.GetTaskWithLogs(ctx, tDM.ID)
	if gotDM.Status != "rolled_back" {
		t.Fatalf("expected rolled_back status under cancelled parent ctx, got %q", gotDM.Status)
	}

	// 3. forwardUpdateToAgent extracts JSON `error` and HTTP non-2xx fallback
	var returnEmpty502 bool
	errAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if returnEmpty502 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"disk full on agent"}`))
	}))
	defer errAgent.Close()

	_ = store.UpsertNode(ctx, models.NodeInfo{Name: "err-node", URL: errAgent.URL, Token: "tok", Status: models.NodeStatusApproved})
	mgrErr := NewManager(cfg, store, &recordingRunner{}, nil)
	mgrErr.SetHTTPClient(errAgent.Client())
	tAgentErr, _ := store.CreateTask(ctx, &models.Task{Node: "err-node", TaskType: "apt_upgrade", TargetType: "apt", TargetName: "curl", Status: "running"})
	if err := mgrErr.RunUpdateSync(ctx, tAgentErr.ID, UpdateRequest{
		Node:       "err-node",
		TargetType: string(models.TargetApt),
		TargetName: "curl",
	}); err == nil || !strings.Contains(err.Error(), "disk full on agent") {
		t.Fatalf("expected forwardUpdateToAgent error to include JSON 'error', got: %v", err)
	}
	gotAgentErr, _, _ := store.GetTaskWithLogs(ctx, tAgentErr.ID)
	if gotAgentErr.Status != "failed" || gotAgentErr.ErrorMsg != "disk full on agent" {
		t.Fatalf("expected task status failed with ErrorMsg 'disk full on agent', got %+v", gotAgentErr)
	}

	returnEmpty502 = true
	tAgent502, _ := store.CreateTask(ctx, &models.Task{Node: "err-node", TaskType: "apt_upgrade", TargetType: "apt", TargetName: "curl", Status: "running"})
	if err := mgrErr.RunUpdateSync(ctx, tAgent502.ID, UpdateRequest{
		Node:       "err-node",
		TargetType: string(models.TargetApt),
		TargetName: "curl",
	}); err == nil || !strings.Contains(err.Error(), "returned HTTP 502") {
		t.Fatalf("expected forwardUpdateToAgent HTTP 502 fallback message, got: %v", err)
	}
}

func TestUpdater_Round3Regressions(t *testing.T) {
	ctx := context.Background()
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.NodeName = "hub"

	// 1. Sibling services in the same Compose stack share the stack lock
	started := make(chan struct{})
	release := make(chan struct{})
	servicesDir := filepath.Join(t.TempDir(), "services")
	stackDir := filepath.Join(servicesDir, "iot")
	if err := os.MkdirAll(stackDir, 0755); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  homeassistant:\n    image: ghcr.io/home-assistant/home-assistant:2025.1.0\n  matter-hub:\n    image: ghcr.io/t0bst4r/home-assistant-matter-hub:1.0.0\n"
	if err := os.WriteFile(filepath.Join(stackDir, "compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Scanner.ServicesDir = servicesDir
	cfg.Updater.DeadManTimeoutSeconds = 1
	blockRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			joined := name + " " + strings.Join(args, " ")
			if strings.Contains(joined, "up -d") {
				select {
				case <-started:
				default:
					close(started)
				}
				<-release
			}
			if strings.Contains(joined, "{{json .State}}") {
				return []byte(`{"Status":"running","Restarting":false}`), nil
			}
			return []byte("ok"), nil
		},
	}
	mgrStack := NewManager(cfg, store, blockRunner, nil)
	if _, err := mgrStack.TriggerUpdate(ctx, UpdateRequest{
		Node:          "hub",
		TargetType:    string(models.TargetDocker),
		TargetName:    "iot/homeassistant",
		TargetVersion: "2025.2.0",
	}); err != nil {
		t.Fatalf("first stack service update failed: %v", err)
	}
	<-started
	if _, err := mgrStack.TriggerUpdate(ctx, UpdateRequest{
		Node:          "hub",
		TargetType:    string(models.TargetDocker),
		TargetName:    "iot/matter-hub",
		TargetVersion: "1.1.0",
	}); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("expected ErrUpdateInProgress for sibling service in same compose stack, got: %v", err)
	}
	close(release)
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if err := mgrStack.Wait(waitCtx); err != nil {
		t.Fatalf("mgrStack.Wait failed: %v", err)
	}

	// 2. RollbackServiceOnNode preserves JSON {"error": "..."} from agent HTTP errors
	rbErrAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"no rollback snapshot for web"}`))
	}))
	defer rbErrAgent.Close()
	_ = store.UpsertNode(ctx, models.NodeInfo{Name: "rb-err-node", URL: rbErrAgent.URL, Token: "tok", Status: models.NodeStatusApproved})
	mgrRB := NewManager(cfg, store, &recordingRunner{}, nil)
	mgrRB.SetHTTPClient(rbErrAgent.Client())
	rbTask, rbErr := mgrRB.RollbackServiceOnNode(ctx, "rb-err-node", "web", "admin")
	if rbErr == nil || !strings.Contains(rbErr.Error(), "no rollback snapshot for web") {
		t.Fatalf("expected RollbackServiceOnNode error to surface agent JSON 'error', got: %v", rbErr)
	}
	gotRB, rbLogs, _ := store.GetTaskWithLogs(ctx, rbTask.ID)
	if gotRB.Status != "failed" || gotRB.ErrorMsg != "no rollback snapshot for web" || len(rbLogs) == 0 {
		t.Fatalf("expected failed rollback task with logged error message, got task=%+v logs=%+v", gotRB, rbLogs)
	}

	// 3. UpdateFileTag fails cleanly when no image line is matched (e.g. flow-style YAML)
	flowCompose := filepath.Join(t.TempDir(), "compose.yml")
	if err := os.WriteFile(flowCompose, []byte("services: {web: {image: nginx:1.24}}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := UpdateFileTag(flowCompose, "", "web", "1.25"); err == nil || !strings.Contains(err.Error(), "no matching image line") {
		t.Fatalf("expected UpdateFileTag error when no matching image line exists, got: %v", err)
	}
}

func TestUpdater_Round4Regressions(t *testing.T) {
	ctx := context.Background()
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.NodeName = "hub"

	// 1. Omitted container_name resolves via docker compose ps -q and inspectDigest falls back to imageRef
	servicesDir := filepath.Join(t.TempDir(), "services")
	webDir := filepath.Join(servicesDir, "myapp")
	if err := os.MkdirAll(webDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "compose.yml"), []byte("services:\n  api:\n    image: nginx:1.25.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Scanner.ServicesDir = servicesDir
	cfg.Updater.DeadManTimeoutSeconds = 1

	composeID := "abcdef0123456789abcdef0123456789"
	psRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			joined := name + " " + strings.Join(args, " ")
			switch {
			case joined == "docker inspect --format {{json .Image}} api":
				return nil, errors.New("No such object: api")
			case joined == "docker image inspect --format {{json .RepoDigests}} nginx:1.25.0":
				return []byte(`["nginx@sha256:1111222233334444"]`), nil
			case strings.Contains(joined, "compose") && strings.Contains(joined, "ps -a -q api"):
				return []byte(composeID + "\n"), nil
			case joined == "docker inspect --format {{json .State}} api":
				return nil, errors.New("No such object: api")
			case joined == "docker inspect --format {{json .State}} "+composeID:
				return []byte(`{"Status":"running","Restarting":false}`), nil
			default:
				return []byte("ok"), nil
			}
		},
	}
	mgrPS := NewManager(cfg, store, psRunner, nil)
	tPS, _ := store.CreateTask(ctx, &models.Task{Node: "hub", TaskType: "docker_update", TargetType: "docker", TargetName: "myapp", Status: "running"})
	if err := mgrPS.RunUpdateSync(ctx, tPS.ID, UpdateRequest{
		Node:          "hub",
		TargetType:    "docker",
		TargetName:    "myapp",
		TargetVersion: "1.26.0",
		EnableDeadMan: true,
	}); err != nil {
		t.Fatalf("expected omitted container_name update to succeed via compose ps -q, got: %v", err)
	}
	snap, err := store.GetLatestSnapshot(ctx, "myapp")
	if err != nil || snap.PreviousDigest != "sha256:1111222233334444" {
		t.Fatalf("expected snapshot digest fallback sha256:1111222233334444, got snap=%+v err=%v", snap, err)
	}

	// 2. RollbackServiceOnNode completes even if caller ctx is cancelled during restoreSnapshot (self-restart)
	rbParentCtx, cancelCaller := context.WithCancel(ctx)
	restoreSawActiveCtx := false
	rbRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			joined := name + " " + strings.Join(args, " ")
			if strings.Contains(joined, "compose") && strings.Contains(joined, "up -d") {
				cancelCaller()
				restoreSawActiveCtx = (c.Err() == nil)
			}
			return []byte("ok"), nil
		},
	}
	mgrRB := NewManager(cfg, store, rbRunner, nil)
	rbTask, err := mgrRB.RollbackServiceOnNode(rbParentCtx, "hub", "myapp", "web")
	if err != nil || !restoreSawActiveCtx {
		t.Fatalf("expected RollbackServiceOnNode to finish cleanly despite caller ctx cancel, err=%v sawActive=%v", err, restoreSawActiveCtx)
	}
	gotRB, _, _ := store.GetTaskWithLogs(ctx, rbTask.ID)
	if gotRB.Status != "succeeded" {
		t.Fatalf("expected rollback task status 'succeeded', got %q", gotRB.Status)
	}

	// 3. Padded TargetType " brew " normalizes cleanly and runs brew upgrade
	var brewRan bool
	brewRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			if name == "brew" && len(args) > 0 && args[0] == "upgrade" {
				brewRan = true
			}
			return []byte("ok"), nil
		},
	}
	mgrBrew := NewManager(cfg, store, brewRunner, nil)
	brewTask, err := mgrBrew.TriggerUpdate(ctx, UpdateRequest{
		Node:       "hub",
		TargetType: " brew ",
		TargetName: " jq ",
	})
	if err != nil || brewTask.TaskType != "brew_upgrade" || brewTask.TargetType != "brew" {
		t.Fatalf("expected trimmed brew task, got task=%+v err=%v", brewTask, err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	if err := mgrBrew.Wait(waitCtx); err != nil {
		t.Fatal(err)
	}
	if !brewRan {
		t.Fatal("expected padded TargetType ' brew ' to execute runBrewUpgrade")
	}

	// 4. RollbackServiceOnNode trims nodeName & serviceName, and RunUpdateSync is tracked by Manager.Wait
	if _, err := mgrRB.RollbackServiceOnNode(ctx, " hub ", " myapp ", "web"); err != nil {
		t.Fatalf("expected padded RollbackServiceOnNode(' hub ', ' myapp ') to succeed, got: %v", err)
	}

	syncStarted := make(chan struct{})
	syncRelease := make(chan struct{})
	syncRunner := &funcRunner{
		run: func(c context.Context, name string, args ...string) ([]byte, error) {
			select {
			case <-syncStarted:
			default:
				close(syncStarted)
			}
			<-syncRelease
			if name == "dpkg" {
				return []byte("Status: install ok installed\n"), nil
			}
			return []byte("ok"), nil
		},
	}
	mgrSync := NewManager(cfg, store, syncRunner, nil)
	tSync, _ := store.CreateTask(ctx, &models.Task{Node: "hub", TaskType: "apt_upgrade", TargetType: "apt", TargetName: "curl", Status: "running"})
	syncDone := make(chan error, 1)
	go func() {
		syncDone <- mgrSync.RunUpdateSync(ctx, tSync.ID, UpdateRequest{Node: "hub", TargetType: "apt", TargetName: "curl"})
	}()
	<-syncStarted
	shortWaitCtx, shortWaitCancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer shortWaitCancel()
	if waitErr := mgrSync.Wait(shortWaitCtx); !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("expected Manager.Wait to block while RunUpdateSync is active, got: %v", waitErr)
	}
	close(syncRelease)
	if syncErr := <-syncDone; syncErr != nil {
		t.Fatalf("RunUpdateSync failed: %v", syncErr)
	}
	doneWaitCtx, doneWaitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer doneWaitCancel()
	if err := mgrSync.Wait(doneWaitCtx); err != nil {
		t.Fatalf("expected Manager.Wait to complete after RunUpdateSync finishes: %v", err)
	}
}


