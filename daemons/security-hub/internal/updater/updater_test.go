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
	if err := mgr.verifyContainerHealthy(ctx, "postgresql", "db"); err != nil {
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
	if err := mgr.verifyContainerHealthy(ctx, "postgresql", "db"); err != nil {
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


