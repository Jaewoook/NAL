package updater

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/notifier"
)

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
