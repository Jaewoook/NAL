package updater

import (
	"context"
	"errors"
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

type funcRunner struct {
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (f *funcRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.run(ctx, name, args...)
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
