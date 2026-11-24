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

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

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
