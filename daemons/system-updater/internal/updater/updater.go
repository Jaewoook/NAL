package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/config"
	"github.com/jaewoook/system-updater/internal/db"
	"github.com/jaewoook/system-updater/internal/models"
	"github.com/jaewoook/system-updater/internal/notifier"
	"github.com/jaewoook/system-updater/internal/scanner"
)

type UpdateRequest struct {
	TargetType    string `json:"target_type"`
	TargetName    string `json:"target_name"`
	TargetVersion string `json:"target_version"`
	RunBackup     bool   `json:"run_backup"`
	EnableDeadMan bool   `json:"enable_dead_man"`
	BrokenLinkage bool   `json:"broken_linkage"`
	TriggeredBy   string `json:"triggered_by"`
}

type Manager struct {
	cfg          *config.Config
	store        db.Store
	runner       scanner.CommandRunner
	alerter      *notifier.Alerter
	pollInterval time.Duration
}

func NewManager(cfg *config.Config, store db.Store, runner scanner.CommandRunner, alerter *notifier.Alerter) *Manager {
	if runner == nil {
		runner = scanner.NewOSCommandRunner()
	}
	return &Manager{
		cfg:          cfg,
		store:        store,
		runner:       runner,
		alerter:      alerter,
		pollInterval: 2 * time.Second,
	}
}

func (m *Manager) newTaskModel(req UpdateRequest, fromVer string) *models.Task {
	taskType := "docker_update"
	if req.TargetType == string(models.TargetBrew) {
		taskType = "brew_upgrade"
	}
	return &models.Task{
		TaskType:    taskType,
		TargetType:  req.TargetType,
		TargetName:  req.TargetName,
		FromVersion: fromVer,
		ToVersion:   req.TargetVersion,
		TriggeredBy: req.TriggeredBy,
		Status:      "running",
	}
}

func (m *Manager) TriggerUpdate(ctx context.Context, req UpdateRequest) (*models.Task, error) {
	task, err := m.store.CreateTask(ctx, m.newTaskModel(req, ""))
	if err != nil {
		return nil, err
	}
	go func() {
		_ = m.RunUpdateSync(context.Background(), task.ID, req)
	}()
	return task, nil
}

func (m *Manager) logStep(ctx context.Context, taskID, stream, msg string) {
	if m.store != nil {
		_, _ = m.store.AppendTaskLog(ctx, taskID, stream, msg)
	}
}

func (m *Manager) RunUpdateSync(ctx context.Context, taskID string, req UpdateRequest) error {
	if req.TargetType == string(models.TargetBrew) {
		return m.runBrewUpgrade(ctx, taskID, req)
	}
	return m.runDockerUpdate(ctx, taskID, req)
}

func (m *Manager) runBrewUpgrade(ctx context.Context, taskID string, req UpdateRequest) error {
	m.logStep(ctx, taskID, "info", fmt.Sprintf("Starting Homebrew upgrade for %s -> %s", req.TargetName, req.TargetVersion))
	action := "upgrade"
	if req.BrokenLinkage {
		action = "reinstall"
	}
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ brew %s %s", action, req.TargetName))
	out, err := m.runner.Run(ctx, "brew", action, req.TargetName)
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			m.logStep(ctx, taskID, "stdout", line)
		}
	}
	if err != nil {
		m.logStep(ctx, taskID, "error", fmt.Sprintf("Homebrew %s failed: %v", action, err))
		_ = m.store.FinishTask(ctx, taskID, "failed", err.Error())
		return err
	}
	// Verify linkage post-upgrade
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ brew linkage --test %s", req.TargetName))
	if linkOut, linkErr := m.runner.Run(ctx, "brew", "linkage", "--test", req.TargetName); linkErr != nil {
		errMsg := fmt.Sprintf("post-upgrade linkage check failed: %s", strings.TrimSpace(string(linkOut)))
		m.logStep(ctx, taskID, "error", errMsg)
		_ = m.store.FinishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf(errMsg)
	}
	m.logStep(ctx, taskID, "info", fmt.Sprintf("Homebrew formula %s is healthy and linked.", req.TargetName))
	_ = m.store.FinishTask(ctx, taskID, "succeeded", "")
	return nil
}

func (m *Manager) runDockerUpdate(ctx context.Context, taskID string, req UpdateRequest) error {
	svcName := req.TargetName
	svcKey := ""
	if idx := strings.IndexByte(svcName, '/'); idx > 0 {
		svcKey = svcName[idx+1:]
		svcName = svcName[:idx]
	}

	composeDir := filepath.Join(m.cfg.Scanner.ServicesDir, svcName)
	refs, err := scanner.ParseComposeImageRefs(composeDir)
	if err != nil || len(refs) == 0 {
		errMsg := fmt.Sprintf("failed to inspect compose service %s: %v", svcName, err)
		m.logStep(ctx, taskID, "error", errMsg)
		_ = m.store.FinishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf(errMsg)
	}

	ref := refs[0]
	if svcKey != "" {
		for _, r := range refs {
			if r.ServiceKey == svcKey {
				ref = r
				break
			}
		}
	}

	// Step 1: Save Rollback Snapshot
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 1/5: Saving rollback snapshot for %s (%s:%s)...", req.TargetName, ref.ImageRepo, ref.Tag))
	composeBytes, _ := os.ReadFile(ref.ComposePath)
	envBytes, _ := os.ReadFile(ref.EnvPath)
	prevDigest := m.inspectDigest(ctx, ref.ContainerName, ref.ImageRepo+":"+ref.Tag)

	snap := &models.RollbackSnapshot{
		ID:              fmt.Sprintf("snap-%s-%d", svcName, time.Now().Unix()),
		ServiceName:     req.TargetName,
		ServiceKey:      ref.ServiceKey,
		ImageRepo:       ref.ImageRepo,
		PreviousVersion: ref.Tag,
		PreviousDigest:  prevDigest,
		ComposePath:     ref.ComposePath,
		ComposeBackup:   composeBytes,
		EnvPath:         ref.EnvPath,
		EnvBackup:       envBytes,
		CreatedAt:       time.Now().UTC(),
	}
	_ = m.store.SaveSnapshot(ctx, snap)
	m.logStep(ctx, taskID, "info", fmt.Sprintf("Snapshot saved: version=%s digest=%s", snap.PreviousVersion, snap.PreviousDigest))

	// Step 2: Optional Pre-Update Volume Backup
	if req.RunBackup {
		volName := m.cfg.Updater.StatefulVolumes[svcName]
		backupScript := filepath.Join(m.cfg.Updater.BatchDir, "backup-volumes.sh")
		var args []string
		if volName != "" {
			args = append(args, volName)
		}
		m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 2/5: Running pre-update volume backup (%s %s)...", backupScript, volName))
		out, bErr := m.runner.Run(ctx, backupScript, args...)
		if len(out) > 0 {
			m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(out)))
		}
		if bErr != nil {
			errMsg := fmt.Sprintf("pre-update volume backup failed, aborting update: %v", bErr)
			m.logStep(ctx, taskID, "error", errMsg)
			_ = m.store.FinishTask(ctx, taskID, "failed", errMsg)
			return fmt.Errorf(errMsg)
		}
	} else {
		m.logStep(ctx, taskID, "info", "STEP 2/5: Pre-update volume backup skipped.")
	}

	// Step 3: Pre-pull target image BEFORE stopping running container
	targetTag := req.TargetVersion
	if targetTag == "" {
		targetTag = ref.Tag
	}
	targetImage := ref.ImageRepo + ":" + targetTag
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 3/5: Pre-pulling target image %s before stopping container...", targetImage))
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker pull %s", targetImage))
	pullOut, pullErr := m.runner.Run(ctx, "docker", "pull", targetImage)
	if len(pullOut) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(pullOut)))
	}
	if pullErr != nil {
		errMsg := fmt.Sprintf("docker pull failed for %s: %v", targetImage, pullErr)
		m.logStep(ctx, taskID, "error", errMsg)
		_ = m.store.FinishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf(errMsg)
	}

	// Step 4: Surgical Config Update & Container Recreate
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 4/5: Applying tag %s and recreating container...", targetTag))
	if _, _, err := UpdateFileTag(ref.ComposePath, ref.EnvPath, ref.ServiceKey, targetTag); err != nil {
		errMsg := fmt.Sprintf("failed to update compose tag: %v", err)
		m.logStep(ctx, taskID, "error", errMsg)
		_ = m.store.FinishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf(errMsg)
	}

	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker compose --project-directory %s up -d", composeDir))
	upOut, upErr := m.runner.Run(ctx, "docker", "compose", "--project-directory", composeDir, "up", "-d")
	if len(upOut) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(upOut)))
	}

	// Step 5: Post-Update Health Verification & 60s Dead-Man's Rollback
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 5/5: Verifying container health (Dead-Man's Rollback armed=%v, timeout=%ds)...", req.EnableDeadMan, m.cfg.Updater.DeadManTimeoutSeconds))
	verifyErr := upErr
	if verifyErr == nil {
		verifyErr = m.verifyContainerHealthy(ctx, ref.ContainerName, svcName)
	}

	if verifyErr != nil {
		reason := fmt.Sprintf("post-update verification failed: %v", verifyErr)
		m.logStep(ctx, taskID, "error", reason)
		if req.EnableDeadMan || m.isCriticalService(svcName) {
			m.logStep(ctx, taskID, "info", "Executing Automatic Dead-Man's Rollback to previous snapshot...")
			if rbErr := m.restoreSnapshot(ctx, taskID, snap, composeDir); rbErr != nil {
				m.logStep(ctx, taskID, "error", fmt.Sprintf("Rollback failed: %v", rbErr))
			}
			_ = m.store.FinishTask(ctx, taskID, "rolled_back", reason)
			if m.alerter != nil {
				_ = m.alerter.NotifyDeadManRollback(ctx, req.TargetName, snap.PreviousVersion, targetTag, reason)
			}
			return fmt.Errorf("update failed and was automatically rolled back: %w", verifyErr)
		}
		_ = m.store.FinishTask(ctx, taskID, "failed", reason)
		return verifyErr
	}

	m.logStep(ctx, taskID, "info", fmt.Sprintf("Service %s updated to %s and verified healthy.", req.TargetName, targetTag))
	_ = m.store.FinishTask(ctx, taskID, "succeeded", "")
	return nil
}

func (m *Manager) RollbackService(ctx context.Context, serviceName, triggeredBy string) (*models.Task, error) {
	snap, err := m.store.GetLatestSnapshot(ctx, serviceName)
	if err != nil {
		return nil, err
	}
	task, err := m.store.CreateTask(ctx, &models.Task{
		TaskType:    "docker_rollback",
		TargetType:  "docker",
		TargetName:  serviceName,
		FromVersion: "current",
		ToVersion:   snap.PreviousVersion,
		TriggeredBy: triggeredBy,
		Status:      "running",
	})
	if err != nil {
		return nil, err
	}

	svcDirName := serviceName
	if idx := strings.IndexByte(svcDirName, '/'); idx > 0 {
		svcDirName = svcDirName[:idx]
	}
	composeDir := filepath.Join(m.cfg.Scanner.ServicesDir, svcDirName)

	if err := m.restoreSnapshot(ctx, task.ID, snap, composeDir); err != nil {
		_ = m.store.FinishTask(ctx, task.ID, "failed", err.Error())
		return task, err
	}
	_ = m.store.FinishTask(ctx, task.ID, "succeeded", "")
	return task, nil
}

func (m *Manager) restoreSnapshot(ctx context.Context, taskID string, snap *models.RollbackSnapshot, composeDir string) error {
	if len(snap.ComposeBackup) > 0 && snap.ComposePath != "" {
		_ = os.WriteFile(snap.ComposePath, snap.ComposeBackup, 0644)
	}
	if len(snap.EnvBackup) > 0 && snap.EnvPath != "" {
		_ = os.WriteFile(snap.EnvPath, snap.EnvBackup, 0600)
	}
	if snap.PreviousDigest != "" && snap.ImageRepo != "" && snap.PreviousVersion != "" {
		src := fmt.Sprintf("%s@%s", snap.ImageRepo, snap.PreviousDigest)
		dst := fmt.Sprintf("%s:%s", snap.ImageRepo, snap.PreviousVersion)
		m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker tag %s %s", src, dst))
		_, _ = m.runner.Run(ctx, "docker", "tag", src, dst)
	}
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker compose --project-directory %s up -d", composeDir))
	out, err := m.runner.Run(ctx, "docker", "compose", "--project-directory", composeDir, "up", "-d")
	if len(out) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(out)))
	}
	return err
}

func (m *Manager) inspectDigest(ctx context.Context, containerName, imageRef string) string {
	out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .Image}}", containerName)
	if err == nil {
		imgID := strings.Trim(strings.TrimSpace(string(out)), `"`)
		if imgID != "" {
			if dOut, err := m.runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imgID); err == nil {
				var digests []string
				if json.Unmarshal(dOut, &digests) == nil && len(digests) > 0 {
					if idx := strings.Index(digests[0], "sha256:"); idx >= 0 {
						return digests[0][idx:]
					}
				}
			}
		}
	}
	return ""
}

func (m *Manager) verifyContainerHealthy(ctx context.Context, containerName string, svcName string) error {
	timeoutSec := 60
	if m.cfg != nil && m.cfg.Updater.DeadManTimeoutSeconds > 0 {
		timeoutSec = m.cfg.Updater.DeadManTimeoutSeconds
	}
	poll := m.pollInterval
	if poll <= 0 {
		poll = 2 * time.Second
	}
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	for {
		out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{.State.Status}}", containerName)
		if err != nil {
			return fmt.Errorf("failed to inspect container %s: %w", containerName, err)
		}
		raw := strings.TrimSpace(string(out))

		var stateObj struct {
			Status       string `json:"Status"`
			Restarting   bool   `json:"Restarting"`
			HealthStatus string `json:"HealthStatus"`
		}
		if strings.HasPrefix(raw, "{") && json.Unmarshal([]byte(raw), &stateObj) == nil {
			if stateObj.Restarting || (stateObj.Status != "running" && stateObj.Status != "ok") {
				return fmt.Errorf("container %s state is %q (restarting=%v)", containerName, stateObj.Status, stateObj.Restarting)
			}
			if stateObj.HealthStatus == "unhealthy" {
				return fmt.Errorf("container %s healthcheck reported unhealthy", containerName)
			}
			if stateObj.HealthStatus == "" || stateObj.HealthStatus == "healthy" {
				return nil
			}
		} else {
			if raw != "running" && raw != "ok" {
				return fmt.Errorf("container %s state is %q (expected running)", containerName, raw)
			}
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("container %s did not become healthy within %ds", containerName, timeoutSec)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func (m *Manager) isCriticalService(svcName string) bool {
	for _, c := range m.cfg.Updater.CriticalServices {
		if c == svcName {
			return true
		}
	}
	return false
}
