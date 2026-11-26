package updater

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/fsutil"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/scanner"
)

func (m *Manager) runDockerUpdate(ctx context.Context, taskID string, req UpdateRequest) error {
	svcName, svcKey, ok := splitDockerTarget(req.TargetName)
	if !ok {
		return m.failTask(ctx, taskID, "invalid service name %q", req.TargetName)
	}

	servicesDir := "../../services"
	batchDir := "../../batch"
	deadManTimeout := 60
	var statefulVolumes map[string]string
	if m.cfg != nil {
		if m.cfg.Scanner.ServicesDir != "" {
			servicesDir = m.cfg.Scanner.ServicesDir
		}
		if m.cfg.Updater.BatchDir != "" {
			batchDir = m.cfg.Updater.BatchDir
		}
		if m.cfg.Updater.DeadManTimeoutSeconds > 0 {
			deadManTimeout = m.cfg.Updater.DeadManTimeoutSeconds
		}
		statefulVolumes = m.cfg.Updater.StatefulVolumes
	}

	composeDir := filepath.Join(servicesDir, svcName)
	refs, err := scanner.ParseComposeImageRefs(composeDir)
	if err != nil || len(refs) == 0 {
		return m.failTask(ctx, taskID, "failed to inspect compose service %s: %v", svcName, err)
	}

	ref := refs[0]
	if svcKey != "" {
		matched := false
		for _, r := range refs {
			if r.ServiceKey == svcKey {
				ref = r
				matched = true
				break
			}
		}
		if !matched {
			return m.failTask(ctx, taskID, "service key %q not found in compose service %s", svcKey, svcName)
		}
	}

	targetTag := strings.TrimSpace(req.TargetVersion)
	if targetTag == "" {
		targetTag = ref.Tag
	}
	if !IsValidDockerTag(targetTag) {
		return m.failTask(ctx, taskID, "invalid target image tag %q", targetTag)
	}

	// Step 1: Save Rollback Snapshot
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 1/6: Saving rollback snapshot for %s (%s:%s)...", req.TargetName, ref.ImageRepo, ref.Tag))
	composeBytes, readErr := os.ReadFile(ref.ComposePath)
	if readErr != nil {
		return m.failTask(ctx, taskID, "failed to read compose file for snapshot: %v", readErr)
	}
	envBytes, _ := os.ReadFile(ref.EnvPath)
	prevDigest := m.inspectDigest(ctx, composeDir, ref.ServiceKey, ref.ContainerName, ref.ImageRepo+":"+ref.Tag)

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
	if m.store != nil {
		_ = m.store.SaveSnapshot(ctx, snap)
	}
	m.logStep(ctx, taskID, "info", fmt.Sprintf("Snapshot saved: version=%s digest=%s", snap.PreviousVersion, snap.PreviousDigest))

	// Step 2: Optional Pre-Update Volume Backup
	if err := m.runPreUpdateBackup(ctx, taskID, req.RunBackup, batchDir, statefulVolumes[svcName]); err != nil {
		return err
	}

	// Step 3: Pre-pull target image BEFORE stopping running container
	targetImage := ref.ImageRepo + ":" + targetTag
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 3/6: Pre-pulling target image %s before stopping container...", targetImage))
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker pull %s", targetImage))
	_, pullErr := m.runLoggedCommand(ctx, taskID, "docker", "pull", targetImage)
	if pullErr != nil {
		return m.failTask(ctx, taskID, "docker pull failed for %s: %v", targetImage, pullErr)
	}

	// Step 4: Surgical Config Update & Container Recreate
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 4/6: Applying tag %s and recreating container...", targetTag))
	if _, _, err := UpdateFileTag(ref.ComposePath, ref.EnvPath, ref.ServiceKey, targetTag); err != nil {
		return m.failTask(ctx, taskID, "failed to update compose tag: %v", err)
	}

	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker compose --project-directory %s up -d --remove-orphans", composeDir))
	_, upErr := m.runLoggedCommand(ctx, taskID, "docker", "compose", "--project-directory", composeDir, "up", "-d", "--remove-orphans")

	// Step 5: Post-Update Health Verification & 60s Dead-Man's Rollback
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 5/6: Verifying container health (Dead-Man's Rollback armed=%v, timeout=%ds)...", req.EnableDeadMan, deadManTimeout))
	verifyErr := upErr
	if verifyErr == nil {
		verifyErr = m.verifyContainerHealthy(ctx, composeDir, ref.ServiceKey, ref.ContainerName, svcName)
	}

	if verifyErr != nil {
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer rbCancel()
		reason := fmt.Sprintf("post-update verification failed: %v", verifyErr)
		m.logStep(rbCtx, taskID, "error", reason)
		if req.EnableDeadMan || m.isCriticalService(svcName) {
			m.logStep(rbCtx, taskID, "info", "Executing Automatic Dead-Man's Rollback to previous snapshot...")
			if rbErr := m.restoreSnapshot(rbCtx, taskID, snap, composeDir); rbErr != nil {
				failMsg := fmt.Sprintf("%s; automatic rollback failed: %v", reason, rbErr)
				m.logStep(rbCtx, taskID, "error", failMsg)
				m.finishTask(rbCtx, taskID, "failed", failMsg)
				if m.alerter != nil {
					_ = m.alerter.NotifyDeadManRollback(rbCtx, req.TargetName, snap.PreviousVersion, targetTag, failMsg)
				}
				return fmt.Errorf("%s", failMsg)
			}
			m.finishTask(rbCtx, taskID, "rolled_back", reason)
			if m.alerter != nil {
				_ = m.alerter.NotifyDeadManRollback(rbCtx, req.TargetName, snap.PreviousVersion, targetTag, reason)
			}
			return fmt.Errorf("update failed and was automatically rolled back: %w", verifyErr)
		}
		m.finishTask(rbCtx, taskID, "failed", reason)
		return verifyErr
	}

	// Step 6: Commit updated compose file to NAL repository using NAL Bot identity
	commitMsg := fmt.Sprintf("chore(services): update %s image to %s", req.TargetName, targetTag)
	m.commitComposeFile(ctx, taskID, "STEP 6/6: ", ref.ComposePath, composeBytes, commitMsg)

	m.logStep(ctx, taskID, "info", fmt.Sprintf("Service %s updated to %s and verified healthy.", req.TargetName, targetTag))
	m.finishTask(ctx, taskID, "succeeded", "")
	return nil
}

func (m *Manager) runPreUpdateBackup(ctx context.Context, taskID string, runBackup bool, batchDir, volName string) error {
	if !runBackup {
		m.logStep(ctx, taskID, "info", "STEP 2/6: Pre-update volume backup skipped.")
		return nil
	}
	backupScript := filepath.Join(batchDir, "backup-volumes.sh")
	var args []string
	if volName != "" {
		args = append(args, volName)
	}
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 2/6: Running pre-update volume backup (%s %s)...", backupScript, volName))
	_, bErr := m.runLoggedCommand(ctx, taskID, backupScript, args...)
	if bErr != nil {
		return m.failTask(ctx, taskID, "pre-update volume backup failed, aborting update: %v", bErr)
	}
	return nil
}

func (m *Manager) RollbackService(ctx context.Context, serviceName, triggeredBy string) (*models.Task, error) {
	return m.RollbackServiceOnNode(ctx, "", serviceName, triggeredBy)
}

func (m *Manager) rollbackLocalService(execCtx context.Context, localNode, svcDirName, serviceName, triggeredBy string) (*models.Task, error) {
	snap, err := m.store.GetLatestSnapshot(execCtx, serviceName)
	if err != nil {
		return nil, err
	}
	task, err := m.store.CreateTask(execCtx, &models.Task{
		Node:        localNode,
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

	servicesDir := "../../services"
	if m.cfg != nil && m.cfg.Scanner.ServicesDir != "" {
		servicesDir = m.cfg.Scanner.ServicesDir
	}
	composeDir := filepath.Join(servicesDir, svcDirName)

	var preRollbackBytes []byte
	if snap.ComposePath != "" {
		preRollbackBytes, _ = os.ReadFile(snap.ComposePath)
	}
	if err := m.restoreSnapshot(execCtx, task.ID, snap, composeDir); err != nil {
		m.finishTask(execCtx, task.ID, "failed", err.Error())
		return task, err
	}
	if snap.ComposePath != "" {
		commitMsg := fmt.Sprintf("revert(services): roll back %s image to %s", serviceName, snap.PreviousVersion)
		m.commitComposeFile(execCtx, task.ID, "", snap.ComposePath, preRollbackBytes, commitMsg)
	}
	m.finishTask(execCtx, task.ID, "succeeded", "")
	return task, nil
}

func (m *Manager) isCriticalService(svcName string) bool {
	if m.cfg == nil {
		return false
	}
	for _, c := range m.cfg.Updater.CriticalServices {
		if c == svcName {
			return true
		}
	}
	return false
}

func existingFilePerm(path string, fallback os.FileMode) os.FileMode {
	if st, err := os.Stat(path); err == nil && st.Mode().Perm() != 0 {
		return st.Mode().Perm()
	}
	return fallback
}

func (m *Manager) restoreSnapshot(ctx context.Context, taskID string, snap *models.RollbackSnapshot, composeDir string) error {
	if len(snap.ComposeBackup) > 0 && snap.ComposePath != "" {
		perm := existingFilePerm(snap.ComposePath, 0644)
		if err := fsutil.WriteFileAtomic(snap.ComposePath, snap.ComposeBackup, perm); err != nil {
			return fmt.Errorf("failed to restore compose file %s: %w", snap.ComposePath, err)
		}
	}
	if len(snap.EnvBackup) > 0 && snap.EnvPath != "" {
		perm := existingFilePerm(snap.EnvPath, 0600)
		if err := fsutil.WriteFileAtomic(snap.EnvPath, snap.EnvBackup, perm); err != nil {
			return fmt.Errorf("failed to restore env file %s: %w", snap.EnvPath, err)
		}
	}
	if snap.PreviousDigest != "" && snap.ImageRepo != "" && snap.PreviousVersion != "" {
		src := fmt.Sprintf("%s@%s", snap.ImageRepo, snap.PreviousDigest)
		dst := fmt.Sprintf("%s:%s", snap.ImageRepo, snap.PreviousVersion)
		m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker tag %s %s", src, dst))
		if tagOut, tagErr := m.runner.Run(ctx, "docker", "tag", src, dst); tagErr != nil {
			m.logStep(ctx, taskID, "warn", fmt.Sprintf("docker tag warning (continuing compose restore): %v %s", tagErr, strings.TrimSpace(string(tagOut))))
		}
	}
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker compose --project-directory %s up -d --remove-orphans", composeDir))
	_, err := m.runLoggedCommand(ctx, taskID, "docker", "compose", "--project-directory", composeDir, "up", "-d", "--remove-orphans")
	return err
}
