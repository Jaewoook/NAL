package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/scanner"
)

func (m *Manager) runDockerUpdate(ctx context.Context, taskID string, req UpdateRequest) error {
	svcName, svcKey, ok := splitDockerTarget(req.TargetName)
	if !ok {
		errMsg := fmt.Sprintf("invalid service name %q", req.TargetName)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
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
		errMsg := fmt.Sprintf("failed to inspect compose service %s: %v", svcName, err)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
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
			errMsg := fmt.Sprintf("service key %q not found in compose service %s", svcKey, svcName)
			m.logStep(ctx, taskID, "error", errMsg)
			m.finishTask(ctx, taskID, "failed", errMsg)
			return fmt.Errorf("%s", errMsg)
		}
	}

	targetTag := strings.TrimSpace(req.TargetVersion)
	if targetTag == "" {
		targetTag = ref.Tag
	}
	if !IsValidDockerTag(targetTag) {
		errMsg := fmt.Sprintf("invalid target image tag %q", targetTag)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	// Step 1: Save Rollback Snapshot
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 1/6: Saving rollback snapshot for %s (%s:%s)...", req.TargetName, ref.ImageRepo, ref.Tag))
	composeBytes, readErr := os.ReadFile(ref.ComposePath)
	if readErr != nil {
		errMsg := fmt.Sprintf("failed to read compose file for snapshot: %v", readErr)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
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
	pullOut, pullErr := m.runner.Run(ctx, "docker", "pull", targetImage)
	if len(pullOut) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(pullOut)))
	}
	if pullErr != nil {
		errMsg := fmt.Sprintf("docker pull failed for %s: %v", targetImage, pullErr)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	// Step 4: Surgical Config Update & Container Recreate
	m.logStep(ctx, taskID, "info", fmt.Sprintf("STEP 4/6: Applying tag %s and recreating container...", targetTag))
	if _, _, err := UpdateFileTag(ref.ComposePath, ref.EnvPath, ref.ServiceKey, targetTag); err != nil {
		errMsg := fmt.Sprintf("failed to update compose tag: %v", err)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker compose --project-directory %s up -d", composeDir))
	upOut, upErr := m.runner.Run(ctx, "docker", "compose", "--project-directory", composeDir, "up", "-d")
	if len(upOut) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(upOut)))
	}

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
	out, bErr := m.runner.Run(ctx, backupScript, args...)
	if len(out) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(out)))
	}
	if bErr != nil {
		errMsg := fmt.Sprintf("pre-update volume backup failed, aborting update: %v", bErr)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

func (m *Manager) commitComposeFile(ctx context.Context, taskID, stepPrefix, composePath string, preEditBytes []byte, commitMsg string) {
	if m.cfg == nil || !m.cfg.Updater.Git.Enabled {
		m.logStep(ctx, taskID, "info", stepPrefix+"Git auto-commit disabled; skipping.")
		return
	}
	m.gitMu.Lock()
	defer m.gitMu.Unlock()
	gitCfg := m.cfg.Updater.Git
	botName := strings.TrimSpace(gitCfg.BotName)
	if botName == "" {
		botName = "NAL Bot"
	}
	botEmail := strings.TrimSpace(gitCfg.BotEmail)
	if botEmail == "" {
		botEmail = "nal-git-system@jaewook.me"
	}
	gpgKey := strings.TrimSpace(gitCfg.GPGKey)
	if gpgKey == "" {
		gpgKey = "024D4017DFF5360A"
	}

	composeDir := filepath.Dir(composePath)
	composeFile := filepath.Base(composePath)

	m.logStep(ctx, taskID, "info", fmt.Sprintf("%sCommitting updated %s as %s <%s>...", stepPrefix, composeFile, botName, botEmail))
	headOut, headErr := m.runner.Run(ctx, "git", "-C", composeDir, "show", "HEAD:./"+composeFile)
	if headErr != nil {
		m.logStep(ctx, taskID, "warn", fmt.Sprintf("Skipping git commit (failed to inspect HEAD version of %s): %v", composePath, headErr))
		return
	}
	if !bytes.Equal(preEditBytes, headOut) {
		m.logStep(ctx, taskID, "warn", fmt.Sprintf("Skipping git commit: %s had pre-existing uncommitted changes before this operation.", composeFile))
		return
	}
	postEditBytes, readErr := os.ReadFile(composePath)
	if readErr != nil || bytes.Equal(postEditBytes, headOut) {
		m.logStep(ctx, taskID, "info", fmt.Sprintf("No git changes in %s; skipping commit.", composeFile))
		return
	}

	args := []string{
		"-C", composeDir,
		"-c", "user.name=" + botName,
		"-c", "user.email=" + botEmail,
		"commit",
		"--only",
		fmt.Sprintf("--author=%s <%s>", botName, botEmail),
	}
	if gitCfg.GPGSign {
		args = append(args, "-S"+gpgKey)
	} else {
		args = append(args, "--no-gpg-sign")
	}
	args = append(args, "-m", commitMsg, "--", composeFile)

	m.logStep(ctx, taskID, "cmd", "$ git "+strings.Join(args, " "))
	commitOut, commitErr := m.runner.Run(ctx, "git", args...)
	if len(commitOut) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(commitOut)))
	}
	if commitErr != nil {
		m.logStep(ctx, taskID, "warn", fmt.Sprintf("Git commit warning (container remains healthy): %v", commitErr))
		return
	}
	m.logStep(ctx, taskID, "info", fmt.Sprintf("Committed %s to NAL repository.", composeFile))
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

func existingFilePerm(path string, fallback os.FileMode) os.FileMode {
	if st, err := os.Stat(path); err == nil && st.Mode().Perm() != 0 {
		return st.Mode().Perm()
	}
	return fallback
}

func (m *Manager) restoreSnapshot(ctx context.Context, taskID string, snap *models.RollbackSnapshot, composeDir string) error {
	if len(snap.ComposeBackup) > 0 && snap.ComposePath != "" {
		perm := existingFilePerm(snap.ComposePath, 0644)
		if err := writeFileAtomic(snap.ComposePath, snap.ComposeBackup, perm); err != nil {
			return fmt.Errorf("failed to restore compose file %s: %w", snap.ComposePath, err)
		}
	}
	if len(snap.EnvBackup) > 0 && snap.EnvPath != "" {
		perm := existingFilePerm(snap.EnvPath, 0600)
		if err := writeFileAtomic(snap.EnvPath, snap.EnvBackup, perm); err != nil {
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
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ docker compose --project-directory %s up -d", composeDir))
	out, err := m.runner.Run(ctx, "docker", "compose", "--project-directory", composeDir, "up", "-d")
	if len(out) > 0 {
		m.logStep(ctx, taskID, "stdout", strings.TrimSpace(string(out)))
	}
	return err
}

func isHexContainerID(s string) bool {
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (m *Manager) resolveComposeContainer(ctx context.Context, composeDir, serviceKey string) string {
	if composeDir == "" || serviceKey == "" {
		return ""
	}
	out, err := m.runner.Run(ctx, "docker", "compose", "--project-directory", composeDir, "ps", "-a", "-q", serviceKey)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		cand := strings.TrimSpace(line)
		if isHexContainerID(cand) {
			return cand
		}
	}
	return ""
}

func extractRepoDigest(dOut []byte) string {
	var digests []string
	if json.Unmarshal(dOut, &digests) == nil && len(digests) > 0 {
		if idx := strings.Index(digests[0], "sha256:"); idx >= 0 {
			return digests[0][idx:]
		}
	}
	return ""
}

func (m *Manager) inspectDigest(ctx context.Context, composeDir, serviceKey, containerName, imageRef string) string {
	var imgID string
	if containerName != "" {
		if out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .Image}}", containerName); err == nil {
			imgID = strings.Trim(strings.TrimSpace(string(out)), `"`)
		}
	}
	if imgID == "" && composeDir != "" && serviceKey != "" {
		if cid := m.resolveComposeContainer(ctx, composeDir, serviceKey); cid != "" {
			if out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .Image}}", cid); err == nil {
				imgID = strings.Trim(strings.TrimSpace(string(out)), `"`)
			}
		}
	}
	if imgID != "" {
		if dOut, err := m.runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imgID); err == nil {
			if dig := extractRepoDigest(dOut); dig != "" {
				return dig
			}
		}
	}
	if imageRef != "" {
		if dOut, err := m.runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imageRef); err == nil {
			if dig := extractRepoDigest(dOut); dig != "" {
				return dig
			}
		}
	}
	return ""
}

func (m *Manager) verifyContainerHealthy(ctx context.Context, composeDir, serviceKey, containerName, svcName string) error {
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
		targetContainer := containerName
		out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .State}}", targetContainer)
		if err != nil && composeDir != "" && serviceKey != "" {
			if cid := m.resolveComposeContainer(ctx, composeDir, serviceKey); cid != "" {
				targetContainer = cid
				out, err = m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .State}}", targetContainer)
			}
		}
		if err != nil {
			if time.Now().After(deadline) {
				return fmt.Errorf("failed to inspect container %s: %w", targetContainer, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(poll):
			}
			continue
		}
		raw := strings.TrimSpace(string(out))

		var stateObj struct {
			Status       string `json:"Status"`
			Restarting   bool   `json:"Restarting"`
			HealthStatus string `json:"HealthStatus"`
			Health       *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		}
		if strings.HasPrefix(raw, "{") && json.Unmarshal([]byte(raw), &stateObj) == nil {
			if stateObj.Status == "created" {
				// Container is still initializing; continue polling until deadline
			} else if stateObj.Restarting || (stateObj.Status != "running" && stateObj.Status != "ok") {
				return fmt.Errorf("container %s state is %q (restarting=%v)", targetContainer, stateObj.Status, stateObj.Restarting)
			} else {
				health := stateObj.HealthStatus
				if health == "" && stateObj.Health != nil {
					health = stateObj.Health.Status
				}
				if health == "unhealthy" {
					return fmt.Errorf("container %s healthcheck reported unhealthy", targetContainer)
				}
				if health == "starting" {
					// Container is still initializing its healthcheck; continue polling until deadline
				} else if health == "" || health == "healthy" {
					return nil
				}
			}
		} else {
			if raw == "created" {
				// Container is still initializing; continue polling until deadline
			} else if raw != "running" && raw != "ok" {
				return fmt.Errorf("container %s state is %q (expected running)", targetContainer, raw)
			} else {
				return nil
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("container %s did not become healthy within %ds", targetContainer, timeoutSec)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
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
