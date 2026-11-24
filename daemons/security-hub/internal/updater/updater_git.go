package updater

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
