package updater

import (
	"context"
	"fmt"
	"strings"
)

func (m *Manager) runBrewUpgrade(ctx context.Context, taskID string, req UpdateRequest) error {
	pkgName := strings.TrimSpace(req.TargetName)
	if !isValidBrewPackageName(pkgName) {
		errMsg := fmt.Sprintf("invalid brew package name %q", req.TargetName)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	m.pkgMu.Lock()
	defer m.pkgMu.Unlock()

	m.logStep(ctx, taskID, "info", fmt.Sprintf("Starting Homebrew upgrade for %s -> %s", pkgName, req.TargetVersion))
	action := "upgrade"
	if req.BrokenLinkage {
		action = "reinstall"
	}
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ brew %s %s", action, pkgName))
	_, err := m.runLoggedCommand(ctx, taskID, "brew", action, pkgName)
	if err != nil {
		m.logStep(ctx, taskID, "error", fmt.Sprintf("Homebrew %s failed: %v", action, err))
		m.finishTask(ctx, taskID, "failed", err.Error())
		return err
	}
	// Verify linkage post-upgrade (skip cleanly for casks since brew linkage only inspects formulae)
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ brew linkage --test %s", pkgName))
	isCask := false
	if linkOut, linkErr := m.runner.Run(ctx, "brew", "linkage", "--test", pkgName); linkErr != nil {
		if m.isBrewCask(ctx, pkgName, linkOut) {
			isCask = true
			m.logStep(ctx, taskID, "info", fmt.Sprintf("Skipping linkage check for Homebrew cask %s.", pkgName))
		} else {
			errMsg := fmt.Sprintf("post-upgrade linkage check failed: %s", strings.TrimSpace(string(linkOut)))
			m.logStep(ctx, taskID, "error", errMsg)
			m.finishTask(ctx, taskID, "failed", errMsg)
			return fmt.Errorf("%s", errMsg)
		}
	}
	if isCask {
		m.logStep(ctx, taskID, "info", fmt.Sprintf("Homebrew cask %s upgrade completed.", pkgName))
	} else {
		m.logStep(ctx, taskID, "info", fmt.Sprintf("Homebrew formula %s is healthy and linked.", pkgName))
	}
	m.finishTask(ctx, taskID, "succeeded", "")
	return nil
}

func (m *Manager) isBrewCask(ctx context.Context, pkgName string, linkOut []byte) bool {
	if strings.Contains(string(linkOut), "No available formula") {
		return true
	}
	out, err := m.runner.Run(ctx, "brew", "list", "--cask", "--versions", pkgName)
	return err == nil && strings.Contains(string(out), pkgName)
}

func isDpkgStatusHealthy(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Status:") {
			return strings.HasSuffix(trimmed, " ok installed")
		}
	}
	return false
}

func (m *Manager) runAptUpgrade(ctx context.Context, taskID string, req UpdateRequest) error {
	pkgName := strings.TrimSpace(req.TargetName)
	if !isValidAptPackageName(pkgName) {
		errMsg := fmt.Sprintf("invalid apt package name %q", req.TargetName)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	m.pkgMu.Lock()
	defer m.pkgMu.Unlock()

	m.logStep(ctx, taskID, "info", fmt.Sprintf("Starting APT upgrade for %s -> %s", pkgName, req.TargetVersion))
	aptArgs := []string{"install", "--only-upgrade", "-y", "-o", "DPkg::Lock::Timeout=60", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--", pkgName}
	if req.BrokenLinkage {
		aptArgs = []string{"install", "--reinstall", "-f", "-y", "-o", "DPkg::Lock::Timeout=60", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--", pkgName}
	}

	m.logStep(ctx, taskID, "cmd", "$ apt-get "+strings.Join(aptArgs, " "))
	out, err := m.runLoggedCommand(ctx, taskID, "apt-get", aptArgs...)
	if err != nil {
		outStr := string(out)
		if strings.Contains(outStr, "Permission denied") || strings.Contains(outStr, "are you root") {
			sudoArgs := append([]string{"-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get"}, aptArgs...)
			m.logStep(ctx, taskID, "cmd", "$ sudo "+strings.Join(sudoArgs, " "))
			_, err = m.runLoggedCommand(ctx, taskID, "sudo", sudoArgs...)
		}
	}
	if err != nil {
		m.logStep(ctx, taskID, "error", fmt.Sprintf("APT upgrade failed: %v", err))
		m.finishTask(ctx, taskID, "failed", err.Error())
		return err
	}

	// Verify package installation state post-upgrade
	m.logStep(ctx, taskID, "cmd", fmt.Sprintf("$ dpkg -s -- %s", pkgName))
	if statusOut, statusErr := m.runner.Run(ctx, "dpkg", "-s", "--", pkgName); statusErr != nil || !isDpkgStatusHealthy(statusOut) {
		errMsg := fmt.Sprintf("post-upgrade package check failed: %s", strings.TrimSpace(string(statusOut)))
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	m.logStep(ctx, taskID, "info", fmt.Sprintf("APT package %s is healthy and installed.", pkgName))
	m.finishTask(ctx, taskID, "succeeded", "")
	return nil
}
