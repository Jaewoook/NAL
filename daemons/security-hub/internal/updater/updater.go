package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/notifier"
	"github.com/jaewoook/security-hub/internal/scanner"
)

var ErrUpdateInProgress = errors.New("update or rollback already in progress for target")

type UpdateRequest struct {
	Node          string `json:"node,omitempty"`
	TargetType    string `json:"target_type"`
	TargetName    string `json:"target_name"`
	TargetVersion string `json:"target_version"`
	RunBackup     bool   `json:"run_backup"`
	EnableDeadMan bool   `json:"enable_dead_man"`
	BrokenLinkage bool   `json:"broken_linkage"`
	TriggeredBy   string `json:"triggered_by"`
}

type Manager struct {
	cfg           *config.Config
	store         db.Store
	runner        scanner.CommandRunner
	alerter       *notifier.Alerter
	httpClient    *http.Client
	pollInterval  time.Duration
	mu            sync.Mutex
	activeTargets map[string]struct{}
	pkgMu         sync.Mutex
	gitMu         sync.Mutex
	wg            sync.WaitGroup
}

func NewManager(cfg *config.Config, store db.Store, runner scanner.CommandRunner, alerter *notifier.Alerter) *Manager {
	if runner == nil {
		runner = scanner.NewOSCommandRunner()
	}
	return &Manager{
		cfg:   cfg,
		store: store,
		runner: runner,
		alerter: alerter,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		pollInterval:  2 * time.Second,
		activeTargets: make(map[string]struct{}),
	}
}

func (m *Manager) SetHTTPClient(c *http.Client) {
	if c != nil {
		m.httpClient = c
	}
}

func (m *Manager) safeHTTPClient() *http.Client {
	var c http.Client
	if m.httpClient != nil {
		c = *m.httpClient
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Minute
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

func (m *Manager) localNodeName() string {
	if m.cfg != nil && m.cfg.NodeName != "" {
		return m.cfg.NodeName
	}
	return config.DefaultNodeName()
}

func (m *Manager) targetLockKey(node, targetType, targetName string) string {
	n := strings.TrimSpace(node)
	local := m.localNodeName()
	if n == "" || strings.EqualFold(n, "local") || strings.EqualFold(n, local) {
		n = local
	}
	tt := strings.TrimSpace(targetType)
	if tt == "" {
		tt = string(models.TargetDocker)
	}
	tn := strings.TrimSpace(targetName)
	if strings.EqualFold(tt, string(models.TargetDocker)) {
		if svcDir, _, ok := splitDockerTarget(tn); ok {
			tn = svcDir
		}
	}
	return strings.ToLower(n) + ":" + strings.ToLower(tt) + ":" + tn
}

func (m *Manager) acquireTarget(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTargets == nil {
		m.activeTargets = make(map[string]struct{})
	}
	if _, busy := m.activeTargets[key]; busy {
		return false
	}
	m.activeTargets[key] = struct{}{}
	return true
}

func (m *Manager) releaseTarget(key string) {
	m.mu.Lock()
	delete(m.activeTargets, key)
	m.mu.Unlock()
}

// Wait blocks until all background updates launched via TriggerUpdate finish or ctx expires.
func (m *Manager) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isASCIIAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isValidBrewPackageName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	if !isASCIIAlphaNum(name[0]) {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasSuffix(name, "/") {
		return false
	}
	if strings.Count(name, "/") > 2 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isASCIIAlphaNum(c) && c != '@' && c != '.' && c != '_' && c != '+' && c != '/' && c != '-' {
			return false
		}
	}
	return true
}

func isValidServiceDirName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 128 {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	return filepath.Base(name) == name
}

func splitDockerTarget(targetName string) (svcName, svcKey string, ok bool) {
	trimmed := strings.TrimSpace(targetName)
	if trimmed == "" {
		return "", "", false
	}
	if idx := strings.IndexByte(trimmed, '/'); idx >= 0 {
		svcName = trimmed[:idx]
		svcKey = trimmed[idx+1:]
		if !isValidServiceDirName(svcName) || !isValidServiceDirName(svcKey) {
			return "", "", false
		}
		return svcName, svcKey, true
	}
	if !isValidServiceDirName(trimmed) {
		return "", "", false
	}
	return trimmed, "", true
}

func normalizeUpdateRequest(req UpdateRequest) UpdateRequest {
	req.Node = strings.TrimSpace(req.Node)
	req.TargetType = strings.TrimSpace(req.TargetType)
	if req.TargetType == "" {
		req.TargetType = string(models.TargetDocker)
	}
	req.TargetName = strings.TrimSpace(req.TargetName)
	req.TargetVersion = strings.TrimSpace(req.TargetVersion)
	return req
}

// ValidateUpdateRequest checks that an incoming update request uses allowed target types and safe identifiers/tags.
func ValidateUpdateRequest(req UpdateRequest) error {
	req = normalizeUpdateRequest(req)
	tt := req.TargetType
	name := req.TargetName
	ver := req.TargetVersion

	switch tt {
	case string(models.TargetDocker):
		if _, _, ok := splitDockerTarget(name); !ok {
			return fmt.Errorf("invalid docker service name %q", req.TargetName)
		}
		if ver != "" && !IsValidDockerTag(ver) {
			return fmt.Errorf("invalid docker target version tag %q", req.TargetVersion)
		}
		return nil
	case string(models.TargetBrew):
		if !isValidBrewPackageName(name) {
			return fmt.Errorf("invalid brew package name %q", req.TargetName)
		}
		return nil
	case string(models.TargetApt):
		if !isValidAptPackageName(name) {
			return fmt.Errorf("invalid apt package name %q", req.TargetName)
		}
		return nil
	case string(models.TargetDaemon):
		if name != "ollama" {
			return fmt.Errorf("unsupported daemon update target %q", req.TargetName)
		}
		return nil
	default:
		return fmt.Errorf("unsupported target_type %q", req.TargetType)
	}
}

func (m *Manager) newTaskModel(req UpdateRequest, fromVer string) *models.Task {
	req = normalizeUpdateRequest(req)
	taskType := "docker_update"
	if req.TargetType == string(models.TargetBrew) {
		taskType = "brew_upgrade"
	} else if req.TargetType == string(models.TargetApt) {
		taskType = "apt_upgrade"
	} else if req.TargetType == string(models.TargetDaemon) {
		taskType = "daemon_upgrade"
	}
	nodeName := req.Node
	if nodeName == "" {
		nodeName = m.localNodeName()
	}
	return &models.Task{
		Node:        nodeName,
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
	if m.store == nil {
		return nil, errors.New("store is not configured")
	}
	req = normalizeUpdateRequest(req)
	if err := ValidateUpdateRequest(req); err != nil {
		return nil, err
	}
	key := m.targetLockKey(req.Node, req.TargetType, req.TargetName)
	if !m.acquireTarget(key) {
		return nil, fmt.Errorf("%w: %s", ErrUpdateInProgress, req.TargetName)
	}

	task, err := m.store.CreateTask(ctx, m.newTaskModel(req, ""))
	if err != nil {
		m.releaseTarget(key)
		return nil, err
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.releaseTarget(key)
		updCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		_ = m.runUpdateSyncOwned(updCtx, task.ID, req)
	}()
	return task, nil
}

func (m *Manager) logStep(ctx context.Context, taskID, stream, msg string) {
	if m.store != nil {
		_, _ = m.store.AppendTaskLog(ctx, taskID, stream, msg)
	}
}

func (m *Manager) RunUpdateSync(ctx context.Context, taskID string, req UpdateRequest) error {
	req = normalizeUpdateRequest(req)
	if err := ValidateUpdateRequest(req); err != nil {
		errMsg := err.Error()
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return err
	}
	key := m.targetLockKey(req.Node, req.TargetType, req.TargetName)
	if !m.acquireTarget(key) {
		err := fmt.Errorf("%w: %s", ErrUpdateInProgress, req.TargetName)
		m.logStep(ctx, taskID, "error", err.Error())
		m.finishTask(ctx, taskID, "failed", err.Error())
		return err
	}
	m.wg.Add(1)
	defer m.wg.Done()
	defer m.releaseTarget(key)
	return m.runUpdateSyncOwned(ctx, taskID, req)
}

func (m *Manager) runUpdateSyncOwned(ctx context.Context, taskID string, req UpdateRequest) error {
	req = normalizeUpdateRequest(req)
	localNode := m.localNodeName()
	if req.Node != "" && !strings.EqualFold(req.Node, "local") && !strings.EqualFold(req.Node, localNode) {
		return m.forwardUpdateToAgent(ctx, taskID, req)
	}
	if req.TargetType == string(models.TargetBrew) || (req.TargetType == string(models.TargetDaemon) && req.TargetName == "ollama") {
		return m.runBrewUpgrade(ctx, taskID, req)
	}
	if req.TargetType == string(models.TargetApt) {
		return m.runAptUpgrade(ctx, taskID, req)
	}
	return m.runDockerUpdate(ctx, taskID, req)
}

func (m *Manager) forwardUpdateToAgent(ctx context.Context, taskID string, req UpdateRequest) error {
	if m.store == nil {
		return errors.New("store is not configured")
	}
	nodeInfo, err := m.store.GetNode(ctx, req.Node)
	if err != nil {
		errMsg := fmt.Sprintf("unknown remote node %q: %v", req.Node, err)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}
	if nodeInfo.Status != models.NodeStatusApproved {
		errMsg := fmt.Sprintf("cannot update unapproved node %q (status: %s)", req.Node, nodeInfo.Status)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}
	m.logStep(ctx, taskID, "info", fmt.Sprintf("Forwarding update for %s (%s -> %s) to remote agent %s (%s)...", req.TargetName, req.TargetType, req.TargetVersion, nodeInfo.Name, nodeInfo.URL))
	agentReq := req
	agentReq.Node = nodeInfo.Name
	body, _ := json.Marshal(agentReq)
	endpoint := strings.TrimRight(nodeInfo.URL, "/") + "/api/agent/update"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		m.finishTask(ctx, taskID, "failed", err.Error())
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	tok := nodeInfo.Token
	if tok == "" && m.cfg != nil {
		tok = m.cfg.AgentToken
	}
	if tok != "" {
		httpReq.Header.Set("X-NAL-Node-Token", tok)
	}
	resp, err := m.safeHTTPClient().Do(httpReq)
	if err != nil {
		errMsg := fmt.Sprintf("failed to contact remote agent %s: %v", nodeInfo.Name, err)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}
	defer resp.Body.Close()

	var payload struct {
		Status   string               `json:"status"`
		ErrorMsg string               `json:"error_msg"`
		Error    string               `json:"error"`
		Logs     []models.TaskLogLine `json:"logs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&payload); err != nil {
		errMsg := fmt.Sprintf("invalid response from agent %s (HTTP %d): %v", nodeInfo.Name, resp.StatusCode, err)
		m.logStep(ctx, taskID, "error", errMsg)
		m.finishTask(ctx, taskID, "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}
	for _, l := range payload.Logs {
		m.logStep(ctx, taskID, l.Stream, fmt.Sprintf("[%s] %s", nodeInfo.Name, l.Line))
	}
	errMsg := payload.ErrorMsg
	if errMsg == "" {
		errMsg = payload.Error
	}
	status := payload.Status
	if status == "" {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			status = "succeeded"
		} else {
			status = "failed"
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if status == "succeeded" {
			status = "failed"
		}
	}
	if status != "succeeded" && errMsg == "" {
		errMsg = fmt.Sprintf("remote agent %s returned HTTP %d", nodeInfo.Name, resp.StatusCode)
	}
	m.finishTask(ctx, taskID, status, errMsg)
	if status != "succeeded" {
		return fmt.Errorf("remote agent %s task finished with status %s: %s", nodeInfo.Name, status, errMsg)
	}
	return nil
}

func (m *Manager) finishTask(ctx context.Context, taskID, status, errMsg string) {
	if m.store != nil {
		_ = m.store.FinishTask(ctx, taskID, status, errMsg)
	}
}

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
	out, err := m.runner.Run(ctx, "brew", action, pkgName)
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			m.logStep(ctx, taskID, "stdout", line)
		}
	}
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

func isValidAptToken(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	if s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 && !isASCIIAlphaNum(c) {
			return false
		}
		if !isASCIIAlphaNum(c) && c != '.' && c != '+' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func isValidAptPackageName(name string) bool {
	if strings.Count(name, ":") > 1 {
		return false
	}
	if idx := strings.IndexByte(name, ':'); idx >= 0 {
		return isValidAptToken(name[:idx], 2, 128) && isValidAptToken(name[idx+1:], 2, 32)
	}
	return isValidAptToken(name, 2, 128)
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
	out, err := m.runner.Run(ctx, "apt-get", aptArgs...)
	if err != nil {
		outStr := string(out)
		if strings.Contains(outStr, "Permission denied") || strings.Contains(outStr, "are you root") {
			sudoArgs := append([]string{"-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get"}, aptArgs...)
			m.logStep(ctx, taskID, "cmd", "$ sudo "+strings.Join(sudoArgs, " "))
			out, err = m.runner.Run(ctx, "sudo", sudoArgs...)
		}
	}
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			m.logStep(ctx, taskID, "stdout", line)
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
	if req.RunBackup {
		volName := statefulVolumes[svcName]
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
	} else {
		m.logStep(ctx, taskID, "info", "STEP 2/6: Pre-update volume backup skipped.")
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

func (m *Manager) RollbackServiceOnNode(ctx context.Context, nodeName, serviceName, triggeredBy string) (*models.Task, error) {
	if m.store == nil {
		return nil, errors.New("store is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nodeName = strings.TrimSpace(nodeName)
	serviceName = strings.TrimSpace(serviceName)
	svcDirName, _, ok := splitDockerTarget(serviceName)
	if !ok {
		return nil, fmt.Errorf("invalid service name %q", serviceName)
	}

	lockKey := m.targetLockKey(nodeName, string(models.TargetDocker), serviceName)
	if !m.acquireTarget(lockKey) {
		return nil, fmt.Errorf("%w: %s", ErrUpdateInProgress, serviceName)
	}
	m.wg.Add(1)
	defer m.wg.Done()
	defer m.releaseTarget(lockKey)

	// Detach from caller HTTP cancellation once validated so self-restarting services
	// (e.g. cloudflare-tunnel, nginx-proxy) complete rollback cleanly.
	execCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
	defer cancel()

	localNode := m.localNodeName()
	if nodeName != "" && !strings.EqualFold(nodeName, "local") && !strings.EqualFold(nodeName, localNode) {
		nodeInfo, err := m.store.GetNode(execCtx, nodeName)
		if err != nil {
			return nil, err
		}
		if nodeInfo.Status != models.NodeStatusApproved {
			return nil, fmt.Errorf("cannot rollback unapproved node %q (status: %s)", nodeName, nodeInfo.Status)
		}
		task, err := m.store.CreateTask(execCtx, &models.Task{
			Node:        nodeName,
			TaskType:    "docker_rollback",
			TargetType:  "docker",
			TargetName:  serviceName,
			FromVersion: "current",
			ToVersion:   "snapshot",
			TriggeredBy: triggeredBy,
			Status:      "running",
		})
		if err != nil {
			return nil, err
		}
		body, _ := json.Marshal(map[string]string{
			"service_name": serviceName,
			"triggered_by": triggeredBy,
		})
		endpoint := strings.TrimRight(nodeInfo.URL, "/") + "/api/agent/rollback"
		httpReq, err := http.NewRequestWithContext(execCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			m.finishTask(execCtx, task.ID, "failed", err.Error())
			return task, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		tok := nodeInfo.Token
		if tok == "" && m.cfg != nil {
			tok = m.cfg.AgentToken
		}
		if tok != "" {
			httpReq.Header.Set("X-NAL-Node-Token", tok)
		}
		resp, err := m.safeHTTPClient().Do(httpReq)
		if err != nil {
			m.finishTask(execCtx, task.ID, "failed", err.Error())
			return task, err
		}
		defer resp.Body.Close()
		var payload struct {
			Status   string               `json:"status"`
			ErrorMsg string               `json:"error_msg"`
			Error    string               `json:"error"`
			Logs     []models.TaskLogLine `json:"logs"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&payload)
		for _, l := range payload.Logs {
			m.logStep(execCtx, task.ID, l.Stream, fmt.Sprintf("[%s] %s", nodeName, l.Line))
		}
		if payload.ErrorMsg == "" && payload.Error != "" {
			payload.ErrorMsg = payload.Error
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errMsg := fmt.Sprintf("remote agent %s returned HTTP %d", nodeName, resp.StatusCode)
			if payload.ErrorMsg != "" {
				errMsg = payload.ErrorMsg
			}
			payload.Status = "failed"
			payload.ErrorMsg = errMsg
			m.logStep(execCtx, task.ID, "error", errMsg)
			m.finishTask(execCtx, task.ID, payload.Status, payload.ErrorMsg)
			return task, fmt.Errorf("%s", errMsg)
		}
		if decodeErr != nil {
			errMsg := fmt.Sprintf("failed to decode agent response from %s: %v", nodeName, decodeErr)
			m.logStep(execCtx, task.ID, "error", errMsg)
			m.finishTask(execCtx, task.ID, "failed", errMsg)
			return task, fmt.Errorf("%s", errMsg)
		}
		if payload.Status == "" {
			payload.Status = "succeeded"
		}
		if payload.Status != "succeeded" {
			errMsg := payload.ErrorMsg
			if errMsg == "" {
				errMsg = fmt.Sprintf("remote rollback on %s ended with status %q", nodeName, payload.Status)
			}
			m.logStep(execCtx, task.ID, "error", errMsg)
			m.finishTask(execCtx, task.ID, payload.Status, errMsg)
			return task, fmt.Errorf("remote rollback on %s ended with status %q: %s", nodeName, payload.Status, errMsg)
		}
		m.finishTask(execCtx, task.ID, payload.Status, payload.ErrorMsg)
		return task, nil
	}

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
