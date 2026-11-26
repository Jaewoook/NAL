package updater

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/broker"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/httputil"
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
	broker        *broker.Broker
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
		cfg:           cfg,
		store:         store,
		runner:        runner,
		alerter:       alerter,
		httpClient:    httputil.NoRedirectClient(nil, 5*time.Minute),
		pollInterval:  2 * time.Second,
		activeTargets: make(map[string]struct{}),
	}
}

func (m *Manager) localNodeName() string {
	if m.cfg != nil && m.cfg.NodeName != "" {
		return m.cfg.NodeName
	}
	return config.DefaultNodeName()
}

func (m *Manager) runLoggedCommand(ctx context.Context, taskID, name string, args ...string) ([]byte, error) {
	if sr, ok := m.runner.(scanner.StreamingCommandRunner); ok {
		return sr.RunStreaming(ctx, func(stream, line string) {
			m.logStep(ctx, taskID, stream, line)
		}, name, args...)
	}
	out, err := m.runner.Run(ctx, name, args...)
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.TrimSpace(line) != "" {
				m.logStep(ctx, taskID, "stdout", line)
			}
		}
	}
	return out, err
}

func (m *Manager) isLocalNode(node string) bool {
	n := strings.TrimSpace(node)
	return n == "" || strings.EqualFold(n, "local") || strings.EqualFold(n, m.localNodeName())
}

func (m *Manager) targetLockKey(node, targetType, targetName string) string {
	n := strings.TrimSpace(node)
	if m.isLocalNode(n) {
		n = m.localNodeName()
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

func (m *Manager) logStep(ctx context.Context, taskID, stream, msg string) {
	if m.store != nil {
		_, _ = m.store.AppendTaskLog(ctx, taskID, stream, msg)
	}
}

func (m *Manager) finishTask(ctx context.Context, taskID, status, errMsg string) {
	if m.store != nil {
		_ = m.store.FinishTask(ctx, taskID, status, errMsg)
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

func (m *Manager) failTask(ctx context.Context, taskID, format string, args ...any) error {
	errMsg := fmt.Sprintf(format, args...)
	m.logStep(ctx, taskID, "error", errMsg)
	m.finishTask(ctx, taskID, "failed", errMsg)
	return fmt.Errorf("%s", errMsg)
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
	if !m.isLocalNode(req.Node) {
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
