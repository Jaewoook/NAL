package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/httputil"
	"github.com/jaewoook/security-hub/internal/models"
)

type agentResponsePayload struct {
	Status   string               `json:"status"`
	ErrorMsg string               `json:"error_msg"`
	Error    string               `json:"error"`
	Logs     []models.TaskLogLine `json:"logs"`
}

func (m *Manager) SetHTTPClient(c *http.Client) {
	if c != nil {
		m.httpClient = c
	}
}

func (m *Manager) safeHTTPClient() *http.Client {
	return httputil.NoRedirectClient(m.httpClient, 5*time.Minute)
}

func (m *Manager) resolveAgentToken(nodeToken string) string {
	if nodeToken != "" {
		return nodeToken
	}
	if m.cfg != nil {
		return m.cfg.AgentToken
	}
	return ""
}

func (m *Manager) forwardUpdateToAgent(ctx context.Context, taskID string, req UpdateRequest) error {
	return m.runRemoteAgentUpdate(ctx, taskID, req)
}

func (m *Manager) runRemoteAgentUpdate(ctx context.Context, taskID string, req UpdateRequest) error {
	if m.store == nil {
		return errors.New("store is not configured")
	}
	nodeInfo, err := m.store.GetNode(ctx, req.Node)
	if err != nil {
		return m.failTask(ctx, taskID, "unknown remote node %q: %v", req.Node, err)
	}
	if nodeInfo.Status != models.NodeStatusApproved {
		return m.failTask(ctx, taskID, "cannot update unapproved node %q (status: %s)", req.Node, nodeInfo.Status)
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
	if tok := m.resolveAgentToken(nodeInfo.Token); tok != "" {
		httpReq.Header.Set("X-NAL-Node-Token", tok)
	}
	resp, err := m.safeHTTPClient().Do(httpReq)
	if err != nil {
		return m.failTask(ctx, taskID, "failed to contact remote agent %s: %v", nodeInfo.Name, err)
	}
	defer resp.Body.Close()

	var payload agentResponsePayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&payload); err != nil {
		return m.failTask(ctx, taskID, "invalid response from agent %s (HTTP %d): %v", nodeInfo.Name, resp.StatusCode, err)
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

	if !m.isLocalNode(nodeName) {
		return m.runRemoteAgentRollback(execCtx, nodeName, serviceName, triggeredBy)
	}
	return m.rollbackLocalService(execCtx, m.localNodeName(), svcDirName, serviceName, triggeredBy)
}

func (m *Manager) runRemoteAgentRollback(execCtx context.Context, nodeName, serviceName, triggeredBy string) (*models.Task, error) {
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
	if tok := m.resolveAgentToken(nodeInfo.Token); tok != "" {
		httpReq.Header.Set("X-NAL-Node-Token", tok)
	}
	resp, err := m.safeHTTPClient().Do(httpReq)
	if err != nil {
		m.finishTask(execCtx, task.ID, "failed", err.Error())
		return task, err
	}
	defer resp.Body.Close()

	var payload agentResponsePayload
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
