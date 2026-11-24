package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/updater"
)

func (s *Server) handleAgentInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(models.NodeInfo{
		Name:       s.localNodeName(),
		Role:       "agent",
		Online:     true,
		LastSeenAt: time.Now().UTC(),
		OSVersion:  runtime.GOOS + "/" + runtime.GOARCH,
	})
}

func (s *Server) handleAgentScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.orch == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "orchestrator not configured")
		return
	}
	items, err := s.orch.ScanLocalNode(r.Context())
	if err != nil && len(items) == 0 {
		auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodeName := s.localNodeName()
	if s.store != nil {
		if snapshots, sErr := s.store.ListSnapshots(r.Context()); sErr == nil {
			for i := range items {
				if items[i].TargetType != models.TargetDocker {
					continue
				}
				if snap, ok := snapshots[items[i].Name]; ok {
					items[i].HasRollback = true
					items[i].RollbackVersion = snap.PreviousVersion
				} else if snap, ok := snapshots[nodeName+":"+items[i].Name]; ok {
					items[i].HasRollback = true
					items[i].RollbackVersion = snap.PreviousVersion
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node":  nodeName,
		"items": items,
	})
}

func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.store == nil || s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	var req updater.UpdateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	nodeName := s.localNodeName()
	req.Node = nodeName
	req.TargetType = strings.TrimSpace(req.TargetType)
	if req.TargetType == "" {
		req.TargetType = string(models.TargetDocker)
	}
	req.TargetName = strings.TrimSpace(req.TargetName)
	req.TargetVersion = strings.TrimSpace(req.TargetVersion)
	if err := updater.ValidateUpdateRequest(req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	updCtx, updCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Minute)
	defer updCancel()
	task, err := s.store.CreateTask(updCtx, &models.Task{
		Node:        nodeName,
		TaskType:    "agent_update",
		TargetType:  req.TargetType,
		TargetName:  req.TargetName,
		ToVersion:   req.TargetVersion,
		TriggeredBy: req.TriggeredBy,
		Status:      "running",
	})
	if err != nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.updMgr.RunUpdateSync(updCtx, task.ID, req)
	finalTask, logs, _ := s.store.GetTaskWithLogs(updCtx, task.ID)
	var status, errMsg string
	if finalTask != nil {
		status = finalTask.Status
		errMsg = finalTask.ErrorMsg
	} else {
		status = task.Status
		errMsg = task.ErrorMsg
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    status,
		"error_msg": errMsg,
		"logs":      logs,
	})
}

func (s *Server) handleAgentRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.store == nil || s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	var req struct {
		ServiceName string `json:"service_name"`
		TriggeredBy string `json:"triggered_by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.ServiceName == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "service_name required")
		return
	}
	rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Minute)
	defer rbCancel()
	task, err := s.updMgr.RollbackService(rbCtx, req.ServiceName, req.TriggeredBy)
	if err != nil && task == nil {
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	finalTask, logs, _ := s.store.GetTaskWithLogs(rbCtx, task.ID)
	status := task.Status
	errMsg := task.ErrorMsg
	if finalTask != nil {
		status = finalTask.Status
		errMsg = finalTask.ErrorMsg
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    status,
		"error_msg": errMsg,
		"logs":      logs,
	})
}
