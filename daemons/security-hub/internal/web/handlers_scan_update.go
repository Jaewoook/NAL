package web

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

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/scanner"
	"github.com/jaewoook/security-hub/internal/updater"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	ctx := r.Context()
	scan, err := s.store.LoadLatestScanResult(ctx)
	if err != nil || scan == nil {
		scan = &models.ScanResult{Items: []models.ManagedItem{}}
	}
	skipped, _ := s.store.ListSkippedVersions(ctx)
	snapshots, _ := s.store.ListSnapshots(ctx)
	hubName := s.localNodeName()
	for i := range scan.Items {
		if scan.Items[i].Node == "" {
			scan.Items[i].Node = hubName
		}
		if scan.Items[i].TargetType != models.TargetDocker || scan.Items[i].HasRollback {
			continue
		}
		if snap, ok := snapshots[scan.Items[i].Node+":"+scan.Items[i].Name]; ok {
			scan.Items[i].HasRollback = true
			scan.Items[i].RollbackVersion = snap.PreviousVersion
		} else if snap, ok := snapshots[scan.Items[i].Name]; ok && strings.EqualFold(scan.Items[i].Node, hubName) {
			scan.Items[i].HasRollback = true
			scan.Items[i].RollbackVersion = snap.PreviousVersion
		}
	}
	nodes := s.buildNodesOverview(ctx)
	summarized := scanner.ApplySkippedAndSummarize(scan.Items, skipped)
	summarized.ScannedAt = scan.ScannedAt
	summarized.Nodes = nodes

	tasks, _ := s.store.ListTasks(ctx, "", 25)

	var scanning bool
	var activeScanTaskID string
	var scanningNodes []string
	if s.orch != nil {
		scanning, activeScanTaskID, scanningNodes = s.orch.GetScanState()
	}
	if scanningNodes == nil {
		scanningNodes = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"hub_node":            hubName,
		"nodes":               nodes,
		"scan":                summarized,
		"recent_tasks":        tasks,
		"snapshots_count":     len(snapshots),
		"scanning":            scanning,
		"active_scan_task_id": activeScanTaskID,
		"scanning_nodes":      scanningNodes,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.orch == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "orchestrator not configured")
		return
	}

	// Parse optional requested node from query param (?node=...) or JSON request body ({"node": "..."})
	queryNode := strings.TrimSpace(r.URL.Query().Get("node"))
	var bodyNode string
	if r.Body != nil {
		rawBody, readErr := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if readErr != nil {
			auth.WriteJSONError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		if len(rawBody) > 1<<20 {
			auth.WriteJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		if len(bytes.TrimSpace(rawBody)) > 0 {
			var req struct {
				Node *string `json:"node"`
			}
			dec := json.NewDecoder(bytes.NewReader(rawBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				auth.WriteJSONError(w, http.StatusBadRequest, "invalid json request body")
				return
			}
			var extra any
			if err := dec.Decode(&extra); err != io.EOF {
				auth.WriteJSONError(w, http.StatusBadRequest, "invalid trailing data in request body")
				return
			}
			if req.Node != nil {
				bodyNode = strings.TrimSpace(*req.Node)
			}
		}
	}
	if queryNode != "" && bodyNode != "" && !strings.EqualFold(queryNode, bodyNode) {
		auth.WriteJSONError(w, http.StatusBadRequest, "conflicting node specified in query and body")
		return
	}
	requestedNode := queryNode
	if requestedNode == "" {
		requestedNode = bodyNode
	}

	s.orch.LockScanStart()
	startLocked := true
	defer func() {
		if startLocked {
			s.orch.UnlockScanStart()
		}
	}()

	if scanning, activeID, scanningNodes := s.orch.GetScanState(); scanning {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":          "scan already running",
			"task_id":        activeID,
			"scanning_nodes": scanningNodes,
		})
		return
	}

	hubName := s.localNodeName()
	actor := "web"
	if claims := s.sessionClaims(r); claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}

	var taskNode string
	var targetType string
	var targetName string
	var initialScanningNodes []string
	var isSingleNode bool

	if requestedNode != "" {
		targetNode, err := s.orch.ResolveTargetNode(r.Context(), requestedNode)
		if err != nil {
			if errors.Is(err, scanner.ErrScanNodeNotFound) {
				auth.WriteJSONError(w, http.StatusNotFound, err.Error())
				return
			}
			if errors.Is(err, scanner.ErrScanNodeNotApproved) {
				auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		isSingleNode = true
		taskNode = targetNode.Name
		targetType = "node"
		targetName = targetNode.Name
		initialScanningNodes = []string{targetNode.Name}
	} else {
		taskNode = hubName
		targetType = "system"
		targetName = "all"
		initialScanningNodes = []string{hubName}
		for _, n := range s.buildNodesOverview(r.Context()) {
			if !strings.EqualFold(n.Name, hubName) && (n.Status == "" || n.Status == models.NodeStatusApproved) {
				initialScanningNodes = append(initialScanningNodes, n.Name)
			}
		}
	}

	var taskID string
	if s.store != nil {
		task, err := s.store.CreateTask(r.Context(), &models.Task{
			Node:        taskNode,
			TaskType:    "security_scan",
			TargetType:  targetType,
			TargetName:  targetName,
			TriggeredBy: actor,
			Status:      "running",
		})
		if err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		taskID = task.ID
	} else {
		taskID = fmt.Sprintf("task_%d", time.Now().UnixNano())
	}

	started, activeID := s.orch.StartScanWithNodes(taskID, initialScanningNodes)
	if !started {
		if s.store != nil {
			abortCtx, abortCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer abortCancel()
			_ = s.store.FinishTask(abortCtx, taskID, "aborted", "scan already running")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":          "scan already running",
			"task_id":        activeID,
			"scanning_nodes": s.orch.ScanningNodes(),
		})
		return
	}
	s.orch.UnlockScanStart()
	startLocked = false

	s.scanWG.Add(1)
	go func(tid string, single bool, singleTarget string) {
		defer s.scanWG.Done()
		defer s.orch.FinishScanTask(tid)

		scanCtx, scanCancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer scanCancel()
		if shutCh := s.shutdownChan(); shutCh != nil {
			go func() {
				select {
				case <-shutCh:
					scanCancel()
				case <-scanCtx.Done():
				}
			}()
		}

		var scan *models.ScanResult
		var err error
		if single {
			scan, err = s.orch.RunNodeScanWithTask(scanCtx, singleTarget, tid)
		} else {
			scan, err = s.orch.RunFullScanWithTask(scanCtx, tid)
		}

		s.orch.FinishScanTask(tid)

		if err != nil {
			if s.store != nil {
				finishCtx, finishCancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer finishCancel()
				_ = s.store.FinishTask(finishCtx, tid, "failed", err.Error())
			}
			return
		}
		if s.store != nil {
			curTask, _, _ := s.store.GetTaskWithLogs(scanCtx, tid)
			if curTask != nil && curTask.Status == "running" {
				_ = s.store.FinishTask(scanCtx, tid, "succeeded", "")
			}
		}
		if s.alerter != nil {
			_, _ = s.alerter.NotifyScanFindings(scanCtx, scan)
		}
	}(taskID, isSingleNode, taskNode)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"task_id":        taskID,
		"status":         "running",
		"node":           taskNode,
		"target_name":    targetName,
		"scanning_nodes": initialScanningNodes,
	})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	claims := s.sessionClaims(r)
	var req updater.UpdateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := updater.ValidateUpdateRequest(req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if claims != nil {
		req.TriggeredBy = claims.Method + ":" + claims.Subject
	}
	task, err := s.updMgr.TriggerUpdate(r.Context(), req)
	if err != nil {
		if errors.Is(err, updater.ErrUpdateInProgress) {
			auth.WriteJSONError(w, http.StatusConflict, err.Error())
			return
		}
		auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(task)
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.updMgr == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "updater not configured")
		return
	}
	claims := s.sessionClaims(r)
	var req struct {
		Node        string `json:"node"`
		ServiceName string `json:"service_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.ServiceName == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "service_name required")
		return
	}
	actor := "web"
	if claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}
	task, err := s.updMgr.RollbackServiceOnNode(r.Context(), req.Node, req.ServiceName, actor)
	if err != nil {
		if errors.Is(err, updater.ErrUpdateInProgress) {
			auth.WriteJSONError(w, http.StatusConflict, err.Error())
			return
		}
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(task)
}

func (s *Server) handleSkip(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	claims := s.sessionClaims(r)
	actor := "web"
	if claims != nil {
		actor = claims.Method + ":" + claims.Subject
	}
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Node       string `json:"node"`
			TargetType string `json:"target_type"`
			TargetName string `json:"target_name"`
			Version    string `json:"version"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			auth.WriteJSONError(w, http.StatusBadRequest, "invalid request")
			return
		}
		tt := strings.TrimSpace(req.TargetType)
		if n := strings.TrimSpace(req.Node); n != "" {
			tt = n + ":" + tt
		}
		if err := s.store.SetSkippedVersion(r.Context(), tt, req.TargetName, req.Version, actor); err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "skipped"})
	case http.MethodDelete:
		node := strings.TrimSpace(r.URL.Query().Get("node"))
		tt := strings.TrimSpace(r.URL.Query().Get("target_type"))
		tn := r.URL.Query().Get("target_name")
		if node != "" {
			if err := s.store.RemoveSkippedVersion(r.Context(), node+":"+tt, tn); err != nil {
				auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		if err := s.store.RemoveSkippedVersion(r.Context(), tt, tn); err != nil {
			auth.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unskipped"})
	default:
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
