package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	}
	scanner.ApplyDockerSnapshots(scan.Items, snapshots, hubName)

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

	writeJSON(w, http.StatusOK, map[string]any{
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

func parseRequestedScanNode(r *http.Request) (string, int, string) {
	queryNode := strings.TrimSpace(r.URL.Query().Get("node"))
	var bodyNode string
	if r.Body != nil {
		rawBody, readErr := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if readErr != nil {
			return "", http.StatusBadRequest, "failed to read request body"
		}
		if len(rawBody) > 1<<20 {
			return "", http.StatusRequestEntityTooLarge, "request body too large"
		}
		if len(bytes.TrimSpace(rawBody)) > 0 {
			var req struct {
				Node *string `json:"node"`
			}
			dec := json.NewDecoder(bytes.NewReader(rawBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				return "", http.StatusBadRequest, "invalid json request body"
			}
			var extra any
			if err := dec.Decode(&extra); err != io.EOF {
				return "", http.StatusBadRequest, "invalid trailing data in request body"
			}
			if req.Node != nil {
				bodyNode = strings.TrimSpace(*req.Node)
			}
		}
	}
	if queryNode != "" && bodyNode != "" && !strings.EqualFold(queryNode, bodyNode) {
		return "", http.StatusBadRequest, "conflicting node specified in query and body"
	}
	if queryNode != "" {
		return queryNode, 0, ""
	}
	return bodyNode, 0, ""
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

	requestedNode, errStatus, errMsg := parseRequestedScanNode(r)
	if errStatus != 0 {
		auth.WriteJSONError(w, errStatus, errMsg)
		return
	}

	reservation, err := s.orch.BeginScan(r.Context(), scanner.BeginScanRequest{
		RequestedNode: requestedNode,
		TriggeredBy:   s.requestActor(r),
	})
	if err != nil {
		var inProg *scanner.ScanInProgressError
		if errors.As(err, &inProg) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":          "scan already running",
				"task_id":        inProg.ActiveTaskID,
				"scanning_nodes": inProg.ScanningNodes,
			})
			return
		}
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

	s.scanWG.Add(1)
	go func(res *scanner.ScanReservation) {
		defer s.scanWG.Done()
		defer s.orch.FinishScanTask(res.TaskID)

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
		var runErr error
		if res.IsSingleNode {
			scan, runErr = s.orch.RunNodeScanWithTask(scanCtx, res.Node, res.TaskID)
		} else {
			scan, runErr = s.orch.RunFullScanWithTask(scanCtx, res.TaskID)
		}

		s.orch.FinishScanTask(res.TaskID)

		if runErr != nil {
			if s.store != nil {
				finishCtx, finishCancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer finishCancel()
				_ = s.store.FinishTask(finishCtx, res.TaskID, "failed", runErr.Error())
			}
			return
		}
		if s.store != nil {
			curTask, _, _ := s.store.GetTaskWithLogs(scanCtx, res.TaskID)
			if curTask != nil && curTask.Status == "running" {
				_ = s.store.FinishTask(scanCtx, res.TaskID, "succeeded", "")
			}
		}
		if s.alerter != nil {
			_, _ = s.alerter.NotifyScanFindings(scanCtx, scan)
		}
	}(reservation)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id":        reservation.TaskID,
		"status":         "running",
		"node":           reservation.Node,
		"target_name":    reservation.TargetName,
		"scanning_nodes": reservation.ScanningNodes,
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
	var req updater.UpdateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := updater.ValidateUpdateRequest(req); err != nil {
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if claims := s.sessionClaims(r); claims != nil {
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
	writeJSON(w, http.StatusOK, task)
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
	var req struct {
		Node        string `json:"node"`
		ServiceName string `json:"service_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.ServiceName == "" {
		auth.WriteJSONError(w, http.StatusBadRequest, "service_name required")
		return
	}
	task, err := s.updMgr.RollbackServiceOnNode(r.Context(), req.Node, req.ServiceName, s.requestActor(r))
	if err != nil {
		if errors.Is(err, updater.ErrUpdateInProgress) {
			auth.WriteJSONError(w, http.StatusConflict, err.Error())
			return
		}
		auth.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) handleSkip(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	actor := s.requestActor(r)
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
		writeJSON(w, http.StatusOK, map[string]string{"status": "skipped"})
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
		writeJSON(w, http.StatusOK, map[string]string{"status": "unskipped"})
	default:
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
