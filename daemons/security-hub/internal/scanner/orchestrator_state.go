package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

// ScanInProgressError reports that another scan already holds the orchestrator lock.
type ScanInProgressError struct {
	ActiveTaskID  string
	ScanningNodes []string
}

func (e *ScanInProgressError) Error() string {
	return ErrScanInProgress.Error()
}

func (e *ScanInProgressError) Unwrap() error {
	return ErrScanInProgress
}

// BeginScanRequest configures an atomic scan reservation via BeginScan.
type BeginScanRequest struct {
	RequestedNode string
	TriggeredBy   string
}

// ScanReservation represents an acquired scan lock and created task metadata.
type ScanReservation struct {
	TaskID        string
	Node          string
	TargetName    string
	ScanningNodes []string
	IsSingleNode  bool
}

// BeginScan atomically verifies no scan is active, resolves target node(s), creates a task
// record in the store (when configured), and acquires the orchestrator scan lock.
func (o *Orchestrator) BeginScan(ctx context.Context, req BeginScanRequest) (*ScanReservation, error) {
	o.startMu.Lock()
	defer o.startMu.Unlock()

	if scanning, activeID, scanningNodes := o.GetScanState(); scanning {
		return nil, &ScanInProgressError{
			ActiveTaskID:  activeID,
			ScanningNodes: scanningNodes,
		}
	}

	hubName := o.hubNodeName()
	triggeredBy := strings.TrimSpace(req.TriggeredBy)
	if triggeredBy == "" {
		triggeredBy = "scanner"
	}

	var taskNode, targetType, targetName string
	var initialNodes []string
	var isSingleNode bool

	requested := strings.TrimSpace(req.RequestedNode)
	if requested != "" {
		targetNode, err := o.ResolveTargetNode(ctx, requested)
		if err != nil {
			return nil, err
		}
		isSingleNode = true
		taskNode = targetNode.Name
		targetType = "node"
		targetName = targetNode.Name
		initialNodes = []string{targetNode.Name}
	} else {
		taskNode = hubName
		targetType = "system"
		targetName = "all"
		initialNodes = o.approvedClusterNodeNames(ctx, hubName)
	}

	var taskID string
	if o.store != nil {
		task, err := o.store.CreateTask(ctx, &models.Task{
			Node:        taskNode,
			TaskType:    "security_scan",
			TargetType:  targetType,
			TargetName:  targetName,
			TriggeredBy: triggeredBy,
			Status:      "running",
		})
		if err != nil {
			return nil, err
		}
		taskID = task.ID
	} else {
		taskID = fmt.Sprintf("task_%d", time.Now().UnixNano())
	}

	started, activeID := o.StartScanWithNodes(taskID, initialNodes)
	if !started {
		if o.store != nil {
			abortCtx, abortCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer abortCancel()
			_ = o.store.FinishTask(abortCtx, taskID, "aborted", "scan already running")
		}
		return nil, &ScanInProgressError{
			ActiveTaskID:  activeID,
			ScanningNodes: o.ScanningNodes(),
		}
	}

	return &ScanReservation{
		TaskID:        taskID,
		Node:          taskNode,
		TargetName:    targetName,
		ScanningNodes: initialNodes,
		IsSingleNode:  isSingleNode,
	}, nil
}

func (o *Orchestrator) approvedClusterNodeNames(ctx context.Context, hubName string) []string {
	nodes := []string{hubName}
	if o.store == nil {
		return nodes
	}
	if remoteNodes, err := o.store.ListNodes(ctx); err == nil {
		for _, rn := range remoteNodes {
			if !strings.EqualFold(rn.Name, hubName) && (rn.Status == "" || rn.Status == models.NodeStatusApproved) {
				nodes = append(nodes, rn.Name)
			}
		}
	}
	return nodes
}

// IsScanning reports whether a scan is currently running and returns the active task ID if so.
func (o *Orchestrator) IsScanning() (bool, string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	return o.activeTaskID != "", o.activeTaskID
}

// StartScan attempts to acquire the scan mutex for taskID.
func (o *Orchestrator) StartScan(taskID string) (bool, string) {
	return o.StartScanWithNodes(taskID, nil)
}

func dedupScanNodes(nodes []string) []string {
	if len(nodes) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(nodes))
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		key := strings.ToLower(n)
		if !seen[key] {
			seen[key] = true
			out = append(out, n)
		}
	}
	return out
}

// StartScanWithNodes attempts to acquire the scan mutex for taskID and records initial scanning nodes.
func (o *Orchestrator) StartScanWithNodes(taskID string, nodes []string) (bool, string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID != "" {
		return false, o.activeTaskID
	}
	if taskID == "" {
		taskID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
	}
	o.activeTaskID = taskID
	o.scanningNodes = dedupScanNodes(nodes)
	return true, ""
}

// FinishScan releases the active scan lock and resets scanning nodes.
func (o *Orchestrator) FinishScan() {
	o.FinishScanTask("")
}

// FinishScanTask releases the active scan lock only if it belongs to taskID (or taskID is empty).
func (o *Orchestrator) FinishScanTask(taskID string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if taskID == "" || o.activeTaskID == taskID {
		o.activeTaskID = ""
		o.scanningNodes = nil
	}
}

// LockScanStart serializes scan-start critical sections (state check, task creation, and lock acquisition).
func (o *Orchestrator) LockScanStart() {
	o.startMu.Lock()
}

// UnlockScanStart releases the scan-start critical section mutex.
func (o *Orchestrator) UnlockScanStart() {
	o.startMu.Unlock()
}

func (o *Orchestrator) claimOrVerifyScanLock(taskID string) (string, error) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID == "" {
		if taskID != "" {
			o.activeTaskID = taskID
		} else {
			o.activeTaskID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
		}
		return o.activeTaskID, nil
	}
	if taskID != "" && o.activeTaskID == taskID {
		return taskID, nil
	}
	return "", fmt.Errorf("%w (task %s)", ErrScanInProgress, o.activeTaskID)
}

func (o *Orchestrator) upgradeScanTaskID(oldID, newID string) string {
	if newID == "" {
		return oldID
	}
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID == oldID {
		o.activeTaskID = newID
		return newID
	}
	return oldID
}

// ScanningNodes returns a copy of node names currently performing a scan.
func (o *Orchestrator) ScanningNodes() []string {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if len(o.scanningNodes) == 0 {
		return []string{}
	}
	return append([]string(nil), o.scanningNodes...)
}

// GetScanState reports whether a scan is currently running, the active task ID, and scanning nodes.
func (o *Orchestrator) GetScanState() (bool, string, []string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID == "" {
		return false, "", []string{}
	}
	if len(o.scanningNodes) == 0 {
		return true, o.activeTaskID, []string{}
	}
	nodes := append([]string(nil), o.scanningNodes...)
	return true, o.activeTaskID, nodes
}

func (o *Orchestrator) setScanningNodes(nodes []string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	o.scanningNodes = dedupScanNodes(nodes)
}

func (o *Orchestrator) removeScanningNodeIfMultiple(nodeName string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if len(o.scanningNodes) <= 1 {
		return
	}
	filtered := make([]string, 0, len(o.scanningNodes))
	for _, n := range o.scanningNodes {
		if !strings.EqualFold(n, nodeName) {
			filtered = append(filtered, n)
		}
	}
	if len(filtered) >= 1 {
		o.scanningNodes = filtered
	}
}
