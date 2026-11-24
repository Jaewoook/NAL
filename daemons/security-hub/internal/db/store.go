package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jaewoook/security-hub/internal/fsutil"
	"github.com/jaewoook/security-hub/internal/models"
)

type Backend interface {
	UpsertTask(ctx context.Context, task models.Task) error
	InsertTaskLog(ctx context.Context, line models.TaskLogLine) error
	InsertTaskLogsBatch(ctx context.Context, lines []models.TaskLogLine) error
	UpsertSnapshot(ctx context.Context, snap models.RollbackSnapshot) error
	UpsertSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error
	DeleteSkippedVersion(ctx context.Context, targetType, targetName string) error
	UpsertSentAlert(ctx context.Context, fingerprint, alertType string) error
	UpsertNode(ctx context.Context, node models.NodeInfo) error
	DeleteNode(ctx context.Context, name string) error
}

type TaskStore interface {
	CreateTask(ctx context.Context, task *models.Task) (*models.Task, error)
	AppendTaskLog(ctx context.Context, taskID string, stream string, line string) (models.TaskLogLine, error)
	FinishTask(ctx context.Context, taskID string, status string, errMsg string) error
	ListTasks(ctx context.Context, filterType string, limit int) ([]models.Task, error)
	GetTaskWithLogs(ctx context.Context, taskID string) (*models.Task, []models.TaskLogLine, error)
	GetRawLogPath(taskID string) string
	SubscribeTaskLogs(taskID string) (<-chan models.TaskLogLine, func())
}

type SnapshotStore interface {
	SaveSnapshot(ctx context.Context, snap *models.RollbackSnapshot) error
	GetLatestSnapshot(ctx context.Context, serviceName string) (*models.RollbackSnapshot, error)
	ListSnapshots(ctx context.Context) (map[string]models.RollbackSnapshot, error)
}

type SkippedStore interface {
	SetSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error
	RemoveSkippedVersion(ctx context.Context, targetType, targetName string) error
	ListSkippedVersions(ctx context.Context) (map[string]string, error)
}

type AlertStore interface {
	RecordAlertSent(ctx context.Context, fingerprint, alertType string) error
	HasAlertBeenSent(ctx context.Context, fingerprint string) (bool, error)
}

type NodeStore interface {
	UpsertNode(ctx context.Context, node models.NodeInfo) error
	UpdateNodeHealth(ctx context.Context, name string, online bool, lastSeen time.Time, lastError string) error
	AnnounceNode(ctx context.Context, req models.NodeInfo) (models.NodeStatus, error)
	RemoveNode(ctx context.Context, name string) error
	GetNode(ctx context.Context, name string) (*models.NodeInfo, error)
	ListNodes(ctx context.Context) ([]models.NodeInfo, error)
	ApproveNode(ctx context.Context, name string) error
	RejectNode(ctx context.Context, name string) error
}

type ScanResultStore interface {
	SaveScanResult(ctx context.Context, scan *models.ScanResult) error
	LoadLatestScanResult(ctx context.Context) (*models.ScanResult, error)
}

type Store interface {
	TaskStore
	SnapshotStore
	SkippedStore
	AlertStore
	NodeStore
	ScanResultStore
	FlushPending(ctx context.Context) error
}

type deletedSkippedKey struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
}

type localStateFile struct {
	NextTaskNum    int                                `json:"next_task_num"`
	Tasks          map[string]models.Task             `json:"tasks"`
	Logs           map[string][]models.TaskLogLine    `json:"logs"`
	LastSeq        map[string]int                     `json:"last_seq"`
	SyncedSeq      map[string]int                     `json:"synced_seq"`
	Snapshots      map[string]models.RollbackSnapshot `json:"snapshots"`
	Skipped        map[string]models.SkippedVersion   `json:"skipped"`
	DeletedSkipped map[string]deletedSkippedKey       `json:"deleted_skipped"`
	Alerts         map[string]string                  `json:"alerts"`
	Nodes          map[string]models.NodeInfo         `json:"nodes"`
	DeletedNodes   map[string]bool                    `json:"deleted_nodes"`
}

type SpoolStore struct {
	mu           sync.RWMutex
	pgMu         sync.Mutex // lock hierarchy: always acquire pgMu before lockState/s.mu, never inside s.mu
	dataDir      string
	statePath    string
	scanPath     string
	logsDir      string
	pg           Backend
	state        localStateFile
	lastDiskHash [32]byte
	lockFile     *os.File
	subscribers  map[string]map[chan models.TaskLogLine]struct{}
}

func initStateMaps(st *localStateFile) {
	if st.NextTaskNum <= 0 {
		st.NextTaskNum = 1
	}
	if st.Tasks == nil {
		st.Tasks = make(map[string]models.Task)
	}
	if st.Logs == nil {
		st.Logs = make(map[string][]models.TaskLogLine)
	}
	if st.LastSeq == nil {
		st.LastSeq = make(map[string]int)
	}
	if st.SyncedSeq == nil {
		st.SyncedSeq = make(map[string]int)
	}
	if st.Snapshots == nil {
		st.Snapshots = make(map[string]models.RollbackSnapshot)
	}
	if st.Skipped == nil {
		st.Skipped = make(map[string]models.SkippedVersion)
	}
	if st.DeletedSkipped == nil {
		st.DeletedSkipped = make(map[string]deletedSkippedKey)
	}
	if st.Alerts == nil {
		st.Alerts = make(map[string]string)
	}
	if st.Nodes == nil {
		st.Nodes = make(map[string]models.NodeInfo)
	}
	if st.DeletedNodes == nil {
		st.DeletedNodes = make(map[string]bool)
	}
}

func NewSpoolStore(dataDir string, pg Backend) (*SpoolStore, error) {
	return newSpoolStore(dataDir, pg, true)
}

// NewCLISpoolStore opens a SpoolStore for short-lived CLI commands without aborting running daemon tasks.
func NewCLISpoolStore(dataDir string, pg Backend) (*SpoolStore, error) {
	return newSpoolStore(dataDir, pg, false)
}

func newSpoolStore(dataDir string, pg Backend, reconcileOrphaned bool) (*SpoolStore, error) {
	logsDir := filepath.Join(dataDir, "logs", "tasks")
	if err := os.MkdirAll(logsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create spool logs dir: %w", err)
	}
	s := &SpoolStore{
		dataDir:     dataDir,
		statePath:   filepath.Join(dataDir, "spool_state.json"),
		scanPath:    filepath.Join(dataDir, "latest_scan.json"),
		logsDir:     logsDir,
		pg:          pg,
		subscribers: make(map[string]map[chan models.TaskLogLine]struct{}),
		state: localStateFile{
			NextTaskNum: 1,
		},
	}
	initStateMaps(&s.state)

	lf, err := s.acquireFileLock()
	if err != nil {
		return nil, err
	}
	defer releaseFileLock(lf)

	dirty := false
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read spool state %s: %w", s.statePath, err)
		}
	} else if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &s.state); err != nil {
			return nil, fmt.Errorf("corrupt spool state file %s: %w", s.statePath, err)
		}
		initStateMaps(&s.state)
		s.lastDiskHash = sha256.Sum256(raw)
		for tid, lines := range s.state.Logs {
			if len(lines) > 0 {
				last := lines[len(lines)-1].Seq
				if last > s.state.LastSeq[tid] {
					s.state.LastSeq[tid] = last
				}
			}
		}
		for name, n := range s.state.Nodes {
			if n.Status == "" {
				n.Status = models.NodeStatusApproved
				s.state.Nodes[name] = n
				dirty = true
			}
		}
	}

	if reconcileOrphaned {
		now := time.Now().UTC()
		for id, t := range s.state.Tasks {
			if t.Status == "running" {
				t.Status = "aborted"
				t.ErrorMsg = "interrupted: daemon restarted"
				t.FinishedAt = now
				t.DurationMs = now.Sub(t.StartedAt).Milliseconds()
				t.SyncedToDB = false
				s.state.Tasks[id] = t
				dirty = true
			}
		}
	}
	if dirty {
		if err := s.saveStateLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *SpoolStore) acquireFileLock() (*os.File, error) {
	lockPath := s.statePath + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open spool state lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("failed to acquire spool state lock %s: %w", lockPath, err)
	}
	return lf, nil
}

func releaseFileLock(lf *os.File) {
	if lf != nil {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		_ = lf.Close()
	}
}

func (s *SpoolStore) lockState() error {
	s.mu.Lock()
	lf, err := s.acquireFileLock()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.lockFile = lf
	if err := s.syncFromDiskLocked(); err != nil {
		s.unlockState()
		return err
	}
	return nil
}

func (s *SpoolStore) unlockState() {
	lf := s.lockFile
	s.lockFile = nil
	releaseFileLock(lf)
	s.mu.Unlock()
}

func (s *SpoolStore) syncFromDiskLocked() error {
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read spool state %s: %w", s.statePath, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	h := sha256.Sum256(raw)
	if h == s.lastDiskHash {
		return nil
	}

	var diskState localStateFile
	if err := json.Unmarshal(raw, &diskState); err != nil {
		return fmt.Errorf("corrupt spool state file %s: %w", s.statePath, err)
	}
	initStateMaps(&diskState)

	if diskState.NextTaskNum > s.state.NextTaskNum {
		s.state.NextTaskNum = diskState.NextTaskNum
	}
	if s.pg != nil {
		for name := range s.state.Nodes {
			if _, existsOnDisk := diskState.Nodes[name]; !existsOnDisk {
				diskState.DeletedNodes[name] = true
			}
		}
		for key, prevSk := range s.state.Skipped {
			if _, existsOnDisk := diskState.Skipped[key]; !existsOnDisk {
				diskState.DeletedSkipped[key] = deletedSkippedKey{
					TargetType: prevSk.TargetType,
					TargetName: prevSk.TargetName,
				}
			}
		}
	}
	for name := range s.state.DeletedNodes {
		if _, existsOnDisk := diskState.Nodes[name]; !existsOnDisk {
			diskState.DeletedNodes[name] = true
		}
	}
	for key, ds := range s.state.DeletedSkipped {
		if _, existsOnDisk := diskState.Skipped[key]; !existsOnDisk {
			diskState.DeletedSkipped[key] = ds
		}
	}

	s.state.Nodes = diskState.Nodes
	s.state.DeletedNodes = diskState.DeletedNodes
	s.state.Skipped = diskState.Skipped
	s.state.DeletedSkipped = diskState.DeletedSkipped
	s.state.Snapshots = diskState.Snapshots
	s.state.Alerts = diskState.Alerts

	for id, dt := range diskState.Tasks {
		cur, exists := s.state.Tasks[id]
		if !exists || (dt.Status != "running" && cur.Status == "running") || (dt.Status == cur.Status && dt.SyncedToDB && !cur.SyncedToDB) {
			s.state.Tasks[id] = dt
		}
	}
	for id, dl := range diskState.LastSeq {
		if dl > s.state.LastSeq[id] {
			s.state.LastSeq[id] = dl
		}
	}
	for id, ds := range diskState.SyncedSeq {
		if ds > s.state.SyncedSeq[id] {
			s.state.SyncedSeq[id] = ds
		}
	}
	for id, dlogs := range diskState.Logs {
		curLogs := s.state.Logs[id]
		if len(dlogs) > 0 && (len(curLogs) == 0 || dlogs[len(dlogs)-1].Seq > curLogs[len(curLogs)-1].Seq) {
			s.state.Logs[id] = dlogs
		}
	}

	s.lastDiskHash = h
	return nil
}

func (s *SpoolStore) withStateLock(fn func() error) error {
	if err := s.lockState(); err != nil {
		return err
	}
	defer s.unlockState()
	return fn()
}

func (s *SpoolStore) saveStateLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(s.statePath, raw, 0600); err != nil {
		return err
	}
	s.lastDiskHash = sha256.Sum256(raw)
	return nil
}

func (s *SpoolStore) RecordAlertSent(ctx context.Context, fingerprint, alertType string) error {
	if err := s.lockState(); err != nil {
		return err
	}
	s.state.Alerts[fingerprint] = alertType
	saveErr := s.saveStateLocked()
	s.unlockState()
	if saveErr != nil {
		return saveErr
	}

	if s.pg != nil {
		s.pgMu.Lock()
		_ = s.pg.UpsertSentAlert(ctx, fingerprint, alertType)
		s.pgMu.Unlock()
	}
	return nil
}

func (s *SpoolStore) HasAlertBeenSent(ctx context.Context, fingerprint string) (bool, error) {
	if err := s.lockState(); err != nil {
		return false, err
	}
	defer s.unlockState()
	_, ok := s.state.Alerts[fingerprint]
	return ok, nil
}

func (s *SpoolStore) SaveScanResult(ctx context.Context, scan *models.ScanResult) error {
	raw, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.scanPath, raw, 0600)
}

func (s *SpoolStore) LoadLatestScanResult(ctx context.Context) (*models.ScanResult, error) {
	raw, err := os.ReadFile(s.scanPath)
	if err != nil {
		return nil, err
	}
	var scan models.ScanResult
	if err := json.Unmarshal(raw, &scan); err != nil {
		return nil, err
	}
	return &scan, nil
}
