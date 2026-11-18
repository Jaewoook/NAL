package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

const (
	maxInMemoryLogsPerTask = 2000
	maxInMemoryLogTasks    = 100
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

type Store interface {
	CreateTask(ctx context.Context, task *models.Task) (*models.Task, error)
	AppendTaskLog(ctx context.Context, taskID string, stream string, line string) (models.TaskLogLine, error)
	FinishTask(ctx context.Context, taskID string, status string, errMsg string) error
	ListTasks(ctx context.Context, filterType string, limit int) ([]models.Task, error)
	GetTaskWithLogs(ctx context.Context, taskID string) (*models.Task, []models.TaskLogLine, error)
	GetRawLogPath(taskID string) string
	SubscribeTaskLogs(taskID string) (<-chan models.TaskLogLine, func())
	SaveSnapshot(ctx context.Context, snap *models.RollbackSnapshot) error
	GetLatestSnapshot(ctx context.Context, serviceName string) (*models.RollbackSnapshot, error)
	ListSnapshots(ctx context.Context) (map[string]models.RollbackSnapshot, error)
	SetSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error
	RemoveSkippedVersion(ctx context.Context, targetType, targetName string) error
	ListSkippedVersions(ctx context.Context) (map[string]string, error)
	RecordAlertSent(ctx context.Context, fingerprint, alertType string) error
	HasAlertBeenSent(ctx context.Context, fingerprint string) (bool, error)
	UpsertNode(ctx context.Context, node models.NodeInfo) error
	UpdateNodeHealth(ctx context.Context, name string, online bool, lastSeen time.Time, lastError string) error
	AnnounceNode(ctx context.Context, req models.NodeInfo) (models.NodeStatus, error)
	RemoveNode(ctx context.Context, name string) error
	GetNode(ctx context.Context, name string) (*models.NodeInfo, error)
	ListNodes(ctx context.Context) ([]models.NodeInfo, error)
	ApproveNode(ctx context.Context, name string) error
	RejectNode(ctx context.Context, name string) error
	SaveScanResult(ctx context.Context, scan *models.ScanResult) error
	LoadLatestScanResult(ctx context.Context) (*models.ScanResult, error)
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

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
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

func (s *SpoolStore) saveStateLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.statePath, raw, 0600); err != nil {
		return err
	}
	s.lastDiskHash = sha256.Sum256(raw)
	return nil
}

func taskIDNumber(id string) (int, bool) {
	if strings.HasPrefix(id, "task-") {
		if n, err := strconv.Atoi(strings.TrimPrefix(id, "task-")); err == nil {
			return n, true
		}
	}
	return 0, false
}

func compareTaskIDDesc(a, b string) bool {
	na, okA := taskIDNumber(a)
	nb, okB := taskIDNumber(b)
	if okA && okB {
		return na > nb
	}
	return a > b
}

func (s *SpoolStore) pruneInMemoryLogsLocked() {
	if len(s.state.Logs) <= maxInMemoryLogTasks {
		return
	}
	type taskEntry struct {
		id     string
		synced bool
	}
	var finished []taskEntry
	for id := range s.state.Logs {
		t, ok := s.state.Tasks[id]
		if !ok || t.Status != "running" {
			allSynced := (s.pg == nil) || (ok && t.SyncedToDB && s.state.SyncedSeq[id] >= s.state.LastSeq[id])
			finished = append(finished, taskEntry{id: id, synced: allSynced})
		}
	}
	sort.Slice(finished, func(i, j int) bool {
		return compareTaskIDDesc(finished[i].id, finished[j].id)
	})
	for i := maxInMemoryLogTasks; i < len(finished); i++ {
		if finished[i].synced {
			delete(s.state.Logs, finished[i].id)
		}
	}
}

func (s *SpoolStore) CreateTask(ctx context.Context, task *models.Task) (*models.Task, error) {
	if err := s.lockState(); err != nil {
		return nil, err
	}
	num := s.state.NextTaskNum
	s.state.NextTaskNum++
	id := fmt.Sprintf("task-%05d", num)
	now := time.Now().UTC()

	created := *task
	created.ID = id
	if created.Status == "" {
		created.Status = "running"
	}
	created.StartedAt = now
	created.SyncedToDB = false

	s.state.Tasks[id] = created
	s.pruneInMemoryLogsLocked()
	saveErr := s.saveStateLocked()
	s.unlockState()
	if saveErr != nil {
		return nil, saveErr
	}

	if s.pg != nil {
		s.pgMu.Lock()
		if err := s.pg.UpsertTask(ctx, created); err == nil {
			if lockErr := s.lockState(); lockErr == nil {
				if cur, exists := s.state.Tasks[id]; exists && cur.Status == created.Status && cur.FinishedAt.Equal(created.FinishedAt) {
					cur.SyncedToDB = true
					s.state.Tasks[id] = cur
					_ = s.saveStateLocked()
				}
				s.unlockState()
			}
		}
		s.pgMu.Unlock()
	}
	return &created, nil
}

func (s *SpoolStore) GetRawLogPath(taskID string) string {
	base := filepath.Base(taskID)
	if base == "" || base == "." || base == ".." {
		base = "invalid"
	}
	return filepath.Join(s.logsDir, fmt.Sprintf("%s.log", base))
}

func (s *SpoolStore) AppendTaskLog(ctx context.Context, taskID string, stream string, line string) (models.TaskLogLine, error) {
	if err := s.lockState(); err != nil {
		return models.TaskLogLine{}, err
	}
	seq := s.state.LastSeq[taskID] + 1
	if cur := len(s.state.Logs[taskID]); cur >= seq {
		seq = cur + 1
	}
	s.state.LastSeq[taskID] = seq

	entry := models.TaskLogLine{
		TaskID:   taskID,
		Seq:      seq,
		LoggedAt: time.Now().UTC(),
		Stream:   stream,
		Line:     line,
	}
	s.state.Logs[taskID] = append(s.state.Logs[taskID], entry)
	if len(s.state.Logs[taskID]) > maxInMemoryLogsPerTask {
		trim := len(s.state.Logs[taskID]) - maxInMemoryLogsPerTask
		if s.pg == nil {
			s.state.Logs[taskID] = append([]models.TaskLogLine(nil), s.state.Logs[taskID][trim:]...)
		} else {
			synced := s.state.SyncedSeq[taskID]
			safeCut := 0
			for safeCut < trim && s.state.Logs[taskID][safeCut].Seq <= synced {
				safeCut++
			}
			if safeCut > 0 {
				s.state.Logs[taskID] = append([]models.TaskLogLine(nil), s.state.Logs[taskID][safeCut:]...)
			}
		}
	}
	if seq%50 == 0 {
		_ = s.saveStateLocked()
	}

	f, err := os.OpenFile(s.GetRawLogPath(taskID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		_, _ = fmt.Fprintf(f, "[%s] [%s] %s\n", entry.LoggedAt.Format("15:04:05.000"), entry.Stream, entry.Line)
		_ = f.Close()
	}

	subs := s.subscribers[taskID]
	for ch := range subs {
		select {
		case ch <- entry:
		default:
		}
	}
	s.unlockState()

	if s.pg != nil {
		var prevSynced int
		var tCopy models.Task
		var exists bool
		if lockErr := s.lockState(); lockErr == nil {
			prevSynced = s.state.SyncedSeq[taskID]
			tCopy, exists = s.state.Tasks[taskID]
			s.unlockState()
		}

		if exists && tCopy.SyncedToDB && prevSynced == seq-1 {
			if err := s.pg.InsertTaskLog(ctx, entry); err == nil {
				if lockErr := s.lockState(); lockErr == nil {
					if s.state.SyncedSeq[taskID] == seq-1 {
						s.state.SyncedSeq[taskID] = seq
						if seq%50 == 0 {
							_ = s.saveStateLocked()
						}
					}
					s.unlockState()
				}
			}
		}
	}

	return entry, nil
}

func (s *SpoolStore) FinishTask(ctx context.Context, taskID string, status string, errMsg string) error {
	if err := s.lockState(); err != nil {
		return err
	}
	t, ok := s.state.Tasks[taskID]
	if !ok {
		s.unlockState()
		return fmt.Errorf("task %s not found", taskID)
	}
	t.Status = status
	t.ErrorMsg = errMsg
	t.FinishedAt = time.Now().UTC()
	t.DurationMs = t.FinishedAt.Sub(t.StartedAt).Milliseconds()
	t.SyncedToDB = false
	s.state.Tasks[taskID] = t
	saveErr := s.saveStateLocked()

	if subs, exists := s.subscribers[taskID]; exists {
		for ch := range subs {
			close(ch)
		}
		delete(s.subscribers, taskID)
	}
	s.unlockState()
	if saveErr != nil {
		return saveErr
	}

	if s.pg != nil {
		// Note: FinishTask intentionally does NOT hold pgMu across s.pg.UpsertTask so
		// re-entrant test hooks firing during FlushPending's UpsertTask cannot deadlock.
		// PostgreSQL ON CONFLICT guard + FlushPending post-check ensure final state wins.
		if err := s.pg.UpsertTask(ctx, t); err == nil {
			if lockErr := s.lockState(); lockErr == nil {
				if current, exists := s.state.Tasks[taskID]; exists {
					if current.Status == t.Status && current.FinishedAt.Equal(t.FinishedAt) {
						current.SyncedToDB = true
						s.state.Tasks[taskID] = current
						_ = s.saveStateLocked()
					}
				}
				s.unlockState()
			}
		}
	}
	return nil
}

func (s *SpoolStore) ListTasks(ctx context.Context, filterType string, limit int) ([]models.Task, error) {
	if err := s.lockState(); err != nil {
		return nil, err
	}
	defer s.unlockState()
	var list []models.Task
	for _, t := range s.state.Tasks {
		if filterType != "" && t.TaskType != filterType {
			continue
		}
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool {
		return compareTaskIDDesc(list[i].ID, list[j].ID)
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list, nil
}

func (s *SpoolStore) GetTaskWithLogs(ctx context.Context, taskID string) (*models.Task, []models.TaskLogLine, error) {
	if err := s.lockState(); err != nil {
		return nil, nil, err
	}
	defer s.unlockState()
	t, ok := s.state.Tasks[taskID]
	if !ok {
		return nil, nil, fmt.Errorf("task %s not found", taskID)
	}
	logs := append([]models.TaskLogLine(nil), s.state.Logs[taskID]...)
	return &t, logs, nil
}

func (s *SpoolStore) SubscribeTaskLogs(taskID string) (<-chan models.TaskLogLine, func()) {
	ch := make(chan models.TaskLogLine, 128)
	s.mu.Lock()
	if s.subscribers[taskID] == nil {
		s.subscribers[taskID] = make(map[chan models.TaskLogLine]struct{})
	}
	s.subscribers[taskID][ch] = struct{}{}
	s.mu.Unlock()

	unsub := func() {
		s.mu.Lock()
		if subs, ok := s.subscribers[taskID]; ok {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(s.subscribers, taskID)
			}
		}
		s.mu.Unlock()
	}
	return ch, unsub
}

func (s *SpoolStore) SaveSnapshot(ctx context.Context, snap *models.RollbackSnapshot) error {
	if err := s.lockState(); err != nil {
		return err
	}
	cp := *snap
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	cp.SyncedToDB = false
	s.state.Snapshots[cp.ServiceName] = cp
	saveErr := s.saveStateLocked()
	s.unlockState()
	if saveErr != nil {
		return saveErr
	}

	if s.pg != nil {
		s.pgMu.Lock()
		var latest models.RollbackSnapshot
		var exists bool
		if lockErr := s.lockState(); lockErr == nil {
			latest, exists = s.state.Snapshots[cp.ServiceName]
			s.unlockState()
		}
		if exists {
			if err := s.pg.UpsertSnapshot(ctx, latest); err == nil {
				if lockErr := s.lockState(); lockErr == nil {
					if cur, still := s.state.Snapshots[cp.ServiceName]; still && cur.ID == latest.ID {
						cur.SyncedToDB = true
						s.state.Snapshots[cp.ServiceName] = cur
						_ = s.saveStateLocked()
					}
					s.unlockState()
				}
			}
		}
		s.pgMu.Unlock()
	}
	return nil
}

func (s *SpoolStore) GetLatestSnapshot(ctx context.Context, serviceName string) (*models.RollbackSnapshot, error) {
	if err := s.lockState(); err != nil {
		return nil, err
	}
	defer s.unlockState()
	snap, ok := s.state.Snapshots[serviceName]
	if !ok {
		return nil, fmt.Errorf("no snapshot found for service %s", serviceName)
	}
	return &snap, nil
}

func (s *SpoolStore) ListSnapshots(ctx context.Context) (map[string]models.RollbackSnapshot, error) {
	if err := s.lockState(); err != nil {
		return nil, err
	}
	defer s.unlockState()
	out := make(map[string]models.RollbackSnapshot, len(s.state.Snapshots))
	for k, v := range s.state.Snapshots {
		out[k] = v
	}
	return out, nil
}

func (s *SpoolStore) SetSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error {
	key := targetType + ":" + targetName
	if err := s.lockState(); err != nil {
		return err
	}
	delete(s.state.DeletedSkipped, key)
	s.state.Skipped[key] = models.SkippedVersion{
		TargetType:     targetType,
		TargetName:     targetName,
		SkippedVersion: version,
		CreatedBy:      actor,
		CreatedAt:      time.Now().UTC(),
	}
	saveErr := s.saveStateLocked()
	s.unlockState()
	if saveErr != nil {
		return saveErr
	}

	if s.pg != nil {
		s.pgMu.Lock()
		var sk models.SkippedVersion
		var exists bool
		if lockErr := s.lockState(); lockErr == nil {
			sk, exists = s.state.Skipped[key]
			s.unlockState()
		}
		if exists {
			_ = s.pg.UpsertSkippedVersion(ctx, sk.TargetType, sk.TargetName, sk.SkippedVersion, sk.CreatedBy)
		}
		s.pgMu.Unlock()
	}
	return nil
}

func (s *SpoolStore) RemoveSkippedVersion(ctx context.Context, targetType, targetName string) error {
	key := targetType + ":" + targetName
	if err := s.lockState(); err != nil {
		return err
	}
	delete(s.state.Skipped, key)
	s.state.DeletedSkipped[key] = deletedSkippedKey{TargetType: targetType, TargetName: targetName}
	saveErr := s.saveStateLocked()
	s.unlockState()
	if saveErr != nil {
		return saveErr
	}

	if s.pg != nil {
		s.pgMu.Lock()
		stillSkipped := false
		if lockErr := s.lockState(); lockErr == nil {
			_, stillSkipped = s.state.Skipped[key]
			s.unlockState()
		}
		if !stillSkipped {
			if err := s.pg.DeleteSkippedVersion(ctx, targetType, targetName); err == nil {
				if lockErr := s.lockState(); lockErr == nil {
					if _, reAdded := s.state.Skipped[key]; !reAdded {
						delete(s.state.DeletedSkipped, key)
						_ = s.saveStateLocked()
					}
					s.unlockState()
				}
			}
		}
		s.pgMu.Unlock()
	}
	return nil
}

func (s *SpoolStore) ListSkippedVersions(ctx context.Context) (map[string]string, error) {
	if err := s.lockState(); err != nil {
		return nil, err
	}
	defer s.unlockState()
	out := make(map[string]string, len(s.state.Skipped))
	for k, v := range s.state.Skipped {
		out[k] = v.SkippedVersion
	}
	return out, nil
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

func (s *SpoolStore) syncNodeToPGLocked(ctx context.Context, name string) {
	if s.pg == nil {
		return
	}
	s.pgMu.Lock()
	defer s.pgMu.Unlock()
	var cur models.NodeInfo
	var exists bool
	if lockErr := s.lockState(); lockErr == nil {
		cur, exists = s.state.Nodes[name]
		s.unlockState()
	}
	if exists {
		_ = s.pg.UpsertNode(ctx, cur)
	}
}

func (s *SpoolStore) UpsertNode(ctx context.Context, node models.NodeInfo) error {
	if node.Name == "" {
		return fmt.Errorf("node name is required")
	}
	if node.Role == "" {
		node.Role = "agent"
	}
	if err := s.lockState(); err != nil {
		return err
	}
	delete(s.state.DeletedNodes, node.Name)
	if existing, ok := s.state.Nodes[node.Name]; ok {
		if node.Token == "" {
			node.Token = existing.Token
		}
		if node.Status == "" {
			node.Status = existing.Status
		}
		if node.OSVersion == "" {
			node.OSVersion = existing.OSVersion
		}
		wasZeroSeen := node.LastSeenAt.IsZero()
		if wasZeroSeen {
			node.LastSeenAt = existing.LastSeenAt
		}
		if !node.Online && node.LastError == "" && wasZeroSeen && !existing.LastSeenAt.IsZero() && time.Since(existing.LastSeenAt) <= 3*time.Minute {
			node.Online = existing.Online
		}
	}
	if node.Status == "" {
		node.Status = models.NodeStatusApproved
	}
	s.state.Nodes[node.Name] = node
	err := s.saveStateLocked()
	s.unlockState()
	if err != nil {
		return err
	}

	s.syncNodeToPGLocked(ctx, node.Name)
	return nil
}

// UpdateNodeHealth atomically updates only runtime reachability fields without touching
// operator-controlled Status, URL, or Token, and no-ops if the node was removed.
func (s *SpoolStore) UpdateNodeHealth(ctx context.Context, name string, online bool, lastSeen time.Time, lastError string) error {
	if err := s.lockState(); err != nil {
		return err
	}
	n, ok := s.state.Nodes[name]
	if !ok {
		s.unlockState()
		return nil
	}
	n.Online = online
	n.LastError = lastError
	if !lastSeen.IsZero() {
		n.LastSeenAt = lastSeen
	}
	s.state.Nodes[name] = n
	err := s.saveStateLocked()
	s.unlockState()
	if err != nil {
		return err
	}
	s.syncNodeToPGLocked(ctx, name)
	return nil
}

// AnnounceNode atomically handles agent registration/heartbeat announcements under lock,
// respecting concurrent operator rejections/removals and demoting URL changes to pending.
func (s *SpoolStore) AnnounceNode(ctx context.Context, req models.NodeInfo) (models.NodeStatus, error) {
	if req.Name == "" || req.URL == "" {
		return "", fmt.Errorf("node name and url are required")
	}
	if err := s.lockState(); err != nil {
		return "", err
	}
	if existing, ok := s.state.Nodes[req.Name]; ok {
		if existing.Status == models.NodeStatusRejected {
			s.unlockState()
			return models.NodeStatusRejected, nil
		}
		existingURL := strings.TrimRight(existing.URL, "/")
		if existing.Status == models.NodeStatusApproved && existingURL != "" && existingURL != req.URL {
			existing.Status = models.NodeStatusPending
		}
		existing.URL = req.URL
		existing.Online = true
		existing.LastSeenAt = time.Now().UTC()
		if req.OSVersion != "" {
			existing.OSVersion = req.OSVersion
		}
		if req.Token != "" {
			existing.Token = req.Token
		}
		if existing.Status == "" {
			existing.Status = models.NodeStatusApproved
		}
		s.state.Nodes[req.Name] = existing
		delete(s.state.DeletedNodes, req.Name)
		err := s.saveStateLocked()
		st := existing.Status
		s.unlockState()
		if err != nil {
			return "", err
		}
		s.syncNodeToPGLocked(ctx, req.Name)
		return st, nil
	}

	newNode := models.NodeInfo{
		Name:       req.Name,
		URL:        req.URL,
		Token:      req.Token,
		Role:       "agent",
		Status:     models.NodeStatusPending,
		Online:     true,
		LastSeenAt: time.Now().UTC(),
		OSVersion:  req.OSVersion,
	}
	s.state.Nodes[req.Name] = newNode
	delete(s.state.DeletedNodes, req.Name)
	err := s.saveStateLocked()
	s.unlockState()
	if err != nil {
		return "", err
	}
	s.syncNodeToPGLocked(ctx, req.Name)
	return models.NodeStatusPending, nil
}

func (s *SpoolStore) RemoveNode(ctx context.Context, name string) error {
	if err := s.lockState(); err != nil {
		return err
	}
	delete(s.state.Nodes, name)
	s.state.DeletedNodes[name] = true
	err := s.saveStateLocked()
	s.unlockState()
	if err != nil {
		return err
	}

	if s.pg != nil {
		s.pgMu.Lock()
		reAdded := false
		if lockErr := s.lockState(); lockErr == nil {
			_, reAdded = s.state.Nodes[name]
			s.unlockState()
		}
		if !reAdded {
			if dErr := s.pg.DeleteNode(ctx, name); dErr == nil {
				if lockErr := s.lockState(); lockErr == nil {
					if _, exists := s.state.Nodes[name]; !exists {
						delete(s.state.DeletedNodes, name)
						_ = s.saveStateLocked()
					}
					s.unlockState()
				}
			}
		}
		s.pgMu.Unlock()
	}
	return nil
}

func (s *SpoolStore) ApproveNode(ctx context.Context, name string) error {
	if err := s.lockState(); err != nil {
		return err
	}
	n, ok := s.state.Nodes[name]
	if !ok {
		s.unlockState()
		return fmt.Errorf("node %q not found", name)
	}
	n.Status = models.NodeStatusApproved
	s.state.Nodes[name] = n
	err := s.saveStateLocked()
	s.unlockState()
	if err != nil {
		return err
	}

	s.syncNodeToPGLocked(ctx, name)
	return nil
}

func (s *SpoolStore) RejectNode(ctx context.Context, name string) error {
	if err := s.lockState(); err != nil {
		return err
	}
	n, ok := s.state.Nodes[name]
	if !ok {
		s.unlockState()
		return fmt.Errorf("node %q not found", name)
	}
	n.Status = models.NodeStatusRejected
	s.state.Nodes[name] = n
	err := s.saveStateLocked()
	s.unlockState()
	if err != nil {
		return err
	}

	s.syncNodeToPGLocked(ctx, name)
	return nil
}

func (s *SpoolStore) GetNode(ctx context.Context, name string) (*models.NodeInfo, error) {
	if err := s.lockState(); err != nil {
		return nil, err
	}
	defer s.unlockState()
	n, ok := s.state.Nodes[name]
	if !ok {
		return nil, fmt.Errorf("node %q not found", name)
	}
	if n.Role == "agent" && (n.LastSeenAt.IsZero() || time.Since(n.LastSeenAt) > 3*time.Minute) {
		n.Online = false
	}
	return &n, nil
}

func (s *SpoolStore) ListNodes(ctx context.Context) ([]models.NodeInfo, error) {
	if err := s.lockState(); err != nil {
		return nil, err
	}
	defer s.unlockState()
	var list []models.NodeInfo
	for _, n := range s.state.Nodes {
		if n.Role == "agent" && (n.LastSeenAt.IsZero() || time.Since(n.LastSeenAt) > 3*time.Minute) {
			n.Online = false
		}
		list = append(list, n)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})
	return list, nil
}

func (s *SpoolStore) SaveScanResult(ctx context.Context, scan *models.ScanResult) error {
	raw, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.scanPath, raw, 0600)
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

func (s *SpoolStore) FlushPending(ctx context.Context) error {
	if s.pg == nil {
		return nil
	}
	s.pgMu.Lock()
	defer s.pgMu.Unlock()

	if err := s.lockState(); err != nil {
		return err
	}
	var taskIDs []string
	for id := range s.state.Tasks {
		taskIDs = append(taskIDs, id)
	}
	s.unlockState()
	sort.Slice(taskIDs, func(i, j int) bool {
		return !compareTaskIDDesc(taskIDs[i], taskIDs[j])
	})

	for _, id := range taskIDs {
		for pass := 0; pass < 2; pass++ {
			if err := s.lockState(); err != nil {
				return err
			}
			t, exists := s.state.Tasks[id]
			s.unlockState()
			if !exists || t.SyncedToDB {
				break
			}
			if err := s.pg.UpsertTask(ctx, t); err != nil {
				return err
			}
			if err := s.lockState(); err != nil {
				return err
			}
			cur, stillExists := s.state.Tasks[id]
			if !stillExists {
				s.unlockState()
				break
			}
			if cur.Status == t.Status && cur.FinishedAt.Equal(t.FinishedAt) {
				cur.SyncedToDB = true
				s.state.Tasks[id] = cur
				_ = s.saveStateLocked()
				s.unlockState()
				break
			}
			// Task changed concurrently during UpsertTask; retry syncing latest state once unless already synced
			needRetry := !cur.SyncedToDB || cur.Status != t.Status
			s.unlockState()
			if !needRetry {
				break
			}
		}

		if err := s.lockState(); err != nil {
			return err
		}
		logs := append([]models.TaskLogLine(nil), s.state.Logs[id]...)
		syncedSeq := s.state.SyncedSeq[id]
		s.unlockState()

		var pendingLogs []models.TaskLogLine
		for _, line := range logs {
			if line.Seq > syncedSeq {
				pendingLogs = append(pendingLogs, line)
			}
		}
		if len(pendingLogs) > 0 {
			batchSize := 200
			for i := 0; i < len(pendingLogs); i += batchSize {
				end := i + batchSize
				if end > len(pendingLogs) {
					end = len(pendingLogs)
				}
				chunk := pendingLogs[i:end]
				if err := s.pg.InsertTaskLogsBatch(ctx, chunk); err != nil {
					return err
				}
				if err := s.lockState(); err != nil {
					return err
				}
				if last := chunk[len(chunk)-1].Seq; last > s.state.SyncedSeq[id] {
					s.state.SyncedSeq[id] = last
					_ = s.saveStateLocked()
				}
				s.unlockState()
			}
		}
	}

	if err := s.lockState(); err != nil {
		return err
	}
	snaps := make([]models.RollbackSnapshot, 0, len(s.state.Snapshots))
	for _, snap := range s.state.Snapshots {
		if !snap.SyncedToDB {
			snaps = append(snaps, snap)
		}
	}
	s.unlockState()

	for _, snap := range snaps {
		if err := s.pg.UpsertSnapshot(ctx, snap); err != nil {
			return err
		}
		if err := s.lockState(); err != nil {
			return err
		}
		if cur, exists := s.state.Snapshots[snap.ServiceName]; exists && cur.ID == snap.ID {
			cur.SyncedToDB = true
			s.state.Snapshots[snap.ServiceName] = cur
			_ = s.saveStateLocked()
		}
		s.unlockState()
	}

	if err := s.lockState(); err != nil {
		return err
	}
	skipped := make([]models.SkippedVersion, 0, len(s.state.Skipped))
	for _, sk := range s.state.Skipped {
		skipped = append(skipped, sk)
	}
	delSkipped := make(map[string]deletedSkippedKey, len(s.state.DeletedSkipped))
	for k, v := range s.state.DeletedSkipped {
		delSkipped[k] = v
	}
	alerts := make(map[string]string, len(s.state.Alerts))
	for k, v := range s.state.Alerts {
		alerts[k] = v
	}
	nodes := make([]models.NodeInfo, 0, len(s.state.Nodes))
	for _, n := range s.state.Nodes {
		nodes = append(nodes, n)
	}
	delNodes := make([]string, 0, len(s.state.DeletedNodes))
	for k := range s.state.DeletedNodes {
		delNodes = append(delNodes, k)
	}
	s.unlockState()

	for _, sk := range skipped {
		if err := s.pg.UpsertSkippedVersion(ctx, sk.TargetType, sk.TargetName, sk.SkippedVersion, sk.CreatedBy); err != nil {
			return err
		}
	}
	for k, ds := range delSkipped {
		if err := s.lockState(); err != nil {
			return err
		}
		_, reAdded := s.state.Skipped[k]
		if reAdded {
			delete(s.state.DeletedSkipped, k)
			_ = s.saveStateLocked()
			s.unlockState()
			continue
		}
		s.unlockState()
		if err := s.pg.DeleteSkippedVersion(ctx, ds.TargetType, ds.TargetName); err != nil {
			return err
		}
		if err := s.lockState(); err != nil {
			return err
		}
		if _, exists := s.state.Skipped[k]; !exists {
			delete(s.state.DeletedSkipped, k)
			_ = s.saveStateLocked()
		}
		s.unlockState()
	}

	for fp, at := range alerts {
		if err := s.pg.UpsertSentAlert(ctx, fp, at); err != nil {
			return err
		}
	}

	for _, n := range nodes {
		// Re-read latest node state inside pgMu in case operator updated or removed it
		if err := s.lockState(); err != nil {
			return err
		}
		cur, exists := s.state.Nodes[n.Name]
		s.unlockState()
		if !exists {
			continue
		}
		if err := s.pg.UpsertNode(ctx, cur); err != nil {
			return err
		}
	}
	for _, name := range delNodes {
		if err := s.lockState(); err != nil {
			return err
		}
		_, reAdded := s.state.Nodes[name]
		if reAdded {
			delete(s.state.DeletedNodes, name)
			_ = s.saveStateLocked()
			s.unlockState()
			continue
		}
		s.unlockState()
		if err := s.pg.DeleteNode(ctx, name); err != nil {
			return err
		}
		if err := s.lockState(); err != nil {
			return err
		}
		if _, exists := s.state.Nodes[name]; !exists {
			delete(s.state.DeletedNodes, name)
			_ = s.saveStateLocked()
		}
		s.unlockState()
	}

	return nil
}
