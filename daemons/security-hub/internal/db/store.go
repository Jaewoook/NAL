package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

type Backend interface {
	UpsertTask(ctx context.Context, task models.Task) error
	InsertTaskLog(ctx context.Context, line models.TaskLogLine) error
	UpsertSnapshot(ctx context.Context, snap models.RollbackSnapshot) error
	UpsertSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error
	DeleteSkippedVersion(ctx context.Context, targetType, targetName string) error
	UpsertSentAlert(ctx context.Context, fingerprint, alertType string) error
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
	RemoveNode(ctx context.Context, name string) error
	GetNode(ctx context.Context, name string) (*models.NodeInfo, error)
	ListNodes(ctx context.Context) ([]models.NodeInfo, error)
	SaveScanResult(ctx context.Context, scan *models.ScanResult) error
	LoadLatestScanResult(ctx context.Context) (*models.ScanResult, error)
	FlushPending(ctx context.Context) error
}

type localStateFile struct {
	NextTaskNum int                                `json:"next_task_num"`
	Tasks       map[string]models.Task             `json:"tasks"`
	Logs        map[string][]models.TaskLogLine    `json:"logs"`
	SyncedSeq   map[string]int                     `json:"synced_seq"`
	Snapshots   map[string]models.RollbackSnapshot `json:"snapshots"`
	Skipped     map[string]models.SkippedVersion   `json:"skipped"`
	Alerts      map[string]string                  `json:"alerts"`
	Nodes       map[string]models.NodeInfo         `json:"nodes"`
}

type SpoolStore struct {
	mu          sync.RWMutex
	dataDir     string
	statePath   string
	scanPath    string
	logsDir     string
	pg          Backend
	state       localStateFile
	subscribers map[string]map[chan models.TaskLogLine]struct{}
}

func NewSpoolStore(dataDir string, pg Backend) (*SpoolStore, error) {
	logsDir := filepath.Join(dataDir, "logs", "tasks")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
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
			Tasks:       make(map[string]models.Task),
			Logs:        make(map[string][]models.TaskLogLine),
			SyncedSeq:   make(map[string]int),
			Snapshots:   make(map[string]models.RollbackSnapshot),
			Skipped:     make(map[string]models.SkippedVersion),
			Alerts:      make(map[string]string),
			Nodes:       make(map[string]models.NodeInfo),
		},
	}
	if raw, err := os.ReadFile(s.statePath); err == nil {
		_ = json.Unmarshal(raw, &s.state)
		if s.state.Tasks == nil {
			s.state.Tasks = make(map[string]models.Task)
		}
		if s.state.Logs == nil {
			s.state.Logs = make(map[string][]models.TaskLogLine)
		}
		if s.state.SyncedSeq == nil {
			s.state.SyncedSeq = make(map[string]int)
		}
		if s.state.Snapshots == nil {
			s.state.Snapshots = make(map[string]models.RollbackSnapshot)
		}
		if s.state.Skipped == nil {
			s.state.Skipped = make(map[string]models.SkippedVersion)
		}
		if s.state.Alerts == nil {
			s.state.Alerts = make(map[string]string)
		}
		if s.state.Nodes == nil {
			s.state.Nodes = make(map[string]models.NodeInfo)
		}
	}
	return s, nil
}

func (s *SpoolStore) saveStateLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath)
}

func (s *SpoolStore) CreateTask(ctx context.Context, task *models.Task) (*models.Task, error) {
	s.mu.Lock()
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
	_ = s.saveStateLocked()
	s.mu.Unlock()

	if s.pg != nil {
		if err := s.pg.UpsertTask(ctx, created); err == nil {
			s.mu.Lock()
			created.SyncedToDB = true
			s.state.Tasks[id] = created
			_ = s.saveStateLocked()
			s.mu.Unlock()
		}
	}
	return &created, nil
}

func (s *SpoolStore) GetRawLogPath(taskID string) string {
	return filepath.Join(s.logsDir, fmt.Sprintf("%s.log", taskID))
}

func (s *SpoolStore) AppendTaskLog(ctx context.Context, taskID string, stream string, line string) (models.TaskLogLine, error) {
	s.mu.Lock()
	seq := len(s.state.Logs[taskID]) + 1
	entry := models.TaskLogLine{
		TaskID:   taskID,
		Seq:      seq,
		LoggedAt: time.Now().UTC(),
		Stream:   stream,
		Line:     line,
	}
	s.state.Logs[taskID] = append(s.state.Logs[taskID], entry)
	_ = s.saveStateLocked()

	// Also append to raw .log file on disk
	f, err := os.OpenFile(s.GetRawLogPath(taskID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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
	s.mu.Unlock()

	if s.pg != nil {
		// Only mark syncedSeq in order if previous lines were already synced
		s.mu.Lock()
		prevSynced := s.state.SyncedSeq[taskID]
		tCopy, exists := s.state.Tasks[taskID]
		s.mu.Unlock()

		if exists && tCopy.SyncedToDB && prevSynced == seq-1 {
			if err := s.pg.InsertTaskLog(ctx, entry); err == nil {
				s.mu.Lock()
				if s.state.SyncedSeq[taskID] == seq-1 {
					s.state.SyncedSeq[taskID] = seq
					_ = s.saveStateLocked()
				}
				s.mu.Unlock()
			}
		}
	}

	return entry, nil
}

func (s *SpoolStore) FinishTask(ctx context.Context, taskID string, status string, errMsg string) error {
	s.mu.Lock()
	t, ok := s.state.Tasks[taskID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("task %s not found", taskID)
	}
	t.Status = status
	t.ErrorMsg = errMsg
	t.FinishedAt = time.Now().UTC()
	t.DurationMs = t.FinishedAt.Sub(t.StartedAt).Milliseconds()
	t.SyncedToDB = false
	s.state.Tasks[taskID] = t
	_ = s.saveStateLocked()

	// Close all live SSE subscriber channels for this task so streaming handlers wake up immediately
	if subs, exists := s.subscribers[taskID]; exists {
		for ch := range subs {
			close(ch)
		}
		delete(s.subscribers, taskID)
	}
	s.mu.Unlock()

	if s.pg != nil {
		if err := s.pg.UpsertTask(ctx, t); err == nil {
			s.mu.Lock()
			t.SyncedToDB = true
			s.state.Tasks[taskID] = t
			_ = s.saveStateLocked()
			s.mu.Unlock()
		}
	}
	return nil
}

func (s *SpoolStore) ListTasks(ctx context.Context, filterType string, limit int) ([]models.Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []models.Task
	for _, t := range s.state.Tasks {
		if filterType != "" && t.TaskType != filterType {
			continue
		}
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID > list[j].ID
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list, nil
}

func (s *SpoolStore) GetTaskWithLogs(ctx context.Context, taskID string) (*models.Task, []models.TaskLogLine, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
		}
		s.mu.Unlock()
	}
	return ch, unsub
}

func (s *SpoolStore) SaveSnapshot(ctx context.Context, snap *models.RollbackSnapshot) error {
	s.mu.Lock()
	cp := *snap
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	cp.SyncedToDB = false
	s.state.Snapshots[cp.ServiceName] = cp
	_ = s.saveStateLocked()
	s.mu.Unlock()

	if s.pg != nil {
		if err := s.pg.UpsertSnapshot(ctx, cp); err == nil {
			s.mu.Lock()
			cp.SyncedToDB = true
			s.state.Snapshots[cp.ServiceName] = cp
			_ = s.saveStateLocked()
			s.mu.Unlock()
		}
	}
	return nil
}

func (s *SpoolStore) GetLatestSnapshot(ctx context.Context, serviceName string) (*models.RollbackSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap, ok := s.state.Snapshots[serviceName]
	if !ok {
		return nil, fmt.Errorf("no snapshot found for service %s", serviceName)
	}
	return &snap, nil
}

func (s *SpoolStore) ListSnapshots(ctx context.Context) (map[string]models.RollbackSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]models.RollbackSnapshot, len(s.state.Snapshots))
	for k, v := range s.state.Snapshots {
		out[k] = v
	}
	return out, nil
}

func (s *SpoolStore) SetSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error {
	key := targetType + ":" + targetName
	s.mu.Lock()
	s.state.Skipped[key] = models.SkippedVersion{
		TargetType:     targetType,
		TargetName:     targetName,
		SkippedVersion: version,
		CreatedBy:      actor,
		CreatedAt:      time.Now().UTC(),
	}
	_ = s.saveStateLocked()
	s.mu.Unlock()

	if s.pg != nil {
		_ = s.pg.UpsertSkippedVersion(ctx, targetType, targetName, version, actor)
	}
	return nil
}

func (s *SpoolStore) RemoveSkippedVersion(ctx context.Context, targetType, targetName string) error {
	key := targetType + ":" + targetName
	s.mu.Lock()
	delete(s.state.Skipped, key)
	_ = s.saveStateLocked()
	s.mu.Unlock()

	if s.pg != nil {
		_ = s.pg.DeleteSkippedVersion(ctx, targetType, targetName)
	}
	return nil
}

func (s *SpoolStore) ListSkippedVersions(ctx context.Context) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.state.Skipped))
	for k, v := range s.state.Skipped {
		out[k] = v.SkippedVersion
	}
	return out, nil
}

func (s *SpoolStore) RecordAlertSent(ctx context.Context, fingerprint, alertType string) error {
	s.mu.Lock()
	s.state.Alerts[fingerprint] = alertType
	_ = s.saveStateLocked()
	s.mu.Unlock()

	if s.pg != nil {
		_ = s.pg.UpsertSentAlert(ctx, fingerprint, alertType)
	}
	return nil
}

func (s *SpoolStore) HasAlertBeenSent(ctx context.Context, fingerprint string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.state.Alerts[fingerprint]
	return ok, nil
}

func (s *SpoolStore) UpsertNode(ctx context.Context, node models.NodeInfo) error {
	if node.Name == "" {
		return fmt.Errorf("node name is required")
	}
	if node.Role == "" {
		node.Role = "agent"
	}
	s.mu.Lock()
	if existing, ok := s.state.Nodes[node.Name]; ok && node.Token == "" {
		node.Token = existing.Token
	}
	s.state.Nodes[node.Name] = node
	err := s.saveStateLocked()
	s.mu.Unlock()
	return err
}

func (s *SpoolStore) RemoveNode(ctx context.Context, name string) error {
	s.mu.Lock()
	delete(s.state.Nodes, name)
	err := s.saveStateLocked()
	s.mu.Unlock()
	return err
}

func (s *SpoolStore) GetNode(ctx context.Context, name string) (*models.NodeInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.state.Nodes[name]
	if !ok {
		return nil, fmt.Errorf("node %q not found", name)
	}
	return &n, nil
}

func (s *SpoolStore) ListNodes(ctx context.Context) ([]models.NodeInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []models.NodeInfo
	for _, n := range s.state.Nodes {
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
	tmp := s.scanPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.scanPath)
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
	s.mu.Lock()
	var taskIDs []string
	for id := range s.state.Tasks {
		taskIDs = append(taskIDs, id)
	}
	sort.Strings(taskIDs)
	s.mu.Unlock()

	for _, id := range taskIDs {
		s.mu.RLock()
		t := s.state.Tasks[id]
		logs := append([]models.TaskLogLine(nil), s.state.Logs[id]...)
		syncedSeq := s.state.SyncedSeq[id]
		s.mu.RUnlock()

		if !t.SyncedToDB {
			if err := s.pg.UpsertTask(ctx, t); err != nil {
				return err
			}
			s.mu.Lock()
			t.SyncedToDB = true
			s.state.Tasks[id] = t
			_ = s.saveStateLocked()
			s.mu.Unlock()
		}

		for _, line := range logs {
			if line.Seq <= syncedSeq {
				continue
			}
			if err := s.pg.InsertTaskLog(ctx, line); err != nil {
				return err
			}
			s.mu.Lock()
			s.state.SyncedSeq[id] = line.Seq
			_ = s.saveStateLocked()
			s.mu.Unlock()
		}
	}

	s.mu.RLock()
	snaps := make([]models.RollbackSnapshot, 0, len(s.state.Snapshots))
	for _, snap := range s.state.Snapshots {
		if !snap.SyncedToDB {
			snaps = append(snaps, snap)
		}
	}
	skipped := make([]models.SkippedVersion, 0, len(s.state.Skipped))
	for _, sk := range s.state.Skipped {
		skipped = append(skipped, sk)
	}
	alerts := make(map[string]string, len(s.state.Alerts))
	for k, v := range s.state.Alerts {
		alerts[k] = v
	}
	s.mu.RUnlock()

	for _, snap := range snaps {
		if err := s.pg.UpsertSnapshot(ctx, snap); err != nil {
			return err
		}
		s.mu.Lock()
		snap.SyncedToDB = true
		s.state.Snapshots[snap.ServiceName] = snap
		_ = s.saveStateLocked()
		s.mu.Unlock()
	}

	for _, sk := range skipped {
		if err := s.pg.UpsertSkippedVersion(ctx, sk.TargetType, sk.TargetName, sk.SkippedVersion, sk.CreatedBy); err != nil {
			return err
		}
	}

	for fp, at := range alerts {
		if err := s.pg.UpsertSentAlert(ctx, fp, at); err != nil {
			return err
		}
	}

	return nil
}
