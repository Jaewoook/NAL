package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

const (
	maxInMemoryLogsPerTask = 2000
	maxInMemoryLogTasks    = 100
)

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
