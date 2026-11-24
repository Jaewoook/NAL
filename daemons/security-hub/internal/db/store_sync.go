package db

import (
	"context"
	"sort"

	"github.com/jaewoook/security-hub/internal/models"
)

func (s *SpoolStore) syncNodeToPGLocked(ctx context.Context, name string) {
	if s.pg == nil {
		return
	}
	s.pgMu.Lock()
	defer s.pgMu.Unlock()
	var cur models.NodeInfo
	var exists bool
	_ = s.withStateLock(func() error {
		cur, exists = s.state.Nodes[name]
		return nil
	})
	if exists {
		_ = s.pg.UpsertNode(ctx, cur)
	}
}

func (s *SpoolStore) FlushPending(ctx context.Context) error {
	if s.pg == nil {
		return nil
	}
	s.pgMu.Lock()
	defer s.pgMu.Unlock()

	if err := s.flushTasksLocked(ctx); err != nil {
		return err
	}
	if err := s.flushSnapshotsLocked(ctx); err != nil {
		return err
	}
	return s.flushRegistryAndAlertsLocked(ctx)
}

func (s *SpoolStore) flushTasksLocked(ctx context.Context) error {
	var taskIDs []string
	if err := s.withStateLock(func() error {
		taskIDs = make([]string, 0, len(s.state.Tasks))
		for id := range s.state.Tasks {
			taskIDs = append(taskIDs, id)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(taskIDs, func(i, j int) bool {
		return !compareTaskIDDesc(taskIDs[i], taskIDs[j])
	})

	for _, id := range taskIDs {
		for pass := 0; pass < 2; pass++ {
			var t models.Task
			var exists bool
			if err := s.withStateLock(func() error {
				t, exists = s.state.Tasks[id]
				return nil
			}); err != nil {
				return err
			}
			if !exists || t.SyncedToDB {
				break
			}
			if err := s.pg.UpsertTask(ctx, t); err != nil {
				return err
			}
			var done bool
			if err := s.withStateLock(func() error {
				cur, stillExists := s.state.Tasks[id]
				if !stillExists {
					done = true
					return nil
				}
				if cur.Status == t.Status && cur.FinishedAt.Equal(t.FinishedAt) {
					cur.SyncedToDB = true
					s.state.Tasks[id] = cur
					_ = s.saveStateLocked()
					done = true
					return nil
				}
				// Task changed concurrently during UpsertTask; retry syncing latest state once unless already synced
				done = cur.SyncedToDB && cur.Status == t.Status
				return nil
			}); err != nil {
				return err
			}
			if done {
				break
			}
		}

		var logs []models.TaskLogLine
		var syncedSeq int
		if err := s.withStateLock(func() error {
			logs = append([]models.TaskLogLine(nil), s.state.Logs[id]...)
			syncedSeq = s.state.SyncedSeq[id]
			return nil
		}); err != nil {
			return err
		}

		var pendingLogs []models.TaskLogLine
		for _, line := range logs {
			if line.Seq > syncedSeq {
				pendingLogs = append(pendingLogs, line)
			}
		}
		if len(pendingLogs) > 0 {
			const batchSize = 200
			for i := 0; i < len(pendingLogs); i += batchSize {
				end := i + batchSize
				if end > len(pendingLogs) {
					end = len(pendingLogs)
				}
				chunk := pendingLogs[i:end]
				if err := s.pg.InsertTaskLogsBatch(ctx, chunk); err != nil {
					return err
				}
				if err := s.withStateLock(func() error {
					if last := chunk[len(chunk)-1].Seq; last > s.state.SyncedSeq[id] {
						s.state.SyncedSeq[id] = last
						_ = s.saveStateLocked()
					}
					return nil
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *SpoolStore) flushSnapshotsLocked(ctx context.Context) error {
	var snaps []models.RollbackSnapshot
	if err := s.withStateLock(func() error {
		snaps = make([]models.RollbackSnapshot, 0, len(s.state.Snapshots))
		for _, snap := range s.state.Snapshots {
			if !snap.SyncedToDB {
				snaps = append(snaps, snap)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	for _, snap := range snaps {
		if err := s.pg.UpsertSnapshot(ctx, snap); err != nil {
			return err
		}
		if err := s.withStateLock(func() error {
			if cur, exists := s.state.Snapshots[snap.ServiceName]; exists && cur.ID == snap.ID {
				cur.SyncedToDB = true
				s.state.Snapshots[snap.ServiceName] = cur
				_ = s.saveStateLocked()
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *SpoolStore) flushTombstone(isReAdded func() bool, clearTombstone func(), deleteRemote func() error) error {
	var reAdded bool
	if err := s.withStateLock(func() error {
		if isReAdded() {
			clearTombstone()
			_ = s.saveStateLocked()
			reAdded = true
		}
		return nil
	}); err != nil {
		return err
	}
	if reAdded {
		return nil
	}
	if err := deleteRemote(); err != nil {
		return err
	}
	return s.withStateLock(func() error {
		if !isReAdded() {
			clearTombstone()
			_ = s.saveStateLocked()
		}
		return nil
	})
}

func (s *SpoolStore) flushRegistryAndAlertsLocked(ctx context.Context) error {
	var skipped []models.SkippedVersion
	var delSkipped map[string]deletedSkippedKey
	var alerts map[string]string
	var nodes []models.NodeInfo
	var delNodes []string

	if err := s.withStateLock(func() error {
		skipped = make([]models.SkippedVersion, 0, len(s.state.Skipped))
		for _, sk := range s.state.Skipped {
			skipped = append(skipped, sk)
		}
		delSkipped = make(map[string]deletedSkippedKey, len(s.state.DeletedSkipped))
		for k, v := range s.state.DeletedSkipped {
			delSkipped[k] = v
		}
		alerts = make(map[string]string, len(s.state.Alerts))
		for k, v := range s.state.Alerts {
			alerts[k] = v
		}
		nodes = make([]models.NodeInfo, 0, len(s.state.Nodes))
		for _, n := range s.state.Nodes {
			nodes = append(nodes, n)
		}
		delNodes = make([]string, 0, len(s.state.DeletedNodes))
		for k := range s.state.DeletedNodes {
			delNodes = append(delNodes, k)
		}
		return nil
	}); err != nil {
		return err
	}

	for _, sk := range skipped {
		if err := s.pg.UpsertSkippedVersion(ctx, sk.TargetType, sk.TargetName, sk.SkippedVersion, sk.CreatedBy); err != nil {
			return err
		}
	}
	for k, ds := range delSkipped {
		if err := s.flushTombstone(
			func() bool { _, ok := s.state.Skipped[k]; return ok },
			func() { delete(s.state.DeletedSkipped, k) },
			func() error { return s.pg.DeleteSkippedVersion(ctx, ds.TargetType, ds.TargetName) },
		); err != nil {
			return err
		}
	}

	for fp, at := range alerts {
		if err := s.pg.UpsertSentAlert(ctx, fp, at); err != nil {
			return err
		}
	}

	for _, n := range nodes {
		// Re-read latest node state inside pgMu in case operator updated or removed it
		var cur models.NodeInfo
		var exists bool
		if err := s.withStateLock(func() error {
			cur, exists = s.state.Nodes[n.Name]
			return nil
		}); err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := s.pg.UpsertNode(ctx, cur); err != nil {
			return err
		}
	}
	for _, name := range delNodes {
		if err := s.flushTombstone(
			func() bool { _, ok := s.state.Nodes[name]; return ok },
			func() { delete(s.state.DeletedNodes, name) },
			func() error { return s.pg.DeleteNode(ctx, name) },
		); err != nil {
			return err
		}
	}

	return nil
}
