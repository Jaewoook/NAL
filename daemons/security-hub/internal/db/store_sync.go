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
	if lockErr := s.lockState(); lockErr == nil {
		cur, exists = s.state.Nodes[name]
		s.unlockState()
	}
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
	return nil
}

func (s *SpoolStore) flushSnapshotsLocked(ctx context.Context) error {
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
	return nil
}

func (s *SpoolStore) flushRegistryAndAlertsLocked(ctx context.Context) error {
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
