package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

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
