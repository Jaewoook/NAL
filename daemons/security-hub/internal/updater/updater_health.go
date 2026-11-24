package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func isHexContainerID(s string) bool {
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	return true
}

func (m *Manager) resolveComposeContainer(ctx context.Context, composeDir, serviceKey string) string {
	if composeDir == "" || serviceKey == "" {
		return ""
	}
	out, err := m.runner.Run(ctx, "docker", "compose", "--project-directory", composeDir, "ps", "-a", "-q", serviceKey)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		cand := strings.TrimSpace(line)
		if isHexContainerID(cand) {
			return cand
		}
	}
	return ""
}

func extractRepoDigest(dOut []byte) string {
	var digests []string
	if json.Unmarshal(dOut, &digests) == nil && len(digests) > 0 {
		if idx := strings.Index(digests[0], "sha256:"); idx >= 0 {
			return digests[0][idx:]
		}
	}
	return ""
}

func (m *Manager) inspectDigest(ctx context.Context, composeDir, serviceKey, containerName, imageRef string) string {
	var imgID string
	if containerName != "" {
		if out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .Image}}", containerName); err == nil {
			imgID = strings.Trim(strings.TrimSpace(string(out)), `"`)
		}
	}
	if imgID == "" && composeDir != "" && serviceKey != "" {
		if cid := m.resolveComposeContainer(ctx, composeDir, serviceKey); cid != "" {
			if out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .Image}}", cid); err == nil {
				imgID = strings.Trim(strings.TrimSpace(string(out)), `"`)
			}
		}
	}
	if imgID != "" {
		if dOut, err := m.runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imgID); err == nil {
			if dig := extractRepoDigest(dOut); dig != "" {
				return dig
			}
		}
	}
	if imageRef != "" {
		if dOut, err := m.runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imageRef); err == nil {
			if dig := extractRepoDigest(dOut); dig != "" {
				return dig
			}
		}
	}
	return ""
}

func (m *Manager) verifyContainerHealthy(ctx context.Context, composeDir, serviceKey, containerName, svcName string) error {
	timeoutSec := 60
	if m.cfg != nil && m.cfg.Updater.DeadManTimeoutSeconds > 0 {
		timeoutSec = m.cfg.Updater.DeadManTimeoutSeconds
	}
	poll := m.pollInterval
	if poll <= 0 {
		poll = 2 * time.Second
	}
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	for {
		targetContainer := containerName
		out, err := m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .State}}", targetContainer)
		if err != nil && composeDir != "" && serviceKey != "" {
			if cid := m.resolveComposeContainer(ctx, composeDir, serviceKey); cid != "" {
				targetContainer = cid
				out, err = m.runner.Run(ctx, "docker", "inspect", "--format", "{{json .State}}", targetContainer)
			}
		}
		if err != nil {
			if time.Now().After(deadline) {
				return fmt.Errorf("failed to inspect container %s: %w", targetContainer, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(poll):
			}
			continue
		}
		raw := strings.TrimSpace(string(out))

		var stateObj struct {
			Status       string `json:"Status"`
			Restarting   bool   `json:"Restarting"`
			HealthStatus string `json:"HealthStatus"`
			Health       *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		}
		if strings.HasPrefix(raw, "{") && json.Unmarshal([]byte(raw), &stateObj) == nil {
			if stateObj.Status == "created" {
				// Container is still initializing; continue polling until deadline
			} else if stateObj.Restarting || (stateObj.Status != "running" && stateObj.Status != "ok") {
				return fmt.Errorf("container %s state is %q (restarting=%v)", targetContainer, stateObj.Status, stateObj.Restarting)
			} else {
				health := stateObj.HealthStatus
				if health == "" && stateObj.Health != nil {
					health = stateObj.Health.Status
				}
				switch health {
				case "unhealthy":
					return fmt.Errorf("container %s healthcheck reported unhealthy", targetContainer)
				case "starting":
					// Container is still initializing its healthcheck; continue polling until deadline
				case "", "healthy":
					return nil
				}
			}
		} else {
			if raw == "created" {
				// Container is still initializing; continue polling until deadline
			} else if raw != "running" && raw != "ok" {
				return fmt.Errorf("container %s state is %q (expected running)", targetContainer, raw)
			} else {
				return nil
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("container %s did not become healthy within %ds", targetContainer, timeoutSec)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}
