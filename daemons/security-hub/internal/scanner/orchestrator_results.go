package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/httputil"
	"github.com/jaewoook/security-hub/internal/models"
)

func (o *Orchestrator) safeAgentHTTPClient() *http.Client {
	return httputil.NoRedirectClient(o.httpClient, 60*time.Second)
}

// ApplySkippedAndSummarize applies skipped version rules (with security overrides for High/Critical CVEs)
// and computes aggregate dashboard counters across items.
func ApplySkippedAndSummarize(items []models.ManagedItem, skipped map[string]string) *models.ScanResult {
	res := &models.ScanResult{
		ScannedAt: time.Now().UTC(),
	}
	for i := range items {
		key := string(items[i].TargetType) + ":" + items[i].Name
		nodeKey := items[i].Node + ":" + key
		skVer, ok := skipped[nodeKey]
		if !ok {
			skVer, ok = skipped[key]
		}
		if ok && skVer != "" && skVer == items[i].LatestVersion {
			if items[i].CritCount > 0 || items[i].HighCount > 0 {
				items[i].SecurityOverride = true
				items[i].Skipped = false
				items[i].SkippedVersion = skVer
				items[i].Outdated = true
			} else {
				items[i].Skipped = true
				items[i].SkippedVersion = skVer
				items[i].Outdated = false
				res.TotalSkipped++
			}
		} else if items[i].Skipped || items[i].SecurityOverride || items[i].SkippedVersion != "" {
			items[i].Skipped = false
			items[i].SkippedVersion = ""
			items[i].SecurityOverride = false
			if !isHeldAptItem(items[i]) {
				if items[i].LatestVersion != "" && items[i].CurrentVersion != "" && items[i].LatestVersion != items[i].CurrentVersion {
					items[i].Outdated = true
				} else if items[i].TargetType == models.TargetDocker && IsFloatingTag(items[i].CurrentVersion) && items[i].CurrentDigest != "" && items[i].RemoteDigest != "" && items[i].CurrentDigest != items[i].RemoteDigest {
					items[i].Outdated = true
				}
			}
		}
		res.TotalCritCVEs += items[i].CritCount
		res.TotalHighCVEs += items[i].HighCount
		if items[i].EoL.Status == models.EoLExpired || items[i].EoL.Status == models.EoLExpiringSoon {
			res.TotalEoLIssues++
		}
		if items[i].Outdated {
			res.TotalOutdated++
		}
		if items[i].BrokenLinkage {
			res.TotalBrokenBrew++
		}
	}
	res.Items = items
	return res
}

// ApplyDockerSnapshots enriches Docker items with rollback metadata from saved snapshots.
func ApplyDockerSnapshots(items []models.ManagedItem, snapshots map[string]models.RollbackSnapshot, hubName string) {
	for i := range items {
		if items[i].TargetType != models.TargetDocker || items[i].HasRollback {
			continue
		}
		if snap, ok := snapshots[items[i].Node+":"+items[i].Name]; ok {
			items[i].HasRollback = true
			items[i].RollbackVersion = snap.PreviousVersion
		} else if snap, ok := snapshots[items[i].Name]; ok && (items[i].Node == "" || strings.EqualFold(items[i].Node, hubName)) {
			items[i].HasRollback = true
			items[i].RollbackVersion = snap.PreviousVersion
		}
	}
}

func (o *Orchestrator) fetchRemoteAgentScan(ctx context.Context, node models.NodeInfo) ([]models.ManagedItem, error) {
	endpoint := strings.TrimRight(node.URL, "/") + "/api/agent/scan"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, err
	}
	tok := node.Token
	if tok == "" && o.cfg != nil {
		tok = o.cfg.AgentToken
	}
	if tok != "" {
		req.Header.Set("X-NAL-Node-Token", tok)
	}
	resp, err := o.safeAgentHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent %s returned HTTP %d", node.Name, resp.StatusCode)
	}
	var payload struct {
		Node  string               `json:"node"`
		Items []models.ManagedItem `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Items {
		payload.Items[i].Node = node.Name
		u := strings.TrimSpace(payload.Items[i].ReleaseNotesURL)
		lower := strings.ToLower(u)
		if u != "" && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
			payload.Items[i].ReleaseNotesURL = ""
		}
	}
	return payload.Items, nil
}

func (o *Orchestrator) finalizeScanResult(ctx context.Context, lockID, taskID, hubName string, allItems []models.ManagedItem, nodesList []models.NodeInfo) (*models.ScanResult, error) {
	o.logTask(ctx, taskID, "info", "Analyzing CVEs against vulnerability feeds...")

	skipped := make(map[string]string)
	snapshots := make(map[string]models.RollbackSnapshot)
	if o.store != nil {
		skipped, _ = o.store.ListSkippedVersions(ctx)
		snapshots, _ = o.store.ListSnapshots(ctx)
	}
	ApplyDockerSnapshots(allItems, snapshots, hubName)

	res := ApplySkippedAndSummarize(allItems, skipped)
	res.Nodes = nodesList

	totalCVEs := 0
	for _, it := range res.Items {
		totalCVEs += len(it.Vulnerabilities)
	}

	if ctx.Err() != nil {
		o.failScanTask(lockID, taskID, "error", fmt.Sprintf("Scan aborted: %v", ctx.Err()), ctx.Err().Error())
		return nil, ctx.Err()
	}

	if o.store != nil {
		_ = o.store.SaveScanResult(ctx, res)
		if taskID != "" {
			o.logTask(ctx, taskID, "info", fmt.Sprintf("Scan complete: %d items scanned, %d CVEs found.", len(res.Items), totalCVEs))
			o.FinishScanTask(lockID)
			_ = o.store.FinishTask(ctx, taskID, "succeeded", "")
			return res, nil
		}
	}

	o.FinishScanTask(lockID)
	return res, nil
}
