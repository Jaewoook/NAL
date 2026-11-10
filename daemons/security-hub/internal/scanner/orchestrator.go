package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

type Orchestrator struct {
	cfg           *config.Config
	store         db.Store
	httpClient    *http.Client
	dockerScanner *DockerScanner
	brewScanner   *BrewScanner
	daemonScanner *DaemonScanner
	vulnScanner   *VulnScanner
	eolChecker    *EoLChecker

	scanMu       sync.Mutex
	activeTaskID string
}

func NewOrchestrator(cfg *config.Config, store db.Store, runner CommandRunner, httpClient *http.Client) *Orchestrator {
	if runner == nil {
		runner = NewOSCommandRunner()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	reg := NewRegistryClient(httpClient)
	return &Orchestrator{
		cfg:           cfg,
		store:         store,
		httpClient:    httpClient,
		dockerScanner: NewDockerScanner(cfg.Scanner.ServicesDir, cfg.Updater.CriticalServices, cfg.Updater.StatefulVolumes, runner, reg),
		brewScanner:   NewBrewScanner(runner),
		daemonScanner: NewDaemonScannerWithHTTP(cfg.Scanner.DaemonsDir, runner, httpClient),
		vulnScanner:   NewVulnScanner(cfg.Scanner.OSVAPIURL, httpClient, runner),
		eolChecker:    NewEoLChecker(cfg.Scanner.EoLAPIURL, httpClient),
	}
}

// IsScanning reports whether a scan is currently running and returns the active task ID if so.
func (o *Orchestrator) IsScanning() (bool, string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	return o.activeTaskID != "", o.activeTaskID
}

// StartScan attempts to acquire the scan mutex for taskID.
// If another scan is already running, it returns false and the active task ID.
// If acquired, it records the active task ID (defaulting to a timestamped string if empty)
// and returns true, "".
func (o *Orchestrator) StartScan(taskID string) (bool, string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID != "" {
		return false, o.activeTaskID
	}
	if taskID == "" {
		taskID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
	}
	o.activeTaskID = taskID
	return true, ""
}

// FinishScan releases the active scan lock.
func (o *Orchestrator) FinishScan() {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	o.activeTaskID = ""
}

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

func (o *Orchestrator) ScanLocalNode(ctx context.Context) ([]models.ManagedItem, error) {
	nodeName := o.cfg.NodeName
	if nodeName == "" {
		nodeName = config.DefaultNodeName()
	}
	var localItems []models.ManagedItem
	if o.dockerScanner != nil {
		if dockerItems, err := o.dockerScanner.ScanDockerServices(ctx); err == nil {
			localItems = append(localItems, dockerItems...)
		}
	}
	if o.brewScanner != nil {
		if brewItems, err := o.brewScanner.ScanBrew(ctx); err == nil {
			localItems = append(localItems, brewItems...)
		}
	}
	if o.daemonScanner != nil {
		if daemonItems, err := o.daemonScanner.ScanDaemonsAndOS(ctx); err == nil {
			localItems = append(localItems, daemonItems...)
		}
	}

	if o.vulnScanner != nil {
		_ = o.vulnScanner.CheckVulnerabilities(ctx, localItems)
	}
	if o.eolChecker != nil && o.cfg != nil {
		_ = o.eolChecker.CheckEoL(ctx, localItems, time.Now().UTC(), o.cfg.Scanner.EoLWarningDays)
	}

	for i := range localItems {
		localItems[i].Node = nodeName
	}
	return localItems, nil
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
	resp, err := o.httpClient.Do(req)
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
	}
	return payload.Items, nil
}

func (o *Orchestrator) RunFullScan(ctx context.Context) (*models.ScanResult, error) {
	return o.RunFullScanWithTask(ctx, "")
}

func (o *Orchestrator) RunFullScanWithTask(ctx context.Context, taskID string) (*models.ScanResult, error) {
	if ctx.Err() != nil {
		if o.store != nil && taskID != "" {
			abortCtx, abortCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer abortCancel()
			_, _ = o.store.AppendTaskLog(abortCtx, taskID, "error", fmt.Sprintf("Scan aborted: %v", ctx.Err()))
			_ = o.store.FinishTask(abortCtx, taskID, "failed", ctx.Err().Error())
		}
		return nil, ctx.Err()
	}

	hubName := ""
	if o.cfg != nil {
		hubName = o.cfg.NodeName
	}
	if hubName == "" {
		hubName = config.DefaultNodeName()
	}
	if taskID == "" && o.store != nil {
		if t, err := o.store.CreateTask(ctx, &models.Task{
			Node:        hubName,
			TaskType:    "security_scan",
			TargetType:  "system",
			TargetName:  "all",
			TriggeredBy: "scanner",
			Status:      "running",
		}); err == nil {
			taskID = t.ID
			o.scanMu.Lock()
			if strings.HasPrefix(o.activeTaskID, "scan_") {
				o.activeTaskID = taskID
			}
			o.scanMu.Unlock()
		}
	}

	if taskID != "" && o.store != nil {
		_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("Starting full scan on Hub (%s)...", hubName))
	}

	localItems, _ := o.ScanLocalNode(ctx)
	allItems := append([]models.ManagedItem(nil), localItems...)
	if taskID != "" && o.store != nil {
		_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("[Hub] Scanned %d local components...", len(localItems)))
	}

	nodesList := []models.NodeInfo{
		{
			Name:       hubName,
			Role:       "hub",
			Status:     models.NodeStatusApproved,
			Online:     true,
			LastSeenAt: time.Now().UTC(),
		},
	}

	if o.store != nil {
		prevScan, _ := o.store.LoadLatestScanResult(ctx)
		remoteNodes, _ := o.store.ListNodes(ctx)

		var approvedRemoteNodes []models.NodeInfo
		for _, rn := range remoteNodes {
			if rn.Name == hubName || rn.Status != models.NodeStatusApproved {
				continue
			}
			approvedRemoteNodes = append(approvedRemoteNodes, rn)
		}

		type nodeScanResult struct {
			node  models.NodeInfo
			items []models.ManagedItem
			err   error
		}
		var wg sync.WaitGroup
		results := make([]nodeScanResult, len(approvedRemoteNodes))

		for i, rn := range approvedRemoteNodes {
			if taskID != "" && o.store != nil {
				_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("[%s] Querying remote agent (%s)...", rn.Name, rn.URL))
			}
			wg.Add(1)
			go func(idx int, node models.NodeInfo) {
				defer wg.Done()
				scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				items, err := o.fetchRemoteAgentScan(scanCtx, node)
				results[idx] = nodeScanResult{node: node, items: items, err: err}
			}(i, rn)
		}
		wg.Wait()

		for _, res := range results {
			rn := res.node
			if rn.Name == "" || rn.Name == hubName {
				continue
			}
			if res.err != nil {
				rn.Online = false
				rn.LastError = res.err.Error()
				_ = o.store.UpsertNode(ctx, rn)
				if taskID != "" {
					_, _ = o.store.AppendTaskLog(ctx, taskID, "stderr", fmt.Sprintf("[%s] Remote agent unreachable (%v) — retaining cached items if available", rn.Name, res.err))
				}
				if prevScan != nil {
					for _, prevItem := range prevScan.Items {
						if prevItem.Node == rn.Name {
							allItems = append(allItems, prevItem)
						}
					}
				}
			} else {
				rn.Online = true
				rn.LastSeenAt = time.Now().UTC()
				rn.LastError = ""
				_ = o.store.UpsertNode(ctx, rn)
				allItems = append(allItems, res.items...)
				if taskID != "" {
					_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("[%s] Scanned %d remote components...", rn.Name, len(res.items)))
				}
			}
			rnCopy := rn
			rnCopy.Token = ""
			nodesList = append(nodesList, rnCopy)
		}
	}

	if taskID != "" && o.store != nil {
		_, _ = o.store.AppendTaskLog(ctx, taskID, "info", "Analyzing CVEs against vulnerability feeds...")
	}

	skipped := make(map[string]string)
	snapshots := make(map[string]models.RollbackSnapshot)
	if o.store != nil {
		skipped, _ = o.store.ListSkippedVersions(ctx)
		snapshots, _ = o.store.ListSnapshots(ctx)
	}

	for i := range allItems {
		if snap, ok := snapshots[allItems[i].Node+":"+allItems[i].Name]; ok {
			allItems[i].HasRollback = true
			allItems[i].RollbackVersion = snap.PreviousVersion
		} else if snap, ok := snapshots[allItems[i].Name]; ok && (allItems[i].Node == "" || allItems[i].Node == hubName) {
			allItems[i].HasRollback = true
			allItems[i].RollbackVersion = snap.PreviousVersion
		}
	}

	res := ApplySkippedAndSummarize(allItems, skipped)
	res.Nodes = nodesList

	totalCVEs := 0
	for _, it := range res.Items {
		totalCVEs += len(it.Vulnerabilities)
	}

	if ctx.Err() != nil {
		if o.store != nil && taskID != "" {
			abortCtx, abortCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer abortCancel()
			_, _ = o.store.AppendTaskLog(abortCtx, taskID, "error", fmt.Sprintf("Scan aborted: %v", ctx.Err()))
			_ = o.store.FinishTask(abortCtx, taskID, "failed", ctx.Err().Error())
		}
		return nil, ctx.Err()
	}

	if o.store != nil {
		_ = o.store.SaveScanResult(ctx, res)
		if taskID != "" {
			_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("Scan complete: %d items scanned, %d CVEs found.", len(res.Items), totalCVEs))
			_ = o.store.FinishTask(ctx, taskID, "succeeded", "")
		}
	}

	return res, nil
}
