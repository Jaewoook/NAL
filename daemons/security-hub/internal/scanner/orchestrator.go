package scanner

import (
	"context"
	"encoding/json"
	"errors"
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
	aptScanner    *AptScanner
	daemonScanner *DaemonScanner
	vulnScanner   *VulnScanner
	eolChecker    *EoLChecker

	startMu       sync.Mutex
	scanMu        sync.Mutex
	activeTaskID  string
	scanningNodes []string
}

var (
	ErrScanNodeNotFound    = errors.New("node not found")
	ErrScanNodeNotApproved = errors.New("node is not approved")
	ErrScanInProgress      = errors.New("scan already running")
)

func NewOrchestrator(cfg *config.Config, store db.Store, runner CommandRunner, httpClient *http.Client) *Orchestrator {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	if runner == nil {
		runner = NewOSCommandRunner()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	reg := NewRegistryClient(httpClient)
	return &Orchestrator{
		cfg:           cfg,
		store:         store,
		httpClient:    httpClient,
		dockerScanner: NewDockerScanner(cfg.Scanner.ServicesDir, cfg.Updater.CriticalServices, cfg.Updater.StatefulVolumes, runner, reg),
		brewScanner:   NewBrewScanner(runner),
		aptScanner:    NewAptScanner(runner),
		daemonScanner: NewDaemonScannerWithHTTP(cfg.Scanner.DaemonsDir, runner, httpClient),
		vulnScanner:   NewVulnScanner(cfg.Scanner.OSVAPIURL, httpClient, runner),
		eolChecker:    NewEoLChecker(cfg.Scanner.EoLAPIURL, httpClient),
	}
}

func (o *Orchestrator) safeAgentHTTPClient() *http.Client {
	var c http.Client
	if o.httpClient != nil {
		c = *o.httpClient
	}
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

func (o *Orchestrator) hubNodeName() string {
	if o.cfg != nil && o.cfg.NodeName != "" {
		return o.cfg.NodeName
	}
	return config.DefaultNodeName()
}

func (o *Orchestrator) logTask(ctx context.Context, taskID, stream, msg string) {
	if taskID == "" || o.store == nil {
		return
	}
	_, _ = o.store.AppendTaskLog(ctx, taskID, stream, msg)
}

func (o *Orchestrator) failScanTask(lockID, taskID, logStream, logMsg, taskErr string) {
	o.FinishScanTask(lockID)
	if o.store != nil && taskID != "" {
		abortCtx, abortCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer abortCancel()
		if logMsg != "" {
			_, _ = o.store.AppendTaskLog(abortCtx, taskID, logStream, logMsg)
		}
		_ = o.store.FinishTask(abortCtx, taskID, "failed", taskErr)
	}
}

func (o *Orchestrator) newHubNodeInfo(hubName string) models.NodeInfo {
	return models.NodeInfo{
		Name:       hubName,
		Role:       "hub",
		Status:     models.NodeStatusApproved,
		Online:     true,
		LastSeenAt: time.Now().UTC(),
	}
}

// IsScanning reports whether a scan is currently running and returns the active task ID if so.
func (o *Orchestrator) IsScanning() (bool, string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	return o.activeTaskID != "", o.activeTaskID
}

// StartScan attempts to acquire the scan mutex for taskID.
func (o *Orchestrator) StartScan(taskID string) (bool, string) {
	return o.StartScanWithNodes(taskID, nil)
}

func dedupScanNodes(nodes []string) []string {
	if len(nodes) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(nodes))
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		key := strings.ToLower(n)
		if !seen[key] {
			seen[key] = true
			out = append(out, n)
		}
	}
	return out
}

// StartScanWithNodes attempts to acquire the scan mutex for taskID and records initial scanning nodes.
func (o *Orchestrator) StartScanWithNodes(taskID string, nodes []string) (bool, string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID != "" {
		return false, o.activeTaskID
	}
	if taskID == "" {
		taskID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
	}
	o.activeTaskID = taskID
	o.scanningNodes = dedupScanNodes(nodes)
	return true, ""
}

// FinishScan releases the active scan lock and resets scanning nodes.
func (o *Orchestrator) FinishScan() {
	o.FinishScanTask("")
}

// FinishScanTask releases the active scan lock only if it belongs to taskID (or taskID is empty).
func (o *Orchestrator) FinishScanTask(taskID string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if taskID == "" || o.activeTaskID == taskID {
		o.activeTaskID = ""
		o.scanningNodes = nil
	}
}

// LockScanStart serializes scan-start critical sections (state check, task creation, and lock acquisition).
func (o *Orchestrator) LockScanStart() {
	o.startMu.Lock()
}

// UnlockScanStart releases the scan-start critical section mutex.
func (o *Orchestrator) UnlockScanStart() {
	o.startMu.Unlock()
}

func (o *Orchestrator) claimOrVerifyScanLock(taskID string) (string, error) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID == "" {
		if taskID != "" {
			o.activeTaskID = taskID
		} else {
			o.activeTaskID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
		}
		return o.activeTaskID, nil
	}
	if taskID != "" && o.activeTaskID == taskID {
		return taskID, nil
	}
	return "", fmt.Errorf("%w (task %s)", ErrScanInProgress, o.activeTaskID)
}

func (o *Orchestrator) upgradeScanTaskID(oldID, newID string) string {
	if newID == "" {
		return oldID
	}
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID == oldID {
		o.activeTaskID = newID
		return newID
	}
	return oldID
}

// ScanningNodes returns a copy of node names currently performing a scan.
func (o *Orchestrator) ScanningNodes() []string {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if len(o.scanningNodes) == 0 {
		return []string{}
	}
	return append([]string(nil), o.scanningNodes...)
}

// GetScanState reports whether a scan is currently running, the active task ID, and scanning nodes.
func (o *Orchestrator) GetScanState() (bool, string, []string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if o.activeTaskID == "" {
		return false, "", []string{}
	}
	if len(o.scanningNodes) == 0 {
		return true, o.activeTaskID, []string{}
	}
	nodes := append([]string(nil), o.scanningNodes...)
	return true, o.activeTaskID, nodes
}

func (o *Orchestrator) setScanningNodes(nodes []string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	o.scanningNodes = dedupScanNodes(nodes)
}

func (o *Orchestrator) removeScanningNodeIfMultiple(nodeName string) {
	o.scanMu.Lock()
	defer o.scanMu.Unlock()
	if len(o.scanningNodes) <= 1 {
		return
	}
	filtered := make([]string, 0, len(o.scanningNodes))
	for _, n := range o.scanningNodes {
		if !strings.EqualFold(n, nodeName) {
			filtered = append(filtered, n)
		}
	}
	if len(filtered) >= 1 {
		o.scanningNodes = filtered
	}
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
		} else if items[i].Skipped || items[i].SecurityOverride || items[i].SkippedVersion != "" {
			items[i].Skipped = false
			items[i].SkippedVersion = ""
			items[i].SecurityOverride = false
			isHeldApt := items[i].TargetType == models.TargetApt && strings.Contains(items[i].EoL.Message, "Held via apt-mark")
			if !isHeldApt {
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

func (o *Orchestrator) ScanLocalNode(ctx context.Context) ([]models.ManagedItem, error) {
	nodeName := o.hubNodeName()

	var localItems []models.ManagedItem
	var scanErrs []error

	if o.dockerScanner != nil {
		if dockerItems, err := o.dockerScanner.ScanDockerServices(ctx); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("docker scanner: %w", err))
		} else {
			localItems = append(localItems, dockerItems...)
		}
	}
	if o.brewScanner != nil {
		if brewItems, err := o.brewScanner.ScanBrew(ctx); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("brew scanner: %w", err))
		} else {
			localItems = append(localItems, brewItems...)
		}
	}
	if o.aptScanner != nil {
		if aptItems, err := o.aptScanner.ScanApt(ctx); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("apt scanner: %w", err))
		} else {
			localItems = append(localItems, aptItems...)
		}
	}
	if o.daemonScanner != nil {
		if daemonItems, err := o.daemonScanner.ScanDaemonsAndOS(ctx); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("daemon scanner: %w", err))
		} else {
			localItems = append(localItems, daemonItems...)
		}
	}

	if o.vulnScanner != nil {
		if err := o.vulnScanner.CheckVulnerabilities(ctx, localItems); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("vuln scanner: %w", err))
		}
	}
	if o.eolChecker != nil {
		warningDays := 30
		if o.cfg != nil && o.cfg.Scanner.EoLWarningDays > 0 {
			warningDays = o.cfg.Scanner.EoLWarningDays
		}
		if err := o.eolChecker.CheckEoL(ctx, localItems, time.Now().UTC(), warningDays); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("eol checker: %w", err))
		}
	}

	for i := range localItems {
		localItems[i].Node = nodeName
	}
	return localItems, errors.Join(scanErrs...)
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

func (o *Orchestrator) RunFullScan(ctx context.Context) (*models.ScanResult, error) {
	return o.RunFullScanWithTask(ctx, "")
}

func applyDockerSnapshots(items []models.ManagedItem, snapshots map[string]models.RollbackSnapshot, hubName string) {
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

func (o *Orchestrator) finalizeScanResult(ctx context.Context, lockID, taskID, hubName string, allItems []models.ManagedItem, nodesList []models.NodeInfo) (*models.ScanResult, error) {
	o.logTask(ctx, taskID, "info", "Analyzing CVEs against vulnerability feeds...")

	skipped := make(map[string]string)
	snapshots := make(map[string]models.RollbackSnapshot)
	if o.store != nil {
		skipped, _ = o.store.ListSkippedVersions(ctx)
		snapshots, _ = o.store.ListSnapshots(ctx)
	}
	applyDockerSnapshots(allItems, snapshots, hubName)

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

func (o *Orchestrator) RunFullScanWithTask(ctx context.Context, taskID string) (*models.ScanResult, error) {
	lockID, err := o.claimOrVerifyScanLock(taskID)
	if err != nil {
		return nil, err
	}
	defer func() {
		o.FinishScanTask(lockID)
	}()
	if ctx.Err() != nil {
		o.failScanTask(lockID, taskID, "error", fmt.Sprintf("Scan aborted: %v", ctx.Err()), ctx.Err().Error())
		return nil, ctx.Err()
	}

	hubName := o.hubNodeName()
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
			lockID = o.upgradeScanTaskID(lockID, taskID)
		}
	}

	if len(o.ScanningNodes()) == 0 {
		initial := []string{hubName}
		if o.store != nil {
			if remoteNodes, _ := o.store.ListNodes(ctx); len(remoteNodes) > 0 {
				for _, rn := range remoteNodes {
					if !strings.EqualFold(rn.Name, hubName) && (rn.Status == "" || rn.Status == models.NodeStatusApproved) {
						initial = append(initial, rn.Name)
					}
				}
			}
		}
		o.setScanningNodes(initial)
	}

	o.logTask(ctx, taskID, "info", fmt.Sprintf("Starting full scan on Hub (%s)...", hubName))

	localItems, localErr := o.ScanLocalNode(ctx)
	if localErr != nil {
		o.logTask(ctx, taskID, "warn", fmt.Sprintf("[Hub] Partial local scan warning: %v", localErr))
	}
	allItems := append([]models.ManagedItem(nil), localItems...)
	o.logTask(ctx, taskID, "info", fmt.Sprintf("[Hub] Scanned %d local components...", len(localItems)))

	nodesList := []models.NodeInfo{o.newHubNodeInfo(hubName)}

	if o.store != nil {
		prevScan, _ := o.store.LoadLatestScanResult(ctx)
		remoteNodes, _ := o.store.ListNodes(ctx)

		var approvedRemoteNodes []models.NodeInfo
		remoteNames := make([]string, 0, len(remoteNodes))
		for _, rn := range remoteNodes {
			if strings.EqualFold(rn.Name, hubName) || (rn.Status != "" && rn.Status != models.NodeStatusApproved) {
				continue
			}
			approvedRemoteNodes = append(approvedRemoteNodes, rn)
			remoteNames = append(remoteNames, rn.Name)
		}
		if len(remoteNames) > 0 {
			o.setScanningNodes(remoteNames)
		}

		type nodeScanResult struct {
			node  models.NodeInfo
			items []models.ManagedItem
			err   error
		}
		var wg sync.WaitGroup
		results := make([]nodeScanResult, len(approvedRemoteNodes))

		for i, rn := range approvedRemoteNodes {
			o.logTask(ctx, taskID, "info", fmt.Sprintf("[%s] Querying remote agent (%s)...", rn.Name, rn.URL))
			wg.Add(1)
			go func(idx int, node models.NodeInfo) {
				defer wg.Done()
				scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				items, err := o.fetchRemoteAgentScan(scanCtx, node)
				results[idx] = nodeScanResult{node: node, items: items, err: err}
				if err != nil {
					logCtx, logCancel := context.WithTimeout(ctx, 3*time.Second)
					o.logTask(logCtx, taskID, "stderr", fmt.Sprintf("[%s] Remote agent unreachable (%v) — retaining cached items if available", node.Name, err))
					logCancel()
				} else {
					o.logTask(ctx, taskID, "info", fmt.Sprintf("[%s] Scanned %d remote components...", node.Name, len(items)))
				}
				o.removeScanningNodeIfMultiple(node.Name)
			}(i, rn)
		}
		wg.Wait()

		for _, res := range results {
			rn := res.node
			if rn.Name == "" || strings.EqualFold(rn.Name, hubName) {
				continue
			}
			if res.err != nil {
				if ctx.Err() == nil {
					_ = o.store.UpdateNodeHealth(ctx, rn.Name, false, time.Time{}, res.err.Error())
				}
				if latest, getErr := o.store.GetNode(ctx, rn.Name); getErr == nil {
					if prevScan != nil {
						for _, prevItem := range prevScan.Items {
							if strings.EqualFold(prevItem.Node, rn.Name) {
								prevItem.Node = latest.Name
								allItems = append(allItems, prevItem)
							}
						}
					}
					rnCopy := *latest
					rnCopy.Token = ""
					nodesList = append(nodesList, rnCopy)
				}
			} else {
				_ = o.store.UpdateNodeHealth(ctx, rn.Name, true, time.Now().UTC(), "")
				if latest, getErr := o.store.GetNode(ctx, rn.Name); getErr == nil {
					allItems = append(allItems, res.items...)
					rnCopy := *latest
					rnCopy.Token = ""
					nodesList = append(nodesList, rnCopy)
				}
			}
		}
	}

	return o.finalizeScanResult(ctx, lockID, taskID, hubName, allItems, nodesList)
}

// ResolveTargetNode finds and validates an approved compute node (Hub or Agent) by name.
func (o *Orchestrator) ResolveTargetNode(ctx context.Context, requested string) (models.NodeInfo, error) {
	hubName := o.hubNodeName()
	target := strings.TrimSpace(requested)
	if target == "" || strings.EqualFold(target, hubName) {
		return o.newHubNodeInfo(hubName), nil
	}
	if o.store == nil {
		return models.NodeInfo{}, ErrScanNodeNotFound
	}
	nodes, err := o.store.ListNodes(ctx)
	if err != nil {
		return models.NodeInfo{}, err
	}
	for _, n := range nodes {
		if strings.EqualFold(n.Name, target) {
			if n.Status != "" && n.Status != models.NodeStatusApproved {
				return n, ErrScanNodeNotApproved
			}
			return n, nil
		}
	}
	return models.NodeInfo{}, ErrScanNodeNotFound
}

// RunNodeScan runs a targeted security scan for a single approved node (Hub or Agent).
func (o *Orchestrator) RunNodeScan(ctx context.Context, nodeName string) (*models.ScanResult, error) {
	return o.RunNodeScanWithTask(ctx, nodeName, "")
}

// RunNodeScanWithTask executes a security scan for nodeName under taskID and merges fresh results with cached items.
func (o *Orchestrator) RunNodeScanWithTask(ctx context.Context, nodeName string, taskID string) (*models.ScanResult, error) {
	lockID, err := o.claimOrVerifyScanLock(taskID)
	if err != nil {
		return nil, err
	}
	defer func() {
		o.FinishScanTask(lockID)
	}()
	if ctx.Err() != nil {
		o.failScanTask(lockID, taskID, "error", fmt.Sprintf("Scan aborted: %v", ctx.Err()), ctx.Err().Error())
		return nil, ctx.Err()
	}

	targetNode, err := o.ResolveTargetNode(ctx, nodeName)
	if err != nil {
		o.failScanTask(lockID, taskID, "error", fmt.Sprintf("Node scan failed: %v", err), err.Error())
		return nil, err
	}

	hubName := o.hubNodeName()
	if taskID == "" && o.store != nil {
		if t, err := o.store.CreateTask(ctx, &models.Task{
			Node:        targetNode.Name,
			TaskType:    "security_scan",
			TargetType:  "node",
			TargetName:  targetNode.Name,
			TriggeredBy: "scanner",
			Status:      "running",
		}); err == nil {
			taskID = t.ID
			lockID = o.upgradeScanTaskID(lockID, taskID)
		}
	}

	o.setScanningNodes([]string{targetNode.Name})

	var nodeItems []models.ManagedItem
	isHub := strings.EqualFold(targetNode.Name, hubName) || targetNode.Role == "hub"

	if isHub {
		o.logTask(ctx, taskID, "info", fmt.Sprintf("Starting single-node scan on Hub (%s)...", hubName))
		localItems, localErr := o.ScanLocalNode(ctx)
		if localErr != nil {
			o.logTask(ctx, taskID, "warn", fmt.Sprintf("[Hub] Partial local scan warning: %v", localErr))
		}
		nodeItems = localItems
		o.logTask(ctx, taskID, "info", fmt.Sprintf("[Hub] Scanned %d local components...", len(nodeItems)))
	} else {
		o.logTask(ctx, taskID, "info", fmt.Sprintf("[%s] Starting single-node scan on remote agent (%s)...", targetNode.Name, targetNode.URL))
		scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		fetchedItems, fetchErr := o.fetchRemoteAgentScan(scanCtx, targetNode)
		if fetchErr != nil {
			o.FinishScanTask(lockID)
			if o.store != nil && ctx.Err() == nil {
				_ = o.store.UpdateNodeHealth(ctx, targetNode.Name, false, time.Time{}, fetchErr.Error())
			}
			o.failScanTask(lockID, taskID, "stderr", fmt.Sprintf("[%s] Remote agent unreachable (%v)", targetNode.Name, fetchErr), fetchErr.Error())
			return nil, fetchErr
		}
		if o.store != nil {
			_ = o.store.UpdateNodeHealth(ctx, targetNode.Name, true, time.Now().UTC(), "")
		}
		o.logTask(ctx, taskID, "info", fmt.Sprintf("[%s] Scanned %d remote components...", targetNode.Name, len(fetchedItems)))
		nodeItems = fetchedItems
	}

	// Build nodesList with Hub first, then approved remote nodes
	nodesList := []models.NodeInfo{o.newHubNodeInfo(hubName)}
	canonicalByLower := map[string]string{
		strings.ToLower(hubName): hubName,
	}

	if o.store != nil {
		if registered, err := o.store.ListNodes(ctx); err == nil {
			for _, rn := range registered {
				if strings.EqualFold(rn.Name, hubName) || (rn.Status != "" && rn.Status != models.NodeStatusApproved) {
					continue
				}
				canonicalByLower[strings.ToLower(rn.Name)] = rn.Name
				rnCopy := rn
				rnCopy.Token = ""
				nodesList = append(nodesList, rnCopy)
			}
		}
	}

	// Merge with cached items from previous scan for other approved nodes
	allItems := make([]models.ManagedItem, 0, len(nodeItems))
	if o.store != nil {
		if prevScan, err := o.store.LoadLatestScanResult(ctx); err == nil && prevScan != nil {
			for _, prevItem := range prevScan.Items {
				itemNode := prevItem.Node
				if itemNode == "" {
					itemNode = hubName
				}
				if strings.EqualFold(itemNode, targetNode.Name) {
					continue // Replace items for the scanned node
				}
				canonNode, ok := canonicalByLower[strings.ToLower(itemNode)]
				if !ok {
					continue // Skip unapproved/removed node
				}
				prevItem.Node = canonNode
				allItems = append(allItems, prevItem)
			}
		}
	}
	if canonTarget, ok := canonicalByLower[strings.ToLower(targetNode.Name)]; ok {
		for i := range nodeItems {
			nodeItems[i].Node = canonTarget
		}
		allItems = append(allItems, nodeItems...)
	}

	return o.finalizeScanResult(ctx, lockID, taskID, hubName, allItems, nodesList)
}
