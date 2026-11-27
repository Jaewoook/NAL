package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/broker"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/version"
)

type Orchestrator struct {
	cfg           *config.Config
	store         db.Store
	broker        *broker.Broker
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

func (o *Orchestrator) SetBroker(b *broker.Broker) {
	o.broker = b
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
		Version:    version.Current(),
	}
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

func (o *Orchestrator) RunFullScan(ctx context.Context) (*models.ScanResult, error) {
	return o.RunFullScanWithTask(ctx, "")
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
		o.setScanningNodes(o.approvedClusterNodeNames(ctx, hubName))
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
				scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
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
		scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		fetchedItems, fetchErr := o.fetchRemoteAgentScan(scanCtx, targetNode)
		if fetchErr != nil {
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
