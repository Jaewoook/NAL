package scanner

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jaewoook/system-updater/internal/config"
	"github.com/jaewoook/system-updater/internal/db"
	"github.com/jaewoook/system-updater/internal/models"
)

type Orchestrator struct {
	cfg           *config.Config
	store         db.Store
	dockerScanner *DockerScanner
	brewScanner   *BrewScanner
	daemonScanner *DaemonScanner
	vulnScanner   *VulnScanner
	eolChecker    *EoLChecker
}

func NewOrchestrator(cfg *config.Config, store db.Store, runner CommandRunner, httpClient *http.Client) *Orchestrator {
	if runner == nil {
		runner = NewOSCommandRunner()
	}
	reg := NewRegistryClient(httpClient)
	return &Orchestrator{
		cfg:           cfg,
		store:         store,
		dockerScanner: NewDockerScanner(cfg.Scanner.ServicesDir, cfg.Updater.CriticalServices, cfg.Updater.StatefulVolumes, runner, reg),
		brewScanner:   NewBrewScanner(runner),
		daemonScanner: NewDaemonScannerWithHTTP(cfg.Scanner.DaemonsDir, runner, httpClient),
		vulnScanner:   NewVulnScanner(cfg.Scanner.OSVAPIURL, httpClient, runner),
		eolChecker:    NewEoLChecker(cfg.Scanner.EoLAPIURL, httpClient),
	}
}

func ApplySkippedAndSummarize(items []models.ManagedItem, skipped map[string]string) *models.ScanResult {
	res := &models.ScanResult{
		ScannedAt: time.Now().UTC(),
	}
	for i := range items {
		key := string(items[i].TargetType) + ":" + items[i].Name
		if skVer, ok := skipped[key]; ok && skVer != "" && skVer == items[i].LatestVersion {
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

func (o *Orchestrator) RunFullScan(ctx context.Context) (*models.ScanResult, error) {
	var taskID string
	if o.store != nil {
		if t, err := o.store.CreateTask(ctx, &models.Task{
			TaskType:    "security_scan",
			TargetType:  "system",
			TargetName:  "all",
			TriggeredBy: "scanner",
		}); err == nil {
			taskID = t.ID
			_, _ = o.store.AppendTaskLog(ctx, taskID, "info", "Starting full NAL Docker, Homebrew, CVE, and LTS/EoL scan...")
		}
	}

	var allItems []models.ManagedItem

	if dockerItems, err := o.dockerScanner.ScanDockerServices(ctx); err == nil {
		allItems = append(allItems, dockerItems...)
		if taskID != "" {
			_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("Discovered %d Docker service images", len(dockerItems)))
		}
	}
	if brewItems, err := o.brewScanner.ScanBrew(ctx); err == nil {
		allItems = append(allItems, brewItems...)
		if taskID != "" {
			_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("Scanned %d Homebrew formulas", len(brewItems)))
		}
	}
	if daemonItems, err := o.daemonScanner.ScanDaemonsAndOS(ctx); err == nil {
		allItems = append(allItems, daemonItems...)
	}

	_ = o.vulnScanner.CheckVulnerabilities(ctx, allItems)
	_ = o.eolChecker.CheckEoL(ctx, allItems, time.Now().UTC(), o.cfg.Scanner.EoLWarningDays)

	skipped := make(map[string]string)
	snapshots := make(map[string]models.RollbackSnapshot)
	if o.store != nil {
		skipped, _ = o.store.ListSkippedVersions(ctx)
		snapshots, _ = o.store.ListSnapshots(ctx)
	}

	for i := range allItems {
		if snap, ok := snapshots[allItems[i].Name]; ok {
			allItems[i].HasRollback = true
			allItems[i].RollbackVersion = snap.PreviousVersion
		}
	}

	res := ApplySkippedAndSummarize(allItems, skipped)

	if o.store != nil {
		_ = o.store.SaveScanResult(ctx, res)
		if taskID != "" {
			_, _ = o.store.AppendTaskLog(ctx, taskID, "info", fmt.Sprintf("Scan complete: %d critical CVEs, %d high CVEs, %d EoL warnings, %d outdated, %d broken brew",
				res.TotalCritCVEs, res.TotalHighCVEs, res.TotalEoLIssues, res.TotalOutdated, res.TotalBrokenBrew))
			_ = o.store.FinishTask(ctx, taskID, "succeeded", "")
		}
	}

	return res, nil
}
