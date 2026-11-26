package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jaewoook/security-hub/internal/auth"
	"github.com/jaewoook/security-hub/internal/broker"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/notifier"
	"github.com/jaewoook/security-hub/internal/scanner"
	"github.com/jaewoook/security-hub/internal/service"
	"github.com/jaewoook/security-hub/internal/updater"
	"github.com/jaewoook/security-hub/internal/web"
)

func serveHTTPWithGracefulShutdown(ctx context.Context, stop context.CancelFunc, addr string, handler http.Handler, onShutdown func(), drain func(context.Context), bgWG *sync.WaitGroup, out io.Writer, label, listenBanner string) int {
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if onShutdown != nil {
		httpSrv.RegisterOnShutdown(onShutdown)
	}

	var shutWG sync.WaitGroup
	shutWG.Add(1)
	go func() {
		defer shutWG.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		if drain != nil {
			drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer drainCancel()
			drain(drainCtx)
		}
	}()

	fmt.Fprintln(out, listenBanner)
	listenErr := httpSrv.ListenAndServe()
	stop()
	shutWG.Wait()
	if bgWG != nil {
		bgWG.Wait()
	}
	if listenErr != nil && listenErr != http.ErrServerClosed {
		fmt.Fprintf(out, "%s error: %v\n", label, listenErr)
		return 1
	}
	return 0
}

func runDaemon(cfg *config.Config, out io.Writer) int {
	pg := db.NewPostgresBackendWithPassword(cfg.Database.ContainerName, cfg.Database.DBName, cfg.Database.DBUser, cfg.Database.DBPass, nil)
	store, err := db.NewSpoolStore(cfg.Database.DataDir, pg)
	if err != nil {
		fmt.Fprintf(out, "Failed to initialize spool store: %v\n", err)
		return 1
	}
	authMgr, err := auth.NewManager(cfg.Auth, filepath.Join(cfg.Database.DataDir, "auth_state.json"))
	if err != nil {
		fmt.Fprintf(out, "Failed to initialize auth manager: %v\n", err)
		return 1
	}
	alerter := notifier.NewAlerter(cfg.Notifications.Email, store)
	cmdBroker := broker.New()
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	orch.SetBroker(cmdBroker)
	updMgr := updater.NewManager(cfg, store, nil, alerter)
	updMgr.SetBroker(cmdBroker)
	srv := web.NewServer(cfg, store, orch, updMgr, authMgr, alerter)
	srv.SetBroker(cmdBroker)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var bgWG sync.WaitGroup

	// Background PostgreSQL Spool Syncer
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = store.FlushPending(ctx)
			}
		}
	}()

	// Background Security, Outdated, Brew/Apt & EoL Scanner
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		runScheduledScan(ctx, orch, alerter)
		interval := time.Duration(cfg.Scanner.IntervalHours) * time.Hour
		if interval <= 0 {
			interval = 6 * time.Hour
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runScheduledScan(ctx, orch, alerter)
			}
		}
	}()

	addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
	return serveHTTPWithGracefulShutdown(
		ctx,
		stop,
		addr,
		srv.Handler(),
		srv.NotifyShutdown,
		func(drainCtx context.Context) {
			_ = updMgr.Wait(drainCtx)
			_ = srv.Wait(drainCtx)
		},
		&bgWG,
		out,
		"HTTP server",
		fmt.Sprintf("NAL Security Hub [hub mode] listening on http://%s", addr),
	)
}

func runScheduledScan(ctx context.Context, orch *scanner.Orchestrator, alerter *notifier.Alerter) {
	reservation, err := orch.BeginScan(ctx, scanner.BeginScanRequest{
		TriggeredBy: "scanner",
	})
	if err != nil {
		if !errors.Is(err, scanner.ErrScanInProgress) {
			fmt.Fprintf(os.Stderr, "[Scheduler] Failed to start scheduled scan: %v\n", err)
		}
		return
	}

	defer orch.FinishScanTask(reservation.TaskID)
	scanCtx, scanCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer scanCancel()
	if res, err := orch.RunFullScanWithTask(scanCtx, reservation.TaskID); err == nil {
		orch.FinishScanTask(reservation.TaskID)
		if alerter != nil {
			_, _ = alerter.NotifyScanFindings(scanCtx, res)
		}
	}
}

func runAgentCommand(rest []string, out io.Writer) int {
	if len(rest) == 0 {
		printAgentUsage(out)
		return 1
	}

	cfg, err := loadAgentConfig()
	if err != nil {
		fmt.Fprintf(out, "Failed to load agent configuration: %v\n", err)
		return 1
	}

	switch rest[0] {
	case "run":
		return runAgentRunCommand(rest[1:], cfg, out)
	case "service":
		return runAgentServiceCLI(rest[1:], cfg, out)
	case "scan":
		return runAgentScanCommand(rest[1:], cfg, out)
	default:
		printAgentUsage(out)
		return 1
	}
}

func runAgentRunCommand(rest []string, cfg *config.Config, out io.Writer) int {
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	fs.SetOutput(out)
	nameFlag := fs.String("name", "", "Node name (defaults to system hostname)")
	hostFlag := fs.String("host", "", "Bind host (default 0.0.0.0)")
	portFlag := fs.Int("port", 0, "Agent bind port (overrides config.agent.yml web.port; default 10247)")
	tokenFlag := fs.String("token", "", "Shared X-NAL-Node-Token secret")
	hubFlag := fs.String("hub", "", "Security Hub URL (e.g. http://hub.lan:10311)")
	advFlag := fs.String("advertise-url", "", "Advertise URL for this agent reachable by the hub")
	if err := fs.Parse(rest); err != nil {
		return 1
	}
	if *nameFlag != "" {
		cfg.NodeName = *nameFlag
	}
	if *hostFlag != "" {
		cfg.Web.Host = *hostFlag
	}
	if *portFlag > 0 {
		cfg.Web.Port = *portFlag
	} else if cfg.Web.Port == 0 || cfg.Web.Port == 10311 {
		if os.Getenv("SECURITY_HUB_PORT") == "" && os.Getenv("PORT") == "" {
			cfg.Web.Port = 10247
		}
	}
	if *tokenFlag != "" {
		cfg.AgentToken = *tokenFlag
	}
	if err := loadAgentTokenFromFile(cfg); err != nil {
		fmt.Fprintf(out, "Error loading agent token: %v\n", err)
		return 1
	}
	if *hubFlag != "" {
		cfg.HubURL = *hubFlag
	}
	if *advFlag != "" {
		cfg.AgentAdvertiseURL = *advFlag
	}
	return runAgentDaemon(cfg, out)
}

func executeAgentJob(ctx context.Context, nodeName string, store db.Store, orch *scanner.Orchestrator, updMgr *updater.Manager, job broker.Job, emitLog func(stream, line string)) broker.JobResult {
	switch job.Action {
	case broker.ActionScan:
		items, err := orch.ScanLocalNode(ctx)
		if err != nil && len(items) == 0 {
			return broker.JobResult{Status: "failed", ErrorMsg: err.Error()}
		}
		if store != nil {
			if snapshots, sErr := store.ListSnapshots(ctx); sErr == nil {
				for i := range items {
					if items[i].TargetType != models.TargetDocker {
						continue
					}
					if snap, ok := snapshots[items[i].Name]; ok {
						items[i].HasRollback = true
						items[i].RollbackVersion = snap.PreviousVersion
					} else if snap, ok := snapshots[nodeName+":"+items[i].Name]; ok {
						items[i].HasRollback = true
						items[i].RollbackVersion = snap.PreviousVersion
					}
				}
			}
		}
		return broker.JobResult{Status: "succeeded", Items: items}

	case broker.ActionUpdate:
		var req updater.UpdateRequest
		if err := json.Unmarshal(job.Payload, &req); err != nil {
			return broker.JobResult{Status: "failed", ErrorMsg: fmt.Sprintf("invalid update payload: %v", err)}
		}
		req.Node = nodeName
		req.TargetType = strings.TrimSpace(req.TargetType)
		if req.TargetType == "" {
			req.TargetType = string(models.TargetDocker)
		}
		req.TargetName = strings.TrimSpace(req.TargetName)
		req.TargetVersion = strings.TrimSpace(req.TargetVersion)
		if err := updater.ValidateUpdateRequest(req); err != nil {
			return broker.JobResult{Status: "failed", ErrorMsg: err.Error()}
		}
		updCtx, updCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
		defer updCancel()
		task, err := store.CreateTask(updCtx, &models.Task{
			Node:        nodeName,
			TaskType:    "agent_update",
			TargetType:  req.TargetType,
			TargetName:  req.TargetName,
			ToVersion:   req.TargetVersion,
			TriggeredBy: req.TriggeredBy,
			Status:      "running",
		})
		if err != nil {
			return broker.JobResult{Status: "failed", ErrorMsg: err.Error()}
		}
		var logWG sync.WaitGroup
		if emitLog != nil {
			logCh, unsub := store.SubscribeTaskLogs(task.ID)
			logWG.Add(1)
			go func() {
				defer logWG.Done()
				defer unsub()
				for line := range logCh {
					emitLog(line.Stream, line.Line)
				}
			}()
		}
		_ = updMgr.RunUpdateSync(updCtx, task.ID, req)
		logWG.Wait()
		finalTask, logs, _ := store.GetTaskWithLogs(updCtx, task.ID)
		status, errMsg := task.Status, task.ErrorMsg
		if finalTask != nil {
			status = finalTask.Status
			errMsg = finalTask.ErrorMsg
		}
		return broker.JobResult{Status: status, ErrorMsg: errMsg, Logs: logs}

	case broker.ActionRollback:
		var req struct {
			ServiceName string `json:"service_name"`
			TriggeredBy string `json:"triggered_by"`
		}
		if err := json.Unmarshal(job.Payload, &req); err != nil || strings.TrimSpace(req.ServiceName) == "" {
			return broker.JobResult{Status: "failed", ErrorMsg: "service_name required"}
		}
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
		defer rbCancel()
		task, err := updMgr.RollbackService(rbCtx, req.ServiceName, req.TriggeredBy)
		if err != nil && task == nil {
			return broker.JobResult{Status: "failed", ErrorMsg: err.Error()}
		}
		finalTask, logs, _ := store.GetTaskWithLogs(rbCtx, task.ID)
		status, errMsg := task.Status, task.ErrorMsg
		if finalTask != nil {
			status = finalTask.Status
			errMsg = finalTask.ErrorMsg
		}
		return broker.JobResult{Status: status, ErrorMsg: errMsg, Logs: logs}

	default:
		return broker.JobResult{Status: "failed", ErrorMsg: fmt.Sprintf("unsupported job action %q", job.Action)}
	}
}

func runAgentDaemon(cfg *config.Config, out io.Writer) int {
	if err := loadAgentTokenFromFile(cfg); err != nil {
		fmt.Fprintf(out, "Error loading agent token: %v\n", err)
		return 1
	}
	if cfg.AgentToken == "" {
		fmt.Fprintln(out, "Error: agent_token (or -token / SECURITY_HUB_AGENT_TOKEN) is required in agent mode")
		return 1
	}
	if strings.TrimSpace(cfg.HubURL) == "" {
		fmt.Fprintln(out, "Error: hub_url (or -hub / SECURITY_HUB_URL) is required in agent mode")
		return 1
	}
	cfg.NodeName = service.ResolveAgentNodeName(cfg)
	if strings.TrimSpace(cfg.AgentAdvertiseURL) == "" {
		cfg.AgentAdvertiseURL = "reverse-poll"
	}
	store, err := db.NewSpoolStore(cfg.Database.DataDir, nil)
	if err != nil {
		fmt.Fprintf(out, "Failed to initialize agent spool store: %v\n", err)
		return 1
	}
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	updMgr := updater.NewManager(cfg, store, nil, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var bgWG sync.WaitGroup

	errCh := service.StartAnnouncer(ctx, cfg, nil)
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		for err := range errCh {
			if err != nil {
				fmt.Fprintf(out, "[Agent Announcer] Warning: %v\n", err)
			}
		}
	}()

	pollErrCh := service.StartAgentPollerStreaming(ctx, cfg, nil, func(jobCtx context.Context, job broker.Job, emitLog func(string, string)) broker.JobResult {
		return executeAgentJob(jobCtx, cfg.NodeName, store, orch, updMgr, job, emitLog)
	})
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		for err := range pollErrCh {
			if err != nil {
				fmt.Fprintf(out, "[Agent Poller] Warning: %v\n", err)
			}
		}
	}()

	fmt.Fprintf(out, "NAL Security Hub Agent [agent mode | %s] connected to %s (reverse-poll)\n", cfg.NodeName, config.NormalizeURL(cfg.HubURL))
	<-ctx.Done()

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer drainCancel()
	_ = updMgr.Wait(drainCtx)
	bgWG.Wait()
	return 0
}
