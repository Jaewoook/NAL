package main

import (
	"context"
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
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/notifier"
	"github.com/jaewoook/security-hub/internal/scanner"
	"github.com/jaewoook/security-hub/internal/service"
	"github.com/jaewoook/security-hub/internal/updater"
	"github.com/jaewoook/security-hub/internal/web"
)

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
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	updMgr := updater.NewManager(cfg, store, nil, alerter)
	srv := web.NewServer(cfg, store, orch, updMgr, authMgr, alerter)

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
		runScheduledScan(ctx, cfg, store, orch, alerter)
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
				runScheduledScan(ctx, cfg, store, orch, alerter)
			}
		}
	}()

	addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	httpSrv.RegisterOnShutdown(srv.NotifyShutdown)

	var shutWG sync.WaitGroup
	shutWG.Add(1)
	go func() {
		defer shutWG.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		updCtx, updCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer updCancel()
		_ = updMgr.Wait(updCtx)
		_ = srv.Wait(updCtx)
	}()

	fmt.Fprintf(out, "NAL Security Hub listening on http://%s\n", addr)
	listenErr := httpSrv.ListenAndServe()
	stop()
	shutWG.Wait()
	bgWG.Wait()
	if listenErr != nil && listenErr != http.ErrServerClosed {
		fmt.Fprintf(out, "HTTP server error: %v\n", listenErr)
		return 1
	}
	return 0
}

func runScheduledScan(ctx context.Context, cfg *config.Config, store *db.SpoolStore, orch *scanner.Orchestrator, alerter *notifier.Alerter) {
	orch.LockScanStart()
	startLocked := true
	defer func() {
		if startLocked {
			orch.UnlockScanStart()
		}
	}()

	if scanning, _ := orch.IsScanning(); scanning {
		return
	}
	hubName := cfg.NodeName
	if hubName == "" {
		hubName = config.DefaultNodeName()
	}
	initialNodes := []string{hubName}
	if store != nil {
		if remoteNodes, err := store.ListNodes(ctx); err == nil {
			for _, rn := range remoteNodes {
				if !strings.EqualFold(rn.Name, hubName) && (rn.Status == "" || rn.Status == models.NodeStatusApproved) {
					initialNodes = append(initialNodes, rn.Name)
				}
			}
		}
	}
	var taskID string
	if store != nil {
		t, err := store.CreateTask(ctx, &models.Task{
			Node:        hubName,
			TaskType:    "security_scan",
			TargetType:  "system",
			TargetName:  "all",
			TriggeredBy: "scanner",
			Status:      "running",
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Scheduler] Failed to create scheduled scan task: %v\n", err)
			return
		}
		taskID = t.ID
	}
	if taskID == "" {
		taskID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
	}
	started, _ := orch.StartScanWithNodes(taskID, initialNodes)
	if !started {
		if store != nil {
			_ = store.FinishTask(context.Background(), taskID, "aborted", "scan already running")
		}
		return
	}
	orch.UnlockScanStart()
	startLocked = false

	defer orch.FinishScanTask(taskID)
	scanCtx, scanCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer scanCancel()
	if res, err := orch.RunFullScanWithTask(scanCtx, taskID); err == nil {
		orch.FinishScanTask(taskID)
		if alerter != nil {
			_, _ = alerter.NotifyScanFindings(scanCtx, res)
		}
	}
}

func runAgentCommand(rest []string, cfg *config.Config, out io.Writer) int {
	if len(rest) > 0 && rest[0] == "service" {
		return runAgentServiceCLI(rest[1:], cfg, out)
	}
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(out)
	nameFlag := fs.String("name", "", "Node name (defaults to system hostname)")
	hostFlag := fs.String("host", "", "Bind host (default 0.0.0.0)")
	portFlag := fs.Int("port", 0, "Agent bind port (overrides config.yml web.port; default 10247)")
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

func runAgentDaemon(cfg *config.Config, out io.Writer) int {
	if err := loadAgentTokenFromFile(cfg); err != nil {
		fmt.Fprintf(out, "Error loading agent token: %v\n", err)
		return 1
	}
	if cfg.AgentToken == "" {
		fmt.Fprintln(out, "Error: agent_token (or -token / SECURITY_HUB_AGENT_TOKEN) is required in agent mode")
		return 1
	}
	cfg.NodeName = service.ResolveAgentNodeName(cfg)
	store, err := db.NewSpoolStore(cfg.Database.DataDir, nil)
	if err != nil {
		fmt.Fprintf(out, "Failed to initialize agent spool store: %v\n", err)
		return 1
	}
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	updMgr := updater.NewManager(cfg, store, nil, nil)
	srv := web.NewServer(cfg, store, orch, updMgr, nil, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var bgWG sync.WaitGroup
	if cfg.HubURL != "" {
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
	}

	addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.AgentHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	httpSrv.RegisterOnShutdown(srv.NotifyShutdown)
	var shutWG sync.WaitGroup
	shutWG.Add(1)
	go func() {
		defer shutWG.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		updCtx, updCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer updCancel()
		_ = updMgr.Wait(updCtx)
	}()

	fmt.Fprintf(out, "NAL Security Hub Agent [%s] listening on http://%s\n", cfg.NodeName, addr)
	listenErr := httpSrv.ListenAndServe()
	stop()
	shutWG.Wait()
	bgWG.Wait()
	if listenErr != nil && listenErr != http.ErrServerClosed {
		fmt.Fprintf(out, "Agent HTTP server error: %v\n", listenErr)
		return 1
	}
	return 0
}
