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
	"runtime"
	"strings"
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

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout))
}

func loadAppConfig(configPath string) *config.Config {
	if configPath != "" {
		if cfg, err := config.LoadConfig(configPath); err == nil {
			return cfg
		}
	}
	if _, err := os.Stat("config.yml"); err == nil {
		if cfg, err := config.LoadConfig("config.yml"); err == nil {
			return cfg
		}
	}
	return config.DefaultConfigWithEnv()
}

func runCLI(args []string, out io.Writer) int {
	if len(args) == 0 {
		printUsage(out)
		return 1
	}

	cmd := args[0]
	rest := args[1:]

	cfg := loadAppConfig("")

	switch cmd {
	case "auth":
		if len(rest) == 0 || rest[0] != "login-link" {
			fmt.Fprintln(out, "Usage: security-hub auth login-link")
			return 1
		}
		stateFile := filepath.Join(cfg.Database.DataDir, "auth_state.json")
		authMgr, err := auth.NewManager(cfg.Auth, stateFile)
		if err != nil {
			fmt.Fprintf(out, "Error initializing auth manager: %v\n", err)
			return 1
		}
		tok, err := authMgr.GenerateBreakGlassToken(5 * time.Minute)
		if err != nil {
			fmt.Fprintf(out, "Error generating login token: %v\n", err)
			return 1
		}
		pub := strings.TrimRight(cfg.Web.PublicURL, "/")
		fmt.Fprintf(out, "Break-Glass One-Time Login URL (valid 5 minutes):\n%s/api/auth/token-login?token=%s\n", pub, tok)
		return 0

	case "service":
		if len(rest) == 0 {
			fmt.Fprintln(out, "Usage: security-hub service <status|start|stop|restart|install>")
			return 1
		}
		sub := rest[0]
		switch sub {
		case "install":
			fs := flag.NewFlagSet("service install", flag.ContinueOnError)
			pathFlag := fs.String("path", "", "Path to write launchd plist")
			_ = fs.Parse(rest[1:])
			exe, _ := os.Executable()
			wd, _ := os.Getwd()
			if err := service.InstallPlist(*pathFlag, exe, wd); err != nil {
				fmt.Fprintf(out, "Failed to install plist: %v\n", err)
				return 1
			}
			fmt.Fprintf(out, "Installed launchd service plist (%s)\n", service.LaunchdLabel)
			return 0
		case "status":
			st, _ := service.Status()
			fmt.Fprintf(out, "Service %s: %s\n", service.LaunchdLabel, st)
			return 0
		case "start":
			if err := service.Start(); err != nil {
				fmt.Fprintf(out, "Failed to start service: %v\n", err)
				return 1
			}
			fmt.Fprintln(out, "Service started.")
			return 0
		case "stop":
			if err := service.Stop(); err != nil {
				fmt.Fprintf(out, "Failed to stop service: %v\n", err)
				return 1
			}
			fmt.Fprintln(out, "Service stopped.")
			return 0
		case "restart":
			if err := service.Restart(); err != nil {
				fmt.Fprintf(out, "Failed to restart service: %v\n", err)
				return 1
			}
			fmt.Fprintln(out, "Service restarted.")
			return 0
		default:
			fmt.Fprintf(out, "Unknown service action: %s\n", sub)
			return 1
		}

	case "db":
		if len(rest) == 0 || rest[0] != "init" {
			fmt.Fprintln(out, "Usage: security-hub db init")
			return 1
		}
		if err := db.ProvisionDatabase(context.Background(), cfg.Database.ContainerName, cfg.Database.DBName, cfg.Database.DBUser, cfg.Database.DBPass, nil); err != nil {
			fmt.Fprintf(out, "Database provisioning failed: %v\n", err)
			fmt.Fprintf(out, "Hint: Ensure the %q container (services/db) is running on this Hub host (`cd ../../services/db && docker compose up -d`).\n", cfg.Database.ContainerName)
			fmt.Fprintf(out, "Note: Remote Agent nodes do not use PostgreSQL (`db init` is only for the Hub), and the Hub can also run with its local spool if PostgreSQL is offline.\n")
			return 1
		}
		fmt.Fprintf(out, "Database %q, role %q, and tables provisioned in container %q.\n", cfg.Database.DBName, cfg.Database.DBUser, cfg.Database.ContainerName)
		return 0

	case "scan":
		pg := db.NewPostgresBackend(cfg.Database.ContainerName, cfg.Database.DBName, cfg.Database.DBUser, nil)
		store, err := db.NewSpoolStore(cfg.Database.DataDir, pg)
		if err != nil {
			fmt.Fprintf(out, "Failed to open spool store: %v\n", err)
			return 1
		}
		orch := scanner.NewOrchestrator(cfg, store, nil, nil)
		res, err := orch.RunFullScan(context.Background())
		if err != nil {
			fmt.Fprintf(out, "Scan failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "=== NAL Security Hub Scan Summary ===\n")
		fmt.Fprintf(out, "Items Scanned:     %d\n", len(res.Items))
		fmt.Fprintf(out, "Critical CVEs:     %d\n", res.TotalCritCVEs)
		fmt.Fprintf(out, "High CVEs:         %d\n", res.TotalHighCVEs)
		fmt.Fprintf(out, "LTS/EoL Warnings:  %d\n", res.TotalEoLIssues)
		fmt.Fprintf(out, "Outdated Packages: %d\n", res.TotalOutdated)
		fmt.Fprintf(out, "Broken Brew Links: %d\n", res.TotalBrokenBrew)
		return 0

	case "rollback":
		if len(rest) == 0 {
			fmt.Fprintln(out, "Usage: security-hub rollback <service-name>")
			return 1
		}
		pg := db.NewPostgresBackend(cfg.Database.ContainerName, cfg.Database.DBName, cfg.Database.DBUser, nil)
		store, err := db.NewSpoolStore(cfg.Database.DataDir, pg)
		if err != nil {
			fmt.Fprintf(out, "Failed to open spool store: %v\n", err)
			return 1
		}
		alerter := notifier.NewAlerter(cfg.Notifications.Email, store)
		updMgr := updater.NewManager(cfg, store, nil, alerter)
		task, err := updMgr.RollbackService(context.Background(), rest[0], "cli")
		if err != nil {
			fmt.Fprintf(out, "Rollback failed for %s: %v\n", rest[0], err)
			return 1
		}
		fmt.Fprintf(out, "Rolled back %s (Task %s -> %s)\n", rest[0], task.ID, task.ToVersion)
		return 0

	case "test-alert":
		store, _ := db.NewSpoolStore(cfg.Database.DataDir, nil)
		alerter := notifier.NewAlerter(cfg.Notifications.Email, store)
		if err := alerter.SendTestEmail(context.Background()); err != nil {
			fmt.Fprintf(out, "Test alert failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "Test alert sent to %s\n", cfg.Notifications.Email.ToEmail)
		return 0

	case "run":
		return runDaemon(cfg, out)

	case "agent":
		if len(rest) > 0 && rest[0] == "service" {
			return runAgentServiceCLI(rest[1:], cfg, out)
		}
		fs := flag.NewFlagSet("agent", flag.ContinueOnError)
		nameFlag := fs.String("name", "", "Node name (defaults to system hostname)")
		hostFlag := fs.String("host", "", "Bind host (default 0.0.0.0)")
		portFlag := fs.Int("port", 0, "Agent bind port (overrides config.yml web.port; default 10247)")
		tokenFlag := fs.String("token", "", "Shared X-NAL-Node-Token secret")
		hubFlag := fs.String("hub", "", "Security Hub URL (e.g. http://hub.lan:10311)")
		advFlag := fs.String("advertise-url", "", "Advertise URL for this agent reachable by the hub")
		_ = fs.Parse(rest)
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
		if *hubFlag != "" {
			cfg.HubURL = *hubFlag
		}
		if *advFlag != "" {
			cfg.AgentAdvertiseURL = *advFlag
		}
		return runAgentDaemon(cfg, out)

	case "node":
		if len(rest) == 0 {
			fmt.Fprintln(out, "Usage: security-hub node <add|list|remove>")
			return 1
		}
		store, err := db.NewSpoolStore(cfg.Database.DataDir, nil)
		if err != nil {
			fmt.Fprintf(out, "Failed to open spool store: %v\n", err)
			return 1
		}
		switch rest[0] {
		case "add":
			if len(rest) < 3 {
				fmt.Fprintln(out, "Usage: security-hub node add <Name> <URL> [-token <secret>]")
				return 1
			}
			nodeName := rest[1]
			nodeURL := rest[2]
			fs := flag.NewFlagSet("node add", flag.ContinueOnError)
			tokFlag := fs.String("token", cfg.AgentToken, "Shared X-NAL-Node-Token secret")
			_ = fs.Parse(rest[3:])
			if err := store.UpsertNode(context.Background(), models.NodeInfo{
				Name:  nodeName,
				URL:   nodeURL,
				Token: *tokFlag,
				Role:  "agent",
			}); err != nil {
				fmt.Fprintf(out, "Failed to add node: %v\n", err)
				return 1
			}
			fmt.Fprintf(out, "Registered node %s (%s)\n", nodeName, nodeURL)
			return 0
		case "list":
			nodes, _ := store.ListNodes(context.Background())
			fmt.Fprintf(out, "• %s (Hub, Local)\n", cfg.NodeName)
			for _, n := range nodes {
				fmt.Fprintf(out, "• %s (%s) — online=%v\n", n.Name, n.URL, n.Online)
			}
			return 0
		case "remove":
			if len(rest) < 2 {
				fmt.Fprintln(out, "Usage: security-hub node remove <Name>")
				return 1
			}
			_ = store.RemoveNode(context.Background(), rest[1])
			fmt.Fprintf(out, "Removed node %s\n", rest[1])
			return 0
		default:
			fmt.Fprintln(out, "Usage: security-hub node <add|list|remove>")
			return 1
		}

	default:
		printUsage(out)
		return 1
	}
}

func runDaemon(cfg *config.Config, out io.Writer) int {
	pg := db.NewPostgresBackend(cfg.Database.ContainerName, cfg.Database.DBName, cfg.Database.DBUser, nil)
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

	// Background PostgreSQL Spool Syncer (flushes queued task logs whenever services/db recovers)
	go func() {
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

	// Background Security, Outdated, Brew & EoL Scanner
	go func() {
		if res, err := orch.RunFullScan(ctx); err == nil {
			_, _ = alerter.NotifyScanFindings(ctx, res)
		}
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
				if res, err := orch.RunFullScan(ctx); err == nil {
					_, _ = alerter.NotifyScanFindings(ctx, res)
				}
			}
		}
	}()

	addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	fmt.Fprintf(out, "NAL Security Hub listening on http://%s\n", addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(out, "HTTP server error: %v\n", err)
		return 1
	}
	return 0
}

func runAgentDaemon(cfg *config.Config, out io.Writer) int {
	if cfg.AgentToken == "" {
		fmt.Fprintln(out, "Error: agent_token (or -token / SECURITY_HUB_AGENT_TOKEN) is required in agent mode")
		return 1
	}
	store, err := db.NewSpoolStore(cfg.Database.DataDir, nil)
	if err != nil {
		fmt.Fprintf(out, "Failed to initialize agent spool store: %v\n", err)
		return 1
	}
	authMgr, _ := auth.NewManager(cfg.Auth, filepath.Join(cfg.Database.DataDir, "auth_state.json"))
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	updMgr := updater.NewManager(cfg, store, nil, nil)
	srv := web.NewServer(cfg, store, orch, updMgr, authMgr, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.HubURL != "" {
		errCh := service.StartAnnouncer(ctx, cfg, nil)
		go func() {
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
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	fmt.Fprintf(out, "NAL Security Hub Agent [%s] listening on http://%s\n", cfg.NodeName, addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(out, "Agent HTTP server error: %v\n", err)
		return 1
	}
	return 0
}

func runAgentServiceCLI(args []string, cfg *config.Config, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, "Usage: security-hub agent service <install|uninstall|start|stop|restart|status>")
		return 1
	}
	sub := args[0]
	switch sub {
	case "install":
		fs := flag.NewFlagSet("agent service install", flag.ContinueOnError)
		nameFlag := fs.String("name", "", "Node name (defaults to system hostname)")
		hostFlag := fs.String("host", "", "Bind host (default 0.0.0.0)")
		portFlag := fs.Int("port", 0, "Agent bind port (default 10247)")
		tokenFlag := fs.String("token", "", "Shared X-NAL-Node-Token secret")
		hubFlag := fs.String("hub", "", "Security Hub URL (e.g. http://hub.lan:10311)")
		advFlag := fs.String("advertise-url", "", "Advertise URL for this agent reachable by the hub")
		pathFlag := fs.String("path", "", "Custom path to write service definition")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}

		name := *nameFlag
		if name == "" {
			name = cfg.NodeName
		}
		host := *hostFlag
		if host == "" {
			host = cfg.Web.Host
		}
		port := *portFlag
		if port <= 0 {
			if cfg.Web.Port > 0 && cfg.Web.Port != 10311 {
				port = cfg.Web.Port
			} else {
				port = 10247
			}
		}
		tok := *tokenFlag
		if tok == "" {
			tok = cfg.AgentToken
		}
		hub := *hubFlag
		if hub == "" {
			hub = cfg.HubURL
		}
		adv := *advFlag
		if adv == "" {
			adv = cfg.AgentAdvertiseURL
		}

		exe, _ := os.Executable()
		wd, _ := os.Getwd()

		opts := service.AgentServiceOptions{
			BinaryPath:   exe,
			WorkingDir:   wd,
			Name:         name,
			Host:         host,
			Port:         port,
			Token:        tok,
			HubURL:       hub,
			AdvertiseURL: adv,
			CustomPath:   *pathFlag,
		}

		if err := service.InstallAgent(opts); err != nil {
			fmt.Fprintf(out, "Failed to install agent service: %v\n", err)
			return 1
		}
		if runtime.GOOS == "darwin" {
			fmt.Fprintf(out, "Installed agent launchd service plist (%s)\n", service.AgentLaunchdLabel)
		} else {
			fmt.Fprintf(out, "Installed agent systemd service (%s)\n", service.AgentSystemdUnit)
		}
		return 0

	case "uninstall":
		if err := service.UninstallAgent(); err != nil {
			fmt.Fprintf(out, "Failed to uninstall agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Agent service uninstalled.")
		return 0

	case "start":
		if err := service.StartAgent(); err != nil {
			fmt.Fprintf(out, "Failed to start agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Agent service started.")
		return 0

	case "stop":
		if err := service.StopAgent(); err != nil {
			fmt.Fprintf(out, "Failed to stop agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Agent service stopped.")
		return 0

	case "restart":
		if err := service.RestartAgent(); err != nil {
			fmt.Fprintf(out, "Failed to restart agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Agent service restarted.")
		return 0

	case "status":
		st, _ := service.StatusAgent()
		if runtime.GOOS == "darwin" {
			fmt.Fprintf(out, "Agent service %s: %s\n", service.AgentLaunchdLabel, st)
		} else {
			fmt.Fprintf(out, "Agent service %s: %s\n", service.AgentSystemdUnit, st)
		}
		return 0

	default:
		fmt.Fprintf(out, "Unknown agent service action: %s\n", sub)
		return 1
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, `Usage:
  security-hub <command> [flags]

Commands:
  run                      Run the Hub scanner, spool syncer, and web dashboard
  agent                    Run the lightweight LAN Agent on a remote compute node
  agent service <action>   Manage Agent daemon service (install, uninstall, start, stop, restart, status)
  node <action>            Manage registered compute nodes (add, list, remove)
  scan                     Run an immediate multi-node Docker, Homebrew, CVE, and EoL scan
  rollback <service>       Roll back a Docker service to its previous snapshot
  auth login-link          Generate a 5-minute break-glass web login link
  db init                  Provision the security_hub_db database in services/db
  test-alert               Send a test SMTP email alert
  service <action>         Manage Hub macOS launchd service (install, start, stop, restart, status)`)
}
