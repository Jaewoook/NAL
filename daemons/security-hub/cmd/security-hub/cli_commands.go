package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
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

func runAuthCommand(rest []string, cfg *config.Config, out io.Writer) int {
	if len(rest) == 0 || rest[0] != "login-link" {
		fmt.Fprintln(out, "Usage: security-hub hub auth login-link")
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
}

func execWithSudo(args []string, out io.Writer) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(out, "Failed to resolve executable path for sudo: %v\n", err)
		return 1
	}
	cmd := exec.Command("sudo", append([]string{exe}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(out, "sudo execution failed: %v\n", err)
		return 1
	}
	return 0
}

func runServiceCommand(rest []string, out io.Writer) int {
	if len(rest) == 0 {
		fmt.Fprintln(out, "Usage: security-hub hub service <status|start|stop|restart|install>")
		return 1
	}
	sub := rest[0]
	switch sub {
	case "install":
		fs := flag.NewFlagSet("hub service install", flag.ContinueOnError)
		fs.SetOutput(out)
		pathFlag := fs.String("path", "", "Path to write launchd plist (defaults to /Library/LaunchDaemons on macOS)")
		userFlag := fs.String("user", "", "UserName for LaunchDaemon execution (defaults to current user)")
		if err := fs.Parse(rest[1:]); err != nil {
			return 1
		}
		if runtime.GOOS == "darwin" && *pathFlag == "" && os.Geteuid() != 0 {
			_ = service.RemoveLegacyUserHubAgent()
			runUser := strings.TrimSpace(*userFlag)
			if runUser == "" {
				if u, uErr := user.Current(); uErr == nil {
					runUser = u.Username
				}
			}
			fmt.Fprintln(out, "Installing Hub as a macOS LaunchDaemon requires administrator privileges (sudo)...")
			sudoArgs := []string{"hub", "service", "install"}
			if runUser != "" {
				sudoArgs = append(sudoArgs, "-user", runUser)
			}
			return execWithSudo(sudoArgs, out)
		}
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(out, "Failed to resolve executable path: %v\n", err)
			return 1
		}
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(out, "Failed to resolve working directory: %v\n", err)
			return 1
		}
		runUser := strings.TrimSpace(*userFlag)
		runHome := ""
		if runUser == "" && os.Geteuid() == 0 {
			runUser = strings.TrimSpace(os.Getenv("SUDO_USER"))
		}
		if runUser != "" {
			if u, uErr := user.Lookup(runUser); uErr == nil {
				runHome = u.HomeDir
			}
		}
		if err := service.InstallHubPlist(*pathFlag, exe, wd, runUser, runHome); err != nil {
			fmt.Fprintf(out, "Failed to install plist: %v\n", err)
			return 1
		}
		if os.Geteuid() == 0 && *pathFlag == "" {
			fmt.Fprintf(out, "Installed hub LaunchDaemon plist (%s) for user %q (hub mode)\n", service.DefaultSystemPlistPath(), runUser)
		} else {
			fmt.Fprintf(out, "Installed hub launchd service plist (%s) (hub mode)\n", service.LaunchdLabel)
		}
		return 0
	case "status":
		st, err := service.Status()
		if err != nil {
			fmt.Fprintf(out, "Failed to check hub service %s status: %v\n", service.LaunchdLabel, err)
			return 1
		}
		fmt.Fprintf(out, "Hub service %s (hub mode): %s\n", service.LaunchdLabel, st)
		return 0
	case "start":
		if runtime.GOOS == "darwin" && service.IsSystemHubInstalled() && os.Geteuid() != 0 {
			return execWithSudo([]string{"hub", "service", "start"}, out)
		}
		if err := service.Start(); err != nil {
			fmt.Fprintf(out, "Failed to start hub service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Service started as hub mode.")
		return 0
	case "stop":
		if runtime.GOOS == "darwin" && service.IsSystemHubInstalled() && os.Geteuid() != 0 {
			return execWithSudo([]string{"hub", "service", "stop"}, out)
		}
		if err := service.Stop(); err != nil {
			fmt.Fprintf(out, "Failed to stop hub service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Hub service stopped (hub mode).")
		return 0
	case "restart":
		if runtime.GOOS == "darwin" && service.IsSystemHubInstalled() && os.Geteuid() != 0 {
			return execWithSudo([]string{"hub", "service", "restart"}, out)
		}
		if err := service.Restart(); err != nil {
			fmt.Fprintf(out, "Failed to restart hub service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Service restarted as hub mode.")
		return 0
	default:
		fmt.Fprintf(out, "Unknown hub service action: %s\n", sub)
		return 1
	}
}

func runDBCommand(rest []string, cfg *config.Config, out io.Writer) int {
	if len(rest) == 0 || rest[0] != "init" {
		fmt.Fprintln(out, "Usage: security-hub hub db init")
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
}

func openCLISpoolStore(cfg *config.Config, withPostgres bool) (*db.SpoolStore, error) {
	var pg db.Backend
	if withPostgres {
		pg = db.NewPostgresBackendWithPassword(cfg.Database.ContainerName, cfg.Database.DBName, cfg.Database.DBUser, cfg.Database.DBPass, nil)
	}
	return db.NewCLISpoolStore(cfg.Database.DataDir, pg)
}

func runScanCommand(rest []string, cfg *config.Config, out io.Writer) int {
	fs := flag.NewFlagSet("hub scan", flag.ContinueOnError)
	fs.SetOutput(out)
	nodeFlag := fs.String("node", "", "Specific compute node to scan (default scans all nodes)")
	if err := fs.Parse(rest); err != nil {
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(out, "Usage: security-hub hub scan [-node <name>]")
		return 1
	}
	store, err := openCLISpoolStore(cfg, true)
	if err != nil {
		fmt.Fprintf(out, "Failed to open spool store: %v\n", err)
		return 1
	}
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	targetNode := strings.TrimSpace(*nodeFlag)
	var res *models.ScanResult
	if targetNode != "" {
		if resolved, rErr := orch.ResolveTargetNode(context.Background(), targetNode); rErr == nil {
			targetNode = resolved.Name
		}
		res, err = orch.RunNodeScan(context.Background(), targetNode)
	} else {
		res, err = orch.RunFullScan(context.Background())
	}
	if err != nil {
		fmt.Fprintf(out, "Scan failed: %v\n", err)
		return 1
	}
	summary := res
	targetLabel := "All Nodes"
	if targetNode != "" {
		targetLabel = "Node " + targetNode
		var nodeItems []models.ManagedItem
		for _, it := range res.Items {
			if strings.EqualFold(it.Node, targetNode) {
				nodeItems = append(nodeItems, it)
			}
		}
		skipped, _ := store.ListSkippedVersions(context.Background())
		summary = scanner.ApplySkippedAndSummarize(nodeItems, skipped)
	}
	fmt.Fprintf(out, "=== NAL Security Hub Scan Summary (%s) ===\n", targetLabel)
	fmt.Fprintf(out, "Items Scanned:     %d\n", len(summary.Items))
	fmt.Fprintf(out, "Critical CVEs:     %d\n", summary.TotalCritCVEs)
	fmt.Fprintf(out, "High CVEs:         %d\n", summary.TotalHighCVEs)
	fmt.Fprintf(out, "LTS/EoL Warnings:  %d\n", summary.TotalEoLIssues)
	fmt.Fprintf(out, "Outdated Packages: %d\n", summary.TotalOutdated)
	fmt.Fprintf(out, "Broken Pkg Links:  %d\n", summary.TotalBrokenBrew)
	return 0
}

func runAgentScanCommand(rest []string, cfg *config.Config, out io.Writer) int {
	fs := flag.NewFlagSet("agent scan", flag.ContinueOnError)
	fs.SetOutput(out)
	if err := fs.Parse(rest); err != nil {
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(out, "Usage: security-hub agent scan")
		return 1
	}
	cfg.NodeName = service.ResolveAgentNodeName(cfg)
	store, err := openCLISpoolStore(cfg, false)
	if err != nil {
		fmt.Fprintf(out, "Failed to open agent spool store: %v\n", err)
		return 1
	}
	orch := scanner.NewOrchestrator(cfg, store, nil, nil)
	items, err := orch.ScanLocalNode(context.Background())
	if err != nil && len(items) == 0 {
		fmt.Fprintf(out, "Agent scan failed: %v\n", err)
		return 1
	}
	skipped, _ := store.ListSkippedVersions(context.Background())
	summary := scanner.ApplySkippedAndSummarize(items, skipped)
	fmt.Fprintf(out, "=== NAL Security Hub Agent Scan Summary (Node %s) ===\n", cfg.NodeName)
	fmt.Fprintf(out, "Items Scanned:     %d\n", len(summary.Items))
	fmt.Fprintf(out, "Critical CVEs:     %d\n", summary.TotalCritCVEs)
	fmt.Fprintf(out, "High CVEs:         %d\n", summary.TotalHighCVEs)
	fmt.Fprintf(out, "LTS/EoL Warnings:  %d\n", summary.TotalEoLIssues)
	fmt.Fprintf(out, "Outdated Packages: %d\n", summary.TotalOutdated)
	fmt.Fprintf(out, "Broken Pkg Links:  %d\n", summary.TotalBrokenBrew)
	return 0
}

func runRollbackCommand(rest []string, cfg *config.Config, out io.Writer) int {
	if len(rest) == 0 {
		fmt.Fprintln(out, "Usage: security-hub hub rollback <service-name>")
		return 1
	}
	store, err := openCLISpoolStore(cfg, true)
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
}

func runTestAlertCommand(cfg *config.Config, out io.Writer) int {
	store, err := openCLISpoolStore(cfg, false)
	if err != nil {
		fmt.Fprintf(out, "Failed to open spool store: %v\n", err)
		return 1
	}
	alerter := notifier.NewAlerter(cfg.Notifications.Email, store)
	if err := alerter.SendTestEmail(context.Background()); err != nil {
		fmt.Fprintf(out, "Test alert failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Test alert sent to %s\n", cfg.Notifications.Email.ToEmail)
	return 0
}

func runNodeCommand(rest []string, cfg *config.Config, out io.Writer) int {
	if len(rest) == 0 {
		fmt.Fprintln(out, "Usage: security-hub hub node <add|list|remove>")
		return 1
	}
	store, err := openCLISpoolStore(cfg, rest[0] == "add" || rest[0] == "remove")
	if err != nil {
		fmt.Fprintf(out, "Failed to open spool store: %v\n", err)
		return 1
	}
	switch rest[0] {
	case "add":
		if len(rest) < 3 {
			fmt.Fprintln(out, "Usage: security-hub hub node add <Name> <URL> [-token <secret>]")
			return 1
		}
		nodeName := strings.TrimSpace(rest[1])
		nodeURL := config.NormalizeURL(rest[2])
		if !web.IsValidAgentHTTPURL(nodeURL) {
			fmt.Fprintf(out, "Error: invalid agent URL %q (must use http:// or https:// with a valid host)\n", rest[2])
			return 1
		}
		hubName := cfg.NodeName
		if hubName == "" {
			hubName = config.DefaultNodeName()
		}
		if strings.EqualFold(nodeName, hubName) {
			fmt.Fprintf(out, "Error: agent node name %q conflicts with hub node name\n", nodeName)
			return 1
		}
		fs := flag.NewFlagSet("node add", flag.ContinueOnError)
		fs.SetOutput(out)
		tokFlag := fs.String("token", cfg.AgentToken, "Shared X-NAL-Node-Token secret")
		if err := fs.Parse(rest[3:]); err != nil {
			return 1
		}
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
		nodes, err := store.ListNodes(context.Background())
		if err != nil {
			fmt.Fprintf(out, "Failed to list nodes: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "• %s (Hub, Local)\n", cfg.NodeName)
		for _, n := range nodes {
			fmt.Fprintf(out, "• %s (%s) — online=%v\n", n.Name, n.URL, n.Online)
		}
		return 0
	case "remove":
		if len(rest) < 2 {
			fmt.Fprintln(out, "Usage: security-hub hub node remove <Name>")
			return 1
		}
		if err := store.RemoveNode(context.Background(), rest[1]); err != nil {
			fmt.Fprintf(out, "Failed to remove node %s: %v\n", rest[1], err)
			return 1
		}
		fmt.Fprintf(out, "Removed node %s\n", rest[1])
		return 0
	default:
		fmt.Fprintln(out, "Usage: security-hub hub node <add|list|remove>")
		return 1
	}
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
		fs.SetOutput(out)
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
		hub := config.NormalizeURL(*hubFlag)
		if hub == "" {
			hub = config.NormalizeURL(cfg.HubURL)
		}
		adv := config.NormalizeURL(*advFlag)
		if adv == "" {
			adv = config.NormalizeURL(cfg.AgentAdvertiseURL)
		}

		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(out, "Failed to resolve executable path: %v\n", err)
			return 1
		}
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(out, "Failed to resolve working directory: %v\n", err)
			return 1
		}

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
			fmt.Fprintf(out, "Installed agent launchd service plist (%s) (agent mode)\n", service.AgentLaunchdLabel)
		} else {
			fmt.Fprintf(out, "Installed agent systemd service (%s) (agent mode)\n", service.AgentSystemdUnit)
		}
		return 0

	case "uninstall":
		if err := service.UninstallAgent(); err != nil {
			fmt.Fprintf(out, "Failed to uninstall agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Agent service uninstalled (agent mode).")
		return 0

	case "start":
		if err := service.StartAgent(); err != nil {
			fmt.Fprintf(out, "Failed to start agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Service started as agent mode.")
		return 0

	case "stop":
		if err := service.StopAgent(); err != nil {
			fmt.Fprintf(out, "Failed to stop agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Agent service stopped (agent mode).")
		return 0

	case "restart":
		if err := service.RestartAgent(); err != nil {
			fmt.Fprintf(out, "Failed to restart agent service: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "Service restarted as agent mode.")
		return 0

	case "status":
		st, err := service.StatusAgent()
		if err != nil {
			if runtime.GOOS == "darwin" {
				fmt.Fprintf(out, "Failed to check agent service %s status: %v\n", service.AgentLaunchdLabel, err)
			} else {
				fmt.Fprintf(out, "Failed to check agent service %s status: %v\n", service.AgentSystemdUnit, err)
			}
			return 1
		}
		if runtime.GOOS == "darwin" {
			fmt.Fprintf(out, "Agent service %s (agent mode): %s\n", service.AgentLaunchdLabel, st)
		} else {
			fmt.Fprintf(out, "Agent service %s (agent mode): %s\n", service.AgentSystemdUnit, st)
		}
		return 0

	default:
		fmt.Fprintf(out, "Unknown agent service action: %s\n", sub)
		return 1
	}
}
