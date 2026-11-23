package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jaewoook/security-hub/internal/config"
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout))
}

func loadAppConfig(configPath string) (*config.Config, error) {
	if configPath != "" {
		return config.LoadConfig(configPath)
	}
	_, err := os.Stat("config.yml")
	if err == nil {
		return config.LoadConfig("config.yml")
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat config.yml: %w", err)
	}
	return config.DefaultConfigWithEnv(), nil
}

func loadAgentTokenFromFile(cfg *config.Config) error {
	if cfg.AgentToken != "" {
		return nil
	}
	tokFile := strings.TrimSpace(os.Getenv("SECURITY_HUB_AGENT_TOKEN_FILE"))
	if tokFile == "" {
		return nil
	}
	raw, err := os.ReadFile(tokFile)
	if err != nil {
		return fmt.Errorf("failed to read SECURITY_HUB_AGENT_TOKEN_FILE %q: %w", tokFile, err)
	}
	cfg.AgentToken = strings.TrimSpace(string(raw))
	return nil
}

func runCLI(args []string, out io.Writer) int {
	if len(args) == 0 {
		printUsage(out)
		return 1
	}

	cmd := args[0]
	rest := args[1:]

	cfg, err := loadAppConfig("")
	if err != nil {
		fmt.Fprintf(out, "Failed to load configuration: %v\n", err)
		return 1
	}

	switch cmd {
	case "auth":
		return runAuthCommand(rest, cfg, out)
	case "service":
		return runServiceCommand(rest, out)
	case "db":
		return runDBCommand(rest, cfg, out)
	case "scan":
		return runScanCommand(rest, cfg, out)
	case "rollback":
		return runRollbackCommand(rest, cfg, out)
	case "test-alert":
		return runTestAlertCommand(cfg, out)
	case "run":
		return runDaemon(cfg, out)
	case "agent":
		return runAgentCommand(rest, cfg, out)
	case "node":
		return runNodeCommand(rest, cfg, out)
	default:
		printUsage(out)
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
  scan [-node <name>]      Run an immediate Docker, Homebrew, CVE, and EoL scan (all nodes or single node)
  rollback <service>       Roll back a Docker service to its previous snapshot
  auth login-link          Generate a 5-minute break-glass web login link
  db init                  Provision the security_hub_db database in services/db
  test-alert               Send a test SMTP email alert
  service <action>         Manage Hub macOS launchd service (install, start, stop, restart, status)`)
}
