package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/version"
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout))
}

func loadModeConfig(mode, path, example string) (*config.Config, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s configuration file %q not found (copy %s to %s to run in %s mode)", mode, path, example, path, mode)
		}
		return nil, fmt.Errorf("failed to stat %s: %w", path, err)
	}
	return config.LoadConfig(path)
}

func loadHubConfig() (*config.Config, error) {
	return loadModeConfig("hub", config.HubConfigFile, "config.hub.example.yml")
}

func loadAgentConfig() (*config.Config, error) {
	return loadModeConfig("agent", config.AgentConfigFile, "config.agent.example.yml")
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

	switch args[0] {
	case "hub":
		return runHubCommand(args[1:], out)
	case "agent":
		return runAgentCommand(args[1:], out)
	case "version", "-v", "--version":
		fmt.Fprintln(out, version.Current())
		return 0
	default:
		printUsage(out)
		return 1
	}
}

func runHubCommand(rest []string, out io.Writer) int {
	if len(rest) == 0 {
		printHubUsage(out)
		return 1
	}

	cfg, err := loadHubConfig()
	if err != nil {
		fmt.Fprintf(out, "Failed to load hub configuration: %v\n", err)
		return 1
	}

	sub := rest[0]
	subRest := rest[1:]
	switch sub {
	case "run":
		return runDaemon(cfg, out)
	case "service":
		return runServiceCommand(subRest, out)
	case "auth":
		return runAuthCommand(subRest, cfg, out)
	case "db":
		return runDBCommand(subRest, cfg, out)
	case "node":
		return runNodeCommand(subRest, cfg, out)
	case "scan":
		return runScanCommand(subRest, cfg, out)
	case "rollback":
		return runRollbackCommand(subRest, cfg, out)
	case "test-alert":
		return runTestAlertCommand(cfg, out)
	default:
		printHubUsage(out)
		return 1
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, `Usage:
  security-hub hub <command> [flags]    (requires config.hub.yml)
  security-hub agent <command> [flags]  (requires config.agent.yml)
  security-hub version                  Print the build version of this binary

Hub Commands:
  hub run                      Run the Hub scanner, spool syncer, and web dashboard
  hub service <action>         Manage Hub macOS launchd service (install, start, stop, restart, status)
  hub node <action>            Manage registered compute nodes (add, list, remove)
  hub scan [-node <name>]      Run an immediate Docker, Homebrew, CVE, and EoL scan (all nodes or single node)
  hub rollback <service>       Roll back a Docker service to its previous snapshot
  hub auth login-link          Generate a 5-minute break-glass web login link
  hub db init                  Provision the security_hub_db database in services/db
  hub test-alert               Send a test SMTP email alert

Agent Commands:
  agent run [flags]            Run the lightweight LAN Agent on a remote compute node
  agent service <action>       Manage Agent daemon service (install, uninstall, start, stop, restart, status)
  agent scan                   Run a local-only Docker, Homebrew, CVE, and EoL scan on this agent node`)
}

func printHubUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: security-hub hub <run|service|node|scan|rollback|auth|db|test-alert>")
}

func printAgentUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: security-hub agent <run|service|scan>")
}
