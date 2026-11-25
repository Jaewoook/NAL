package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/jaewoook/server-monitor/internal/service"
)

type serviceAction struct {
	fn        func(serviceType, serviceName, targetPath string) (string, error)
	errVerb   string
	noNewline bool
}

var serviceActions = map[string]serviceAction{
	"uninstall": {fn: service.UninstallService, errVerb: "uninstall service"},
	"start":     {fn: service.StartService, errVerb: "start service"},
	"stop":      {fn: service.StopService, errVerb: "stop service"},
	"restart":   {fn: service.RestartService, errVerb: "restart service"},
	"status":    {fn: service.StatusService, errVerb: "get service status", noNewline: true},
}

func runService(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: server-monitor service <install|uninstall|start|stop|restart|status> [options]")
		return 1
	}

	subCmd := args[0]
	if subCmd == "install" {
		return runServiceInstall(args[1:], stdout, stderr)
	}

	action, ok := serviceActions[subCmd]
	if !ok {
		fmt.Fprintf(stderr, "unknown service subcommand: %q. Valid subcommands: install, uninstall, start, stop, restart, status\n", subCmd)
		return 1
	}

	fs := flag.NewFlagSet("service "+subCmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	serviceType := fs.String("type", "", "Service manager type: systemd or launchd")
	targetPath := fs.String("path", "", "Custom path to service file")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}

	msg, err := action.fn(*serviceType, "server-monitor", *targetPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed to %s: %v\n", action.errVerb, err)
		return 1
	}
	if action.noNewline {
		fmt.Fprint(stdout, msg)
	} else {
		fmt.Fprintln(stdout, msg)
	}
	return 0
}

func runServiceInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("service install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serviceType := fs.String("type", "", "Service manager type: systemd or launchd")
	targetPath := fs.String("path", "", "Destination path to write service file")
	cfgPath := fs.String("config", "", "Path to config file for service")
	binPath := fs.String("bin", "", "Path to executable binary for service")
	userFlag := fs.String("user", "", "User to run service as")
	workDir := fs.String("workdir", "", "Working directory for service")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	resolvedType := service.ResolveServiceType(*serviceType)

	opts := service.ServiceOptions{
		BinaryPath: *binPath,
		ConfigPath: *cfgPath,
		User:       *userFlag,
		WorkingDir: *workDir,
	}

	if *targetPath != "" && *targetPath != "-" {
		if err := service.Install(resolvedType, opts, *targetPath); err != nil {
			fmt.Fprintf(stderr, "failed to install service: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Successfully installed %s service to %s\n", resolvedType, *targetPath)
		return 0
	}

	content, err := service.Generate(resolvedType, opts)
	if err != nil {
		fmt.Fprintf(stderr, "failed to generate service: %v\n", err)
		return 1
	}
	fmt.Fprint(stdout, content)
	return 0
}
