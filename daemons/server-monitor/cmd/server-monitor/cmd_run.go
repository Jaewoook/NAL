package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jaewoook/server-monitor/internal/daemon"
	"github.com/jaewoook/server-monitor/internal/logger"
)

func runDaemon(args []string, stdout, stderr io.Writer, appCfg *appConfig) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to configuration file")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed to load configuration: %v\n", err)
		return 1
	}

	appLogger, logCloser, err := logger.NewLogger(logger.Options{
		Enabled:    cfg.Logging.Enabled,
		FilePath:   cfg.Logging.FilePath,
		MaxSizeMB:  cfg.Logging.MaxSizeMB,
		MaxBackups: cfg.Logging.MaxBackups,
		Console:    cfg.Logging.Console,
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "failed to initialize logger: %v\n", err)
		return 1
	}
	defer func() {
		if logCloser != nil {
			_ = logCloser.Close()
		}
	}()

	d, err := daemon.New(cfg, daemon.WithLogger(appLogger))
	if err != nil {
		fmt.Fprintf(stderr, "failed to initialize daemon: %v\n", err)
		return 1
	}

	ctx := appCfg.ctx
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
	}

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "daemon exited with error: %v\n", err)
		return 1
	}
	return 0
}
