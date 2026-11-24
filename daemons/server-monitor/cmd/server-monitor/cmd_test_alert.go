package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
	"github.com/jaewoook/server-monitor/internal/notifier"
)

func runTestAlert(args []string, stdout, stderr io.Writer, appCfg *appConfig) int {
	fs := flag.NewFlagSet("test-alert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to configuration file")
	channelName := fs.String("channel", "", "Specific notification channel to test")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed to load configuration: %v\n", err)
		return 1
	}

	var dispOpts []notifier.DispatcherOption
	if appCfg.transport != nil {
		dispOpts = append(dispOpts, notifier.WithTransport(appCfg.transport))
	}
	disp := notifier.NewDispatcherFromConfig(&cfg.Notifications, dispOpts...)

	if *channelName != "" {
		var matched notifier.Channel
		for _, ch := range disp.Channels() {
			if strings.EqualFold(ch.Name(), *channelName) {
				matched = ch
				break
			}
		}
		if matched == nil {
			fmt.Fprintf(stderr, "channel %q is not enabled or not recognized in configuration\n", *channelName)
			return 1
		}
		disp = notifier.NewDispatcher(matched)
	} else if len(disp.Channels()) == 0 {
		fmt.Fprintln(stderr, "no notification channels are enabled in configuration")
		return 1
	}

	channelNames := make([]string, 0, len(disp.Channels()))
	for _, ch := range disp.Channels() {
		channelNames = append(channelNames, ch.Name())
	}

	testAlert := &models.Alert{
		Title:        "Server Monitor: Test Alert",
		Message:      fmt.Sprintf("This is a test notification from %s to verify channel connectivity.", cfg.Server.Name),
		Level:        models.AlertLevelInfo,
		MetricName:   "Test",
		CurrentValue: 0,
		Timestamp:    time.Now(),
		Hostname:     cfg.Server.Name,
	}

	errs := disp.Dispatch(testAlert)
	if len(errs) > 0 {
		for name, dispatchErr := range errs {
			fmt.Fprintf(stderr, "failed to dispatch alert to %s: %v\n", name, dispatchErr)
		}
		return 1
	}

	fmt.Fprintf(stdout, "Test alert successfully sent to: %s\n", strings.Join(channelNames, ", "))
	return 0
}
