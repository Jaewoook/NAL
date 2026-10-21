package daemon

import (
	"context"
	"log"
	"time"

	"github.com/jaewoook/server-monitor/internal/alert"
	"github.com/jaewoook/server-monitor/internal/collector"
	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/detector"
	"github.com/jaewoook/server-monitor/internal/digest"
	"github.com/jaewoook/server-monitor/internal/heartbeat"
	"github.com/jaewoook/server-monitor/internal/models"
	"github.com/jaewoook/server-monitor/internal/notifier"
)

// MetricsCollector defines the interface for gathering point-in-time system metrics.
type MetricsCollector interface {
	Collect() (*models.SystemMetrics, error)
}

// Daemon coordinates continuous system metric collection, anomaly detection,
// alert dispatching, heartbeat pings, and periodic digests.
type Daemon struct {
	cfg        *config.Config
	collector  MetricsCollector
	detector   *detector.Detector
	alertMgr   *alert.Manager
	dispatcher *notifier.Dispatcher
	heartbeat  *heartbeat.Sender
	digest     *digest.Engine
	interval   time.Duration
}

// Option configures Daemon instances.
type Option func(*Daemon)

// WithCollector overrides the default MetricsCollector.
func WithCollector(c MetricsCollector) Option {
	return func(d *Daemon) {
		d.collector = c
	}
}

// WithDetector overrides the default Detector.
func WithDetector(det *detector.Detector) Option {
	return func(d *Daemon) {
		d.detector = det
	}
}

// WithAlertManager overrides the default alert Manager.
func WithAlertManager(mgr *alert.Manager) Option {
	return func(d *Daemon) {
		d.alertMgr = mgr
	}
}

// WithDispatcher overrides the default notification Dispatcher.
func WithDispatcher(disp *notifier.Dispatcher) Option {
	return func(d *Daemon) {
		d.dispatcher = disp
	}
}

// WithHeartbeat overrides the default heartbeat Sender.
func WithHeartbeat(hb *heartbeat.Sender) Option {
	return func(d *Daemon) {
		d.heartbeat = hb
	}
}

// WithDigest overrides the default digest Engine.
func WithDigest(dig *digest.Engine) Option {
	return func(d *Daemon) {
		d.digest = dig
	}
}

// New creates and initializes a Daemon with the provided configuration and options.
func New(cfg *config.Config, opts ...Option) (*Daemon, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	interval := time.Duration(cfg.Server.CheckIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	coll := collector.New(cfg.CPU.TopProcessesCount, cfg.Health.Disk.MountPoint)
	det := detector.New(cfg)

	cooldowns := map[string]time.Duration{
		detector.RuleCPUSpike:  time.Duration(cfg.CPU.Spike.CooldownMinutes) * time.Minute,
		detector.RuleCPUPlunge: time.Duration(cfg.CPU.PlungeDrop.CooldownMinutes) * time.Minute,
		detector.RuleCPUFloor:  time.Duration(cfg.CPU.FloorDrop.CooldownMinutes) * time.Minute,
		detector.RuleMemory:    time.Duration(cfg.Health.Memory.CooldownMinutes) * time.Minute,
		detector.RuleDisk:      time.Duration(cfg.Health.Disk.CooldownMinutes) * time.Minute,
	}
	mgr := alert.NewManager(cfg.Server.Name, cooldowns, cfg.Alerting.NotifyOnRecovery)

	disp := notifier.NewDispatcherFromConfig(&cfg.Notifications)

	var hb *heartbeat.Sender
	if cfg.Heartbeat.Enabled && cfg.Heartbeat.URL != "" {
		hb = heartbeat.New(cfg.Heartbeat.URL, time.Duration(cfg.Heartbeat.IntervalSeconds)*time.Second)
	}

	var dig *digest.Engine
	if cfg.Digest.Enabled {
		dig = digest.New(cfg.Server.Name, time.Duration(cfg.Digest.IntervalHours)*time.Hour)
		dig.SetLastTick(time.Now())
	}

	d := &Daemon{
		cfg:        cfg,
		collector:  coll,
		detector:   det,
		alertMgr:   mgr,
		dispatcher: disp,
		heartbeat:  hb,
		digest:     dig,
		interval:   interval,
	}

	for _, opt := range opts {
		opt(d)
	}

	return d, nil
}

// Step performs a single monitoring iteration: collecting metrics, evaluating
// anomaly rules, dispatching alerts, triggering heartbeat, and running digest checks.
func (d *Daemon) Step(ctx context.Context) error {
	now := time.Now()

	// 1. Gather point-in-time system telemetry
	metrics, err := d.collector.Collect()
	if err != nil {
		log.Printf("[daemon] warning: metric collection failed: %v", err)
	}

	// 2. Evaluate anomaly detection and process alert state machine
	if metrics != nil && d.detector != nil && d.alertMgr != nil {
		events := d.detector.Evaluate(metrics)
		alerts := d.alertMgr.ProcessEvents(events, metrics)

		for _, a := range alerts {
			alertCopy := a
			errs := d.dispatcher.Dispatch(&alertCopy)
			for chName, chErr := range errs {
				log.Printf("[daemon] failed to dispatch alert %q to channel %q: %v", alertCopy.Title, chName, chErr)
			}
		}

		// 3. Periodic health digest check
		if d.digest != nil && d.cfg.Digest.Enabled {
			digestAlert, err := d.digest.Tick(now, metrics)
			if err != nil {
				log.Printf("[daemon] digest generation failed: %v", err)
			} else if digestAlert != nil {
				errs := d.dispatcher.Dispatch(digestAlert)
				for chName, chErr := range errs {
					log.Printf("[daemon] failed to dispatch digest to channel %q: %v", chName, chErr)
				}
			}
		}
	}

	// 4. Dead-man's-switch aliveness ping
	if d.heartbeat != nil && d.cfg.Heartbeat.Enabled {
		d.heartbeat.Tick(now)
	}

	return nil
}

// Run starts the continuous monitoring daemon loop. It runs Step on each ticker tick
// and terminates cleanly when ctx is canceled.
func (d *Daemon) Run(ctx context.Context) error {
	log.Printf("[daemon] starting server-monitor daemon for %q (check interval: %v)", d.cfg.Server.Name, d.interval)

	// Execute initial check on startup
	if err := d.Step(ctx); err != nil {
		log.Printf("[daemon] initial step error: %v", err)
	}

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[daemon] shutdown signal received, terminating monitor loop cleanly")
			return nil
		case <-ticker.C:
			if err := d.Step(ctx); err != nil {
				log.Printf("[daemon] step error: %v", err)
			}
		}
	}
}
