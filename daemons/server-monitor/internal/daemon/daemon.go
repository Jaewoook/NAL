package daemon

import (
	"context"
	"fmt"
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

// TopProcessPopulator is an optional extension of MetricsCollector that can
// lazily populate top process diagnostics when an anomaly is detected.
type TopProcessPopulator interface {
	PopulateTopProcesses(*models.SystemMetrics)
}

// AnomalyDetector evaluates system metrics and emits raw condition events.
type AnomalyDetector interface {
	Evaluate(*models.SystemMetrics) []models.RawConditionEvent
}

// AlertProcessor converts raw condition events into actionable alerts with cooldowns.
type AlertProcessor interface {
	ProcessEvents([]models.RawConditionEvent, *models.SystemMetrics) []models.Alert
}

// AlertDispatcher delivers alerts to configured notification channels.
type AlertDispatcher interface {
	DispatchContext(context.Context, *models.Alert) map[string]error
}

// HeartbeatSender performs periodic dead-man's-switch aliveness pings.
type HeartbeatSender interface {
	TickContext(context.Context, time.Time) bool
}

// DigestEngine generates periodic health summary alerts.
type DigestEngine interface {
	Tick(time.Time, *models.SystemMetrics) (*models.Alert, error)
}

// Daemon coordinates continuous system metric collection, anomaly detection,
// alert dispatching, heartbeat pings, and periodic digests.
type Daemon struct {
	cfg        *config.Config
	collector  MetricsCollector
	detector   AnomalyDetector
	alertMgr   AlertProcessor
	dispatcher AlertDispatcher
	heartbeat  HeartbeatSender
	digest     DigestEngine
	logger     *log.Logger
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
		if det == nil {
			d.detector = nil
			return
		}
		d.detector = det
	}
}

// WithAlertManager overrides the default alert Manager.
func WithAlertManager(mgr *alert.Manager) Option {
	return func(d *Daemon) {
		if mgr == nil {
			d.alertMgr = nil
			return
		}
		d.alertMgr = mgr
	}
}

// WithDispatcher overrides the default notification Dispatcher.
func WithDispatcher(disp *notifier.Dispatcher) Option {
	return func(d *Daemon) {
		if disp == nil {
			d.dispatcher = nil
			return
		}
		d.dispatcher = disp
	}
}

// WithHeartbeat overrides the default heartbeat Sender.
func WithHeartbeat(hb *heartbeat.Sender) Option {
	return func(d *Daemon) {
		if hb == nil {
			d.heartbeat = nil
			return
		}
		d.heartbeat = hb
	}
}

// WithDigest overrides the default digest Engine.
func WithDigest(dig *digest.Engine) Option {
	return func(d *Daemon) {
		if dig == nil {
			d.digest = nil
			return
		}
		d.digest = dig
	}
}

// WithLogger configures a custom logger for daemon operational logs.
func WithLogger(l *log.Logger) Option {
	return func(d *Daemon) {
		d.logger = l
	}
}

func (d *Daemon) logf(format string, args ...any) {
	if d.logger != nil {
		d.logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
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

	det := detector.New(cfg)

	coll := collector.New(cfg.CPU.TopProcessesCount, cfg.Health.Disk.MountPoint)
	if elevated := det.ElevatedCPUThreshold(); elevated > 0 {
		coll.SetLazyTopProcessesThreshold(elevated)
	}

	cooldowns := map[string]time.Duration{
		models.RuleCPUSpike:  time.Duration(cfg.CPU.Spike.CooldownMinutes) * time.Minute,
		models.RuleCPUPlunge: time.Duration(cfg.CPU.PlungeDrop.CooldownMinutes) * time.Minute,
		models.RuleCPUFloor:  time.Duration(cfg.CPU.FloorDrop.CooldownMinutes) * time.Minute,
		models.RuleMemory:    time.Duration(cfg.Health.Memory.CooldownMinutes) * time.Minute,
		models.RuleDisk:      time.Duration(cfg.Health.Disk.CooldownMinutes) * time.Minute,
		models.RuleCPUTemp:   time.Duration(cfg.Health.Temperature.CooldownMinutes) * time.Minute,
		models.RuleGPUTemp:   time.Duration(cfg.Health.Temperature.CooldownMinutes) * time.Minute,
	}
	mgr := alert.NewManager(cfg.Server.Name, cooldowns, cfg.Alerting.NotifyOnRecovery)
	disp := notifier.NewDispatcherFromConfig(&cfg.Notifications)

	var hb HeartbeatSender
	var hbConcrete *heartbeat.Sender
	if cfg.Heartbeat.Enabled && cfg.Heartbeat.URL != "" {
		hbConcrete = heartbeat.New(cfg.Heartbeat.URL, time.Duration(cfg.Heartbeat.IntervalSeconds)*time.Second)
		hb = hbConcrete
	}

	var dig DigestEngine
	if cfg.Digest.Enabled {
		digEngine := digest.New(cfg.Server.Name, time.Duration(cfg.Digest.IntervalHours)*time.Hour)
		digEngine.SetLastTick(time.Now())
		dig = digEngine
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

	if d.logger != nil && hbConcrete != nil {
		hbConcrete.SetLogger(d.logger)
	}

	return d, nil
}

// Step performs a single monitoring iteration: collecting metrics, evaluating
// anomaly rules, dispatching alerts, triggering heartbeat, and running digest checks.
func (d *Daemon) Step(ctx context.Context) error {
	_, err := d.step(ctx)
	return err
}

func (d *Daemon) step(ctx context.Context) (*models.SystemMetrics, error) {
	now := time.Now()

	// 1. Gather point-in-time system telemetry
	metrics, err := d.collector.Collect()
	if err != nil {
		d.logf("[daemon] warning: metric collection failed: %v", err)
	}

	// 2. Evaluate anomaly detection and process alert state machine
	if metrics != nil && d.detector != nil && d.alertMgr != nil {
		events := d.detector.Evaluate(metrics)
		if len(events) > 0 && len(metrics.TopProcesses) == 0 {
			if populator, ok := d.collector.(TopProcessPopulator); ok {
				populator.PopulateTopProcesses(metrics)
				for i := range events {
					if len(events[i].TopProcesses) == 0 {
						events[i].TopProcesses = metrics.TopProcesses
					}
				}
			}
		}

		alerts := d.alertMgr.ProcessEvents(events, metrics)
		for _, a := range alerts {
			alertCopy := a
			d.dispatch(ctx, &alertCopy, fmt.Sprintf("alert %q", alertCopy.Title))
		}

		// 3. Periodic health digest check
		if d.digest != nil && d.cfg.Digest.Enabled {
			digestAlert, err := d.digest.Tick(now, metrics)
			if err != nil {
				d.logf("[daemon] digest generation failed: %v", err)
			} else if digestAlert != nil {
				d.dispatch(ctx, digestAlert, "digest")
			}
		}
	}

	// 4. Dead-man's-switch aliveness ping
	if d.heartbeat != nil && d.cfg.Heartbeat.Enabled {
		d.heartbeat.TickContext(ctx, now)
	}

	return metrics, nil
}

func (d *Daemon) dispatch(ctx context.Context, a *models.Alert, label string) {
	if d.dispatcher == nil || a == nil {
		return
	}
	errs := d.dispatcher.DispatchContext(ctx, a)
	for chName, chErr := range errs {
		d.logf("[daemon] failed to dispatch %s to channel %q: %v", label, chName, chErr)
	}
}

// Run starts the continuous monitoring daemon loop. It runs Step on each ticker tick
// and terminates cleanly when ctx is canceled.
func (d *Daemon) Run(ctx context.Context) error {
	d.logf("[daemon] starting server-monitor daemon for %q (check interval: %v)", d.cfg.Server.Name, d.interval)

	// Execute initial check on startup and reuse its metrics for startup notification
	initialMetrics, err := d.step(ctx)
	if err != nil {
		d.logf("[daemon] initial step error: %v", err)
	}

	// Dispatch startup notification if enabled
	if d.cfg.Alerting.NotifyOnStartup && d.dispatcher != nil {
		d.sendLifecycleNotification(ctx, true, initialMetrics)
	}

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logf("[daemon] shutdown signal received, terminating monitor loop cleanly")
			if d.cfg.Alerting.NotifyOnShutdown && d.dispatcher != nil {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				var shutdownMetrics *models.SystemMetrics
				if d.collector != nil {
					if m, err := d.collector.Collect(); err == nil {
						shutdownMetrics = m
					}
				}
				d.sendLifecycleNotification(shutdownCtx, false, shutdownMetrics)
				cancel()
			}
			return nil
		case <-ticker.C:
			if _, err := d.step(ctx); err != nil {
				d.logf("[daemon] step error: %v", err)
			}
		}
	}
}

func (d *Daemon) sendLifecycleNotification(ctx context.Context, isStartup bool, m *models.SystemMetrics) {
	var title, label, msg string
	var level models.AlertLevel

	if isStartup {
		title = fmt.Sprintf("[%s] Server Monitor Online", d.cfg.Server.Name)
		label = "startup notification"
		level = models.AlertLevelResolved
		msg = fmt.Sprintf("Daemon online and monitoring %s (check interval: %v).", d.cfg.Server.Name, d.interval)
		if m != nil {
			msg = fmt.Sprintf("Daemon online and monitoring %s.\nCheck Interval: %v | %s",
				d.cfg.Server.Name, d.interval, formatMetricsSummary(m))
		}
	} else {
		title = fmt.Sprintf("[%s] Server Monitor Shutting Down", d.cfg.Server.Name)
		label = "shutdown notification"
		level = models.AlertLevelWarning
		msg = fmt.Sprintf("Daemon received termination signal on %s. Monitoring stopped cleanly.", d.cfg.Server.Name)
		if m != nil {
			msg = fmt.Sprintf("Daemon received termination signal on %s. Monitoring stopped cleanly.\n%s",
				d.cfg.Server.Name, formatMetricsSummary(m))
		}
	}

	d.dispatch(ctx, &models.Alert{
		Title:     title,
		Message:   msg,
		Level:     level,
		Timestamp: time.Now(),
		Hostname:  d.cfg.Server.Name,
	}, label)
}

func formatMetricsSummary(m *models.SystemMetrics) string {
	extra := ""
	if m.HasCPUTemp {
		extra += fmt.Sprintf(" | Temp: %.1f°C", m.CPUTempCelsius)
	}
	if m.HasGPUTemp {
		extra += fmt.Sprintf(" | GPU Temp: %.1f°C", m.GPUTempCelsius)
	}
	return fmt.Sprintf("Uptime: %s | CPU: %.1f%% | RAM: %.1f%%%s",
		models.FormatUptime(m.UptimeSeconds), m.CPUPercent, m.MemoryPercent, extra)
}
