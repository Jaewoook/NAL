package daemon

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"runtime/debug"
	"sync"
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

const (
	defaultCollectTimeout       = 10 * time.Second
	defaultDeliveryRetryBackoff = 60 * time.Second
	maxHeartbeatLoopTick        = 15 * time.Second
)

// MetricsCollector defines the interface for gathering point-in-time system metrics.
type MetricsCollector interface {
	Collect() (*models.SystemMetrics, error)
}

// ContextMetricsCollector is an optional extension of MetricsCollector that honors ctx.
type ContextMetricsCollector interface {
	CollectContext(context.Context) (*models.SystemMetrics, error)
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
	cfg            *config.Config
	collector      MetricsCollector
	detector       AnomalyDetector
	alertMgr       AlertProcessor
	dispatcher     AlertDispatcher
	heartbeat      HeartbeatSender
	digest         DigestEngine
	logger         *log.Logger
	interval       time.Duration
	collectTimeout time.Duration

	metricsMu   sync.Mutex
	lastMetrics *models.SystemMetrics
}

// Option configures Daemon instances.
type Option func(*Daemon)

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}

// WithCollector overrides the default MetricsCollector.
func WithCollector(c MetricsCollector) Option {
	return func(d *Daemon) {
		if isNilInterface(c) {
			d.collector = nil
			return
		}
		d.collector = c
	}
}

// WithDetector overrides the default AnomalyDetector.
func WithDetector(det AnomalyDetector) Option {
	return func(d *Daemon) {
		if isNilInterface(det) {
			d.detector = nil
			return
		}
		d.detector = det
	}
}

// WithAlertManager overrides the default AlertProcessor.
func WithAlertManager(mgr AlertProcessor) Option {
	return func(d *Daemon) {
		if isNilInterface(mgr) {
			d.alertMgr = nil
			return
		}
		d.alertMgr = mgr
	}
}

// WithDispatcher overrides the default AlertDispatcher.
func WithDispatcher(disp AlertDispatcher) Option {
	return func(d *Daemon) {
		if isNilInterface(disp) {
			d.dispatcher = nil
			return
		}
		d.dispatcher = disp
	}
}

// WithHeartbeat overrides the default HeartbeatSender.
func WithHeartbeat(hb HeartbeatSender) Option {
	return func(d *Daemon) {
		if isNilInterface(hb) {
			d.heartbeat = nil
			return
		}
		d.heartbeat = hb
	}
}

// WithDigest overrides the default DigestEngine.
func WithDigest(dig DigestEngine) Option {
	return func(d *Daemon) {
		if isNilInterface(dig) {
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

	mgr := alert.NewManager(cfg.Server.Name, cfg.RuleCooldowns(), cfg.Alerting.NotifyOnRecovery)
	disp := notifier.NewDispatcherFromConfig(&cfg.Notifications)

	var hb HeartbeatSender
	if cfg.Heartbeat.Enabled && cfg.Heartbeat.URL != "" {
		hb = heartbeat.New(cfg.Heartbeat.URL, time.Duration(cfg.Heartbeat.IntervalSeconds)*time.Second)
	}

	var dig DigestEngine
	if cfg.Digest.Enabled {
		digEngine := digest.New(cfg.Server.Name, time.Duration(cfg.Digest.IntervalHours)*time.Hour)
		digEngine.SetLastTick(time.Now())
		dig = digEngine
	}

	d := &Daemon{
		cfg:            cfg,
		collector:      coll,
		detector:       det,
		alertMgr:       mgr,
		dispatcher:     disp,
		heartbeat:      hb,
		digest:         dig,
		interval:       interval,
		collectTimeout: defaultCollectTimeout,
	}

	for _, opt := range opts {
		opt(d)
	}

	if d.logger != nil {
		if loggerSetter, ok := d.heartbeat.(interface{ SetLogger(*log.Logger) }); ok {
			loggerSetter.SetLogger(d.logger)
		}
	}

	return d, nil
}

// Step performs a single monitoring iteration: collecting metrics, evaluating
// anomaly rules, dispatching alerts, triggering heartbeat, and running digest checks.
func (d *Daemon) Step(ctx context.Context) error {
	d.step(ctx)
	return nil
}

func (d *Daemon) collectMetrics(ctx context.Context) (*models.SystemMetrics, error) {
	if d.collector == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if d.collectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.collectTimeout)
		defer cancel()
	}
	if cc, ok := d.collector.(ContextMetricsCollector); ok {
		return cc.CollectContext(ctx)
	}
	return d.collector.Collect()
}

func (d *Daemon) setLastMetrics(m *models.SystemMetrics) {
	if m == nil {
		return
	}
	d.metricsMu.Lock()
	d.lastMetrics = m
	d.metricsMu.Unlock()
}

func (d *Daemon) getLastMetrics() *models.SystemMetrics {
	d.metricsMu.Lock()
	defer d.metricsMu.Unlock()
	return d.lastMetrics
}

func (d *Daemon) step(ctx context.Context) (metrics *models.SystemMetrics) {
	defer func() {
		if r := recover(); r != nil {
			d.logf("[daemon] recovered from panic in monitoring step: %v\n%s", r, debug.Stack())
		}
	}()

	now := time.Now()

	// 1. Gather point-in-time system telemetry (bounded by collectTimeout)
	var err error
	metrics, err = d.collectMetrics(ctx)
	if err != nil {
		d.logf("[daemon] warning: metric collection failed: %v", err)
	}
	d.setLastMetrics(metrics)

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
			if !d.dispatch(ctx, &alertCopy, fmt.Sprintf("alert %q", alertCopy.Title)) &&
				ctx.Err() == nil && alertCopy.Level != models.AlertLevelResolved && alertCopy.MetricName != "" {
				// All configured channels failed: shorten cooldown to a bounded retry backoff
				// instead of burning the full cooldown window or thrashing on every tick.
				if retryScheduler, ok := d.alertMgr.(interface{ ScheduleRetry(string, time.Duration) }); ok {
					retryScheduler.ScheduleRetry(alertCopy.MetricName, defaultDeliveryRetryBackoff)
					d.logf("[daemon] all channels failed for %q; scheduling delivery retry in %v", alertCopy.MetricName, defaultDeliveryRetryBackoff)
				}
			}
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

	// 4. Dead-man's-switch aliveness ping (also ticked independently in Run)
	if d.heartbeat != nil && d.cfg.Heartbeat.Enabled {
		d.heartbeat.TickContext(ctx, now)
	}

	return metrics
}

func (d *Daemon) dispatch(ctx context.Context, a *models.Alert, label string) bool {
	if d.dispatcher == nil || a == nil {
		return true
	}
	errs := d.dispatcher.DispatchContext(ctx, a)
	for chName, chErr := range errs {
		d.logf("[daemon] failed to dispatch %s to channel %q: %v", label, chName, chErr)
	}
	if len(errs) == 0 {
		return true
	}
	if chProvider, ok := d.dispatcher.(interface{ Channels() []notifier.Channel }); ok {
		total := len(chProvider.Channels())
		if total > 0 && len(errs) >= total {
			return false
		}
	}
	return true
}

func (d *Daemon) warnIfNoChannels() {
	if d.dispatcher == nil {
		d.logf("[daemon] warning: no notification dispatcher configured; alerts will not be delivered")
		return
	}
	if chProvider, ok := d.dispatcher.(interface{ Channels() []notifier.Channel }); ok {
		if len(chProvider.Channels()) == 0 {
			d.logf("[daemon] warning: no notification channels enabled; alerts will not be delivered")
		}
	}
}

func (d *Daemon) runHeartbeatLoop(ctx context.Context) {
	hbInterval := time.Duration(d.cfg.Heartbeat.IntervalSeconds) * time.Second
	if hbInterval <= 0 {
		hbInterval = 60 * time.Second
	}
	tickInterval := hbInterval
	if tickInterval > maxHeartbeatLoopTick {
		tickInterval = maxHeartbeatLoopTick
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			d.heartbeat.TickContext(ctx, now)
		}
	}
}

// Run starts the continuous monitoring daemon loop. It runs Step on each ticker tick
// and terminates cleanly when ctx is canceled.
func (d *Daemon) Run(ctx context.Context) error {
	d.logf("[daemon] starting server-monitor daemon for %q (check interval: %v)", d.cfg.Server.Name, d.interval)
	d.warnIfNoChannels()

	// Run heartbeat on an independent goroutine so slow collection or alert dispatch
	// never starves dead-man's-switch aliveness pings.
	var bgWG sync.WaitGroup
	if d.heartbeat != nil && d.cfg.Heartbeat.Enabled {
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			d.runHeartbeatLoop(ctx)
		}()
	}

	// Execute initial check on startup and reuse its metrics for startup notification
	initialMetrics := d.step(ctx)

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
			bgWG.Wait()
			if d.cfg.Alerting.NotifyOnShutdown && d.dispatcher != nil {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				// Reuse last cached metrics so a wedged collector cannot delay shutdown alerting.
				d.sendLifecycleNotification(shutdownCtx, false, d.getLastMetrics())
				cancel()
			}
			return nil
		case <-ticker.C:
			d.step(ctx)
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
