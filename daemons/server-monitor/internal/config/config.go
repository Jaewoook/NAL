package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jaewoook/server-monitor/internal/models"
)

// DefaultConfigFilenames defines the canonical config file search order.
var DefaultConfigFilenames = []string{"config.yml", "config.yaml"}

// ServerConfig defines basic server identification and sampling rate.
type ServerConfig struct {
	Name                 string `yaml:"name"`
	CheckIntervalSeconds int    `yaml:"check_interval_seconds"`
}

// CPUSpikeConfig configures high CPU spike alerting.
type CPUSpikeConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent"`
	SustainedSeconds int     `yaml:"sustained_seconds"`
	CooldownMinutes  int     `yaml:"cooldown_minutes"`
}

// CPUPlungeDropConfig configures abrupt CPU plunge drop alerting.
type CPUPlungeDropConfig struct {
	Enabled         bool    `yaml:"enabled"`
	DeltaPercent    float64 `yaml:"delta_percent"`
	FromMinPercent  float64 `yaml:"from_min_percent"`
	WindowSeconds   int     `yaml:"window_seconds"`
	CooldownMinutes int     `yaml:"cooldown_minutes"`
}

// CPUFloorDropConfig configures idle floor drop alerting.
type CPUFloorDropConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent"`
	SustainedSeconds int     `yaml:"sustained_seconds"`
	CooldownMinutes  int     `yaml:"cooldown_minutes"`
}

// CPUConfig bundles CPU anomaly detection parameters.
type CPUConfig struct {
	Spike             CPUSpikeConfig      `yaml:"spike"`
	PlungeDrop        CPUPlungeDropConfig `yaml:"plunge_drop"`
	FloorDrop         CPUFloorDropConfig  `yaml:"floor_drop"`
	TopProcessesCount int                 `yaml:"top_processes_count"`
}

// MemoryHealthConfig configures memory usage alerting.
type MemoryHealthConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent"`
	SustainedSeconds int     `yaml:"sustained_seconds"`
	CooldownMinutes  int     `yaml:"cooldown_minutes"`
}

// DiskHealthConfig configures disk usage alerting.
type DiskHealthConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent"`
	MountPoint       string  `yaml:"mount_point"`
	CooldownMinutes  int     `yaml:"cooldown_minutes"`
}

// TemperatureHealthConfig configures CPU and GPU thermal alerting.
type TemperatureHealthConfig struct {
	Enabled             bool    `yaml:"enabled"`
	CPUThresholdCelsius float64 `yaml:"cpu_threshold_celsius"`
	GPUThresholdCelsius float64 `yaml:"gpu_threshold_celsius"`
	SustainedSeconds    int     `yaml:"sustained_seconds"`
	CooldownMinutes     int     `yaml:"cooldown_minutes"`
}

// HealthConfig bundles general system health checks.
type HealthConfig struct {
	Memory      MemoryHealthConfig      `yaml:"memory"`
	Disk        DiskHealthConfig        `yaml:"disk"`
	Temperature TemperatureHealthConfig `yaml:"temperature"`
}

// AlertingConfig defines global alert manager options.
type AlertingConfig struct {
	NotifyOnRecovery bool `yaml:"notify_on_recovery"`
	NotifyOnStartup  bool `yaml:"notify_on_startup"`
	NotifyOnShutdown bool `yaml:"notify_on_shutdown"`
}

// HeartbeatConfig configures dead-man's-switch aliveness pings.
type HeartbeatConfig struct {
	Enabled         bool   `yaml:"enabled"`
	URL             string `yaml:"url"`
	IntervalSeconds int    `yaml:"interval_seconds"`
}

// DigestConfig configures periodic health status summaries.
type DigestConfig struct {
	Enabled       bool `yaml:"enabled"`
	IntervalHours int  `yaml:"interval_hours"`
}

// TelegramConfig defines settings for Telegram bot notifications.
type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

// DiscordConfig defines settings for Discord webhook notifications.
type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// SlackConfig defines settings for Slack incoming webhooks.
type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// EmailConfig defines SMTP settings for email alerting.
type EmailConfig struct {
	Enabled   bool   `yaml:"enabled"`
	SMTPHost  string `yaml:"smtp_host"`
	SMTPPort  int    `yaml:"smtp_port"`
	UseTLS    bool   `yaml:"use_tls"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	FromEmail string `yaml:"from_email"`
	ToEmail   string `yaml:"to_email"`
}

// WebhookConfig defines generic HTTP webhook notification settings.
type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

// NotificationsConfig bundles all supported notification channels.
type NotificationsConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Discord  DiscordConfig  `yaml:"discord"`
	Slack    SlackConfig    `yaml:"slack"`
	Email    EmailConfig    `yaml:"email"`
	Webhook  WebhookConfig  `yaml:"webhook"`
}

// LoggingConfig configures dedicated file logging and log rotation.
type LoggingConfig struct {
	Enabled    bool   `yaml:"enabled"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	Console    bool   `yaml:"console"`
}

// Config represents the complete daemon configuration.
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	CPU           CPUConfig           `yaml:"cpu"`
	Health        HealthConfig        `yaml:"health"`
	Alerting      AlertingConfig      `yaml:"alerting"`
	Heartbeat     HeartbeatConfig     `yaml:"heartbeat"`
	Digest        DigestConfig        `yaml:"digest"`
	Notifications NotificationsConfig `yaml:"notifications"`
	Logging       LoggingConfig       `yaml:"logging"`
}

// DefaultConfig returns a Config struct populated with sensible production defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Name:                 "server",
			CheckIntervalSeconds: 5,
		},
		CPU: CPUConfig{
			Spike: CPUSpikeConfig{
				Enabled:          true,
				ThresholdPercent: 85.0,
				SustainedSeconds: 15,
				CooldownMinutes:  30,
			},
			PlungeDrop: CPUPlungeDropConfig{
				Enabled:         true,
				DeltaPercent:    40.0,
				FromMinPercent:  50.0,
				WindowSeconds:   15,
				CooldownMinutes: 15,
			},
			FloorDrop: CPUFloorDropConfig{
				Enabled:          false,
				ThresholdPercent: 5.0,
				SustainedSeconds: 30,
				CooldownMinutes:  30,
			},
			TopProcessesCount: 5,
		},
		Health: HealthConfig{
			Memory: MemoryHealthConfig{
				Enabled:          true,
				ThresholdPercent: 90.0,
				SustainedSeconds: 15,
				CooldownMinutes:  30,
			},
			Disk: DiskHealthConfig{
				Enabled:          true,
				ThresholdPercent: 85.0,
				MountPoint:       "/",
				CooldownMinutes:  60,
			},
			Temperature: TemperatureHealthConfig{
				Enabled:             true,
				CPUThresholdCelsius: 75.0,
				GPUThresholdCelsius: 75.0,
				SustainedSeconds:    30,
				CooldownMinutes:     30,
			},
		},
		Alerting: AlertingConfig{
			NotifyOnRecovery: true,
			NotifyOnStartup:  false,
			NotifyOnShutdown: false,
		},
		Heartbeat: HeartbeatConfig{
			Enabled:         false,
			URL:             "",
			IntervalSeconds: 60,
		},
		Digest: DigestConfig{
			Enabled:       false,
			IntervalHours: 24,
		},
		Notifications: NotificationsConfig{
			Telegram: TelegramConfig{
				Enabled:  false,
				BotToken: "",
				ChatID:   "",
			},
			Discord: DiscordConfig{
				Enabled:    false,
				WebhookURL: "",
			},
			Slack: SlackConfig{
				Enabled:    false,
				WebhookURL: "",
			},
			Email: EmailConfig{
				Enabled:   false,
				SMTPHost:  "smtp.gmail.com",
				SMTPPort:  587,
				UseTLS:    true,
				Username:  "",
				Password:  "",
				FromEmail: "",
				ToEmail:   "",
			},
			Webhook: WebhookConfig{
				Enabled: false,
				URL:     "",
			},
		},
		Logging: LoggingConfig{
			Enabled:    true,
			FilePath:   "server-monitor.log",
			MaxSizeMB:  10,
			MaxBackups: 3,
			Console:    true,
		},
	}
}

// DefaultConfigWithEnv returns a default configuration with environment variable
// overrides and validated defaults applied.
func DefaultConfigWithEnv() *Config {
	cfg := DefaultConfig()
	ApplyEnvOverrides(cfg)
	ValidateAndApplyDefaults(cfg)
	return cfg
}

// LoadConfig reads a YAML configuration file from path, merges with defaults,
// and applies any environment variable overrides.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config %q: %w", path, err)
	}

	ApplyEnvOverrides(cfg)
	ValidateAndApplyDefaults(cfg)

	return cfg, nil
}

// ApplyEnvOverrides overrides configuration fields from environment variables.
func ApplyEnvOverrides(cfg *Config) {
	// Server
	applyEnvString(&cfg.Server.Name, "SERVER_NAME")
	applyEnvInt(&cfg.Server.CheckIntervalSeconds, 1, "CHECK_INTERVAL_SECONDS")

	// CPU & Health thresholds
	applyEnvFloat(&cfg.CPU.Spike.ThresholdPercent, 0.0001, "CPU_SPIKE_THRESHOLD")
	applyEnvInt(&cfg.CPU.Spike.SustainedSeconds, 1, "CPU_SPIKE_SUSTAINED_SECONDS")
	applyEnvFloat(&cfg.Health.Memory.ThresholdPercent, 0.0001, "MEMORY_THRESHOLD")
	applyEnvFloat(&cfg.Health.Disk.ThresholdPercent, 0.0001, "DISK_THRESHOLD")

	// Temperature
	applyEnvBool(&cfg.Health.Temperature.Enabled, "TEMP_ENABLED", "TEMPERATURE_ENABLED")
	applyEnvFloat(&cfg.Health.Temperature.CPUThresholdCelsius, 0.0001, "TEMP_CPU_THRESHOLD", "CPU_TEMP_THRESHOLD")
	applyEnvFloat(&cfg.Health.Temperature.GPUThresholdCelsius, 0.0001, "TEMP_GPU_THRESHOLD", "GPU_TEMP_THRESHOLD")
	applyEnvInt(&cfg.Health.Temperature.SustainedSeconds, 1, "TEMP_SUSTAINED_SECONDS")
	applyEnvInt(&cfg.Health.Temperature.CooldownMinutes, 1, "TEMP_COOLDOWN_MINUTES")

	// Notifications
	if val := getEnv("TELEGRAM_BOT_TOKEN", "BOT_TOKEN"); val != "" {
		cfg.Notifications.Telegram.BotToken = val
		cfg.Notifications.Telegram.Enabled = true
	}
	applyEnvString(&cfg.Notifications.Telegram.ChatID, "TELEGRAM_CHAT_ID", "DEFAULT_CHAT_ID", "CHAT_ID")
	applyEnvBool(&cfg.Notifications.Telegram.Enabled, "TELEGRAM_ENABLED")

	if val := getEnv("DISCORD_WEBHOOK_URL"); val != "" {
		cfg.Notifications.Discord.WebhookURL = val
		cfg.Notifications.Discord.Enabled = true
	}
	applyEnvBool(&cfg.Notifications.Discord.Enabled, "DISCORD_ENABLED")

	if val := getEnv("SLACK_WEBHOOK_URL"); val != "" {
		cfg.Notifications.Slack.WebhookURL = val
		cfg.Notifications.Slack.Enabled = true
	}
	applyEnvBool(&cfg.Notifications.Slack.Enabled, "SLACK_ENABLED")

	applyEnvString(&cfg.Notifications.Email.Username, "EMAIL_USERNAME")
	applyEnvString(&cfg.Notifications.Email.Password, "EMAIL_PASSWORD")
	applyEnvString(&cfg.Notifications.Email.FromEmail, "EMAIL_FROM")
	applyEnvString(&cfg.Notifications.Email.ToEmail, "EMAIL_TO")
	applyEnvBool(&cfg.Notifications.Email.Enabled, "EMAIL_ENABLED")

	if val := getEnv("WEBHOOK_URL"); val != "" {
		cfg.Notifications.Webhook.URL = val
		cfg.Notifications.Webhook.Enabled = true
	}
	applyEnvBool(&cfg.Notifications.Webhook.Enabled, "WEBHOOK_ENABLED")

	// Heartbeat
	if val := getEnv("HEARTBEAT_URL"); val != "" {
		cfg.Heartbeat.URL = val
		cfg.Heartbeat.Enabled = true
	}
	applyEnvBool(&cfg.Heartbeat.Enabled, "HEARTBEAT_ENABLED")
	applyEnvInt(&cfg.Heartbeat.IntervalSeconds, 1, "HEARTBEAT_INTERVAL_SECONDS")

	// Alerting
	applyEnvBool(&cfg.Alerting.NotifyOnRecovery, "NOTIFY_ON_RECOVERY")
	applyEnvBool(&cfg.Alerting.NotifyOnStartup, "NOTIFY_ON_STARTUP")
	applyEnvBool(&cfg.Alerting.NotifyOnShutdown, "NOTIFY_ON_SHUTDOWN")

	// Logging
	applyEnvString(&cfg.Logging.FilePath, "LOG_FILE", "LOG_FILE_PATH")
	applyEnvBool(&cfg.Logging.Enabled, "LOG_ENABLED")
	applyEnvInt(&cfg.Logging.MaxSizeMB, 1, "LOG_MAX_SIZE_MB")
	applyEnvInt(&cfg.Logging.MaxBackups, 0, "LOG_MAX_BACKUPS")
	applyEnvBool(&cfg.Logging.Console, "LOG_CONSOLE")
}

func getEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func applyEnvString(dst *string, keys ...string) {
	if val := getEnv(keys...); val != "" {
		*dst = val
	}
}

func applyEnvBool(dst *bool, keys ...string) {
	if val := getEnv(keys...); val != "" {
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true", "1", "yes":
			*dst = true
		default:
			*dst = false
		}
	}
}

func applyEnvInt(dst *int, minVal int, keys ...string) {
	if val := getEnv(keys...); val != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && n >= minVal {
			*dst = n
		}
	}
}

func applyEnvFloat(dst *float64, minVal float64, keys ...string) {
	if val := getEnv(keys...); val != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil && f >= minVal {
			*dst = f
		}
	}
}

func defaultInt(dst *int, fallback int) {
	if *dst <= 0 {
		*dst = fallback
	}
}

func defaultFloat(dst *float64, fallback float64) {
	if *dst <= 0 {
		*dst = fallback
	}
}

func defaultString(dst *string, fallback string) {
	if *dst == "" {
		*dst = fallback
	}
}

// ValidateAndApplyDefaults ensures required fields have valid fallback values
// sourced from DefaultConfig.
func ValidateAndApplyDefaults(cfg *Config) {
	def := DefaultConfig()

	defaultInt(&cfg.Server.CheckIntervalSeconds, def.Server.CheckIntervalSeconds)

	defaultFloat(&cfg.CPU.Spike.ThresholdPercent, def.CPU.Spike.ThresholdPercent)
	defaultInt(&cfg.CPU.Spike.SustainedSeconds, def.CPU.Spike.SustainedSeconds)
	defaultInt(&cfg.CPU.Spike.CooldownMinutes, def.CPU.Spike.CooldownMinutes)

	defaultFloat(&cfg.CPU.PlungeDrop.DeltaPercent, def.CPU.PlungeDrop.DeltaPercent)
	defaultFloat(&cfg.CPU.PlungeDrop.FromMinPercent, def.CPU.PlungeDrop.FromMinPercent)
	defaultInt(&cfg.CPU.PlungeDrop.WindowSeconds, def.CPU.PlungeDrop.WindowSeconds)
	defaultInt(&cfg.CPU.PlungeDrop.CooldownMinutes, def.CPU.PlungeDrop.CooldownMinutes)

	defaultFloat(&cfg.CPU.FloorDrop.ThresholdPercent, def.CPU.FloorDrop.ThresholdPercent)
	defaultInt(&cfg.CPU.FloorDrop.SustainedSeconds, def.CPU.FloorDrop.SustainedSeconds)
	defaultInt(&cfg.CPU.FloorDrop.CooldownMinutes, def.CPU.FloorDrop.CooldownMinutes)
	defaultInt(&cfg.CPU.TopProcessesCount, def.CPU.TopProcessesCount)

	defaultFloat(&cfg.Health.Memory.ThresholdPercent, def.Health.Memory.ThresholdPercent)
	defaultInt(&cfg.Health.Memory.SustainedSeconds, def.Health.Memory.SustainedSeconds)
	defaultInt(&cfg.Health.Memory.CooldownMinutes, def.Health.Memory.CooldownMinutes)

	defaultFloat(&cfg.Health.Disk.ThresholdPercent, def.Health.Disk.ThresholdPercent)
	defaultString(&cfg.Health.Disk.MountPoint, def.Health.Disk.MountPoint)
	defaultInt(&cfg.Health.Disk.CooldownMinutes, def.Health.Disk.CooldownMinutes)

	defaultFloat(&cfg.Health.Temperature.CPUThresholdCelsius, def.Health.Temperature.CPUThresholdCelsius)
	defaultFloat(&cfg.Health.Temperature.GPUThresholdCelsius, def.Health.Temperature.GPUThresholdCelsius)
	defaultInt(&cfg.Health.Temperature.SustainedSeconds, def.Health.Temperature.SustainedSeconds)
	defaultInt(&cfg.Health.Temperature.CooldownMinutes, def.Health.Temperature.CooldownMinutes)

	defaultInt(&cfg.Heartbeat.IntervalSeconds, def.Heartbeat.IntervalSeconds)
	defaultInt(&cfg.Digest.IntervalHours, def.Digest.IntervalHours)

	defaultString(&cfg.Logging.FilePath, def.Logging.FilePath)
	defaultInt(&cfg.Logging.MaxSizeMB, def.Logging.MaxSizeMB)
	if cfg.Logging.MaxBackups < 0 {
		cfg.Logging.MaxBackups = def.Logging.MaxBackups
	}
}

// RuleCooldowns returns the configured per-rule cooldown durations keyed by canonical rule ID.
func (c *Config) RuleCooldowns() map[string]time.Duration {
	if c == nil {
		return nil
	}
	return map[string]time.Duration{
		models.RuleCPUSpike:  time.Duration(c.CPU.Spike.CooldownMinutes) * time.Minute,
		models.RuleCPUPlunge: time.Duration(c.CPU.PlungeDrop.CooldownMinutes) * time.Minute,
		models.RuleCPUFloor:  time.Duration(c.CPU.FloorDrop.CooldownMinutes) * time.Minute,
		models.RuleMemory:    time.Duration(c.Health.Memory.CooldownMinutes) * time.Minute,
		models.RuleDisk:      time.Duration(c.Health.Disk.CooldownMinutes) * time.Minute,
		models.RuleCPUTemp:   time.Duration(c.Health.Temperature.CooldownMinutes) * time.Minute,
		models.RuleGPUTemp:   time.Duration(c.Health.Temperature.CooldownMinutes) * time.Minute,
	}
}
