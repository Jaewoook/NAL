package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

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

// HealthConfig bundles general system health checks.
type HealthConfig struct {
	Memory MemoryHealthConfig `yaml:"memory"`
	Disk   DiskHealthConfig   `yaml:"disk"`
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
	Enabled  bool   `yaml:"enabled"`
	SMTPHost string `yaml:"smtp_host"`
	SMTPPort int    `yaml:"smtp_port"`
	UseTLS   bool   `yaml:"use_tls"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	ToEmail  string `yaml:"to_email"`
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
				Enabled:  false,
				SMTPHost: "smtp.gmail.com",
				SMTPPort: 587,
				UseTLS:   true,
				Username: "",
				Password: "",
				ToEmail:  "",
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
	if val := getEnv("SERVER_NAME"); val != "" {
		cfg.Server.Name = val
	}
	if val := getEnv("TELEGRAM_BOT_TOKEN", "BOT_TOKEN"); val != "" {
		cfg.Notifications.Telegram.BotToken = val
		cfg.Notifications.Telegram.Enabled = true
	}
	if val := getEnv("TELEGRAM_CHAT_ID", "DEFAULT_CHAT_ID", "CHAT_ID"); val != "" {
		cfg.Notifications.Telegram.ChatID = val
	}
	if val := getEnv("TELEGRAM_ENABLED"); val != "" {
		cfg.Notifications.Telegram.Enabled = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("DISCORD_WEBHOOK_URL"); val != "" {
		cfg.Notifications.Discord.WebhookURL = val
		cfg.Notifications.Discord.Enabled = true
	}
	if val := getEnv("DISCORD_ENABLED"); val != "" {
		cfg.Notifications.Discord.Enabled = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("SLACK_WEBHOOK_URL"); val != "" {
		cfg.Notifications.Slack.WebhookURL = val
		cfg.Notifications.Slack.Enabled = true
	}
	if val := getEnv("SLACK_ENABLED"); val != "" {
		cfg.Notifications.Slack.Enabled = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("EMAIL_USERNAME"); val != "" {
		cfg.Notifications.Email.Username = val
	}
	if val := getEnv("EMAIL_PASSWORD"); val != "" {
		cfg.Notifications.Email.Password = val
	}
	if val := getEnv("EMAIL_TO"); val != "" {
		cfg.Notifications.Email.ToEmail = val
	}
	if val := getEnv("EMAIL_ENABLED"); val != "" {
		cfg.Notifications.Email.Enabled = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("WEBHOOK_URL"); val != "" {
		cfg.Notifications.Webhook.URL = val
		cfg.Notifications.Webhook.Enabled = true
	}
	if val := getEnv("WEBHOOK_ENABLED"); val != "" {
		cfg.Notifications.Webhook.Enabled = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("HEARTBEAT_URL"); val != "" {
		cfg.Heartbeat.URL = val
		cfg.Heartbeat.Enabled = true
	}
	if val := getEnv("HEARTBEAT_ENABLED"); val != "" {
		cfg.Heartbeat.Enabled = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("NOTIFY_ON_RECOVERY"); val != "" {
		cfg.Alerting.NotifyOnRecovery = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("NOTIFY_ON_STARTUP"); val != "" {
		cfg.Alerting.NotifyOnStartup = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("NOTIFY_ON_SHUTDOWN"); val != "" {
		cfg.Alerting.NotifyOnShutdown = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("LOG_FILE", "LOG_FILE_PATH"); val != "" {
		cfg.Logging.FilePath = val
	}
	if val := getEnv("LOG_ENABLED"); val != "" {
		cfg.Logging.Enabled = (val == "true" || val == "1" || val == "yes")
	}
	if val := getEnv("LOG_MAX_SIZE_MB"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Logging.MaxSizeMB = n
		}
	}
	if val := getEnv("LOG_MAX_BACKUPS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 0 {
			cfg.Logging.MaxBackups = n
		}
	}
	if val := getEnv("LOG_CONSOLE"); val != "" {
		cfg.Logging.Console = (val == "true" || val == "1" || val == "yes")
	}
}

func getEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// ValidateAndApplyDefaults ensures required fields have valid fallback values.
func ValidateAndApplyDefaults(cfg *Config) {
	if cfg.Server.CheckIntervalSeconds <= 0 {
		cfg.Server.CheckIntervalSeconds = 5
	}
	if cfg.CPU.Spike.ThresholdPercent <= 0 {
		cfg.CPU.Spike.ThresholdPercent = 85.0
	}
	if cfg.CPU.Spike.SustainedSeconds <= 0 {
		cfg.CPU.Spike.SustainedSeconds = 15
	}
	if cfg.CPU.Spike.CooldownMinutes <= 0 {
		cfg.CPU.Spike.CooldownMinutes = 30
	}
	if cfg.CPU.PlungeDrop.DeltaPercent <= 0 {
		cfg.CPU.PlungeDrop.DeltaPercent = 40.0
	}
	if cfg.CPU.PlungeDrop.FromMinPercent <= 0 {
		cfg.CPU.PlungeDrop.FromMinPercent = 50.0
	}
	if cfg.CPU.PlungeDrop.WindowSeconds <= 0 {
		cfg.CPU.PlungeDrop.WindowSeconds = 15
	}
	if cfg.CPU.PlungeDrop.CooldownMinutes <= 0 {
		cfg.CPU.PlungeDrop.CooldownMinutes = 15
	}
	if cfg.CPU.FloorDrop.ThresholdPercent <= 0 {
		cfg.CPU.FloorDrop.ThresholdPercent = 5.0
	}
	if cfg.CPU.FloorDrop.SustainedSeconds <= 0 {
		cfg.CPU.FloorDrop.SustainedSeconds = 30
	}
	if cfg.CPU.FloorDrop.CooldownMinutes <= 0 {
		cfg.CPU.FloorDrop.CooldownMinutes = 30
	}
	if cfg.CPU.TopProcessesCount <= 0 {
		cfg.CPU.TopProcessesCount = 5
	}
	if cfg.Health.Memory.ThresholdPercent <= 0 {
		cfg.Health.Memory.ThresholdPercent = 90.0
	}
	if cfg.Health.Memory.SustainedSeconds <= 0 {
		cfg.Health.Memory.SustainedSeconds = 15
	}
	if cfg.Health.Memory.CooldownMinutes <= 0 {
		cfg.Health.Memory.CooldownMinutes = 30
	}
	if cfg.Health.Disk.ThresholdPercent <= 0 {
		cfg.Health.Disk.ThresholdPercent = 85.0
	}
	if cfg.Health.Disk.MountPoint == "" {
		cfg.Health.Disk.MountPoint = "/"
	}
	if cfg.Health.Disk.CooldownMinutes <= 0 {
		cfg.Health.Disk.CooldownMinutes = 60
	}
	if cfg.Heartbeat.IntervalSeconds <= 0 {
		cfg.Heartbeat.IntervalSeconds = 60
	}
	if cfg.Digest.IntervalHours <= 0 {
		cfg.Digest.IntervalHours = 24
	}
	if cfg.Logging.FilePath == "" {
		cfg.Logging.FilePath = "server-monitor.log"
	}
	if cfg.Logging.MaxSizeMB <= 0 {
		cfg.Logging.MaxSizeMB = 10
	}
	if cfg.Logging.MaxBackups <= 0 {
		cfg.Logging.MaxBackups = 3
	}
}
