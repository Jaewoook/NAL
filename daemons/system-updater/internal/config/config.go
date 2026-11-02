package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type WebConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	PublicURL string `yaml:"public_url"`
}

type AuthConfig struct {
	OIDCIssuer       string `yaml:"oidc_issuer"`
	OIDCClientID     string `yaml:"oidc_client_id"`
	OIDCClientSecret string `yaml:"oidc_client_secret"`
	RedirectURL      string `yaml:"redirect_url"`
	SessionSecret    string `yaml:"session_secret"`
	SessionTTLHours  int    `yaml:"session_ttl_hours"`
	RPID             string `yaml:"rp_id"`
	RPOrigin         string `yaml:"rp_origin"`
}

type DatabaseConfig struct {
	DSN           string `yaml:"dsn"`
	ContainerName string `yaml:"container_name"`
	DBName        string `yaml:"db_name"`
	DBUser        string `yaml:"db_user"`
	DBPass        string `yaml:"db_pass"`
	DataDir       string `yaml:"data_dir"`
}

type ScannerConfig struct {
	IntervalHours  int    `yaml:"interval_hours"`
	EoLWarningDays int    `yaml:"eol_warning_days"`
	ServicesDir    string `yaml:"services_dir"`
	DaemonsDir     string `yaml:"daemons_dir"`
	OSVAPIURL      string `yaml:"osv_api_url"`
	EoLAPIURL      string `yaml:"eol_api_url"`
}

type UpdaterConfig struct {
	BatchDir              string            `yaml:"batch_dir"`
	DeadManTimeoutSeconds int               `yaml:"deadman_timeout_seconds"`
	CriticalServices      []string          `yaml:"critical_services"`
	StatefulVolumes       map[string]string `yaml:"stateful_volumes"`
	ExternalProbeURL      string            `yaml:"external_probe_url"`
}

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

type NotificationsConfig struct {
	Email EmailConfig `yaml:"email"`
}

type LoggingConfig struct {
	Enabled  bool   `yaml:"enabled"`
	FilePath string `yaml:"file_path"`
	Console  bool   `yaml:"console"`
}

type Config struct {
	NodeName      string              `yaml:"node_name"`
	AgentToken    string              `yaml:"agent_token"`
	Web           WebConfig           `yaml:"web"`
	Auth          AuthConfig          `yaml:"auth"`
	Database      DatabaseConfig      `yaml:"database"`
	Scanner       ScannerConfig       `yaml:"scanner"`
	Updater       UpdaterConfig       `yaml:"updater"`
	Notifications NotificationsConfig `yaml:"notifications"`
	Logging       LoggingConfig       `yaml:"logging"`
}

func DefaultConfig() *Config {
	return &Config{
		NodeName: "Axis",
		Web: WebConfig{
			Host:      "0.0.0.0",
			Port:      10246,
			PublicURL: "http://localhost:10246",
		},
		Auth: AuthConfig{
			OIDCIssuer:      "",
			OIDCClientID:    "system-updater",
			RedirectURL:     "http://localhost:10246/api/auth/oidc/callback",
			SessionSecret:   "default-dev-session-secret-change-in-prod",
			SessionTTLHours: 24,
			RPID:            "localhost",
			RPOrigin:        "http://localhost:10246",
		},
		Database: DatabaseConfig{
			DSN:           "postgres://system_updater:system_updater_pass@127.0.0.1:5432/system_updater?sslmode=disable",
			ContainerName: "postgresql",
			DBName:        "system_updater",
			DBUser:        "system_updater",
			DBPass:        "system_updater_pass",
			DataDir:       "data",
		},
		Scanner: ScannerConfig{
			IntervalHours:  6,
			EoLWarningDays: 30,
			ServicesDir:    "../../services",
			DaemonsDir:     "..",
			OSVAPIURL:      "https://api.osv.dev/v1/querybatch",
			EoLAPIURL:      "https://endoflife.date/api/v1/products",
		},
		Updater: UpdaterConfig{
			BatchDir:              "../../batch",
			DeadManTimeoutSeconds: 60,
			CriticalServices: []string{
				"cloudflare-tunnel",
				"nginx-proxy",
				"auth",
				"db",
				"dns",
			},
			StatefulVolumes: map[string]string{
				"db":          "nal_main_db",
				"dns":         "nal_dns_config",
				"iot":         "nal_ha_config",
				"nginx-proxy": "nginx_proxy_data",
			},
			ExternalProbeURL: "https://auth.jaewook.dev",
		},
		Notifications: NotificationsConfig{
			Email: EmailConfig{
				Enabled:  false,
				SMTPHost: "smtp.gmail.com",
				SMTPPort: 587,
				UseTLS:   true,
			},
		},
		Logging: LoggingConfig{
			Enabled:  true,
			FilePath: "system-updater.log",
			Console:  true,
		},
	}
}

func DefaultConfigWithEnv() *Config {
	cfg := DefaultConfig()
	ApplyEnvOverrides(cfg)
	ValidateAndApplyDefaults(cfg)
	return cfg
}

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

func ApplyEnvOverrides(cfg *Config) {
	if v := getEnv("UPDATER_NODE_NAME", "NODE_NAME"); v != "" {
		cfg.NodeName = v
	}
	if v := getEnv("UPDATER_AGENT_TOKEN", "NODE_TOKEN"); v != "" {
		cfg.AgentToken = v
	}
	if v := getEnv("UPDATER_HOST"); v != "" {
		cfg.Web.Host = v
	}
	if v := getEnv("UPDATER_PORT", "PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			cfg.Web.Port = p
		}
	}
	if v := getEnv("UPDATER_PUBLIC_URL"); v != "" {
		cfg.Web.PublicURL = v
	}
	if v := getEnv("AUTHENTIK_ISSUER", "OIDC_ISSUER"); v != "" {
		cfg.Auth.OIDCIssuer = v
	}
	if v := getEnv("AUTHENTIK_CLIENT_ID", "OIDC_CLIENT_ID"); v != "" {
		cfg.Auth.OIDCClientID = v
	}
	if v := getEnv("AUTHENTIK_CLIENT_SECRET", "OIDC_CLIENT_SECRET"); v != "" {
		cfg.Auth.OIDCClientSecret = v
	}
	if v := getEnv("SESSION_SECRET", "NEXTAUTH_SECRET"); v != "" {
		cfg.Auth.SessionSecret = v
	}
	if v := getEnv("PG_DSN", "DATABASE_URL"); v != "" {
		cfg.Database.DSN = v
	}
	if v := getEnv("SYSTEM_UPDATER_DB_NAME", "PG_DB"); v != "" {
		cfg.Database.DBName = v
	}
	if v := getEnv("SYSTEM_UPDATER_DB_USER", "PG_USER"); v != "" {
		cfg.Database.DBUser = v
	}
	if v := getEnv("SYSTEM_UPDATER_DB_PASS", "PG_PASS"); v != "" {
		cfg.Database.DBPass = v
	}
	if v := getEnv("UPDATER_DATA_DIR"); v != "" {
		cfg.Database.DataDir = v
	}
	if v := getEnv("EMAIL_HOST", "SMTP_HOST"); v != "" {
		cfg.Notifications.Email.SMTPHost = v
	}
	if v := getEnv("EMAIL_PORT", "SMTP_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			cfg.Notifications.Email.SMTPPort = p
		}
	}
	if v := getEnv("EMAIL_USERNAME", "SMTP_USERNAME"); v != "" {
		cfg.Notifications.Email.Username = v
	}
	if v := getEnv("EMAIL_PASSWORD", "SMTP_PASSWORD"); v != "" {
		cfg.Notifications.Email.Password = v
	}
	if v := getEnv("EMAIL_FROM", "SMTP_FROM"); v != "" {
		cfg.Notifications.Email.FromEmail = v
	}
	if v := getEnv("EMAIL_TO", "SMTP_TO"); v != "" {
		cfg.Notifications.Email.ToEmail = v
		cfg.Notifications.Email.Enabled = true
	}
	if v := getEnv("EMAIL_ENABLED"); v != "" {
		cfg.Notifications.Email.Enabled = (v == "true" || v == "1" || v == "yes")
	}
}

func ValidateAndApplyDefaults(cfg *Config) {
	if cfg.NodeName == "" {
		cfg.NodeName = "Axis"
	}
	if cfg.Web.Port <= 0 {
		cfg.Web.Port = 10246
	}
	if cfg.Auth.SessionTTLHours <= 0 {
		cfg.Auth.SessionTTLHours = 24
	}
	if cfg.Database.DataDir == "" {
		cfg.Database.DataDir = "data"
	}
	if cfg.Scanner.IntervalHours <= 0 {
		cfg.Scanner.IntervalHours = 6
	}
	if cfg.Scanner.EoLWarningDays <= 0 {
		cfg.Scanner.EoLWarningDays = 30
	}
	if cfg.Updater.DeadManTimeoutSeconds <= 0 {
		cfg.Updater.DeadManTimeoutSeconds = 60
	}
	if len(cfg.Updater.CriticalServices) == 0 {
		cfg.Updater.CriticalServices = []string{"cloudflare-tunnel", "nginx-proxy", "auth", "db", "dns"}
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
