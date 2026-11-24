package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultWebPort         = 10311
	defaultSessionTTLHours = 24
	defaultDataDir         = "data"
	defaultScanIntervalHrs = 6
	defaultEoLWarningDays  = 30
	defaultDeadManTimeoutS = 60
	defaultGitBotName      = "NAL Bot"
	defaultGitBotEmail     = "nal-git-system@jaewook.me"
	defaultGitGPGKey       = "024D4017DFF5360A"

	placeholderSessionSecret = "replace-with-openssl-rand-hex-32"
	placeholderAgentToken    = "replace-with-shared-lan-agent-secret"
)

func defaultCriticalServices() []string {
	return []string{"cloudflare-tunnel", "nginx-proxy", "auth", "db", "dns"}
}

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
	PublicURL        string `yaml:"public_url"`
}

type DatabaseConfig struct {
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

type GitBotConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotName  string `yaml:"bot_name"`
	BotEmail string `yaml:"bot_email"`
	GPGSign  bool   `yaml:"gpg_sign"`
	GPGKey   string `yaml:"gpg_key"`
}

type UpdaterConfig struct {
	BatchDir              string            `yaml:"batch_dir"`
	DeadManTimeoutSeconds int               `yaml:"deadman_timeout_seconds"`
	CriticalServices      []string          `yaml:"critical_services"`
	StatefulVolumes       map[string]string `yaml:"stateful_volumes"`
	Git                   GitBotConfig      `yaml:"git"`
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

type Config struct {
	NodeName          string              `yaml:"node_name"`
	AgentToken        string              `yaml:"agent_token"`
	HubURL            string              `yaml:"hub_url"`
	AgentAdvertiseURL string              `yaml:"agent_advertise_url"`
	Web               WebConfig           `yaml:"web"`
	Auth              AuthConfig          `yaml:"auth"`
	Database          DatabaseConfig      `yaml:"database"`
	Scanner           ScannerConfig       `yaml:"scanner"`
	Updater           UpdaterConfig       `yaml:"updater"`
	Notifications     NotificationsConfig `yaml:"notifications"`
}

func DefaultNodeName() string {
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSuffix(strings.TrimSpace(h), ".local")
	}
	return "local"
}

func DefaultConfig() *Config {
	return &Config{
		NodeName: DefaultNodeName(),
		Web: WebConfig{
			Host:      "0.0.0.0",
			Port:      defaultWebPort,
			PublicURL: "http://localhost:10311",
		},
		Auth: AuthConfig{
			OIDCIssuer:      "",
			OIDCClientID:    "security-hub",
			RedirectURL:     "http://localhost:10311/api/auth/oidc/callback",
			SessionSecret:   "",
			SessionTTLHours: defaultSessionTTLHours,
			RPID:            "",
			PublicURL:       "",
		},
		Database: DatabaseConfig{
			ContainerName: "postgresql",
			DBName:        "security_hub_db",
			DBUser:        "security_hub",
			DBPass:        "security_hub_pass",
			DataDir:       defaultDataDir,
		},
		Scanner: ScannerConfig{
			IntervalHours:  defaultScanIntervalHrs,
			EoLWarningDays: defaultEoLWarningDays,
			ServicesDir:    "../../services",
			DaemonsDir:     "..",
			OSVAPIURL:      "https://api.osv.dev/v1/querybatch",
			EoLAPIURL:      "https://endoflife.date/api/v1/products",
		},
		Updater: UpdaterConfig{
			BatchDir:              "../../batch",
			DeadManTimeoutSeconds: defaultDeadManTimeoutS,
			CriticalServices:      defaultCriticalServices(),
			StatefulVolumes: map[string]string{
				"db":          "nal_main_db",
				"dns":         "nal_dns_config",
				"iot":         "nal_ha_config",
				"nginx-proxy": "nginx_proxy_data",
			},
			Git: GitBotConfig{
				Enabled:  true,
				BotName:  defaultGitBotName,
				BotEmail: defaultGitBotEmail,
				GPGSign:  true,
				GPGKey:   defaultGitGPGKey,
			},
		},
		Notifications: NotificationsConfig{
			Email: EmailConfig{
				Enabled:  false,
				SMTPHost: "smtp.gmail.com",
				SMTPPort: 587,
				UseTLS:   true,
			},
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

func applyEnvString(dst *string, keys ...string) bool {
	if v := getEnv(keys...); v != "" {
		*dst = v
		return true
	}
	return false
}

func applyEnvPositiveInt(dst *int, keys ...string) {
	if v := getEnv(keys...); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			*dst = p
		}
	}
}

func applyEnvBool(dst *bool, keys ...string) {
	if v := getEnv(keys...); v != "" {
		if b, ok := parseBoolEnv(v); ok {
			*dst = b
		}
	}
}

func ApplyEnvOverrides(cfg *Config) {
	applyEnvString(&cfg.NodeName, "SECURITY_HUB_NODE_NAME", "NODE_NAME")
	applyEnvString(&cfg.AgentToken, "SECURITY_HUB_AGENT_TOKEN", "NODE_TOKEN")
	applyEnvString(&cfg.HubURL, "SECURITY_HUB_URL", "HUB_URL")
	applyEnvString(&cfg.AgentAdvertiseURL, "SECURITY_HUB_ADVERTISE_URL", "AGENT_ADVERTISE_URL")
	applyEnvString(&cfg.Web.Host, "SECURITY_HUB_HOST")
	applyEnvPositiveInt(&cfg.Web.Port, "SECURITY_HUB_PORT", "PORT")
	applyEnvString(&cfg.Web.PublicURL, "SECURITY_HUB_PUBLIC_URL")

	applyEnvString(&cfg.Auth.OIDCIssuer, "AUTHENTIK_ISSUER", "OIDC_ISSUER")
	applyEnvString(&cfg.Auth.OIDCClientID, "AUTHENTIK_CLIENT_ID", "OIDC_CLIENT_ID")
	applyEnvString(&cfg.Auth.OIDCClientSecret, "AUTHENTIK_CLIENT_SECRET", "OIDC_CLIENT_SECRET")
	applyEnvString(&cfg.Auth.SessionSecret, "SESSION_SECRET", "NEXTAUTH_SECRET")

	applyEnvString(&cfg.Database.DBName, "SECURITY_HUB_DB_NAME", "PG_DB")
	applyEnvString(&cfg.Database.DBUser, "SECURITY_HUB_DB_USER", "PG_USER")
	applyEnvString(&cfg.Database.DBPass, "SECURITY_HUB_DB_PASS", "PG_PASS")
	applyEnvString(&cfg.Database.DataDir, "SECURITY_HUB_DATA_DIR")

	applyEnvString(&cfg.Notifications.Email.SMTPHost, "EMAIL_HOST", "SMTP_HOST")
	applyEnvPositiveInt(&cfg.Notifications.Email.SMTPPort, "EMAIL_PORT", "SMTP_PORT")
	applyEnvString(&cfg.Notifications.Email.Username, "EMAIL_USERNAME", "SMTP_USERNAME")
	applyEnvString(&cfg.Notifications.Email.Password, "EMAIL_PASSWORD", "SMTP_PASSWORD")
	applyEnvString(&cfg.Notifications.Email.FromEmail, "EMAIL_FROM", "SMTP_FROM")
	if applyEnvString(&cfg.Notifications.Email.ToEmail, "EMAIL_TO", "SMTP_TO") {
		cfg.Notifications.Email.Enabled = true
	}
	applyEnvBool(&cfg.Notifications.Email.Enabled, "EMAIL_ENABLED")

	applyEnvBool(&cfg.Updater.Git.Enabled, "SECURITY_HUB_GIT_COMMIT_ENABLED", "GIT_BOT_ENABLED")
	applyEnvString(&cfg.Updater.Git.BotName, "SECURITY_HUB_GIT_BOT_NAME", "GIT_BOT_NAME")
	applyEnvString(&cfg.Updater.Git.BotEmail, "SECURITY_HUB_GIT_BOT_EMAIL", "GIT_BOT_EMAIL")
	applyEnvBool(&cfg.Updater.Git.GPGSign, "SECURITY_HUB_GIT_GPG_SIGN", "GIT_BOT_GPG_SIGN")
	applyEnvString(&cfg.Updater.Git.GPGKey, "SECURITY_HUB_GIT_GPG_KEY", "GIT_BOT_GPG_KEY")
}

func ValidateAndApplyDefaults(cfg *Config) {
	if strings.TrimSpace(cfg.NodeName) == "" {
		cfg.NodeName = DefaultNodeName()
	}
	if cfg.AgentToken == placeholderAgentToken {
		cfg.AgentToken = ""
	}
	if cfg.Web.Port <= 0 {
		cfg.Web.Port = defaultWebPort
	}
	if cfg.Auth.SessionSecret == "" ||
		cfg.Auth.SessionSecret == "default-dev-session-secret-change-in-prod" ||
		cfg.Auth.SessionSecret == placeholderSessionSecret {
		randBytes := make([]byte, 32)
		if _, err := rand.Read(randBytes); err == nil {
			cfg.Auth.SessionSecret = hex.EncodeToString(randBytes)
		} else {
			cfg.Auth.SessionSecret = ""
		}
	}
	if cfg.Auth.SessionTTLHours <= 0 {
		cfg.Auth.SessionTTLHours = defaultSessionTTLHours
	}
	if cfg.Auth.PublicURL == "" && cfg.Web.PublicURL != "" {
		cfg.Auth.PublicURL = cfg.Web.PublicURL
	}
	if strings.TrimSpace(cfg.Auth.RPID) == "" {
		for _, candidate := range []string{cfg.Auth.PublicURL, cfg.Web.PublicURL, cfg.Auth.RedirectURL} {
			if candidate == "" {
				continue
			}
			if u, err := url.Parse(candidate); err == nil && u.Hostname() != "" {
				cfg.Auth.RPID = u.Hostname()
				break
			}
		}
		if strings.TrimSpace(cfg.Auth.RPID) == "" {
			cfg.Auth.RPID = "localhost"
		}
	}
	if cfg.Database.DataDir == "" {
		cfg.Database.DataDir = defaultDataDir
	}
	if cfg.Scanner.IntervalHours <= 0 {
		cfg.Scanner.IntervalHours = defaultScanIntervalHrs
	}
	if cfg.Scanner.EoLWarningDays <= 0 {
		cfg.Scanner.EoLWarningDays = defaultEoLWarningDays
	}
	if cfg.Updater.DeadManTimeoutSeconds <= 0 {
		cfg.Updater.DeadManTimeoutSeconds = defaultDeadManTimeoutS
	}
	if len(cfg.Updater.CriticalServices) == 0 {
		cfg.Updater.CriticalServices = defaultCriticalServices()
	}
	if strings.TrimSpace(cfg.Updater.Git.BotName) == "" {
		cfg.Updater.Git.BotName = defaultGitBotName
	}
	if strings.TrimSpace(cfg.Updater.Git.BotEmail) == "" {
		cfg.Updater.Git.BotEmail = defaultGitBotEmail
	}
	if strings.TrimSpace(cfg.Updater.Git.GPGKey) == "" {
		cfg.Updater.Git.GPGKey = defaultGitGPGKey
	}
}

func parseBoolEnv(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true, true
	case "false", "0", "no", "off":
		return false, true
	default:
		return false, false
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

// NormalizeURL trims whitespace, trailing slashes, and ensures an http:// or https:// scheme is present.
func NormalizeURL(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "https://"):
		return "https://" + s[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		return "http://" + s[len("http://"):]
	case strings.Contains(s, "://"):
		// Preserve non-HTTP schemes unchanged so validators reject unsupported protocols cleanly.
		return s
	default:
		return "http://" + s
	}
}
