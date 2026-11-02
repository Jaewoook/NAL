package models

import "time"

type TargetType string

const (
	TargetDocker TargetType = "docker"
	TargetBrew   TargetType = "brew"
	TargetDaemon TargetType = "daemon"
	TargetMacOS  TargetType = "macos"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type EoLStatus string

const (
	EoLSupported    EoLStatus = "supported"
	EoLExpiringSoon EoLStatus = "expiring_soon"
	EoLExpired      EoLStatus = "expired"
	EoLUnknown      EoLStatus = "unknown"
)

type Vulnerability struct {
	ID           string   `json:"id"`
	Summary      string   `json:"summary"`
	Severity     Severity `json:"severity"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	URL          string   `json:"url,omitempty"`
}

type EoLInfo struct {
	Product       string    `json:"product,omitempty"`
	Cycle         string    `json:"cycle,omitempty"`
	Status        EoLStatus `json:"status"`
	EoLDate       string    `json:"eol_date,omitempty"`
	DaysRemaining int       `json:"days_remaining,omitempty"`
	Message       string    `json:"message,omitempty"`
}

type NodeInfo struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Token      string    `json:"token,omitempty"`
	Role       string    `json:"role"` // "hub" or "agent"
	Online     bool      `json:"online"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	OSVersion  string    `json:"os_version,omitempty"`
}

type ManagedItem struct {
	Node             string          `json:"node,omitempty"`
	TargetType       TargetType      `json:"target_type"`
	Name             string          `json:"name"`
	ServiceKey       string          `json:"service_key,omitempty"`
	ImageRef         string          `json:"image_ref,omitempty"`
	CurrentVersion   string          `json:"current_version"`
	CurrentDigest    string          `json:"current_digest,omitempty"`
	LatestVersion    string          `json:"latest_version"`
	RemoteDigest     string          `json:"remote_digest,omitempty"`
	AvailableTags    []string        `json:"available_tags,omitempty"`
	Outdated         bool            `json:"outdated"`
	Skipped          bool            `json:"skipped"`
	SkippedVersion   string          `json:"skipped_version,omitempty"`
	SecurityOverride bool            `json:"security_override"`
	CriticalPath     bool            `json:"critical_path"`
	Stateful         bool            `json:"stateful"`
	BrokenLinkage    bool            `json:"broken_linkage"`
	LinkageDetails   string          `json:"linkage_details,omitempty"`
	ReleaseNotesURL  string          `json:"release_notes_url,omitempty"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities,omitempty"`
	CritCount        int             `json:"crit_count"`
	HighCount        int             `json:"high_count"`
	MedCount         int             `json:"med_count"`
	LowCount         int             `json:"low_count"`
	EoL              EoLInfo         `json:"eol"`
	HasRollback      bool            `json:"has_rollback"`
	RollbackVersion  string          `json:"rollback_version,omitempty"`
	LastCheckedAt    time.Time       `json:"last_checked_at"`
}

type ScanResult struct {
	ScannedAt       time.Time     `json:"scanned_at"`
	Nodes           []NodeInfo    `json:"nodes,omitempty"`
	Items           []ManagedItem `json:"items"`
	TotalCritCVEs   int           `json:"total_crit_cves"`
	TotalHighCVEs   int           `json:"total_high_cves"`
	TotalEoLIssues  int           `json:"total_eol_issues"`
	TotalOutdated   int           `json:"total_outdated"`
	TotalSkipped    int           `json:"total_skipped"`
	TotalBrokenBrew int           `json:"total_broken_brew"`
}

type Task struct {
	ID          string    `json:"id"`
	Node        string    `json:"node,omitempty"`
	TaskType    string    `json:"task_type"`
	TargetType  string    `json:"target_type"`
	TargetName  string    `json:"target_name"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	TriggeredBy string    `json:"triggered_by"`
	Status      string    `json:"status"`
	ErrorMsg    string    `json:"error_msg,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
	DurationMs  int64     `json:"duration_ms"`
	SyncedToDB  bool      `json:"synced_to_db"`
}

type TaskLogLine struct {
	TaskID   string    `json:"task_id"`
	Seq      int       `json:"seq"`
	LoggedAt time.Time `json:"logged_at"`
	Stream   string    `json:"stream"`
	Line     string    `json:"line"`
}

type RollbackSnapshot struct {
	ID              string    `json:"id"`
	ServiceName     string    `json:"service_name"`
	ServiceKey      string    `json:"service_key"`
	ImageRepo       string    `json:"image_repo"`
	PreviousVersion string    `json:"previous_version"`
	PreviousDigest  string    `json:"previous_digest"`
	ComposePath     string    `json:"compose_path"`
	ComposeBackup   []byte    `json:"compose_backup"`
	EnvPath         string    `json:"env_path,omitempty"`
	EnvBackup       []byte    `json:"env_backup,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	SyncedToDB      bool      `json:"synced_to_db"`
}

type SkippedVersion struct {
	TargetType     string    `json:"target_type"`
	TargetName     string    `json:"target_name"`
	SkippedVersion string    `json:"skipped_version"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}
