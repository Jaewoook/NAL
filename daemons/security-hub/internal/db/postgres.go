package db

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

type CLIRunner func(name string, args ...string) ([]byte, error)

func defaultRunner(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// PostgresBackend syncs SpoolStore state and task logs into the shared NAL
// PostgreSQL container (`services/db`) via psql over loopback or docker exec,
// requiring zero external C/Go driver dependencies.
type PostgresBackend struct {
	containerName string
	dbName        string
	dbUser        string
	runner        CLIRunner
	schemaReady   bool
}

func NewPostgresBackend(containerName, dbName, dbUser string, runner CLIRunner) *PostgresBackend {
	if runner == nil {
		runner = defaultRunner
	}
	if containerName == "" {
		containerName = "postgresql"
	}
	if dbName == "" {
		dbName = "system_updater"
	}
	if dbUser == "" {
		dbUser = "system_updater"
	}
	return &PostgresBackend{
		containerName: containerName,
		dbName:        dbName,
		dbUser:        dbUser,
		runner:        runner,
	}
}

func (p *PostgresBackend) execSQL(sql string) error {
	if !p.schemaReady {
		if err := p.ensureSchema(); err != nil {
			return err
		}
		p.schemaReady = true
	}
	_, err := p.runner("docker", "exec", "-i", p.containerName,
		"psql", "-v", "ON_ERROR_STOP=1", "-U", p.dbUser, "-d", p.dbName, "-c", sql)
	return err
}

func (p *PostgresBackend) ensureSchema() error {
	schema := `
CREATE TABLE IF NOT EXISTS tasks (
	id TEXT PRIMARY KEY,
	task_type TEXT NOT NULL,
	target_type TEXT NOT NULL,
	target_name TEXT NOT NULL,
	from_version TEXT,
	to_version TEXT,
	triggered_by TEXT,
	status TEXT NOT NULL,
	error_msg TEXT,
	started_at TIMESTAMPTZ NOT NULL,
	finished_at TIMESTAMPTZ,
	duration_ms BIGINT DEFAULT 0
);
CREATE TABLE IF NOT EXISTS task_logs (
	task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
	seq INT NOT NULL,
	logged_at TIMESTAMPTZ NOT NULL,
	stream TEXT NOT NULL,
	line TEXT NOT NULL,
	PRIMARY KEY (task_id, seq)
);
CREATE TABLE IF NOT EXISTS rollback_snapshots (
	service_name TEXT PRIMARY KEY,
	service_key TEXT,
	image_repo TEXT,
	previous_version TEXT,
	previous_digest TEXT,
	compose_path TEXT,
	compose_backup_b64 TEXT,
	env_path TEXT,
	env_backup_b64 TEXT,
	created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS skipped_versions (
	target_type TEXT NOT NULL,
	target_name TEXT NOT NULL,
	skipped_version TEXT NOT NULL,
	created_by TEXT,
	created_at TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (target_type, target_name)
);
CREATE TABLE IF NOT EXISTS sent_alerts (
	fingerprint TEXT PRIMARY KEY,
	alert_type TEXT NOT NULL,
	sent_at TIMESTAMPTZ NOT NULL
);`
	_, err := p.runner("docker", "exec", "-i", p.containerName,
		"psql", "-v", "ON_ERROR_STOP=1", "-U", p.dbUser, "-d", p.dbName, "-c", schema)
	return err
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (p *PostgresBackend) UpsertTask(ctx context.Context, t models.Task) error {
	fin := "NULL"
	if !t.FinishedAt.IsZero() {
		fin = quoteLiteral(t.FinishedAt.Format(time.RFC3339Nano))
	}
	sql := fmt.Sprintf(`INSERT INTO tasks (id, task_type, target_type, target_name, from_version, to_version, triggered_by, status, error_msg, started_at, finished_at, duration_ms)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d)
ON CONFLICT (id) DO UPDATE SET
status = EXCLUDED.status,
error_msg = EXCLUDED.error_msg,
finished_at = EXCLUDED.finished_at,
duration_ms = EXCLUDED.duration_ms;`,
		quoteLiteral(t.ID), quoteLiteral(t.TaskType), quoteLiteral(t.TargetType), quoteLiteral(t.TargetName),
		quoteLiteral(t.FromVersion), quoteLiteral(t.ToVersion), quoteLiteral(t.TriggeredBy),
		quoteLiteral(t.Status), quoteLiteral(t.ErrorMsg), quoteLiteral(t.StartedAt.Format(time.RFC3339Nano)),
		fin, t.DurationMs)
	return p.execSQL(sql)
}

func (p *PostgresBackend) InsertTaskLog(ctx context.Context, l models.TaskLogLine) error {
	return p.InsertTaskLogsBatch(ctx, []models.TaskLogLine{l})
}

func (p *PostgresBackend) InsertTaskLogsBatch(ctx context.Context, lines []models.TaskLogLine) error {
	if len(lines) == 0 {
		return nil
	}
	var values []string
	for _, l := range lines {
		lineB64 := base64.StdEncoding.EncodeToString([]byte(l.Line))
		values = append(values, fmt.Sprintf("(%s, %d, %s, %s, convert_from(decode(%s, 'base64'), 'UTF8'))",
			quoteLiteral(l.TaskID), l.Seq, quoteLiteral(l.LoggedAt.Format(time.RFC3339Nano)),
			quoteLiteral(l.Stream), quoteLiteral(lineB64)))
	}
	sql := fmt.Sprintf("INSERT INTO task_logs (task_id, seq, logged_at, stream, line) VALUES %s ON CONFLICT (task_id, seq) DO NOTHING;",
		strings.Join(values, ", "))
	return p.execSQL(sql)
}

func (p *PostgresBackend) UpsertSnapshot(ctx context.Context, snap models.RollbackSnapshot) error {
	cb := base64.StdEncoding.EncodeToString(snap.ComposeBackup)
	eb := base64.StdEncoding.EncodeToString(snap.EnvBackup)
	sql := fmt.Sprintf(`INSERT INTO rollback_snapshots (service_name, service_key, image_repo, previous_version, previous_digest, compose_path, compose_backup_b64, env_path, env_backup_b64, created_at)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (service_name) DO UPDATE SET
previous_version = EXCLUDED.previous_version,
previous_digest = EXCLUDED.previous_digest,
compose_backup_b64 = EXCLUDED.compose_backup_b64,
env_backup_b64 = EXCLUDED.env_backup_b64,
created_at = EXCLUDED.created_at;`,
		quoteLiteral(snap.ServiceName), quoteLiteral(snap.ServiceKey), quoteLiteral(snap.ImageRepo),
		quoteLiteral(snap.PreviousVersion), quoteLiteral(snap.PreviousDigest),
		quoteLiteral(snap.ComposePath), quoteLiteral(cb), quoteLiteral(snap.EnvPath), quoteLiteral(eb),
		quoteLiteral(snap.CreatedAt.Format(time.RFC3339Nano)))
	return p.execSQL(sql)
}

func (p *PostgresBackend) UpsertSkippedVersion(ctx context.Context, targetType, targetName, version, actor string) error {
	sql := fmt.Sprintf(`INSERT INTO skipped_versions (target_type, target_name, skipped_version, created_by, created_at)
VALUES (%s, %s, %s, %s, NOW())
ON CONFLICT (target_type, target_name) DO UPDATE SET
skipped_version = EXCLUDED.skipped_version,
created_by = EXCLUDED.created_by,
created_at = NOW();`,
		quoteLiteral(targetType), quoteLiteral(targetName), quoteLiteral(version), quoteLiteral(actor))
	return p.execSQL(sql)
}

func (p *PostgresBackend) DeleteSkippedVersion(ctx context.Context, targetType, targetName string) error {
	sql := fmt.Sprintf(`DELETE FROM skipped_versions WHERE target_type = %s AND target_name = %s;`,
		quoteLiteral(targetType), quoteLiteral(targetName))
	return p.execSQL(sql)
}

func (p *PostgresBackend) UpsertSentAlert(ctx context.Context, fingerprint, alertType string) error {
	sql := fmt.Sprintf(`INSERT INTO sent_alerts (fingerprint, alert_type, sent_at)
VALUES (%s, %s, NOW())
ON CONFLICT (fingerprint) DO UPDATE SET sent_at = NOW();`,
		quoteLiteral(fingerprint), quoteLiteral(alertType))
	return p.execSQL(sql)
}

func ProvisionDatabase(ctx context.Context, containerName, dbName, dbUser, dbPass string, runner CLIRunner) error {
	if runner == nil {
		runner = defaultRunner
	}
	if containerName == "" {
		containerName = "postgresql"
	}
	if dbName == "" {
		dbName = "system_updater"
	}
	if dbUser == "" {
		dbUser = "system_updater"
	}

	roleSQL := fmt.Sprintf("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN CREATE USER %s WITH PASSWORD %s; ELSE ALTER USER %s WITH PASSWORD %s; END IF; END $$;",
		quoteLiteral(dbUser), dbUser, quoteLiteral(dbPass), dbUser, quoteLiteral(dbPass))
	if out, err := runner("docker", "exec", "-i", containerName,
		"sh", "-c", `psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -c "$1"`, "--", roleSQL); err != nil {
		return fmt.Errorf("failed to create/update role %s in container %q: %w (%s)", dbUser, containerName, err, strings.TrimSpace(string(out)))
	}

	checkSQL := fmt.Sprintf("SELECT 1 FROM pg_database WHERE datname=%s", quoteLiteral(dbName))
	checkDB, _ := runner("docker", "exec", "-i", containerName,
		"sh", "-c", `psql -tAc "$1" -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}"`, "--", checkSQL)
	if strings.TrimSpace(string(checkDB)) != "1" {
		createDB := fmt.Sprintf("CREATE DATABASE %s OWNER %s;", dbName, dbUser)
		if out, err := runner("docker", "exec", "-i", containerName,
			"sh", "-c", `psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -c "$1"`, "--", createDB); err != nil {
			return fmt.Errorf("failed to create database %s: %w (%s)", dbName, err, strings.TrimSpace(string(out)))
		}
	}

	grantSQL := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s;", dbName, dbUser)
	_, _ = runner("docker", "exec", "-i", containerName,
		"sh", "-c", `psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -c "$1"`, "--", grantSQL)

	pg := NewPostgresBackend(containerName, dbName, dbUser, runner)
	if err := pg.ensureSchema(); err != nil {
		return fmt.Errorf("failed to initialize schema in database %s: %w", dbName, err)
	}
	return nil
}
