#!/bin/bash
set -euo pipefail

# Ensure standard bin paths are accessible on macOS / Linux
export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.docker/bin:${PATH}"

# 1. Determine script directory and locate .env if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../.env" ]]; then
    # Running from host repository checkout
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/../.env"
elif [[ -f "${SCRIPT_DIR}/.env" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
fi

# 2. Extract configuration without default values (fail immediately if not set)
POSTGRES_USER="${POSTGRES_USER:-${PG_USER:-}}"
POSTGRES_DB="${POSTGRES_DB:-${PG_DB:-}}"

: "${POSTGRES_USER:?POSTGRES_USER (or PG_USER) must be set}"
: "${POSTGRES_DB:?POSTGRES_DB (or PG_DB) must be set}"
: "${SECURITY_HUB_DB_USER:?SECURITY_HUB_DB_USER must be set}"
: "${SECURITY_HUB_DB_PASS:?SECURITY_HUB_DB_PASS must be set}"
: "${SECURITY_HUB_DB_NAME:?SECURITY_HUB_DB_NAME must be set}"

# 3. Helper to execute SQL either inside container (via local psql) or from host (via docker exec)
run_sql() {
    local target_db="$1"
    if command -v psql >/dev/null 2>&1; then
        psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$target_db"
    elif command -v docker >/dev/null 2>&1; then
        docker exec -i postgresql psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$target_db"
    else
        echo "Error: Neither psql nor docker is available to execute PostgreSQL commands." >&2
        exit 1
    fi
}

echo "Provisioning Security Hub PostgreSQL user '${SECURITY_HUB_DB_USER}' and database '${SECURITY_HUB_DB_NAME}'..."

# 4. Create user and database idempotently
run_sql "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE USER "${SECURITY_HUB_DB_USER}" WITH PASSWORD ''${SECURITY_HUB_DB_PASS}'''
    WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${SECURITY_HUB_DB_USER}')\gexec

    SELECT 'CREATE DATABASE "${SECURITY_HUB_DB_NAME}" OWNER "${SECURITY_HUB_DB_USER}"'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${SECURITY_HUB_DB_NAME}')\gexec

    ALTER USER "${SECURITY_HUB_DB_USER}" WITH PASSWORD '${SECURITY_HUB_DB_PASS}';
EOSQL

# 5. Grant database and schema privileges
run_sql "$SECURITY_HUB_DB_NAME" <<-EOSQL
    GRANT ALL PRIVILEGES ON DATABASE "${SECURITY_HUB_DB_NAME}" TO "${SECURITY_HUB_DB_USER}";
    GRANT ALL ON SCHEMA public TO "${SECURITY_HUB_DB_USER}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "${SECURITY_HUB_DB_USER}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "${SECURITY_HUB_DB_USER}";
EOSQL

echo "Security Hub PostgreSQL database '${SECURITY_HUB_DB_NAME}' provisioned successfully."
