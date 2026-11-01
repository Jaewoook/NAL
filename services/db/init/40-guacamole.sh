#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/40-guacamole-schema.sql.inc"

# 1. Create dedicated user and database
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE USER ${GUACAMOLE_DB_USER:-guacamole} WITH PASSWORD ''${GUACAMOLE_DB_PASS:-guacamole_pass}'''
    WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${GUACAMOLE_DB_USER:-guacamole}')\gexec

    SELECT 'CREATE DATABASE ${GUACAMOLE_DB_NAME:-guacamole_db} OWNER ${GUACAMOLE_DB_USER:-guacamole}'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${GUACAMOLE_DB_NAME:-guacamole_db}')\gexec
EOSQL

# 2. Grant initial database and schema permissions
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "${GUACAMOLE_DB_NAME:-guacamole_db}" <<-EOSQL
    GRANT ALL PRIVILEGES ON DATABASE "${GUACAMOLE_DB_NAME:-guacamole_db}" TO "${GUACAMOLE_DB_USER:-guacamole}";
    GRANT ALL ON SCHEMA public TO "${GUACAMOLE_DB_USER:-guacamole}";
EOSQL

# 3. Initialize schema if tables do not exist
if ! psql -U "$POSTGRES_USER" -d "${GUACAMOLE_DB_NAME:-guacamole_db}" -c "SELECT 1 FROM guacamole_user LIMIT 1;" &>/dev/null; then
    echo "Initializing Guacamole database schema..."
    if [[ -f "$SCHEMA_FILE" ]]; then
        psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "${GUACAMOLE_DB_NAME:-guacamole_db}" -f "$SCHEMA_FILE"
    else
        echo "Error: Schema file $SCHEMA_FILE not found." >&2
        exit 1
    fi
fi

# 4. Bootstrap jaewook admin user for Authentik SSO
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "${GUACAMOLE_DB_NAME:-guacamole_db}" <<-EOSQL
    -- Insert user if not exists
    INSERT INTO guacamole_entity (name, type)
    VALUES ('jaewook', 'USER')
    ON CONFLICT (name, type) DO NOTHING;

    INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date)
    SELECT entity_id, decode('', 'hex'), decode('', 'hex'), CURRENT_TIMESTAMP
    FROM guacamole_entity
    WHERE name = 'jaewook' AND type = 'USER'
    ON CONFLICT (entity_id) DO NOTHING;

    -- Grant system administrator permissions
    INSERT INTO guacamole_system_permission (entity_id, permission)
    SELECT entity_id, 'ADMINISTER'
    FROM guacamole_entity
    WHERE name = 'jaewook' AND type = 'USER'
    ON CONFLICT (entity_id, permission) DO NOTHING;

    -- Ensure guacamole user has full permissions on all created tables and sequences
    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "${GUACAMOLE_DB_USER:-guacamole}";
    GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "${GUACAMOLE_DB_USER:-guacamole}";
    GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO "${GUACAMOLE_DB_USER:-guacamole}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "${GUACAMOLE_DB_USER:-guacamole}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "${GUACAMOLE_DB_USER:-guacamole}";
EOSQL

echo "Guacamole database provisioning completed successfully."
