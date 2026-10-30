#!/bin/bash
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER "${SYSTEM_UPDATER_DB_USER:-system_updater}" WITH PASSWORD '${SYSTEM_UPDATER_DB_PASS:-system_updater_pass}';
    CREATE DATABASE "${SYSTEM_UPDATER_DB_NAME:-system_updater}" OWNER "${SYSTEM_UPDATER_DB_USER:-system_updater}";
EOSQL
