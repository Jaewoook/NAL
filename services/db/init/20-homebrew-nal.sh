#!/bin/bash
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER "${HOMEBREW_NAL_DB_USER:-homebrew_nal}" WITH PASSWORD '${HOMEBREW_NAL_DB_PASS:-homebrew_nal_pass}';
    CREATE DATABASE "${HOMEBREW_NAL_DB_NAME:-homebrew_nal}" OWNER "${HOMEBREW_NAL_DB_USER:-homebrew_nal}";
EOSQL
