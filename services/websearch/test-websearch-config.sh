#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Testing SearXNG configuration in $DIR..."

# Check settings.yml exists and has required keys
test -f "$DIR/settings.yml" || { echo "settings.yml missing"; exit 1; }
grep -q "limiter: false" "$DIR/settings.yml" || { echo "limiter: false missing in settings.yml"; exit 1; }
grep -A 5 "formats:" "$DIR/settings.yml" | grep -q "json" || { echo "json missing in search.formats"; exit 1; }

# Check compose.yml exists and validates
test -f "$DIR/compose.yml" || { echo "compose.yml missing"; exit 1; }
grep -q "searxng/searxng" "$DIR/compose.yml" || { echo "searxng image missing in compose.yml"; exit 1; }
grep -q "nginx_network" "$DIR/compose.yml" || { echo "nginx_network missing in compose.yml"; exit 1; }

echo "Configuration files test passed!"
