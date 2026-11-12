#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Testing Open WebUI web search configuration in $DIR..."

# Check .env has web search settings
test -f "$DIR/.env" || { echo "$DIR/.env missing"; exit 1; }
grep -q "ENABLE_WEB_SEARCH=True" "$DIR/.env" || { echo "ENABLE_WEB_SEARCH=True missing in .env"; exit 1; }
grep -q "WEB_SEARCH_ENGINE=searxng" "$DIR/.env" || { echo "WEB_SEARCH_ENGINE=searxng missing in .env"; exit 1; }
grep -q "ENABLE_RAG_WEB_SEARCH=True" "$DIR/.env" || { echo "ENABLE_RAG_WEB_SEARCH=True missing in .env"; exit 1; }
grep -q "RAG_WEB_SEARCH_ENGINE=searxng" "$DIR/.env" || { echo "RAG_WEB_SEARCH_ENGINE=searxng missing in .env"; exit 1; }
grep -q "SEARXNG_QUERY_URL=http://searxng:8080/search?q=<query>" "$DIR/.env" || { echo "SEARXNG_QUERY_URL missing in .env"; exit 1; }

# Check .env.example documents the keys
grep -q "ENABLE_RAG_WEB_SEARCH" "$DIR/.env.example" || { echo "ENABLE_RAG_WEB_SEARCH missing in .env.example"; exit 1; }
grep -q "RAG_WEB_SEARCH_ENGINE" "$DIR/.env.example" || { echo "RAG_WEB_SEARCH_ENGINE missing in .env.example"; exit 1; }
grep -q "SEARXNG_QUERY_URL" "$DIR/.env.example" || { echo "SEARXNG_QUERY_URL missing in .env.example"; exit 1; }

# Check docker-compose.yml defines them under environment
grep -q "ENABLE_RAG_WEB_SEARCH" "$DIR/docker-compose.yml" || { echo "ENABLE_RAG_WEB_SEARCH missing in docker-compose.yml"; exit 1; }
grep -q "RAG_WEB_SEARCH_ENGINE" "$DIR/docker-compose.yml" || { echo "RAG_WEB_SEARCH_ENGINE missing in docker-compose.yml"; exit 1; }
grep -q "SEARXNG_QUERY_URL" "$DIR/docker-compose.yml" || { echo "SEARXNG_QUERY_URL missing in docker-compose.yml"; exit 1; }

echo "Open WebUI web search test passed!"
