#!/bin/bash
set -euo pipefail

# Bootstrap API Keys for LiteLLM Gateway
# Generates sk-openwebui-service using LITELLM_MASTER_KEY via POST /key/generate.

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:4000}"
LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:-sk-master-change-me}"
KEY="${KEY:-sk-openwebui-service}"
KEY_ALIAS="${KEY_ALIAS:-openwebui-service}"
DRY_RUN=false
VERBOSE=false

show_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Bootstrap API keys in LiteLLM Gateway for downstream services (e.g. Open WebUI).

Options:
  --dry-run              Validate payload and parameters offline without network calls
  -u, --gateway-url URL  LiteLLM Gateway base URL (default: http://127.0.0.1:4000)
  -k, --master-key KEY   LiteLLM Master Key (default: sk-master-change-me)
  --key KEY              Key token to generate (default: sk-openwebui-service)
  --key-alias ALIAS      Key alias/name (default: openwebui-service)
  -v, --verbose          Show detailed payload and response logs
  -h, --help             Show this help message
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -u|--gateway-url)
      GATEWAY_URL="$2"
      shift 2
      ;;
    --gateway-url=*)
      GATEWAY_URL="${1#*=}"
      shift
      ;;
    -k|--master-key)
      LITELLM_MASTER_KEY="$2"
      shift 2
      ;;
    --master-key=*)
      LITELLM_MASTER_KEY="${1#*=}"
      shift
      ;;
    --key)
      KEY="$2"
      shift 2
      ;;
    --key=*)
      KEY="${1#*=}"
      shift
      ;;
    --key-alias)
      KEY_ALIAS="$2"
      shift 2
      ;;
    --key-alias=*)
      KEY_ALIAS="${1#*=}"
      shift
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      show_help
      exit 1
      ;;
  esac
done

# Strip trailing slash from GATEWAY_URL if present
GATEWAY_URL="${GATEWAY_URL%/}"

payload=$(cat <<EOF
{
  "key": "${KEY}",
  "key_alias": "${KEY_ALIAS}",
  "models": ["default", "claude-3-5-sonnet", "claude-3-5-sonnet-20241022", "*"],
  "metadata": {"service": "open-webui", "description": "Bootstrap key for Open WebUI"}
}
EOF
)

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Checking key generation payload and parameters..."
  echo "$payload" | python3 -c '
import sys, json
data = json.load(sys.stdin)
assert "key" in data and data["key"], "Missing key"
assert "key_alias" in data and data["key_alias"], "Missing key_alias"
assert "models" in data and isinstance(data["models"], list), "Missing models list"
'
  echo "  - Target: POST ${GATEWAY_URL}/key/generate"
  echo "  - Authorization: Bearer <masked>"
  echo "  - Key: ${KEY}"
  echo "  - Key Alias: ${KEY_ALIAS}"
  echo "  - Models: [\"default\", \"claude-3-5-sonnet\", \"claude-3-5-sonnet-20241022\", \"*\"]"
  echo "[DRY-RUN] Key generation payload validated successfully."
  exit 0
fi

echo "[RUN] Generating API key '${KEY}' (alias: '${KEY_ALIAS}') at ${GATEWAY_URL}/key/generate..."
response=$(curl -s -w "\n%{http_code}" \
  --connect-timeout 5 --max-time 30 \
  -X POST "${GATEWAY_URL}/key/generate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${LITELLM_MASTER_KEY}" \
  -d "$payload" || true)

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [ "$http_code" = "200" ]; then
  echo "[PASS] Successfully generated bootstrap key: ${KEY} (alias: ${KEY_ALIAS})"
  if [ "$VERBOSE" = true ]; then
    echo "Response body: ${body}"
  fi
else
  echo "[FAIL] Failed to generate bootstrap key. HTTP code: ${http_code}" >&2
  echo "Response body: ${body}" >&2
  exit 1
fi
