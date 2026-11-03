#!/bin/bash
set -euo pipefail

# End-to-End Verification Tooling for LiteLLM Gateway
# Validates OpenAI /v1/chat/completions, Anthropic /v1/messages, and HTTP 401 Unauthorized handling.

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:4000}"
API_KEY="${API_KEY:-sk-master-change-me}"
MODEL="${MODEL:-claude-3-5-sonnet}"
DRY_RUN=false
VERBOSE=false

show_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Validate LiteLLM Gateway agent protocols and authentication.

Options:
  --dry-run              Validate request payloads, headers, and schemas offline
  -u, --gateway-url URL  LiteLLM Gateway base URL (default: http://127.0.0.1:4000)
  -k, --api-key KEY      API key / Bearer token (default: sk-master-change-me)
  -m, --model MODEL      Model name (default: claude-3-5-sonnet)
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
    -k|--api-key)
      API_KEY="$2"
      shift 2
      ;;
    --api-key=*)
      API_KEY="${1#*=}"
      shift
      ;;
    -m|--model)
      MODEL="$2"
      shift 2
      ;;
    --model=*)
      MODEL="${1#*=}"
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

validate_json_payload() {
  local payload="$1"
  local schema_type="$2"

  echo "$payload" | python3 -c '
import sys, json

schema_type = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception as e:
    print(f"[-] Invalid JSON for {schema_type}: {e}", file=sys.stderr)
    sys.exit(1)

assert "model" in data and isinstance(data["model"], str) and data["model"], "Missing or empty model"
assert "messages" in data and isinstance(data["messages"], list) and len(data["messages"]) > 0, "Missing or invalid messages"
for msg in data["messages"]:
    assert "role" in msg and "content" in msg, "Message must contain role and content"

if schema_type == "openai_tools":
    assert "tools" in data and isinstance(data["tools"], list), "Missing tools list"
    for tool in data["tools"]:
        assert tool.get("type") == "function", "OpenAI tool type must be function"
        assert "function" in tool and isinstance(tool["function"], dict), "Tool missing function object"
        assert "name" in tool["function"] and tool["function"]["name"], "Tool missing function name"
        assert "parameters" in tool["function"] and isinstance(tool["function"]["parameters"], dict), "Tool missing function parameters"

elif schema_type == "anthropic_tools":
    assert "tools" in data and isinstance(data["tools"], list), "Missing tools list"
    for tool in data["tools"]:
        assert "name" in tool and tool["name"], "Anthropic tool missing name"
        assert "input_schema" in tool and isinstance(tool["input_schema"], dict), "Anthropic tool missing input_schema"
' "$schema_type"
}

test_unauthorized() {
  local endpoint="${GATEWAY_URL}/v1/chat/completions"
  local invalid_key="invalid-unauthorized-key-test"
  local payload='{"model":"default","messages":[{"role":"user","content":"test"}]}'

  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Checking unauthorized rejection configuration..."
    local auth_header="Authorization: Bearer ${invalid_key}"
    if [[ "$auth_header" != Authorization:\ Bearer\ * ]]; then
      echo "[-] Invalid auth header format" >&2
      return 1
    fi
    echo "  - Target: POST ${endpoint}"
    echo "  - Header: ${auth_header}"
    echo "  - Expected: HTTP 401 Unauthorized"
    return 0
  fi

  echo "[RUN] Testing unauthorized request (expected HTTP 401)..."
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 --max-time 15 \
    -X POST "${endpoint}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${invalid_key}" \
    -d "$payload" || true)

  if [ "$http_code" = "401" ]; then
    echo "[PASS] test_unauthorized: Received expected HTTP 401 Unauthorized."
  else
    echo "[FAIL] test_unauthorized: Expected HTTP 401, but got ${http_code}." >&2
    return 1
  fi
}

test_openai_completion() {
  local endpoint="${GATEWAY_URL}/v1/chat/completions"
  local payload
  payload=$(cat <<EOF
{
  "model": "${MODEL}",
  "messages": [
    {"role": "user", "content": "ping"}
  ],
  "max_tokens": 10
}
EOF
)

  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Checking OpenAI /v1/chat/completions request structure..."
    validate_json_payload "$payload" "openai"
    local auth_header="Authorization: Bearer ${API_KEY}"
    local content_header="Content-Type: application/json"
    if [[ "$auth_header" != Authorization:\ Bearer\ * ]] || [[ "$content_header" != "Content-Type: application/json" ]]; then
      echo "[-] Invalid OpenAI request headers" >&2
      return 1
    fi
    echo "  - Target: POST ${endpoint}"
    echo "  - Headers: ${content_header}, Authorization: Bearer <masked>"
    echo "  - Model: ${MODEL}"
    return 0
  fi

  echo "[RUN] Testing OpenAI /v1/chat/completions with model '${MODEL}'..."
  local response
  local http_code
  local body

  response=$(curl -s -w "\n%{http_code}" \
    --connect-timeout 5 --max-time 30 \
    -X POST "${endpoint}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${API_KEY}" \
    -d "$payload" || true)

  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" = "200" ]; then
    echo "[PASS] test_openai_completion: Received HTTP 200 OK."
    if [ "$VERBOSE" = true ]; then
      echo "Response body: ${body}"
    fi
  else
    echo "[FAIL] test_openai_completion: Expected HTTP 200, got ${http_code}." >&2
    echo "Response body: ${body}" >&2
    return 1
  fi
}

test_anthropic_messages() {
  local endpoint="${GATEWAY_URL}/v1/messages"
  local payload
  payload=$(cat <<EOF
{
  "model": "${MODEL}",
  "messages": [
    {"role": "user", "content": "ping"}
  ],
  "max_tokens": 10
}
EOF
)

  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Checking Anthropic /v1/messages request structure..."
    validate_json_payload "$payload" "anthropic"
    local key_header="x-api-key: ${API_KEY}"
    local version_header="anthropic-version: 2023-06-01"
    local content_header="Content-Type: application/json"
    if [[ "$key_header" != x-api-key:\ * ]] || [[ "$version_header" != "anthropic-version: 2023-06-01" ]]; then
      echo "[-] Invalid Anthropic request headers" >&2
      return 1
    fi
    echo "  - Target: POST ${endpoint}"
    echo "  - Headers: ${content_header}, x-api-key: <masked>, ${version_header}"
    echo "  - Model: ${MODEL}"
    return 0
  fi

  echo "[RUN] Testing Anthropic /v1/messages with model '${MODEL}'..."
  local response
  local http_code
  local body

  response=$(curl -s -w "\n%{http_code}" \
    --connect-timeout 5 --max-time 30 \
    -X POST "${endpoint}" \
    -H "Content-Type: application/json" \
    -H "x-api-key: ${API_KEY}" \
    -H "anthropic-version: 2023-06-01" \
    -d "$payload" || true)

  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" = "200" ]; then
    echo "[PASS] test_anthropic_messages: Received HTTP 200 OK."
    if [ "$VERBOSE" = true ]; then
      echo "Response body: ${body}"
    fi
  else
    echo "[FAIL] test_anthropic_messages: Expected HTTP 200, got ${http_code}." >&2
    echo "Response body: ${body}" >&2
    return 1
  fi
}

test_tool_definitions() {
  local openai_tool_payload
  local anthropic_tool_payload

  openai_tool_payload=$(cat <<EOF
{
  "model": "${MODEL}",
  "messages": [{"role": "user", "content": "Check weather in Seoul"}],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "Get current weather for location",
        "parameters": {
          "type": "object",
          "properties": {
            "location": {"type": "string", "description": "City name"}
          },
          "required": ["location"]
        }
      }
    }
  ],
  "max_tokens": 20
}
EOF
)

  anthropic_tool_payload=$(cat <<EOF
{
  "model": "${MODEL}",
  "messages": [{"role": "user", "content": "Check weather in Seoul"}],
  "tools": [
    {
      "name": "get_weather",
      "description": "Get current weather for location",
      "input_schema": {
        "type": "object",
        "properties": {
          "location": {"type": "string", "description": "City name"}
        },
        "required": ["location"]
      }
    }
  ],
  "max_tokens": 20
}
EOF
)

  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Checking Agent Tool Definition schemas (OpenAI & Anthropic formats)..."
    validate_json_payload "$openai_tool_payload" "openai_tools"
    validate_json_payload "$anthropic_tool_payload" "anthropic_tools"
    echo "  - OpenAI function-calling tool schema: validated"
    echo "  - Anthropic input_schema tool schema: validated"
    return 0
  fi

  echo "[RUN] Testing OpenAI function calling with model '${MODEL}'..."
  local openai_response
  local openai_code
  local openai_body

  openai_response=$(curl -s -w "\n%{http_code}" \
    --connect-timeout 5 --max-time 30 \
    -X POST "${GATEWAY_URL}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${API_KEY}" \
    -d "$openai_tool_payload" || true)

  openai_code=$(echo "$openai_response" | tail -n1)
  openai_body=$(echo "$openai_response" | sed '$d')

  if [ "$openai_code" = "200" ]; then
    echo "[PASS] test_tool_definitions (OpenAI): Received HTTP 200 OK."
    if [ "$VERBOSE" = true ]; then
      echo "Response body: ${openai_body}"
    fi
  else
    echo "[FAIL] test_tool_definitions (OpenAI): Expected HTTP 200, got ${openai_code}." >&2
    echo "Response body: ${openai_body}" >&2
    return 1
  fi

  echo "[RUN] Testing Anthropic tool definitions with model '${MODEL}'..."
  local anthropic_response
  local anthropic_code
  local anthropic_body

  anthropic_response=$(curl -s -w "\n%{http_code}" \
    --connect-timeout 5 --max-time 30 \
    -X POST "${GATEWAY_URL}/v1/messages" \
    -H "Content-Type: application/json" \
    -H "x-api-key: ${API_KEY}" \
    -H "anthropic-version: 2023-06-01" \
    -d "$anthropic_tool_payload" || true)

  anthropic_code=$(echo "$anthropic_response" | tail -n1)
  anthropic_body=$(echo "$anthropic_response" | sed '$d')

  if [ "$anthropic_code" = "200" ]; then
    echo "[PASS] test_tool_definitions (Anthropic): Received HTTP 200 OK."
    if [ "$VERBOSE" = true ]; then
      echo "Response body: ${anthropic_body}"
    fi
  else
    echo "[FAIL] test_tool_definitions (Anthropic): Expected HTTP 200, got ${anthropic_code}." >&2
    echo "Response body: ${anthropic_body}" >&2
    return 1
  fi
}

main() {
  echo "=== LiteLLM Gateway Verification ==="
  echo "Gateway URL: ${GATEWAY_URL}"
  echo "Model:       ${MODEL}"
  echo "Mode:        $( [ "$DRY_RUN" = true ] && echo "DRY-RUN (Offline)" || echo "LIVE" )"
  echo "======================================"

  test_unauthorized
  test_openai_completion
  test_anthropic_messages
  test_tool_definitions

  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Payloads and headers validated successfully."
  else
    echo "[PASS] All gateway verification checks passed successfully."
  fi
}

main "$@"
