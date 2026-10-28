#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLIST_FILE="$SCRIPT_DIR/me.jaewook.nal.ollama.plist"
SERVICE_SCRIPT="$SCRIPT_DIR/service.sh"
README_FILE="$SCRIPT_DIR/README.md"

echo "=== Running Ollama Daemon Unit Tests ==="

# 1. Check plist exists
if [[ ! -f "$PLIST_FILE" ]]; then
    echo "FAIL: Plist file $PLIST_FILE does not exist"
    exit 1
fi

# 2. Check plist syntax (substitute placeholders to temp file for plutil test)
TMP_PLIST="$(mktemp /tmp/test-plist.XXXXXX)"
sed -e "s|__HOME__|$HOME|g" -e "s|__OLLAMA_BIN__|/opt/homebrew/bin/ollama|g" "$PLIST_FILE" > "$TMP_PLIST"
plutil -lint "$TMP_PLIST" >/dev/null || {
    echo "FAIL: Plist syntax invalid"
    rm -f "$TMP_PLIST"
    exit 1
}
rm -f "$TMP_PLIST"

# 3. Check plist contents and environment variables
grep -q "<string>me.jaewook.nal.ollama</string>" "$PLIST_FILE" || {
    echo "FAIL: Plist missing label me.jaewook.nal.ollama"
    exit 1
}

grep -q "0.0.0.0:11434" "$PLIST_FILE" || {
    echo "FAIL: Plist missing OLLAMA_HOST 0.0.0.0:11434"
    exit 1
}

grep -q "OLLAMA_ORIGINS" "$PLIST_FILE" || {
    echo "FAIL: Plist missing OLLAMA_ORIGINS"
    exit 1
}

grep -q "OLLAMA_FLASH_ATTENTION" "$PLIST_FILE" || {
    echo "FAIL: Plist missing OLLAMA_FLASH_ATTENTION"
    exit 1
}

grep -q "OLLAMA_KV_CACHE_TYPE" "$PLIST_FILE" || {
    echo "FAIL: Plist missing OLLAMA_KV_CACHE_TYPE"
    exit 1
}

grep -q "<key>RunAtLoad</key>" "$PLIST_FILE" || {
    echo "FAIL: Plist missing RunAtLoad"
    exit 1
}

grep -q "<key>KeepAlive</key>" "$PLIST_FILE" || {
    echo "FAIL: Plist missing KeepAlive"
    exit 1
}

# Ensure template does not hardcode developer absolute path
if grep -q "/Users/jaewookahn" "$PLIST_FILE"; then
    echo "FAIL: Plist template should use __HOME__ placeholder instead of hardcoded developer path"
    exit 1
fi

# 4. Check service.sh
if [[ ! -x "$SERVICE_SCRIPT" ]]; then
    echo "FAIL: Service script $SERVICE_SCRIPT is missing or not executable"
    exit 1
fi

"$SERVICE_SCRIPT" help | grep -q "Usage:" || {
    echo "FAIL: Service script help output missing Usage:"
    exit 1
}

# Check that service.sh has port conflict logic
grep -q "check_port_conflict" "$SERVICE_SCRIPT" || {
    echo "FAIL: Service script missing check_port_conflict function"
    exit 1
}

# 5. Check README.md
if [[ ! -f "$README_FILE" ]]; then
    echo "FAIL: README file $README_FILE does not exist"
    exit 1
fi

echo "=== ALL TESTS PASSED ==="
