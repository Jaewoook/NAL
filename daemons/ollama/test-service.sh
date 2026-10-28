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

# 2. Check plist syntax
plutil -lint "$PLIST_FILE" >/dev/null || {
    echo "FAIL: Plist syntax invalid"
    exit 1
}

# 3. Check plist contents
grep -q "<string>me.jaewook.nal.ollama</string>" "$PLIST_FILE" || {
    echo "FAIL: Plist missing label me.jaewook.nal.ollama"
    exit 1
}

grep -q "0.0.0.0:11434" "$PLIST_FILE" || {
    echo "FAIL: Plist missing OLLAMA_HOST 0.0.0.0:11434"
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

# 4. Check service.sh
if [[ ! -x "$SERVICE_SCRIPT" ]]; then
    echo "FAIL: Service script $SERVICE_SCRIPT is missing or not executable"
    exit 1
fi

"$SERVICE_SCRIPT" help | grep -q "Usage:" || {
    echo "FAIL: Service script help output missing Usage:"
    exit 1
}

# 5. Check README.md
if [[ ! -f "$README_FILE" ]]; then
    echo "FAIL: README file $README_FILE does not exist"
    exit 1
fi

echo "=== ALL TESTS PASSED ==="
