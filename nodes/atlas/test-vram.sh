#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VRAM_SCRIPT="$SCRIPT_DIR/vram.sh"
PLIST_FILE="$SCRIPT_DIR/me.jaewook.atlas.vram.plist"
README_FILE="$SCRIPT_DIR/README.md"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

echo "=== Running Atlas VRAM Script Tests ==="

# 1. Required files and executable permissions
for f in "$VRAM_SCRIPT" "$PLIST_FILE" "$README_FILE" "$ENV_EXAMPLE"; do
    if [[ ! -f "$f" ]]; then
        echo "FAIL: Missing required file: $f"
        exit 1
    fi
done

if [[ ! -x "$VRAM_SCRIPT" ]]; then
    echo "FAIL: $VRAM_SCRIPT is not executable"
    exit 1
fi

# 2. Bash syntax check
bash -n "$VRAM_SCRIPT"

# 3. Plist template checks & plutil validation
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

sed 's|__VRAM_MB__|122880|g' "$PLIST_FILE" > "$TMP_DIR/me.jaewook.atlas.vram.plist"
plutil -lint "$TMP_DIR/me.jaewook.atlas.vram.plist" >/dev/null

grep -q "<string>me.jaewook.atlas.vram</string>" "$PLIST_FILE"
grep -q "<string>/usr/sbin/sysctl</string>" "$PLIST_FILE"
grep -q "<string>iogpu.wired_limit_mb=__VRAM_MB__</string>" "$PLIST_FILE"
grep -q "<key>RunAtLoad</key>" "$PLIST_FILE"

# 4. Help and status output (non-root)
help_out="$("$VRAM_SCRIPT" help)"
grep -q "Usage:" <<< "$help_out"

status_out="$("$VRAM_SCRIPT" status)"
grep -q "Live Limit:" <<< "$status_out"

# 5. Env file override test
cat > "$TMP_DIR/.env" <<EOF
ATLAS_VRAM_LIMIT_MB=98304
EOF
env_status_out="$(NAL_ATLAS_ENV_FILE="$TMP_DIR/.env" "$VRAM_SCRIPT" status)"
grep -q "Target Limit:  98304 MB" <<< "$env_status_out"

# 6. Validation errors (safe non-root checks)
if "$VRAM_SCRIPT" apply --mb 0 >/dev/null 2>&1; then
    echo "FAIL: --mb 0 should be rejected"
    exit 1
fi

if "$VRAM_SCRIPT" apply --mb abc >/dev/null 2>&1; then
    echo "FAIL: --mb abc should be rejected"
    exit 1
fi

if "$VRAM_SCRIPT" apply --mb 999999999 >/dev/null 2>&1; then
    echo "FAIL: oversized --mb should be rejected before sudo"
    exit 1
fi

if "$VRAM_SCRIPT" bogus-cmd >/dev/null 2>&1; then
    echo "FAIL: unknown command should fail"
    exit 1
fi

echo "=== ALL TESTS PASSED ==="
