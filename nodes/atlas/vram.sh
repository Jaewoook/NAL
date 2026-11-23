#!/bin/bash
set -euo pipefail

# Manage persistent Apple Silicon GPU wired memory (VRAM) limit on Atlas (macOS).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${NAL_ATLAS_ENV_FILE:-$SCRIPT_DIR/.env}"

# shellcheck source=../lib/common.sh
. "$NODES_DIR/lib/common.sh"

ensure_macos_paths

LABEL="me.jaewook.atlas.vram"
SOURCE_PLIST="$SCRIPT_DIR/${LABEL}.plist"
LAUNCH_DAEMONS_DIR="/Library/LaunchDaemons"
TARGET_PLIST="$LAUNCH_DAEMONS_DIR/${LABEL}.plist"

LEGACY_LABEL="com.vram.limit"
LEGACY_PLIST="$LAUNCH_DAEMONS_DIR/${LEGACY_LABEL}.plist"

DEFAULT_VRAM_MB="122880"
WORK_DIR=""

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<EOF
Usage: $(basename "$0") <install|uninstall|apply|status|help> [options]

Manage persistent Apple Silicon GPU wired memory (iogpu.wired_limit_mb) on Atlas via launchd.

Commands:
  install [mb]    Migrate legacy $LEGACY_LABEL if present, install $LABEL LaunchDaemon, and apply limit (default: ${ATLAS_VRAM_LIMIT_MB} MB)
  uninstall       Unload and remove $LABEL (and legacy $LEGACY_LABEL if present) and reset limit to 0 (macOS default)
  apply [mb]      Apply iogpu.wired_limit_mb immediately without installing a LaunchDaemon (resets on reboot)
  status          Show live sysctl limit, LaunchDaemon registration, and legacy daemon status
  help            Show this help message

Options (override values from $ENV_FILE):
  --mb <megabytes>   GPU wired memory limit in MB (default: ${ATLAS_VRAM_LIMIT_MB})
  -h, --help         Show this help message
EOF
}

validate_vram_mb() {
    local val="$1"
    if [[ ! "$val" =~ ^[1-9][0-9]*$ ]]; then
        echo "Error: VRAM limit must be a positive integer in MB (got '$val')." >&2
        exit 1
    fi

    local hw_memsize total_ram_mb
    hw_memsize="$(sysctl -n hw.memsize 2>/dev/null || true)"
    if [[ "$hw_memsize" =~ ^[0-9]+$ ]] && (( hw_memsize > 0 )); then
        total_ram_mb=$(( hw_memsize / 1024 / 1024 ))
        if (( val >= total_ram_mb )); then
            echo "Error: requested VRAM limit (${val} MB) must be less than physical unified memory (${total_ram_mb} MB)." >&2
            exit 1
        fi
    fi
}

is_system_service_loaded() {
    local svc_label="$1"
    if launchctl print "system/$svc_label" >/dev/null 2>&1; then
        return 0
    fi
    if launchctl list "$svc_label" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

unload_system_daemon() {
    local svc_label="$1"
    local plist_path="$2"

    if sudo launchctl print "system/$svc_label" >/dev/null 2>&1; then
        sudo launchctl bootout "system/$svc_label" 2>/dev/null || true
    fi
    if [[ -f "$plist_path" ]]; then
        sudo launchctl unload -w "$plist_path" 2>/dev/null || true
    fi
    sudo launchctl remove "$svc_label" 2>/dev/null || true
}

cleanup_legacy_daemon() {
    local found=false
    if [[ -f "$LEGACY_PLIST" ]] || is_system_service_loaded "$LEGACY_LABEL" || sudo launchctl print "system/$LEGACY_LABEL" >/dev/null 2>&1; then
        found=true
    fi

    if [[ "$found" == true ]]; then
        echo "==> Migrating away from legacy $LEGACY_LABEL LaunchDaemon..."
        unload_system_daemon "$LEGACY_LABEL" "$LEGACY_PLIST"
        if [[ -f "$LEGACY_PLIST" ]]; then
            sudo rm -f "$LEGACY_PLIST"
            echo "Removed $LEGACY_PLIST"
        fi
    fi
}

render_plist() {
    local vram_mb="$1"
    local out_plist="$2"

    if [[ ! -f "$SOURCE_PLIST" ]]; then
        echo "Error: template plist not found at $SOURCE_PLIST." >&2
        exit 1
    fi

    sed "s|__VRAM_MB__|${vram_mb}|g" "$SOURCE_PLIST" > "$out_plist"
    if ! plutil -lint "$out_plist" >/dev/null 2>&1; then
        echo "Error: generated plist failed plutil validation." >&2
        exit 1
    fi
}

extract_plist_vram_mb() {
    local plist_path="$1"
    if [[ ! -f "$plist_path" ]]; then
        return 0
    fi
    grep -o 'iogpu\.wired_limit_mb=[0-9]*' "$plist_path" 2>/dev/null | head -n 1 | cut -d= -f2 || true
}

cmd_install() {
    local vram_mb="$1"
    validate_vram_mb "$vram_mb"

    echo "==> Installing $LABEL LaunchDaemon (${vram_mb} MB)..."

    WORK_DIR="$(mktemp -d)"
    chmod 700 "$WORK_DIR"
    local rendered_plist="$WORK_DIR/${LABEL}.plist"
    render_plist "$vram_mb" "$rendered_plist"

    cleanup_legacy_daemon

    if sudo launchctl print "system/$LABEL" >/dev/null 2>&1; then
        echo "Existing $LABEL service found. Booting out before reinstall..."
        unload_system_daemon "$LABEL" "$TARGET_PLIST"
    fi

    sudo mkdir -p "$LAUNCH_DAEMONS_DIR"
    sudo cp "$rendered_plist" "$TARGET_PLIST"
    sudo chown root:wheel "$TARGET_PLIST"
    sudo chmod 644 "$TARGET_PLIST"

    if sudo launchctl bootstrap system "$TARGET_PLIST" 2>/dev/null; then
        echo "Bootstrapped $LABEL into system launchd domain."
    else
        sudo launchctl load -w "$TARGET_PLIST"
        echo "Loaded $LABEL via legacy launchctl."
    fi

    # Enforce immediately in case launchd runs RunAtLoad asynchronously.
    sudo /usr/sbin/sysctl "iogpu.wired_limit_mb=$vram_mb" >/dev/null

    local live_mb
    live_mb="$(sysctl -n iogpu.wired_limit_mb 2>/dev/null || true)"
    if [[ "$live_mb" != "$vram_mb" ]]; then
        echo "Error: expected iogpu.wired_limit_mb=$vram_mb, got '${live_mb:-unknown}'." >&2
        exit 1
    fi

    echo "==> $LABEL installed and active (iogpu.wired_limit_mb=${live_mb} MB)."
    cmd_status
}

cmd_uninstall() {
    echo "==> Uninstalling $LABEL LaunchDaemon..."

    unload_system_daemon "$LABEL" "$TARGET_PLIST"
    if [[ -f "$TARGET_PLIST" ]]; then
        sudo rm -f "$TARGET_PLIST"
        echo "Removed $TARGET_PLIST"
    fi

    cleanup_legacy_daemon

    echo "==> Resetting iogpu.wired_limit_mb to 0 (macOS default)..."
    sudo /usr/sbin/sysctl iogpu.wired_limit_mb=0 >/dev/null

    echo "==> $LABEL uninstalled."
    cmd_status
}

cmd_apply() {
    local vram_mb="$1"
    validate_vram_mb "$vram_mb"

    echo "==> Applying temporary iogpu.wired_limit_mb=${vram_mb} MB (until reboot)..."
    sudo /usr/sbin/sysctl "iogpu.wired_limit_mb=$vram_mb"
    cmd_status
}

cmd_status() {
    local host_name hw_memsize total_ram_mb="unknown" live_mb configured_mb=""
    host_name="$(hostname)"
    hw_memsize="$(sysctl -n hw.memsize 2>/dev/null || true)"
    if [[ "$hw_memsize" =~ ^[0-9]+$ ]] && (( hw_memsize > 0 )); then
        total_ram_mb="$(( hw_memsize / 1024 / 1024 )) MB"
    fi
    live_mb="$(sysctl -n iogpu.wired_limit_mb 2>/dev/null || echo "unavailable")"

    echo "--------------------------------------------------"
    echo "Host:          $host_name"
    echo "Unified RAM:   $total_ram_mb"
    if [[ "$live_mb" == "0" ]]; then
        echo "Live Limit:    0 MB (macOS default)"
    elif [[ "$live_mb" =~ ^[0-9]+$ ]]; then
        echo "Live Limit:    ${live_mb} MB"
    else
        echo "Live Limit:    $live_mb"
    fi
    echo "Target Limit:  ${VRAM_MB} MB"

    if [[ -f "$TARGET_PLIST" ]]; then
        configured_mb="$(extract_plist_vram_mb "$TARGET_PLIST")"
        echo "LaunchDaemon:  installed ($TARGET_PLIST${configured_mb:+, configured=${configured_mb} MB})"
    else
        echo "LaunchDaemon:  not installed ($TARGET_PLIST)"
    fi

    if is_system_service_loaded "$LABEL"; then
        echo "Service State: LOADED ($LABEL)"
    else
        echo "Service State: NOT LOADED ($LABEL)"
    fi

    if [[ -f "$LEGACY_PLIST" ]] || is_system_service_loaded "$LEGACY_LABEL"; then
        echo "Warning:       legacy daemon '$LEGACY_LABEL' is still present; run '$(basename "$0") install' to migrate/remove it."
    fi
    echo "--------------------------------------------------"
}

load_env_file "$ENV_FILE"
ATLAS_VRAM_LIMIT_MB="${ATLAS_VRAM_LIMIT_MB:-$DEFAULT_VRAM_MB}"
VRAM_MB="$ATLAS_VRAM_LIMIT_MB"

COMMAND="status"
if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help|help)
            usage
            exit 0
            ;;
        install|uninstall|apply|status)
            COMMAND="$1"
            shift
            ;;
        *)
            echo "Error: unknown command '$1'." >&2
            usage >&2
            exit 1
            ;;
    esac
fi

POSITIONAL_MB=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mb)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "Error: --mb requires a numeric value in MB." >&2
                exit 1
            fi
            VRAM_MB="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ "$COMMAND" == "install" || "$COMMAND" == "apply" ]] && [[ -z "$POSITIONAL_MB" && "$1" != -* ]]; then
                POSITIONAL_MB="$1"
                VRAM_MB="$1"
                shift
            else
                echo "Error: unexpected argument '$1'." >&2
                usage >&2
                exit 1
            fi
            ;;
    esac
done

case "$COMMAND" in
    install)   cmd_install "$VRAM_MB" ;;
    uninstall) cmd_uninstall ;;
    apply)     cmd_apply "$VRAM_MB" ;;
    status)    cmd_status ;;
esac
