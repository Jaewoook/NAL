#!/bin/bash
set -euo pipefail

# Runs on your MacBook to remotely prepare Aegis (Raspberry Pi 3B+) or join it to k3s.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${NAL_AEGIS_ENV_FILE:-$SCRIPT_DIR/.env}"

# shellcheck source=../lib/common.sh
. "$NODES_DIR/lib/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") <sd|prep|join|status> [options]

Provision Aegis (Raspberry Pi 3B+) from your MacBook: post-flash SD setup,
remote OS tuning, and Kubernetes node joining.

Commands:
  sd        Step 0: Prepare mounted SD card right after flashing (ssh, userconf.txt, boot/cgroups).
  prep      Step 1: Tune OS, cgroups, zram, SD logging, and port 53 over SSH, then reboot.
  join      Step 2: Install and join k3s-agent to Axis's cluster over SSH (after Axis k3s is up).
  status    Show live RAM, zram, cgroup, port 53, and k3s-agent status on Aegis.

Options (override values from $ENV_FILE):
  --host <host>           SSH hostname or IP (default: aegis.local)
  --user <user>           Initial user (sd) and SSH username (default: pi)
  --password <pass>       Initial account password for userconf.txt (sd only; prefer .env or prompt)
  --boot-dir <path>       Mounted SD boot partition (sd only; default: auto-detect /Volumes/bootfs)
  --eject                 Eject the SD card after 'sd' completes
  --port <port>           SSH port (default: 22)
  --key <path>            SSH private key file
  --k3s-url <url>         k3s server URL, e.g. https://192.168.0.10:6443 (join only)
  --k3s-token <token>     k3s node join token (join only)
  --k3s-version <ver>     Pin k3s version to match Axis, e.g. v1.31.4+k3s1 (join only)
  --refresh-host-key      Remove cached SSH host keys for Aegis before connecting (after reset)
  --no-reboot             Skip automatic reboot at the end of 'prep'
  -h, --help              Show this help message
EOF
}

COMMAND=""
NO_REBOOT="false"
REFRESH_HOST_KEY="false"
AEGIS_EJECT="false"
LOCAL_ENV_FILE=""
CONTROL_PATH=""
REMOTE_DIR=""

parse_args() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        sd|prep|join|status)
            COMMAND="$1"
            shift
            ;;
        *)
            echo "Error: unknown command '$1'." >&2
            usage >&2
            exit 1
            ;;
    esac

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --host)             AEGIS_HOST="${2:?missing value for --host}"; shift 2 ;;
            --user)             AEGIS_USER="${2:?missing value for --user}"; shift 2 ;;
            --password)         AEGIS_PASSWORD="${2:?missing value for --password}"; shift 2 ;;
            --boot-dir)         AEGIS_BOOT_DIR="${2:?missing value for --boot-dir}"; shift 2 ;;
            --eject)            AEGIS_EJECT="true"; shift ;;
            --port)             AEGIS_SSH_PORT="${2:?missing value for --port}"; shift 2 ;;
            --key)              AEGIS_SSH_KEY="${2:?missing value for --key}"; shift 2 ;;
            --k3s-url)          K3S_URL="${2:?missing value for --k3s-url}"; shift 2 ;;
            --k3s-token)        K3S_TOKEN="${2:?missing value for --k3s-token}"; shift 2 ;;
            --k3s-version)      K3S_VERSION="${2:?missing value for --k3s-version}"; shift 2 ;;
            --refresh-host-key) REFRESH_HOST_KEY="true"; shift ;;
            --no-reboot)        NO_REBOOT="true"; shift ;;
            -h|--help)          usage; exit 0 ;;
            *)
                echo "Error: unknown option '$1'." >&2
                usage >&2
                exit 1
                ;;
        esac
    done
}

build_ssh_opts() {
    local target_hash uid
    uid="${UID:-$(id -u)}"
    # Keep socket path short for macOS 104-byte Unix socket limit.
    target_hash="$(printf '%s@%s:%s' "$AEGIS_USER" "$AEGIS_HOST" "$AEGIS_SSH_PORT" | cksum | awk '{print $1}')"
    CONTROL_PATH="/tmp/nal-aegis-${uid}-${target_hash}.sock"

    SSH_OPTS=(
        -p "$AEGIS_SSH_PORT"
        -o "ControlMaster=auto"
        -o "ControlPersist=60"
        -o "ControlPath=$CONTROL_PATH"
        -o "ConnectTimeout=10"
        -o "SetEnv=LANG=C.UTF-8 LC_ALL=C.UTF-8"
    )
    SCP_OPTS=(
        -P "$AEGIS_SSH_PORT"
        -o "ControlMaster=auto"
        -o "ControlPersist=60"
        -o "ControlPath=$CONTROL_PATH"
        -o "ConnectTimeout=10"
        -o "SetEnv=LANG=C.UTF-8 LC_ALL=C.UTF-8"
    )
    if [[ -n "${AEGIS_SSH_KEY:-}" ]]; then
        SSH_OPTS+=(-i "$AEGIS_SSH_KEY")
        SCP_OPTS+=(-i "$AEGIS_SSH_KEY")
    fi
    SSH_TARGET="${AEGIS_USER}@${AEGIS_HOST}"
}

refresh_known_host() {
    local host="$1"
    if [[ "$AEGIS_SSH_PORT" == "22" ]]; then
        ssh-keygen -R "$host" &>/dev/null || true
    else
        ssh-keygen -R "[${host}]:${AEGIS_SSH_PORT}" &>/dev/null || true
    fi
}

close_control_master() {
    if [[ -n "$CONTROL_PATH" && -S "$CONTROL_PATH" ]]; then
        ssh "${SSH_OPTS[@]}" -O exit "$SSH_TARGET" &>/dev/null || rm -f "$CONTROL_PATH"
    fi
}

cleanup() {
    if [[ -n "$LOCAL_ENV_FILE" && -f "$LOCAL_ENV_FILE" ]]; then
        rm -f "$LOCAL_ENV_FILE"
    fi
    if [[ "$REMOTE_DIR" =~ ^/tmp/nal-aegis\.[A-Za-z0-9]+$ && -n "$CONTROL_PATH" && -S "$CONTROL_PATH" ]]; then
        ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$SSH_TARGET" "rm -rf '${REMOTE_DIR}'" &>/dev/null || true
    fi
    close_control_master
}

write_local_env() {
    LOCAL_ENV_FILE="$(mktemp)"
    write_env_vars "$LOCAL_ENV_FILE" "$@"
}

open_ssh_session() {
    # Open ControlMaster on a foreground tty first so host-key errors or prompts stay visible.
    if ! ssh "${SSH_OPTS[@]}" "$SSH_TARGET" true; then
        echo "Hint: if Aegis was just re-flashed, clear its old host key with --refresh-host-key." >&2
        return 1
    fi
}

run_remote_privileged() {
    local local_script="$1"
    shift

    open_ssh_session
    REMOTE_DIR="$(ssh "${SSH_OPTS[@]}" "$SSH_TARGET" 'umask 077 && mktemp -d /tmp/nal-aegis.XXXXXX')"
    if [[ ! "$REMOTE_DIR" =~ ^/tmp/nal-aegis\.[A-Za-z0-9]+$ ]]; then
        echo "Error: unexpected remote temporary directory output: '$REMOTE_DIR'." >&2
        REMOTE_DIR=""
        return 1
    fi
    scp -q "${SCP_OPTS[@]}" "$LOCAL_ENV_FILE" "${SSH_TARGET}:${REMOTE_DIR}/env"
    scp -q "${SCP_OPTS[@]}" "$local_script" "${SSH_TARGET}:${REMOTE_DIR}/run.sh"
    local helper
    for helper in "$@"; do
        scp -q "${SCP_OPTS[@]}" "$helper" "${SSH_TARGET}:${REMOTE_DIR}/$(basename "$helper")"
    done

    local rc=0
    ssh -t "${SSH_OPTS[@]}" "$SSH_TARGET" \
        "trap 'rm -rf '\''${REMOTE_DIR}'\''' EXIT; chmod 700 '${REMOTE_DIR}/run.sh' && sudo '${REMOTE_DIR}/run.sh' '${REMOTE_DIR}/env'" || rc=$?
    REMOTE_DIR=""
    return "$rc"
}

wait_for_reboot() {
    local pre_host="$1"
    local post_host="$2"
    local down_wait=0 up_wait=0 down_timeout=45 up_timeout=120
    local saw_down="false"

    echo "==> Waiting for $pre_host to power down..."
    sleep 2
    while (( down_wait < down_timeout )); do
        if ! nc -z -w 1 "$pre_host" "$AEGIS_SSH_PORT" &>/dev/null; then
            saw_down="true"
            break
        fi
        sleep 1
        down_wait=$((down_wait + 1))
    done

    if [[ "$pre_host" == "$post_host" && "$saw_down" != "true" ]]; then
        echo "Error: $pre_host:$AEGIS_SSH_PORT stayed reachable for ${down_timeout}s; reboot may not have started." >&2
        return 1
    fi

    echo "==> Waiting for $post_host:$AEGIS_SSH_PORT to come back online..."
    while (( up_wait < up_timeout )); do
        if nc -z -w 2 "$post_host" "$AEGIS_SSH_PORT" &>/dev/null; then
            sleep 2
            echo "==> Aegis is back online."
            return 0
        fi
        sleep 3
        up_wait=$((up_wait + 3))
    done
    echo "Error: timed out waiting for $post_host:$AEGIS_SSH_PORT after ${up_timeout}s." >&2
    return 1
}

run_status() {
    echo "==> Checking status on $SSH_TARGET"
    open_ssh_session
    ssh "${SSH_OPTS[@]}" "$SSH_TARGET" 'bash -s' < "$SCRIPT_DIR/scripts/status.sh"
}

run_sd() {
    echo "==> Step 0: Preparing flashed SD card boot partition"
    AEGIS_BOOT_DIR="$AEGIS_BOOT_DIR" \
    AEGIS_USER="$AEGIS_USER" \
    AEGIS_PASSWORD="$AEGIS_PASSWORD" \
    AEGIS_PASSWORD_HASH="$AEGIS_PASSWORD_HASH" \
    AEGIS_NODE_NAME="$AEGIS_NODE_NAME" \
    AEGIS_GPU_MEM="$AEGIS_GPU_MEM" \
    AEGIS_DISABLE_WIFI="$AEGIS_DISABLE_WIFI" \
    AEGIS_DISABLE_BLUETOOTH="$AEGIS_DISABLE_BLUETOOTH" \
    AEGIS_EJECT="$AEGIS_EJECT" \
        "$SCRIPT_DIR/scripts/00-prepare-sd.sh"
}

run_prep() {
    local pre_host="$AEGIS_HOST"
    local post_host="$AEGIS_HOST"

    if [[ "$NO_REBOOT" == "true" ]]; then
        AEGIS_REBOOT="false"
    else
        AEGIS_REBOOT="true"
    fi

    echo "==> Step 1: Preparing host $SSH_TARGET"
    write_local_env \
        AEGIS_NODE_NAME \
        AEGIS_LOCALE \
        AEGIS_GPU_MEM \
        AEGIS_ZRAM_PERCENT \
        AEGIS_ZRAM_ALGO \
        AEGIS_DISABLE_WIFI \
        AEGIS_DISABLE_BLUETOOTH \
        AEGIS_DISABLE_RESOLVED_STUB \
        AEGIS_REBOOT

    run_remote_privileged "$SCRIPT_DIR/scripts/01-prepare-host.sh" "$SCRIPT_DIR/scripts/boot-files.sh"

    if [[ "$NO_REBOOT" == "true" ]]; then
        echo "==> Reboot skipped (--no-reboot). Reboot Aegis manually before running 'join'."
        return 0
    fi

    # Close pre-reboot ControlMaster so post-reboot status opens a clean connection.
    close_control_master

    case "$pre_host" in
        *.local)
            if [[ "$pre_host" != "${AEGIS_NODE_NAME}.local" ]]; then
                post_host="${AEGIS_NODE_NAME}.local"
                echo "==> Hostname updated to '${AEGIS_NODE_NAME}'; switching target to $post_host"
                AEGIS_HOST="$post_host"
                build_ssh_opts
                if [[ "$REFRESH_HOST_KEY" == "true" ]]; then
                    refresh_known_host "$post_host"
                fi
            fi
            ;;
    esac

    wait_for_reboot "$pre_host" "$post_host"
    run_status
}

run_join() {
    if [[ -z "${K3S_URL:-}" || -z "${K3S_TOKEN:-}" ]]; then
        echo "Error: K3S_URL and K3S_TOKEN are required for 'join' (set in .env or pass --k3s-url / --k3s-token)." >&2
        exit 1
    fi
    if [[ ! "$K3S_URL" =~ ^https://[^[:space:]]+$ ]]; then
        echo "Error: K3S_URL must be an https:// URL with no whitespace (got '$K3S_URL')." >&2
        exit 1
    fi
    if [[ -n "${K3S_VERSION:-}" && "$K3S_VERSION" =~ [[:space:]] ]]; then
        echo "Error: K3S_VERSION cannot contain whitespace (got '$K3S_VERSION')." >&2
        exit 1
    fi

    echo "==> Step 2: Joining $SSH_TARGET to $K3S_URL"
    write_local_env AEGIS_NODE_NAME K3S_URL K3S_TOKEN K3S_VERSION
    run_remote_privileged "$SCRIPT_DIR/scripts/02-join-k3s.sh"
    run_status
}

validate_common_inputs() {
    if [[ ! "$AEGIS_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        echo "Error: invalid Linux username AEGIS_USER='$AEGIS_USER'." >&2
        exit 1
    fi
    validate_node_name "AEGIS_NODE_NAME" "$AEGIS_NODE_NAME"

    if [[ "$COMMAND" != "sd" ]]; then
        if [[ -z "$AEGIS_HOST" || "$AEGIS_HOST" =~ [[:space:]] ]]; then
            echo "Error: AEGIS_HOST must be non-empty without whitespace (got '$AEGIS_HOST')." >&2
            exit 1
        fi
        if [[ ! "$AEGIS_SSH_PORT" =~ ^[0-9]+$ ]] || (( AEGIS_SSH_PORT < 1 || AEGIS_SSH_PORT > 65535 )); then
            echo "Error: AEGIS_SSH_PORT must be an integer between 1 and 65535 (got '$AEGIS_SSH_PORT')." >&2
            exit 1
        fi
        if [[ -n "${AEGIS_SSH_KEY:-}" ]]; then
            AEGIS_SSH_KEY="$(expand_tilde "$AEGIS_SSH_KEY")"
            if [[ ! -f "$AEGIS_SSH_KEY" || ! -r "$AEGIS_SSH_KEY" ]]; then
                echo "Error: SSH key file not found or unreadable: '$AEGIS_SSH_KEY'." >&2
                exit 1
            fi
        fi
    fi

    if [[ "$COMMAND" == "sd" || "$COMMAND" == "prep" ]]; then
        if [[ ! "$AEGIS_GPU_MEM" =~ ^[0-9]+$ ]]; then
            echo "Error: AEGIS_GPU_MEM must be an integer (got '$AEGIS_GPU_MEM')." >&2
            exit 1
        fi
        validate_bool "AEGIS_DISABLE_WIFI" "$AEGIS_DISABLE_WIFI"
        validate_bool "AEGIS_DISABLE_BLUETOOTH" "$AEGIS_DISABLE_BLUETOOTH"
    fi

    if [[ "$COMMAND" == "prep" ]]; then
        if [[ -n "$AEGIS_LOCALE" && ! "$AEGIS_LOCALE" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
            echo "Error: invalid locale AEGIS_LOCALE='$AEGIS_LOCALE'." >&2
            exit 1
        fi
        if [[ ! "$AEGIS_ZRAM_PERCENT" =~ ^[0-9]+$ ]] || (( AEGIS_ZRAM_PERCENT < 1 || AEGIS_ZRAM_PERCENT > 200 )); then
            echo "Error: AEGIS_ZRAM_PERCENT must be an integer between 1 and 200 (got '$AEGIS_ZRAM_PERCENT')." >&2
            exit 1
        fi
        if [[ ! "$AEGIS_ZRAM_ALGO" =~ ^(lz4|zstd|lzo|lzo-rle)$ ]]; then
            echo "Error: AEGIS_ZRAM_ALGO must be one of lz4, zstd, lzo, lzo-rle (got '$AEGIS_ZRAM_ALGO')." >&2
            exit 1
        fi
        validate_bool "AEGIS_DISABLE_RESOLVED_STUB" "$AEGIS_DISABLE_RESOLVED_STUB"
    fi
}

main() {
    if [[ $# -eq 0 ]]; then
        usage >&2
        exit 1
    fi
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        exit 0
    fi

    load_env_file "$ENV_FILE"
    AEGIS_HOST="${AEGIS_HOST:-aegis.local}"
    AEGIS_USER="${AEGIS_USER:-pi}"
    AEGIS_PASSWORD="${AEGIS_PASSWORD:-}"
    AEGIS_PASSWORD_HASH="${AEGIS_PASSWORD_HASH:-}"
    AEGIS_BOOT_DIR="${AEGIS_BOOT_DIR:-}"
    AEGIS_SSH_PORT="${AEGIS_SSH_PORT:-22}"
    AEGIS_NODE_NAME="${AEGIS_NODE_NAME:-aegis}"
    if [[ -z "${AEGIS_LOCALE+x}" ]]; then
        AEGIS_LOCALE="en_US.UTF-8"
    fi
    AEGIS_GPU_MEM="${AEGIS_GPU_MEM:-16}"
    AEGIS_ZRAM_PERCENT="${AEGIS_ZRAM_PERCENT:-50}"
    AEGIS_ZRAM_ALGO="${AEGIS_ZRAM_ALGO:-lz4}"
    AEGIS_DISABLE_WIFI="${AEGIS_DISABLE_WIFI:-true}"
    AEGIS_DISABLE_BLUETOOTH="${AEGIS_DISABLE_BLUETOOTH:-true}"
    AEGIS_DISABLE_RESOLVED_STUB="${AEGIS_DISABLE_RESOLVED_STUB:-true}"
    K3S_VERSION="${K3S_VERSION:-}"

    parse_args "$@"
    validate_common_inputs

    if [[ "$COMMAND" == "sd" ]]; then
        run_sd
        return 0
    fi

    if [[ "$REFRESH_HOST_KEY" == "true" ]]; then
        echo "==> Clearing cached SSH host key for $AEGIS_HOST"
        refresh_known_host "$AEGIS_HOST"
    fi
    build_ssh_opts
    trap cleanup EXIT

    case "$COMMAND" in
        prep)   run_prep ;;
        join)   run_join ;;
        status) run_status ;;
    esac
}

main "$@"
