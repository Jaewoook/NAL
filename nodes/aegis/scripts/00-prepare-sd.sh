#!/bin/bash
set -euo pipefail

# Runs locally on your MacBook against a newly-flashed Raspberry Pi OS boot partition.
# Enables SSH, writes userconf.txt from .env credentials, and pre-applies boot/cgroup settings.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-files.sh
. "$SCRIPT_DIR/boot-files.sh"

AEGIS_BOOT_DIR="${AEGIS_BOOT_DIR:-}"
AEGIS_USER="${AEGIS_USER:-pi}"
AEGIS_PASSWORD="${AEGIS_PASSWORD:-}"
AEGIS_PASSWORD_HASH="${AEGIS_PASSWORD_HASH:-}"
AEGIS_NODE_NAME="${AEGIS_NODE_NAME:-aegis}"
AEGIS_GPU_MEM="${AEGIS_GPU_MEM:-16}"
AEGIS_DISABLE_WIFI="${AEGIS_DISABLE_WIFI:-true}"
AEGIS_DISABLE_BLUETOOTH="${AEGIS_DISABLE_BLUETOOTH:-true}"
AEGIS_EJECT="${AEGIS_EJECT:-false}"

detect_boot_dir() {
    local dir=""
    if [[ -n "$AEGIS_BOOT_DIR" ]]; then
        dir="$AEGIS_BOOT_DIR"
    elif [[ -d "/Volumes/bootfs" ]]; then
        dir="/Volumes/bootfs"
    elif [[ -d "/Volumes/boot" ]]; then
        dir="/Volumes/boot"
    else
        echo "Error: could not find a mounted Raspberry Pi boot partition (/Volumes/bootfs or /Volumes/boot)." >&2
        echo "Insert the flashed SD card or pass --boot-dir <path>." >&2
        exit 1
    fi
    while [[ "$dir" != "/" && "$dir" == */ ]]; do
        dir="${dir%/}"
    done
    printf '%s\n' "$dir"
}

validate_inputs() {
    local boot_dir="$1"
    if [[ ! -d "$boot_dir" || ! -w "$boot_dir" ]]; then
        echo "Error: boot directory '$boot_dir' does not exist or is not writable." >&2
        exit 1
    fi
    if [[ ! -f "$boot_dir/config.txt" || ! -f "$boot_dir/cmdline.txt" ]]; then
        echo "Error: '$boot_dir' does not look like a Raspberry Pi boot partition (missing config.txt or cmdline.txt)." >&2
        exit 1
    fi
    if ! [[ "$AEGIS_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        echo "Error: invalid Linux username AEGIS_USER='$AEGIS_USER'." >&2
        exit 1
    fi
    if ! [[ "$AEGIS_NODE_NAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        echo "Error: AEGIS_NODE_NAME must be a valid lowercase RFC 1123 label (got '$AEGIS_NODE_NAME')." >&2
        exit 1
    fi
    if ! [[ "$AEGIS_GPU_MEM" =~ ^[0-9]+$ ]]; then
        echo "Error: AEGIS_GPU_MEM must be an integer (got '$AEGIS_GPU_MEM')." >&2
        exit 1
    fi
}

resolve_password_hash() {
    if [[ -n "$AEGIS_PASSWORD_HASH" ]]; then
        if [[ ! "$AEGIS_PASSWORD_HASH" =~ ^\$(6|5|y|1)\$[^[:space:]:$]+(\$[^[:space:]:$]+)+$ ]]; then
            echo "Error: AEGIS_PASSWORD_HASH must be a valid \$6\$/\$5\$/\$y\$/\$1\$ crypt hash with no spaces or colons." >&2
            exit 1
        fi
        printf '%s\n' "$AEGIS_PASSWORD_HASH"
        return 0
    fi

    if ! command -v python3 &>/dev/null; then
        echo "Error: python3 is required to generate SHA-512 password hashes on macOS." >&2
        exit 1
    fi

    local pw="$AEGIS_PASSWORD"
    local pw_confirm=""
    if [[ -z "$pw" ]]; then
        if ! exec 3< /dev/tty 2>/dev/null; then
            echo "Error: no TTY available for password prompt; set AEGIS_PASSWORD or AEGIS_PASSWORD_HASH." >&2
            exit 1
        fi
        printf "Enter initial password for user '%s': " "$AEGIS_USER" >&2
        read -rs pw <&3 || true
        echo >&2
        if [[ -z "$pw" ]]; then
            exec 3<&-
            echo "Error: password cannot be empty." >&2
            exit 1
        fi
        printf "Confirm password for user '%s': " "$AEGIS_USER" >&2
        read -rs pw_confirm <&3 || true
        echo >&2
        exec 3<&-
        if [[ "$pw" != "$pw_confirm" ]]; then
            echo "Error: passwords do not match." >&2
            exit 1
        fi
    fi

    printf '%s' "$pw" | python3 "$SCRIPT_DIR/hash-password.py" --raw
}

main() {
    local boot_dir password_hash
    boot_dir="$(detect_boot_dir)"
    validate_inputs "$boot_dir"

    password_hash="$(resolve_password_hash)"

    echo "==> Enabling SSH on $boot_dir/ssh"
    : > "$boot_dir/ssh"

    echo "==> Writing initial account '$AEGIS_USER' to $boot_dir/userconf.txt"
    printf '%s:%s\n' "$AEGIS_USER" "$password_hash" > "$boot_dir/userconf.txt"

    update_boot_config_file "$boot_dir/config.txt"
    update_cmdline_cgroups_file "$boot_dir/cmdline.txt"

    if [[ "$AEGIS_EJECT" == "true" ]]; then
        if command -v diskutil &>/dev/null; then
            echo "==> Ejecting $boot_dir"
            diskutil eject "$boot_dir"
        else
            echo "Warning: diskutil not found; eject '$boot_dir' manually." >&2
        fi
    else
        echo "==> SD preparation complete. Safely eject '$boot_dir' before removing the card."
    fi

    echo "==> Next: boot Aegis on wired Ethernet, then run:"
    echo "    ./nodes/aegis/setup.sh prep --refresh-host-key"
    echo "    (If you did not set hostname to '${AEGIS_NODE_NAME}' in Imager, add: --host raspberrypi.local)"
}

main "$@"
