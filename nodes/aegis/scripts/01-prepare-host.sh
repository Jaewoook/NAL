#!/bin/bash
set -euo pipefail

# Runs on Aegis (Raspberry Pi OS Lite) as root via sudo.
# Idempotently prepares the OS, kernel cgroups, swap/zram, and ports for k3s.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-files.sh
. "$SCRIPT_DIR/boot-files.sh"

if [[ -n "${1:-}" && -f "$1" ]]; then
    set -a
    # shellcheck source=/dev/null
    . "$1"
    set +a
fi

AEGIS_NODE_NAME="${AEGIS_NODE_NAME:-aegis}"
AEGIS_GPU_MEM="${AEGIS_GPU_MEM:-16}"
AEGIS_ZRAM_PERCENT="${AEGIS_ZRAM_PERCENT:-50}"
AEGIS_ZRAM_ALGO="${AEGIS_ZRAM_ALGO:-lz4}"
AEGIS_DISABLE_WIFI="${AEGIS_DISABLE_WIFI:-true}"
AEGIS_DISABLE_BLUETOOTH="${AEGIS_DISABLE_BLUETOOTH:-true}"
AEGIS_DISABLE_RESOLVED_STUB="${AEGIS_DISABLE_RESOLVED_STUB:-true}"
AEGIS_REBOOT="${AEGIS_REBOOT:-false}"

validate_bool() {
    local name="$1" val="$2"
    if [[ "$val" != "true" && "$val" != "false" ]]; then
        echo "Error: $name must be 'true' or 'false' (got '$val')." >&2
        exit 1
    fi
}

validate_inputs() {
    if ! [[ "$AEGIS_NODE_NAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        echo "Error: AEGIS_NODE_NAME must be a valid lowercase RFC 1123 label (got '$AEGIS_NODE_NAME')." >&2
        exit 1
    fi
    if ! [[ "$AEGIS_GPU_MEM" =~ ^[0-9]+$ ]]; then
        echo "Error: AEGIS_GPU_MEM must be an integer (got '$AEGIS_GPU_MEM')." >&2
        exit 1
    fi
    if ! [[ "$AEGIS_ZRAM_PERCENT" =~ ^[0-9]+$ ]] || (( AEGIS_ZRAM_PERCENT < 1 || AEGIS_ZRAM_PERCENT > 200 )); then
        echo "Error: AEGIS_ZRAM_PERCENT must be an integer between 1 and 200 (got '$AEGIS_ZRAM_PERCENT')." >&2
        exit 1
    fi
    if ! [[ "$AEGIS_ZRAM_ALGO" =~ ^(lz4|zstd|lzo|lzo-rle)$ ]]; then
        echo "Error: AEGIS_ZRAM_ALGO must be one of lz4, zstd, lzo, lzo-rle (got '$AEGIS_ZRAM_ALGO')." >&2
        exit 1
    fi
    validate_bool "AEGIS_DISABLE_WIFI" "$AEGIS_DISABLE_WIFI"
    validate_bool "AEGIS_DISABLE_BLUETOOTH" "$AEGIS_DISABLE_BLUETOOTH"
    validate_bool "AEGIS_DISABLE_RESOLVED_STUB" "$AEGIS_DISABLE_RESOLVED_STUB"
    validate_bool "AEGIS_REBOOT" "$AEGIS_REBOOT"
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Error: this script must run as root." >&2
        exit 1
    fi
}

check_platform() {
    local arch
    arch="$(uname -m)"
    if [[ "$arch" != "aarch64" ]]; then
        echo "Warning: expected 64-bit ARM (aarch64), detected '$arch'." >&2
        echo "         Many modern Kubernetes images no longer publish 32-bit armhf builds." >&2
    fi
    if ! command -v apt-get &>/dev/null; then
        echo "Error: apt-get not found; this script targets Raspberry Pi OS / Debian." >&2
        exit 1
    fi
}

resolve_boot_file() {
    local name="$1"
    if [[ -f "/boot/firmware/$name" ]]; then
        echo "/boot/firmware/$name"
    elif [[ -f "/boot/$name" ]]; then
        echo "/boot/$name"
    else
        echo "Error: could not find $name under /boot/firmware or /boot." >&2
        exit 1
    fi
}

configure_hostname() {
    local current
    current="$(hostname)"
    if [[ "$current" != "$AEGIS_NODE_NAME" ]]; then
        echo "==> Setting hostname: $current -> $AEGIS_NODE_NAME"
        hostnamectl set-hostname "$AEGIS_NODE_NAME"
    else
        echo "==> Hostname already set to $AEGIS_NODE_NAME"
    fi

    if grep -qE '^127\.0\.1\.1[[:space:]]+' /etc/hosts; then
        sed -i -E "s|^127\.0\.1\.1[[:space:]]+.*|127.0.1.1\t${AEGIS_NODE_NAME}|" /etc/hosts
    else
        printf '127.0.1.1\t%s\n' "$AEGIS_NODE_NAME" >> /etc/hosts
    fi
}

install_packages() {
    local pkgs=(curl ca-certificates iptables)
    # Only install zram-tools on older releases that lack native rpi-swap.
    if [[ ! -f /etc/rpi/swap.conf ]]; then
        pkgs+=(zram-tools)
    fi

    echo "==> Updating apt metadata and installing base packages: ${pkgs[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=60 update -qq
    apt-get -o DPkg::Lock::Timeout=60 install -y -qq "${pkgs[@]}"
}

configure_boot_config() {
    update_boot_config_file "$(resolve_boot_file config.txt)"
}

configure_cmdline_cgroups() {
    update_cmdline_cgroups_file "$(resolve_boot_file cmdline.txt)"
}

disable_unit_if_present() {
    local unit="$1" unit_out
    unit_out="$(systemctl list-unit-files "$unit" --no-legend 2>/dev/null || true)"
    if grep -q "^${unit}[[:space:]]" <<< "$unit_out"; then
        systemctl disable --now "$unit" &>/dev/null || true
    fi
}

configure_wireless_services() {
    if [[ "$AEGIS_DISABLE_BLUETOOTH" == "true" ]]; then
        echo "==> Disabling Bluetooth services"
        disable_unit_if_present bluetooth.service
        disable_unit_if_present hciuart.service
    fi
    if [[ "$AEGIS_DISABLE_WIFI" == "true" ]]; then
        echo "==> Disabling Wi-Fi supplicant service"
        disable_unit_if_present wpa_supplicant.service
    fi
}

configure_swap_zram() {
    if [[ -f /etc/rpi/swap.conf ]]; then
        # Raspberry Pi OS Trixie+ manages swap via rpi-swap (systemd-zram-generator).
        # Setting Mechanism=zram prevents SD-card writeback swapfile wear.
        local mem_kib zram_mib
        mem_kib="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
        zram_mib=$(( (mem_kib / 1024) * AEGIS_ZRAM_PERCENT / 100 ))
        if (( zram_mib < 256 )); then
            zram_mib=256
        fi

        echo "==> Configuring rpi-swap for zram-only (${zram_mib} MiB)"
        mkdir -p /etc/rpi/swap.conf.d
        cat <<EOF > /etc/rpi/swap.conf.d/90-nal-aegis.conf
[Main]
Mechanism=zram

[Zram]
FixedSizeMiB=${zram_mib}
EOF
    else
        # Legacy Bookworm / Bullseye path: disable SD swapfile and enable zram-tools.
        echo "==> Disabling dphys-swapfile and configuring zramswap (${AEGIS_ZRAM_ALGO}, ${AEGIS_ZRAM_PERCENT}%)"
        if command -v dphys-swapfile &>/dev/null; then
            dphys-swapfile swapoff &>/dev/null || true
            dphys-swapfile uninstall &>/dev/null || true
            disable_unit_if_present dphys-swapfile.service
        fi
        cat <<EOF > /etc/default/zramswap
ALGO=${AEGIS_ZRAM_ALGO}
PERCENT=${AEGIS_ZRAM_PERCENT}
PRIORITY=100
EOF
        systemctl enable zramswap.service &>/dev/null || true
        if ! systemctl restart zramswap.service; then
            echo "Warning: failed to restart zramswap.service (check AEGIS_ZRAM_ALGO='$AEGIS_ZRAM_ALGO')." >&2
        fi
    fi

    # High swappiness is optimal for in-RAM zram so idle pages compress before OOM.
    cat <<EOF > /etc/sysctl.d/90-nal-aegis.conf
vm.swappiness=100
EOF
    sysctl -p /etc/sysctl.d/90-nal-aegis.conf &>/dev/null || true
}

configure_journald_ram() {
    echo "==> Setting systemd-journald to volatile RAM storage (32M cap) to protect SD card"
    mkdir -p /etc/systemd/journald.conf.d
    cat <<EOF > /etc/systemd/journald.conf.d/90-nal-aegis.conf
[Journal]
Storage=volatile
RuntimeMaxUse=32M
EOF
    systemctl restart systemd-journald || true
}

configure_port_53() {
    if [[ "$AEGIS_DISABLE_RESOLVED_STUB" != "true" ]]; then
        return
    fi
    if ! systemctl is-active systemd-resolved &>/dev/null; then
        local ss_out=""
        if command -v ss &>/dev/null; then
            ss_out="$(ss -tuln 2>/dev/null || true)"
        fi
        if grep -qE '[:.]53[[:space:]]' <<< "$ss_out"; then
            echo "Warning: systemd-resolved is not active, but port 53 is already in use by another process." >&2
        else
            echo "==> systemd-resolved not active; port 53 is free"
        fi
        return
    fi

    echo "==> Disabling systemd-resolved DNSStubListener to free port 53"
    mkdir -p /etc/systemd/resolved.conf.d
    cat <<EOF > /etc/systemd/resolved.conf.d/90-nal-aegis.conf
[Resolve]
DNSStubListener=no
EOF
    systemctl restart systemd-resolved

    # Repoint /etc/resolv.conf away from 127.0.0.53 stub once upstream nameservers exist.
    if [[ -L /etc/resolv.conf ]] && [[ "$(readlink /etc/resolv.conf)" == *stub-resolv.conf* ]] \
        && grep -qE '^[[:space:]]*nameserver[[:space:]]+' /run/systemd/resolve/resolv.conf 2>/dev/null; then
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi
}

main() {
    require_root
    validate_inputs
    check_platform
    configure_hostname
    install_packages
    configure_boot_config
    configure_cmdline_cgroups
    configure_wireless_services
    configure_swap_zram
    configure_journald_ram
    configure_port_53
    echo "==> Host preparation complete."
    if [[ "$AEGIS_REBOOT" == "true" ]]; then
        echo "==> Scheduling reboot in 2s..."
        # Delayed background reboot lets SSH exit cleanly and remote cleanup traps finish.
        nohup sh -c 'sleep 2 && systemctl reboot' </dev/null >/dev/null 2>&1 &
    fi
}

main "$@"
