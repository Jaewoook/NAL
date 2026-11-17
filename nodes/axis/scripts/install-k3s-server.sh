#!/bin/bash
set -euo pipefail

# Runs inside the Axis Lima VM as root via sudo.
# Idempotently configures and installs/updates k3s server bound to the bridged `lima0` interface.

if [[ -n "${1:-}" && -f "$1" ]]; then
    set -a
    # shellcheck source=/dev/null
    . "$1"
    set +a
fi

AXIS_NODE_NAME="${AXIS_NODE_NAME:-axis}"
AXIS_NODE_IP="${AXIS_NODE_IP:-}"
AXIS_K3S_VERSION="${AXIS_K3S_VERSION:-}"
AXIS_K3S_DISABLE_TRAEFIK="${AXIS_K3S_DISABLE_TRAEFIK:-false}"
AXIS_K3S_DISABLE_SERVICELB="${AXIS_K3S_DISABLE_SERVICELB:-false}"
FORCE_K3S_REINSTALL="${FORCE_K3S_REINSTALL:-false}"
CONFIG_CHANGED="false"
TMP_CFG=""

cleanup() {
    if [[ -n "$TMP_CFG" && -f "$TMP_CFG" ]]; then
        rm -f "$TMP_CFG"
    fi
}

trap cleanup EXIT

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Error: this script must run as root." >&2
        exit 1
    fi
}

validate_ipv4() {
    local name="$1" val="$2"
    if [[ ! "$val" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Error: invalid $name='$val'." >&2
        exit 1
    fi
    local IFS='.' octet
    local -a octets
    read -r -a octets <<< "$val"
    for octet in "${octets[@]}"; do
        if [[ "$octet" =~ ^0[0-9]+$ ]] || (( 10#$octet > 255 )); then
            echo "Error: $name contains invalid IPv4 octet '$octet' (got '$val')." >&2
            exit 1
        fi
    done
    if [[ "$val" == "0.0.0.0" || "$val" == "255.255.255.255" || "$val" == 127.* ]]; then
        echo "Error: $name cannot be '$val' (must be a routable LAN IPv4)." >&2
        exit 1
    fi
}

validate_inputs() {
    if [[ ! "$AXIS_NODE_NAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        echo "Error: AXIS_NODE_NAME must be a valid lowercase RFC 1123 label (got '$AXIS_NODE_NAME')." >&2
        exit 1
    fi
    if [[ -n "$AXIS_NODE_IP" ]]; then
        validate_ipv4 "AXIS_NODE_IP" "$AXIS_NODE_IP"
    fi
    if [[ -n "$AXIS_K3S_VERSION" && "$AXIS_K3S_VERSION" =~ [[:space:]] ]]; then
        echo "Error: AXIS_K3S_VERSION cannot contain whitespace (got '$AXIS_K3S_VERSION')." >&2
        exit 1
    fi
    for flag in AXIS_K3S_DISABLE_TRAEFIK AXIS_K3S_DISABLE_SERVICELB FORCE_K3S_REINSTALL; do
        if [[ "${!flag}" != "true" && "${!flag}" != "false" ]]; then
            echo "Error: $flag must be 'true' or 'false' (got '${!flag}')." >&2
            exit 1
        fi
    done
}

detect_bridged_ip() {
    local waited=0 timeout=30 ip="" mac=""
    if ! ip link show dev lima0 &>/dev/null; then
        echo "Error: bridged interface 'lima0' not found inside VM." >&2
        exit 1
    fi

    while (( waited < timeout )); do
        ip="$(ip -4 -o addr show dev lima0 scope global 2>/dev/null | awk '{ split($4, a, "/"); if (a[1] !~ /^169\.254\./) { print a[1]; exit } }')"
        if [[ -n "$ip" ]]; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done

    if [[ -z "$ip" ]]; then
        mac="$(cat /sys/class/net/lima0/address 2>/dev/null || echo unknown)"
        echo "Error: timed out waiting for DHCP IPv4 on bridged interface 'lima0' (MAC: $mac)." >&2
        echo "Check that AXIS_BRIDGE_IFACE is wired Ethernet and reachable by your router DHCP." >&2
        exit 1
    fi

    if [[ -n "$AXIS_NODE_IP" && "$ip" != "$AXIS_NODE_IP" ]]; then
        mac="$(cat /sys/class/net/lima0/address 2>/dev/null || echo unknown)"
        echo "Error: bridged interface 'lima0' got IP '$ip', expected AXIS_NODE_IP='$AXIS_NODE_IP' (MAC: $mac)." >&2
        echo "Reserve '$AXIS_NODE_IP' for MAC '$mac' on your router or clear AXIS_NODE_IP in .env." >&2
        exit 1
    fi

    printf '%s' "$ip"
}

write_k3s_config() {
    local bridged_ip="$1"
    local disabled=()

    if [[ "$AXIS_K3S_DISABLE_TRAEFIK" == "true" ]]; then
        disabled+=("traefik")
    fi
    if [[ "$AXIS_K3S_DISABLE_SERVICELB" == "true" ]]; then
        disabled+=("servicelb")
    fi

    TMP_CFG="$(mktemp)"
    {
        cat <<EOF
node-name: ${AXIS_NODE_NAME}
node-ip: ${bridged_ip}
advertise-address: ${bridged_ip}
flannel-iface: lima0
write-kubeconfig-mode: "0644"
tls-san:
  - "127.0.0.1"
  - "localhost"
  - "${bridged_ip}"
kubelet-arg:
  - "container-log-max-size=10Mi"
  - "container-log-max-files=3"
EOF
        if [[ "${#disabled[@]}" -gt 0 ]]; then
            echo "disable:"
            local item
            for item in "${disabled[@]}"; do
                echo "  - \"${item}\""
            done
        fi
    } > "$TMP_CFG"

    mkdir -p /etc/rancher/k3s
    if [[ -f /etc/rancher/k3s/config.yaml ]] && cmp -s "$TMP_CFG" /etc/rancher/k3s/config.yaml; then
        CONFIG_CHANGED="false"
        rm -f "$TMP_CFG"
        TMP_CFG=""
        echo "==> /etc/rancher/k3s/config.yaml unchanged"
    else
        echo "==> Writing /etc/rancher/k3s/config.yaml (node=$AXIS_NODE_NAME, ip=$bridged_ip, iface=lima0)"
        install -m 644 "$TMP_CFG" /etc/rancher/k3s/config.yaml
        rm -f "$TMP_CFG"
        TMP_CFG=""
        CONFIG_CHANGED="true"
    fi
}

install_k3s_server() {
    local installed_ver="" need_install="false"
    if command -v k3s &>/dev/null; then
        installed_ver="$(k3s --version 2>/dev/null | awk 'NR==1 { print $3 }')"
    fi

    if [[ -z "$installed_ver" || "$FORCE_K3S_REINSTALL" == "true" ]]; then
        need_install="true"
    elif [[ -n "$AXIS_K3S_VERSION" && "$installed_ver" != "$AXIS_K3S_VERSION" ]]; then
        need_install="true"
    fi

    if [[ "$need_install" == "true" ]]; then
        echo "==> Installing / updating k3s server${AXIS_K3S_VERSION:+ ($AXIS_K3S_VERSION)}"
        export INSTALL_K3S_EXEC="server"
        if [[ -n "$AXIS_K3S_VERSION" ]]; then
            export INSTALL_K3S_VERSION="$AXIS_K3S_VERSION"
        fi
        curl -sfL --connect-timeout 10 --max-time 60 https://get.k3s.io | sh -s -
    elif [[ "$CONFIG_CHANGED" == "true" ]]; then
        echo "==> Restarting k3s.service to apply updated config.yaml"
        systemctl restart k3s
    elif ! systemctl is-active --quiet k3s; then
        echo "==> Starting k3s.service"
        systemctl start k3s
    else
        echo "==> k3s server already active and up to date ($installed_ver)"
        return 0
    fi

    if ! systemctl is-active --quiet k3s; then
        echo "Error: k3s.service failed to become active. Check 'journalctl -u k3s'." >&2
        exit 1
    fi

    local waited=0
    while (( waited < 60 )); do
        if k3s kubectl get node "$AXIS_NODE_NAME" &>/dev/null; then
            echo "==> k3s server is active: $(k3s --version | head -n 1)"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    echo "Error: k3s API did not register node '$AXIS_NODE_NAME' within 60s." >&2
    exit 1
}

main() {
    local bridged_ip
    require_root
    validate_inputs
    bridged_ip="$(detect_bridged_ip)"
    write_k3s_config "$bridged_ip"
    install_k3s_server
}

main "$@"
