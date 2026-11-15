#!/bin/bash
set -euo pipefail

# Runs on Aegis as root via sudo.
# Idempotently configures and joins Aegis to Axis's k3s cluster as a tainted edge agent.

if [[ -n "${1:-}" && -f "$1" ]]; then
    set -a
    # shellcheck source=/dev/null
    . "$1"
    set +a
fi

AEGIS_NODE_NAME="${AEGIS_NODE_NAME:-aegis}"
K3S_URL="${K3S_URL:-}"
K3S_TOKEN="${K3S_TOKEN:-}"
K3S_VERSION="${K3S_VERSION:-}"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Error: this script must run as root." >&2
        exit 1
    fi
}

validate_inputs() {
    if [[ ! "$AEGIS_NODE_NAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        echo "Error: AEGIS_NODE_NAME must be a valid lowercase RFC 1123 label (got '$AEGIS_NODE_NAME')." >&2
        exit 1
    fi
    if [[ -z "$K3S_URL" || -z "$K3S_TOKEN" ]]; then
        echo "Error: K3S_URL and K3S_TOKEN must both be set before running join." >&2
        exit 1
    fi
    if [[ ! "$K3S_URL" =~ ^https://[^[:space:]]+$ ]]; then
        echo "Error: K3S_URL must be an https:// URL with no whitespace (got '$K3S_URL')." >&2
        exit 1
    fi
    if [[ -n "$K3S_VERSION" && "$K3S_VERSION" =~ [[:space:]] ]]; then
        echo "Error: K3S_VERSION cannot contain whitespace (got '$K3S_VERSION')." >&2
        exit 1
    fi
}

check_memory_cgroups() {
    if grep -qw memory /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
        return 0
    fi
    if awk '$1 == "memory" && $4 == 1 { found=1 } END { exit !found }' /proc/cgroups 2>/dev/null; then
        return 0
    fi
    echo "Error: memory cgroup controller is not active." >&2
    echo "Run './nodes/aegis/setup.sh prep' and ensure Aegis has rebooted first." >&2
    exit 1
}

check_server_reachable() {
    echo "==> Checking k3s control plane reachability at $K3S_URL"
    # Any HTTP response (including 401 Unauthorized) proves TCP/TLS connectivity to the API server.
    if ! curl -ks --connect-timeout 5 --max-time 10 -o /dev/null "$K3S_URL"; then
        echo "Error: cannot connect to k3s server at '$K3S_URL' from Aegis." >&2
        exit 1
    fi
}

write_k3s_config() {
    echo "==> Writing /etc/rancher/k3s/config.yaml for node '$AEGIS_NODE_NAME'"
    # Note: node-taint and node-label are only applied on initial node registration.
    # For an already-registered node, update them via kubectl on Axis.
    mkdir -p /etc/rancher/k3s
    cat <<EOF > /etc/rancher/k3s/config.yaml
node-name: ${AEGIS_NODE_NAME}
node-taint:
  - "role=edge:NoSchedule"
node-label:
  - "hardware=rpi3b"
  - "nal.role=edge"
kubelet-arg:
  - "container-log-max-size=10Mi"
  - "container-log-max-files=2"
  # Specify all eviction signals explicitly so customizing memory does not zero out disk defaults.
  - "eviction-hard=memory.available<120Mi,nodefs.available<10%,imagefs.available<15%,nodefs.inodesFree<5%,imagefs.inodesFree<5%"
EOF
    chmod 644 /etc/rancher/k3s/config.yaml
}

install_k3s_agent() {
    echo "==> Installing / updating k3s-agent${K3S_VERSION:+ ($K3S_VERSION)}"
    export K3S_URL K3S_TOKEN
    export INSTALL_K3S_EXEC="agent"
    if [[ -n "$K3S_VERSION" ]]; then
        export INSTALL_K3S_VERSION="$K3S_VERSION"
    fi
    curl -sfL --connect-timeout 10 --max-time 60 https://get.k3s.io | sh -s -

    if ! systemctl is-active --quiet k3s-agent; then
        echo "Error: k3s-agent failed to become active. Check 'journalctl -u k3s-agent'." >&2
        exit 1
    fi
    echo "==> k3s-agent is active. Run 'kubectl get nodes' on Axis to verify node registration."
}

main() {
    require_root
    validate_inputs
    check_memory_cgroups
    check_server_reachable
    write_k3s_config
    install_k3s_agent
}

main "$@"
