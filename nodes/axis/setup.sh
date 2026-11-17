#!/bin/bash
set -euo pipefail

# Runs on Axis (Mac Mini M2, macOS) to provision and manage a bridged Lima Linux VM
# hosting the k3s control plane for Axis + external LAN nodes (such as Aegis).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${NAL_AXIS_ENV_FILE:-$SCRIPT_DIR/.env}"

# shellcheck source=../lib/common.sh
. "$NODES_DIR/lib/common.sh"

ensure_macos_paths

usage() {
    cat <<EOF
Usage: $(basename "$0") <bootstrap|up|k3s|kubeconfig|join-info|autostart|status|stop|destroy> [options]

Provision and manage Axis's k3s control plane inside a bridged Lima (vz) Linux VM.

Commands:
  bootstrap   One-time host setup: install lima, build root-owned socket_vmnet, configure networks.yaml & sudoers
  up          Create (if needed) and start the Lima VM, install k3s server, sync kubeconfig, set autostart
  k3s         Re-apply k3s server configuration/version inside the running VM and refresh kubeconfig
  kubeconfig  Sync VM kubeconfig to local macOS kubectl context (\$AXIS_KUBECONFIG_PATH)
  join-info   Print K3S_URL, K3S_TOKEN, and K3S_VERSION for joining Aegis (nodes/aegis/.env)
  autostart   Apply launchd autostart policy (AXIS_AUTOSTART_MODE: login | boot | none)
  status      Show Lima VM state, lima0 bridged IP, k3s status, and Kubernetes nodes
  stop        Stop the Lima VM cleanly
  destroy     Delete the Lima VM and its disk (pass --yes to skip confirmation)

Options (override values from $ENV_FILE):
  --vm-name <name>           Lima instance name (default: axis-k3s)
  --node-name <name>         Kubernetes node name (default: axis)
  --cpus <n>                 VM vCPU count (default: 4)
  --memory <size>            VM RAM limit, e.g. 6GiB (default: 6GiB)
  --disk <size>              VM disk limit, e.g. 64GiB (default: 64GiB)
  --iface <iface>            macOS physical interface to bridge (default: en0)
  --mac <mac>                Custom bridged MAC address (default: deterministic from VM name)
  --node-ip <ip>             Expected router-assigned IPv4 on lima0
  --k3s-version <ver>        Pin k3s version, e.g. v1.31.6+k3s1
  --autostart <mode>         Autostart mode: login, boot, or none (default: login)
  --reinstall-vmnet          Rebuild and reinstall /opt/socket_vmnet during bootstrap
  --yes                      Skip confirmation prompt for destroy
  -h, --help                 Show this help message
EOF
}

COMMAND=""
REINSTALL_VMNET="false"
ASSUME_YES="false"
CREATED_VM="false"
REMOTE_GUEST_DIR=""
WORK_DIR=""

init_work_dir() {
    if [[ -z "$WORK_DIR" ]]; then
        WORK_DIR="$(mktemp -d)"
        chmod 700 "$WORK_DIR"
    fi
}

cleanup() {
    if [[ "$REMOTE_GUEST_DIR" =~ ^/tmp/nal-axis\.[A-Za-z0-9]+$ ]] && command -v limactl &>/dev/null; then
        vm_shell rm -rf "$REMOTE_GUEST_DIR" &>/dev/null || true
    fi
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
}

make_temp_file() {
    if [[ -z "$WORK_DIR" || ! -d "$WORK_DIR" ]]; then
        echo "Internal error: WORK_DIR is not initialized." >&2
        exit 1
    fi
    mktemp "${WORK_DIR}/file.XXXXXX"
}

make_temp_dir() {
    if [[ -z "$WORK_DIR" || ! -d "$WORK_DIR" ]]; then
        echo "Internal error: WORK_DIR is not initialized." >&2
        exit 1
    fi
    mktemp -d "${WORK_DIR}/dir.XXXXXX"
}

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
        bootstrap|up|k3s|kubeconfig|join-info|autostart|status|stop|destroy)
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
            --vm-name)         AXIS_VM_NAME="${2:?missing value for --vm-name}"; shift 2 ;;
            --node-name)       AXIS_NODE_NAME="${2:?missing value for --node-name}"; shift 2 ;;
            --cpus)            AXIS_CPUS="${2:?missing value for --cpus}"; shift 2 ;;
            --memory)          AXIS_MEMORY="${2:?missing value for --memory}"; shift 2 ;;
            --disk)            AXIS_DISK="${2:?missing value for --disk}"; shift 2 ;;
            --iface)           AXIS_BRIDGE_IFACE="${2:?missing value for --iface}"; shift 2 ;;
            --mac)             AXIS_BRIDGE_MAC="${2:?missing value for --mac}"; shift 2 ;;
            --node-ip)         AXIS_NODE_IP="${2:?missing value for --node-ip}"; shift 2 ;;
            --k3s-version)     AXIS_K3S_VERSION="${2:?missing value for --k3s-version}"; shift 2 ;;
            --autostart)       AXIS_AUTOSTART_MODE="${2:?missing value for --autostart}"; shift 2 ;;
            --reinstall-vmnet) REINSTALL_VMNET="true"; shift ;;
            --yes)             ASSUME_YES="true"; shift ;;
            -h|--help)         usage; exit 0 ;;
            *)
                echo "Error: unknown option '$1'." >&2
                usage >&2
                exit 1
                ;;
        esac
    done
}

validate_inputs() {
    if [[ "$(uname -s)" != "Darwin" ]]; then
        echo "Error: nodes/axis/setup.sh must run on macOS (Axis host)." >&2
        exit 1
    fi
    validate_node_name "AXIS_VM_NAME" "$AXIS_VM_NAME"
    validate_node_name "AXIS_NODE_NAME" "$AXIS_NODE_NAME"

    if [[ ! "$AXIS_CPUS" =~ ^[1-9][0-9]*$ ]]; then
        echo "Error: AXIS_CPUS must be a positive integer (got '$AXIS_CPUS')." >&2
        exit 1
    fi
    if [[ ! "$AXIS_MEMORY" =~ ^[1-9][0-9]*(MiB|GiB|M|G)$ ]]; then
        echo "Error: AXIS_MEMORY must be like '6GiB' or '4096MiB' (got '$AXIS_MEMORY')." >&2
        exit 1
    fi
    if [[ ! "$AXIS_DISK" =~ ^[1-9][0-9]*(MiB|GiB|M|G)$ ]]; then
        echo "Error: AXIS_DISK must be like '64GiB' (got '$AXIS_DISK')." >&2
        exit 1
    fi
    if [[ ! "$AXIS_BRIDGE_IFACE" =~ ^en[0-9]+$ ]]; then
        echo "Error: AXIS_BRIDGE_IFACE must be a macOS interface like en0 (got '$AXIS_BRIDGE_IFACE')." >&2
        exit 1
    fi
    if [[ -n "$AXIS_BRIDGE_MAC" && ! "$AXIS_BRIDGE_MAC" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        echo "Error: AXIS_BRIDGE_MAC must be formatted like 52:54:00:aa:bb:cc (got '$AXIS_BRIDGE_MAC')." >&2
        exit 1
    fi
    if [[ -n "$AXIS_NODE_IP" ]]; then
        validate_ipv4 "AXIS_NODE_IP" "$AXIS_NODE_IP"
    fi
    if [[ ! "$AXIS_SOCKET_VMNET_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]]; then
        echo "Error: invalid AXIS_SOCKET_VMNET_VERSION='$AXIS_SOCKET_VMNET_VERSION'." >&2
        exit 1
    fi
    if [[ ! "$AXIS_AUTOSTART_MODE" =~ ^(login|boot|none)$ ]]; then
        echo "Error: AXIS_AUTOSTART_MODE must be login, boot, or none (got '$AXIS_AUTOSTART_MODE')." >&2
        exit 1
    fi
    if [[ -n "$AXIS_K3S_VERSION" && "$AXIS_K3S_VERSION" =~ [[:space:]] ]]; then
        echo "Error: AXIS_K3S_VERSION cannot contain whitespace (got '$AXIS_K3S_VERSION')." >&2
        exit 1
    fi
    validate_bool "AXIS_K3S_DISABLE_TRAEFIK" "$AXIS_K3S_DISABLE_TRAEFIK"
    validate_bool "AXIS_K3S_DISABLE_SERVICELB" "$AXIS_K3S_DISABLE_SERVICELB"

    if [[ ! "$AXIS_KUBECONFIG_CONTEXT" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "Error: AXIS_KUBECONFIG_CONTEXT must use only [A-Za-z0-9._-] (got '$AXIS_KUBECONFIG_CONTEXT')." >&2
        exit 1
    fi
    if [[ ! "$AXIS_LOCAL_API_PORT" =~ ^[0-9]+$ ]] || (( AXIS_LOCAL_API_PORT < 1 || AXIS_LOCAL_API_PORT > 65535 )); then
        echo "Error: AXIS_LOCAL_API_PORT must be between 1 and 65535 (got '$AXIS_LOCAL_API_PORT')." >&2
        exit 1
    fi
    AXIS_KUBECONFIG_PATH="$(expand_tilde "$AXIS_KUBECONFIG_PATH")"
}

lima_home_dir() {
    printf '%s' "${LIMA_HOME:-$HOME/.lima}"
}

vm_status() {
    limactl list --format '{{.Status}}' "$AXIS_VM_NAME" 2>/dev/null || true
}

vm_shell() {
    # Always start in /tmp inside the guest since mounts: [] omits host working directories.
    limactl shell --workdir /tmp "$AXIS_VM_NAME" -- "$@"
}

check_bridge_interface() {
    local if_info
    if ! if_info="$(ifconfig "$AXIS_BRIDGE_IFACE" 2>/dev/null)"; then
        echo "Error: network interface '$AXIS_BRIDGE_IFACE' does not exist on this Mac." >&2
        exit 1
    fi
    if grep -qE '^[[:space:]]*status:[[:space:]]*inactive$' <<< "$if_info"; then
        echo "Warning: '$AXIS_BRIDGE_IFACE' link is currently inactive (no carrier); guest DHCP will fail until connected." >&2
    fi
    local port_info
    port_info="$(networksetup -listallhardwareports 2>/dev/null || true)"
    if awk -v dev="$AXIS_BRIDGE_IFACE" '
        /^Hardware Port:/ { port=$0 }
        $1 == "Device:" && $2 == dev { if (port ~ /Wi-Fi|AirPort/) found=1 }
        END { exit !found }
    ' <<< "$port_info"; then
        echo "Warning: '$AXIS_BRIDGE_IFACE' is Wi-Fi; macOS wireless drivers drop L2 bridged VM frames." >&2
        echo "         Use wired Ethernet (e.g. en0) for bridged k3s networking." >&2
    fi
}

verify_root_owned_tree() {
    python3 - <<'PY'
import os
import sys

paths = [
    "/opt",
    "/opt/socket_vmnet",
    "/opt/socket_vmnet/bin",
    "/opt/socket_vmnet/bin/socket_vmnet",
]
for p in paths:
    if not os.path.exists(p):
        print(f"Error: missing required path '{p}'.", file=sys.stderr)
        sys.exit(1)
    st = os.lstat(p)
    if st.st_uid != 0 or (st.st_mode & 0o022):
        print(
            f"Error: '{p}' must be owned by root (uid=0) and not group/world writable "
            f"(uid={st.st_uid}, mode={oct(st.st_mode & 0o777)}).",
            file=sys.stderr,
        )
        sys.exit(1)
PY
}

install_socket_vmnet() {
    local lima_dir version_marker installed_uid=""
    lima_dir="$(lima_home_dir)"
    version_marker="${lima_dir}/_config/socket_vmnet.version"

    if [[ -x /opt/socket_vmnet/bin/socket_vmnet ]]; then
        installed_uid="$(stat -f '%u' /opt/socket_vmnet/bin/socket_vmnet 2>/dev/null || true)"
    fi

    if [[ "$REINSTALL_VMNET" != "true" && "$installed_uid" == "0" \
        && -f "$version_marker" && "$(cat "$version_marker" 2>/dev/null || true)" == "$AXIS_SOCKET_VMNET_VERSION" ]] \
        && verify_root_owned_tree &>/dev/null; then
        echo "==> /opt/socket_vmnet/bin/socket_vmnet ($AXIS_SOCKET_VMNET_VERSION) already installed"
        return 0
    fi

    local tool
    for tool in git make cc; do
        if ! command -v "$tool" &>/dev/null; then
            echo "Error: '$tool' is required to build socket_vmnet (install Xcode Command Line Tools)." >&2
            exit 1
        fi
    done

    local src_dir
    src_dir="$(make_temp_dir)"
    echo "==> Building lima-vm/socket_vmnet ($AXIS_SOCKET_VMNET_VERSION)"
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$AXIS_SOCKET_VMNET_VERSION" \
        https://github.com/lima-vm/socket_vmnet.git "$src_dir/socket_vmnet"
    make -C "$src_dir/socket_vmnet"
    echo "==> Installing socket_vmnet into root-owned /opt/socket_vmnet (requires sudo)"
    sudo make -C "$src_dir/socket_vmnet" PREFIX=/opt/socket_vmnet install.bin

    verify_root_owned_tree
    mkdir -p "${lima_dir}/_config"
    printf '%s\n' "$AXIS_SOCKET_VMNET_VERSION" > "$version_marker"
}

configure_networks_yaml() {
    local lima_dir networks_file
    lima_dir="$(lima_home_dir)"
    networks_file="${lima_dir}/_config/networks.yaml"
    mkdir -p "${lima_dir}/_config"

    echo "==> Configuring $networks_file (bridged interface=$AXIS_BRIDGE_IFACE)"
    if [[ ! -s "$networks_file" ]]; then
        # Let installed limactl generate its native version-matched networks.yaml schema first.
        limactl sudoers >/dev/null 2>&1 || true
    fi

    python3 - "$networks_file" "$AXIS_BRIDGE_IFACE" <<'PY'
import os
import re
import sys

path, iface = sys.argv[1], sys.argv[2]
socket_bin = "/opt/socket_vmnet/bin/socket_vmnet"

default_doc = f"""paths:
  socketVMNet: "{socket_bin}"
  varRun: /private/var/run/lima
  sudoers: /private/etc/sudoers.d/lima
group: admin
networks:
  shared:
    mode: shared
    gateway: 192.168.105.1
    dhcpEnd: 192.168.105.254
    netmask: 255.255.255.0
  bridged:
    mode: bridged
    interface: {iface}
  host:
    mode: host
    gateway: 192.168.106.1
    dhcpEnd: 192.168.106.254
    netmask: 255.255.255.0
"""

if not os.path.exists(path) or os.path.getsize(path) == 0:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(default_doc)
    raise SystemExit(0)

with open(path, "r", encoding="utf-8") as fh:
    old_text = fh.read()
lines = old_text.splitlines()

out = []
section = None
sub = None
seen_socket = False
seen_top_group = False
seen_bridged = False
seen_bridged_mode = False
seen_bridged_iface = False
seen_paths = False
seen_networks = False

for line in lines:
    group_match = re.match(r"^group:\s*(.*)$", line)
    if group_match:
        if section == "paths" and not seen_socket:
            out.append(f'  socketVMNet: "{socket_bin}"')
            seen_socket = True
        if section == "networks" and sub == "bridged":
            if not seen_bridged_mode:
                out.append("    mode: bridged")
            if not seen_bridged_iface:
                out.append(f"    interface: {iface}")
        if section == "networks" and not seen_bridged:
            out.extend(["  bridged:", "    mode: bridged", f"    interface: {iface}"])
            seen_bridged = True
        section = None
        sub = None
        seen_top_group = True
        val = group_match.group(1).strip()
        if not val or val.startswith("#"):
            out.append("group: admin")
        else:
            out.append(line)
        continue

    top_match = re.match(r"^([A-Za-z0-9_-]+):\s*(?:\{\s*\}\s*)?(#.*)?$", line)
    if top_match:
        if section == "paths" and not seen_socket:
            out.append(f'  socketVMNet: "{socket_bin}"')
            seen_socket = True
        if section == "networks" and sub == "bridged":
            if not seen_bridged_mode:
                out.append("    mode: bridged")
            if not seen_bridged_iface:
                out.append(f"    interface: {iface}")
        if section == "networks" and not seen_bridged:
            out.extend(["  bridged:", "    mode: bridged", f"    interface: {iface}"])
            seen_bridged = True

        section = top_match.group(1)
        sub = None
        if section == "paths":
            seen_paths = True
            line = "paths:"
        elif section == "networks":
            seen_networks = True
            line = "networks:"
        out.append(line)
        continue

    if section == "paths":
        if re.match(r"^\s+socketVMNet:", line):
            out.append(f'  socketVMNet: "{socket_bin}"')
            seen_socket = True
            continue
        # Lima 2.x moved `group` from `paths.group` to top-level `group`.
        if re.match(r"^\s+group:", line):
            continue

    if section == "networks":
        sub_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:\{\s*\}\s*)?(#.*)?$", line)
        if sub_match:
            if sub == "bridged":
                if not seen_bridged_mode:
                    out.append("    mode: bridged")
                if not seen_bridged_iface:
                    out.append(f"    interface: {iface}")
            sub = sub_match.group(1)
            if sub == "bridged":
                seen_bridged = True
                line = "  bridged:"
            out.append(line)
            continue
        if sub == "bridged":
            if re.match(r"^\s+mode:", line):
                out.append("    mode: bridged")
                seen_bridged_mode = True
                continue
            if re.match(r"^\s+interface:", line):
                out.append(f"    interface: {iface}")
                seen_bridged_iface = True
                continue

    out.append(line)

if section == "paths" and not seen_socket:
    out.append(f'  socketVMNet: "{socket_bin}"')
if section == "networks":
    if sub == "bridged":
        if not seen_bridged_mode:
            out.append("    mode: bridged")
        if not seen_bridged_iface:
            out.append(f"    interface: {iface}")
    elif not seen_bridged:
        out.extend(["  bridged:", "    mode: bridged", f"    interface: {iface}"])

if not seen_paths:
    out.extend(["paths:", f'  socketVMNet: "{socket_bin}"', "  varRun: /private/var/run/lima",
                "  sudoers: /private/etc/sudoers.d/lima"])
if not seen_top_group:
    out.append("group: admin")
if not seen_networks:
    out.extend(["networks:", "  bridged:", "    mode: bridged", f"    interface: {iface}"])

new_text = "\n".join(out) + "\n"
if new_text != old_text:
    with open(path + ".bak", "w", encoding="utf-8") as bak:
        bak.write(old_text)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new_text)
PY
}

install_lima_sudoers() {
    local tmp_sudoers
    tmp_sudoers="$(make_temp_file)"
    echo "==> Syncing /etc/sudoers.d/lima via limactl sudoers (requires sudo)"
    limactl sudoers > "$tmp_sudoers"
    if [[ ! -s "$tmp_sudoers" ]]; then
        echo "Error: 'limactl sudoers' returned empty output." >&2
        exit 1
    fi
    if grep -qE '^%[[:space:]]' "$tmp_sudoers"; then
        echo "Error: 'limactl sudoers' generated an empty group; verify top-level 'group:' in $(lima_home_dir)/_config/networks.yaml." >&2
        exit 1
    fi
    sudo visudo -cf "$tmp_sudoers"
    sudo install -o root -g wheel -m 0440 "$tmp_sudoers" /etc/sudoers.d/lima
}

cmd_bootstrap() {
    check_bridge_interface
    if ! command -v limactl &>/dev/null; then
        if ! command -v brew &>/dev/null; then
            echo "Error: Homebrew is required to install Lima." >&2
            exit 1
        fi
        echo "==> Installing lima via Homebrew"
        brew install lima
    else
        echo "==> Lima already installed: $(limactl --version)"
    fi

    install_socket_vmnet
    configure_networks_yaml
    install_lima_sudoers
    echo "==> Bootstrap complete. Next: ./nodes/axis/setup.sh up"
}

require_bootstrapped() {
    local lima_dir
    lima_dir="$(lima_home_dir)"
    if ! command -v limactl &>/dev/null; then
        echo "Error: limactl not found. Run './nodes/axis/setup.sh bootstrap' first." >&2
        exit 1
    fi
    if ! verify_root_owned_tree &>/dev/null; then
        echo "Error: root-owned /opt/socket_vmnet/bin/socket_vmnet is missing or insecure. Run './nodes/axis/setup.sh bootstrap' first." >&2
        exit 1
    fi
    if [[ ! -f "${lima_dir}/_config/networks.yaml" ]] || [[ ! -f /etc/sudoers.d/lima ]]; then
        echo "Error: Lima bridged network config or /etc/sudoers.d/lima is missing. Run './nodes/axis/setup.sh bootstrap' first." >&2
        exit 1
    fi
}

warn_if_vm_config_drifted() {
    local vm_yaml
    vm_yaml="$(lima_home_dir)/${AXIS_VM_NAME}/lima.yaml"
    [[ -f "$vm_yaml" ]] || return 0
    python3 - "$vm_yaml" "$AXIS_CPUS" "$AXIS_MEMORY" "$AXIS_DISK" "$AXIS_BRIDGE_MAC" "$AXIS_LOCAL_API_PORT" <<'PY'
import re
import sys

path, cpus, memory, disk, mac, port = sys.argv[1:7]
with open(path, "r", encoding="utf-8") as fh:
    text = fh.read()

drifts = []
checks = [
    ("AXIS_CPUS", rf"(?m)^cpus:\s*{re.escape(cpus)}\s*(?:#.*)?$"),
    ("AXIS_MEMORY", rf"""(?m)^memory:\s*['"]?{re.escape(memory)}['"]?\s*(?:#.*)?$"""),
    ("AXIS_DISK", rf"""(?m)^disk:\s*['"]?{re.escape(disk)}['"]?\s*(?:#.*)?$"""),
    ("AXIS_LOCAL_API_PORT", rf"(?m)^\s*(?:-\s*)?hostPort:\s*{re.escape(port)}\b"),
]
for label, pat in checks:
    if not re.search(pat, text):
        drifts.append(label)
if mac and not re.search(
    rf"""(?m)^\s*(?:-\s*)?macAddress:\s*['"]?{re.escape(mac)}['"]?\s*(?:#.*)?$""",
    text,
    re.IGNORECASE,
):
    drifts.append("AXIS_BRIDGE_MAC")

if drifts:
    print(
        f"Note: existing VM ignores updated {', '.join(drifts)}; recreate with 'destroy' + 'up' or update via 'limactl edit'.",
        file=sys.stderr,
    )
PY
}

render_axis_yaml() {
    local out_yaml="$1"
    python3 - "$SCRIPT_DIR/axis.yaml" "$out_yaml" \
        "$AXIS_CPUS" "$AXIS_MEMORY" "$AXIS_DISK" "$AXIS_BRIDGE_MAC" "$AXIS_LOCAL_API_PORT" <<'PY'
import sys

src, dst, cpus, memory, disk, mac, local_port = sys.argv[1:8]
with open(src, "r", encoding="utf-8") as fh:
    content = fh.read()

replacements = {
    "__AXIS_CPUS__": cpus,
    "__AXIS_MEMORY__": memory,
    "__AXIS_DISK__": disk,
    "__AXIS_BRIDGE_MAC__": mac,
    "__AXIS_LOCAL_API_PORT__": local_port,
}
for k, v in replacements.items():
    content = content.replace(k, v)

with open(dst, "w", encoding="utf-8") as fh:
    fh.write(content)
PY
}

launchd_agent_label() {
    printf 'io.lima-vm.autostart.%s' "$AXIS_VM_NAME"
}

launchd_agent_plist() {
    printf '%s/Library/LaunchAgents/%s.plist' "$HOME" "$(launchd_agent_label)"
}

show_vm_start_logs() {
    local inst_dir log_file
    inst_dir="$(lima_home_dir)/${AXIS_VM_NAME}"
    for log_file in launchd.stderr.log ha.stderr.log; do
        if [[ -s "${inst_dir}/${log_file}" ]]; then
            echo "--- tail ${inst_dir}/${log_file} ---" >&2
            tail -n 20 "${inst_dir}/${log_file}" >&2 || true
        fi
    done
}

start_vm_with_launchd_recovery() {
    if limactl start --tty=false "$AXIS_VM_NAME"; then
        return 0
    fi

    # Lima delegates `limactl start` to launchctl bootstrap when an autostart LaunchAgent
    # exists, relying on RunAtLoad. Headless/remote/on-demand GUI sessions defer RunAtLoad
    # ("pending spawn, domain in on-demand-only mode"), causing a 5s ha.pid timeout unless kickstarted.
    local plist target svc_info
    plist="$(launchd_agent_plist)"
    target="gui/$(id -u)/$(launchd_agent_label)"
    if [[ ! -f "$plist" ]]; then
        return 1
    fi

    svc_info="$(launchctl print "$target" 2>/dev/null || true)"
    if ! grep -qE '^[[:space:]]*runs = 0$' <<< "$svc_info" \
        || grep -qE '^[[:space:]]*state = running$' <<< "$svc_info"; then
        show_vm_start_logs
        return 1
    fi

    echo "==> macOS deferred LaunchAgent spawn (on-demand session); kickstarting '$target'"
    launchctl kickstart "$target"

    local waited=0 timeout=120 st=""
    while (( waited < timeout )); do
        st="$(vm_status)"
        if [[ "$st" == "Running" ]] && vm_shell test -s /run/lima-boot-done &>/dev/null; then
            echo "==> Lima VM '$AXIS_VM_NAME' is running via LaunchAgent"
            return 0
        fi
        if (( waited >= 6 )); then
            svc_info="$(launchctl print "$target" 2>/dev/null || true)"
            if grep -qE '^[[:space:]]*last exit code = [1-9][0-9]*([[:space:]]|$)' <<< "$svc_info" \
                && ! grep -qE '^[[:space:]]*state = running$' <<< "$svc_info"; then
                echo "Error: LaunchAgent '$target' exited unexpectedly while starting '$AXIS_VM_NAME'." >&2
                show_vm_start_logs
                return 1
            fi
        fi
        sleep 2
        waited=$((waited + 2))
    done

    echo "Error: timed out waiting for '$AXIS_VM_NAME' boot readiness after LaunchAgent kickstart (status='${st:-unknown}')." >&2
    show_vm_start_logs
    return 1
}

ensure_vm_running() {
    require_bootstrapped
    local status
    status="$(vm_status)"
    if [[ -z "$status" ]]; then
        local rendered_yaml
        rendered_yaml="$(make_temp_dir)/${AXIS_VM_NAME}.yaml"
        render_axis_yaml "$rendered_yaml"
        echo "==> Creating Lima VM '$AXIS_VM_NAME' (vz, ${AXIS_CPUS} vCPU, ${AXIS_MEMORY}, ${AXIS_DISK}, bridged=${AXIS_BRIDGE_IFACE})"
        limactl create --name="$AXIS_VM_NAME" --tty=false "$rendered_yaml"
        CREATED_VM="true"
        status="Stopped"
    else
        warn_if_vm_config_drifted
    fi

    if [[ "$status" != "Running" ]]; then
        echo "==> Starting Lima VM '$AXIS_VM_NAME'"
        start_vm_with_launchd_recovery
    fi
}

require_vm_running() {
    if ! command -v limactl &>/dev/null; then
        echo "Error: limactl not found." >&2
        exit 1
    fi
    if [[ "$(vm_status)" != "Running" ]]; then
        echo "Error: Lima VM '$AXIS_VM_NAME' is not running. Run './nodes/axis/setup.sh up' first." >&2
        exit 1
    fi
}

cmd_k3s() {
    local force_reinstall="${1:-false}"
    require_vm_running
    local env_tmp
    env_tmp="$(make_temp_file)"
    FORCE_K3S_REINSTALL="$force_reinstall"
    write_env_vars "$env_tmp" \
        AXIS_NODE_NAME AXIS_NODE_IP AXIS_K3S_VERSION \
        AXIS_K3S_DISABLE_TRAEFIK AXIS_K3S_DISABLE_SERVICELB FORCE_K3S_REINSTALL

    REMOTE_GUEST_DIR="$(vm_shell sh -c 'umask 077 && mktemp -d /tmp/nal-axis.XXXXXX')"
    if [[ ! "$REMOTE_GUEST_DIR" =~ ^/tmp/nal-axis\.[A-Za-z0-9]+$ ]]; then
        echo "Error: unexpected guest temp directory '$REMOTE_GUEST_DIR'." >&2
        REMOTE_GUEST_DIR=""
        exit 1
    fi

    local rc=0
    limactl copy "$env_tmp" "${AXIS_VM_NAME}:${REMOTE_GUEST_DIR}/env"
    limactl copy "$SCRIPT_DIR/scripts/install-k3s-server.sh" "${AXIS_VM_NAME}:${REMOTE_GUEST_DIR}/run.sh"
    vm_shell sh -c \
        "trap 'rm -rf '\''${REMOTE_GUEST_DIR}'\''' EXIT; chmod 700 '${REMOTE_GUEST_DIR}/run.sh' && sudo '${REMOTE_GUEST_DIR}/run.sh' '${REMOTE_GUEST_DIR}/env'" || rc=$?
    REMOTE_GUEST_DIR=""
    return "$rc"
}

cmd_kubeconfig() {
    require_vm_running
    local raw_kc new_kc kc_dir
    raw_kc="$(make_temp_file)"
    new_kc="$(make_temp_file)"

    vm_shell sudo cat /etc/rancher/k3s/k3s.yaml > "$raw_kc"
    if [[ ! -s "$raw_kc" ]]; then
        echo "Error: /etc/rancher/k3s/k3s.yaml inside '$AXIS_VM_NAME' is empty or unreadable." >&2
        exit 1
    fi

    python3 - "$raw_kc" "$new_kc" "$AXIS_KUBECONFIG_CONTEXT" "$AXIS_LOCAL_API_PORT" <<'PY'
import re
import sys

src, dst, ctx, port = sys.argv[1:5]
with open(src, "r", encoding="utf-8") as fh:
    text = fh.read()

text = text.replace("https://127.0.0.1:6443", f"https://127.0.0.1:{port}")
# Rename generic k3s 'default' names (including YAML list items like `- name: default`) so merging never collides.
text = re.sub(
    r"""(?m)^(\s*(?:-\s+)?(?:name|cluster|user|current-context):\s*)['"]?default['"]?\s*$""",
    lambda m: f"{m.group(1)}{ctx}",
    text,
)
if ctx != "default" and re.search(
    r"""(?m)^\s*(?:-\s+)?(?:name|cluster|user|current-context):\s*['"]?default['"]?\s*$""",
    text,
):
    raise SystemExit(f"Failed to rename all kubeconfig 'default' identifiers to '{ctx}'.")

with open(dst, "w", encoding="utf-8") as fh:
    fh.write(text)
PY
    chmod 600 "$new_kc"

    kc_dir="$(dirname "$AXIS_KUBECONFIG_PATH")"
    mkdir -p "$kc_dir"
    chmod 700 "$kc_dir"

    if [[ -s "$AXIS_KUBECONFIG_PATH" ]] && command -v kubectl &>/dev/null; then
        local existing_clean merged_kc
        existing_clean="$(make_temp_file)"
        merged_kc="$(make_temp_file)"
        cp "$AXIS_KUBECONFIG_PATH" "$existing_clean"
        kubectl --kubeconfig "$existing_clean" config delete-context "$AXIS_KUBECONFIG_CONTEXT" &>/dev/null || true
        kubectl --kubeconfig "$existing_clean" config delete-cluster "$AXIS_KUBECONFIG_CONTEXT" &>/dev/null || true
        kubectl --kubeconfig "$existing_clean" config delete-user "$AXIS_KUBECONFIG_CONTEXT" &>/dev/null || true
        KUBECONFIG="${new_kc}:${existing_clean}" kubectl config view --flatten --raw > "$merged_kc"
        chmod 600 "$merged_kc"
        mv "$merged_kc" "$AXIS_KUBECONFIG_PATH"
        kubectl --kubeconfig "$AXIS_KUBECONFIG_PATH" config use-context "$AXIS_KUBECONFIG_CONTEXT" >/dev/null
    else
        if [[ -s "$AXIS_KUBECONFIG_PATH" ]]; then
            cp "$AXIS_KUBECONFIG_PATH" "${AXIS_KUBECONFIG_PATH}.bak"
            chmod 600 "${AXIS_KUBECONFIG_PATH}.bak"
            echo "Warning: kubectl not found to merge configs; backed up existing file to ${AXIS_KUBECONFIG_PATH}.bak" >&2
        fi
        cp "$new_kc" "$AXIS_KUBECONFIG_PATH"
        chmod 600 "$AXIS_KUBECONFIG_PATH"
    fi

    echo "==> Synced kubeconfig context '$AXIS_KUBECONFIG_CONTEXT' (https://127.0.0.1:${AXIS_LOCAL_API_PORT}) to $AXIS_KUBECONFIG_PATH"
}

cmd_autostart() {
    if ! command -v limactl &>/dev/null; then
        echo "Error: limactl not found." >&2
        exit 1
    fi
    case "$AXIS_AUTOSTART_MODE" in
        login)
            echo "==> Enabling login LaunchAgent autostart for '$AXIS_VM_NAME'"
            limactl autostart enable "$AXIS_VM_NAME"
            ;;
        boot)
            echo "==> Enabling boot LaunchDaemon autostart for '$AXIS_VM_NAME' (may prompt for sudo)"
            limactl autostart enable --condition=boot "$AXIS_VM_NAME"
            ;;
        none)
            echo "==> Disabling autostart for '$AXIS_VM_NAME'"
            limactl autostart disable "$AXIS_VM_NAME" &>/dev/null || true
            ;;
    esac
}

guest_bridged_ip() {
    vm_shell ip -4 -o addr show dev lima0 scope global 2>/dev/null \
        | awk '{ split($4, a, "/"); if (a[1] !~ /^169\.254\./) { print a[1]; exit } }'
}

cmd_join_info() {
    require_vm_running
    local ip ver token
    ip="$(guest_bridged_ip || true)"
    if [[ -z "$ip" ]]; then
        echo "Error: bridged interface 'lima0' inside '$AXIS_VM_NAME' has no IPv4 address." >&2
        exit 1
    fi
    ver="$(vm_shell k3s --version 2>/dev/null | awk 'NR==1 { print $3 }')"
    token="$(vm_shell sudo cat /var/lib/rancher/k3s/server/node-token)"

    cat <<EOF
# Copy into nodes/aegis/.env (do not commit):
K3S_URL=https://${ip}:6443
K3S_TOKEN=${token}
K3S_VERSION=${ver}

# Then join Aegis:
./nodes/aegis/setup.sh join
EOF
}

cmd_status() {
    if ! command -v limactl &>/dev/null; then
        echo "Error: limactl not found." >&2
        exit 1
    fi
    echo "=== Lima VM ==="
    if [[ -n "$(vm_status)" ]]; then
        limactl list "$AXIS_VM_NAME"
    else
        echo "VM '$AXIS_VM_NAME' has not been created yet."
    fi
    if [[ "$(vm_status)" == "Running" ]]; then
        echo
        vm_shell bash -s < "$SCRIPT_DIR/scripts/status.sh"
    fi
}

wait_for_local_api_forward() {
    if ! python3 - "$AXIS_LOCAL_API_PORT" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.monotonic() + 20.0
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            sys.exit(0)
    except OSError:
        time.sleep(0.5)
sys.exit(1)
PY
    then
        echo "Warning: local Kubernetes API forward 127.0.0.1:${AXIS_LOCAL_API_PORT} is still starting; retry 'kubectl get nodes' in a few seconds." >&2
    fi
}

cmd_up() {
    ensure_vm_running
    cmd_k3s "false"
    cmd_kubeconfig
    wait_for_local_api_forward
    if [[ "$CREATED_VM" == "true" || "$AXIS_AUTOSTART_MODE" != "boot" ]]; then
        cmd_autostart
    else
        echo "==> Boot LaunchDaemon autostart kept as-is (run './nodes/axis/setup.sh autostart' to update)"
    fi

    local ip
    ip="$(guest_bridged_ip || true)"
    echo "==> Axis Kubernetes control plane is up."
    if [[ -n "$ip" ]]; then
        echo "    LAN API endpoint : https://${ip}:6443"
    fi
    echo "    Local kubectl    : kubectl get nodes -o wide"
    echo "    Aegis join vars  : ./nodes/axis/setup.sh join-info"
}

cmd_reconfigure_k3s() {
    cmd_k3s "true"
    cmd_kubeconfig
}

cmd_stop() {
    if ! command -v limactl &>/dev/null; then
        echo "Error: limactl not found." >&2
        exit 1
    fi
    if [[ "$(vm_status)" == "Running" ]]; then
        echo "==> Stopping Lima VM '$AXIS_VM_NAME'"
        limactl stop "$AXIS_VM_NAME"
    else
        echo "==> Lima VM '$AXIS_VM_NAME' is not running"
    fi
}

cmd_destroy() {
    if ! command -v limactl &>/dev/null; then
        echo "Error: limactl not found." >&2
        exit 1
    fi
    if [[ -z "$(vm_status)" ]]; then
        echo "==> Lima VM '$AXIS_VM_NAME' does not exist"
        return 0
    fi
    if [[ "$ASSUME_YES" != "true" ]]; then
        local reply=""
        if ! exec 3< /dev/tty 2>/dev/null; then
            echo "Error: no TTY available for confirmation prompt; pass --yes to destroy non-interactively." >&2
            return 1
        fi
        printf "Delete Lima VM '%s' and its Kubernetes cluster state? [y/N]: " "$AXIS_VM_NAME" >&2
        read -r reply <&3 || true
        exec 3<&-
        if [[ "$reply" != "y" && "$reply" != "Y" ]]; then
            echo "Aborted."
            return 1
        fi
    fi
    limactl autostart disable "$AXIS_VM_NAME" &>/dev/null || true
    limactl delete --force "$AXIS_VM_NAME"
    echo "==> Deleted Lima VM '$AXIS_VM_NAME'"
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

    init_work_dir
    trap cleanup EXIT

    load_env_file "$ENV_FILE"
    AXIS_VM_NAME="${AXIS_VM_NAME:-axis-k3s}"
    AXIS_NODE_NAME="${AXIS_NODE_NAME:-axis}"
    AXIS_CPUS="${AXIS_CPUS:-4}"
    AXIS_MEMORY="${AXIS_MEMORY:-6GiB}"
    AXIS_DISK="${AXIS_DISK:-64GiB}"
    AXIS_BRIDGE_IFACE="${AXIS_BRIDGE_IFACE:-en0}"
    AXIS_BRIDGE_MAC="${AXIS_BRIDGE_MAC:-}"
    AXIS_NODE_IP="${AXIS_NODE_IP:-}"
    AXIS_SOCKET_VMNET_VERSION="${AXIS_SOCKET_VMNET_VERSION:-v1.2.2}"
    AXIS_AUTOSTART_MODE="${AXIS_AUTOSTART_MODE:-login}"
    AXIS_K3S_VERSION="${AXIS_K3S_VERSION:-}"
    AXIS_K3S_DISABLE_TRAEFIK="${AXIS_K3S_DISABLE_TRAEFIK:-false}"
    AXIS_K3S_DISABLE_SERVICELB="${AXIS_K3S_DISABLE_SERVICELB:-false}"
    AXIS_KUBECONFIG_PATH="${AXIS_KUBECONFIG_PATH:-~/.kube/config}"
    AXIS_KUBECONFIG_CONTEXT="${AXIS_KUBECONFIG_CONTEXT:-nal}"
    AXIS_LOCAL_API_PORT="${AXIS_LOCAL_API_PORT:-6443}"

    parse_args "$@"
    validate_inputs

    case "$COMMAND" in
        bootstrap)  cmd_bootstrap ;;
        up)         cmd_up ;;
        k3s)        cmd_reconfigure_k3s ;;
        kubeconfig) cmd_kubeconfig ;;
        join-info)  cmd_join_info ;;
        autostart)  cmd_autostart ;;
        status)     cmd_status ;;
        stop)       cmd_stop ;;
        destroy)    cmd_destroy ;;
    esac
}

main "$@"
