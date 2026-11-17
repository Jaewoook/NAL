#!/bin/bash
set -euo pipefail

# Read-only guest diagnostics for Axis Lima VM.

for sbin_dir in /usr/local/sbin /usr/sbin /sbin; do
    case ":${PATH:-}:" in
        *":${sbin_dir}:"*) ;;
        *) PATH="${PATH:+$PATH:}${sbin_dir}" ;;
    esac
done
export PATH

echo "=== Guest Host ==="
echo "Hostname : $(hostname)"
echo "Kernel   : $(uname -srm)"
if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    echo "OS       : ${PRETTY_NAME:-unknown}"
fi

echo
echo "=== Bridged Network (lima0) ==="
if ip link show dev lima0 &>/dev/null; then
    echo "MAC      : $(cat /sys/class/net/lima0/address 2>/dev/null || echo unknown)"
    ip -4 -o addr show dev lima0 2>/dev/null | awk '{print "IPv4     :", $4}'
else
    echo "lima0    : NOT FOUND"
fi

echo
echo "=== Memory & Disk ==="
free -h
echo
df -h /

echo
echo "=== Kubernetes Control Plane ==="
unit_out="$(systemctl list-unit-files k3s.service --no-legend 2>/dev/null || true)"
if [[ "$unit_out" == k3s.service* ]]; then
    echo "k3s      : $(systemctl is-active k3s || true)"
    if command -v k3s &>/dev/null; then
        echo "Version  : $(k3s --version | head -n 1)"
        k3s kubectl get nodes -o wide 2>/dev/null || true
    fi
else
    echo "k3s      : not installed"
fi
