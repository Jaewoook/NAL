#!/bin/bash
set -euo pipefail

# Read-only diagnostics for Aegis (safe to run without sudo).

# Non-login SSH sessions for non-root users can omit sbin directories where swapon/zramctl live.
for sbin_dir in /usr/local/sbin /usr/sbin /sbin; do
    case ":${PATH:-}:" in
        *":${sbin_dir}:"*) ;;
        *) PATH="${PATH:+$PATH:}${sbin_dir}" ;;
    esac
done
export PATH

echo "=== Host ==="
echo "Hostname : $(hostname)"
echo "Kernel   : $(uname -srm)"
if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    echo "OS       : ${PRETTY_NAME:-unknown}"
fi

echo
echo "=== Memory & Swap / Zram ==="
free -h
echo
if command -v swapon &>/dev/null; then
    swapon --show || true
fi
if command -v zramctl &>/dev/null; then
    zram_out="$(zramctl --output NAME,ALGORITHM,DISKSIZE,DATA,COMPR,TOTAL 2>/dev/null || true)"
    if [[ "$zram_out" == *"/dev/zram"* ]]; then
        echo
        printf '%s\n' "$zram_out"
    fi
fi

echo
echo "=== Boot & Kernel Readiness ==="
if command -v vcgencmd &>/dev/null; then
    echo "GPU mem  : $(vcgencmd get_mem gpu 2>/dev/null || echo 'unavailable')"
fi
if grep -qw memory /sys/fs/cgroup/cgroup.controllers 2>/dev/null || awk '$1 == "memory" && $4 == 1 { found=1 } END { exit !found }' /proc/cgroups 2>/dev/null; then
    echo "Cgroups  : memory enabled"
else
    echo "Cgroups  : memory DISABLED (reboot after prep required)"
fi

if command -v ss &>/dev/null; then
    ss_out="$(ss -tuln 2>/dev/null || true)"
    port53_lines="$(grep -E '[:.]53[[:space:]]' <<< "$ss_out" || true)"
    if [[ -n "$port53_lines" ]]; then
        echo "Port 53  : IN USE"
        printf '%s\n' "$port53_lines"
    else
        echo "Port 53  : free"
    fi
fi

echo
echo "=== Kubernetes Agent ==="
unit_out="$(systemctl list-unit-files k3s-agent.service --no-legend 2>/dev/null || true)"
if [[ "$unit_out" == k3s-agent.service* ]]; then
    echo "k3s-agent: $(systemctl is-active k3s-agent || true)"
else
    echo "k3s-agent: not installed"
fi
