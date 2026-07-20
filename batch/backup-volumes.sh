#!/bin/bash
set -eo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") [volume...]

Back up docker volumes to a remote/cloud destination via rclone.

  - No arguments: back up every named (non-anonymous) volume on this host,
    except any listed in \$NAL_BACKUP_EXCLUDE (space-separated volume names).
  - One or more volume names: back up only those volumes.

Requires:
  - rclone installed and configured (see: rclone config)
  - NAL_BACKUP_REMOTE set to an rclone remote:path, e.g. "b2:my-bucket/nal"

Each volume is streamed as a gzip tarball directly to
\$NAL_BACKUP_REMOTE/<volume>_<timestamp>.tar.gz — no local staging file.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if ! command -v docker &>/dev/null; then
    echo "Error: docker command is not available." >&2
    exit 1
fi
if ! command -v rclone &>/dev/null; then
    echo "Error: rclone command is not available. Install it and run 'rclone config' first." >&2
    exit 1
fi
if [[ -z "${NAL_BACKUP_REMOTE:-}" ]]; then
    echo "Error: NAL_BACKUP_REMOTE is not set (expected an rclone remote:path)." >&2
    exit 1
fi

is_anonymous_volume() {
    [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

is_excluded() {
    local name="$1" excluded
    for excluded in ${NAL_BACKUP_EXCLUDE:-}; do
        [[ "$name" == "$excluded" ]] && return 0
    done
    return 1
}

targets=()
if [[ $# -gt 0 ]]; then
    targets=("$@")
else
    while IFS= read -r name; do
        is_anonymous_volume "$name" && continue
        is_excluded "$name" && continue
        targets+=("$name")
    done < <(docker volume ls -q | sort)
fi

if [[ ${#targets[@]} -eq 0 ]]; then
    echo "No volumes to back up." >&2
    exit 0
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
for name in "${targets[@]}"; do
    if ! docker volume inspect "$name" &>/dev/null; then
        echo "Error: volume '$name' does not exist, skipping." >&2
        continue
    fi
    dest="${NAL_BACKUP_REMOTE%/}/${name}_${timestamp}.tar.gz"
    echo "==> backing up $name -> $dest"
    docker run --rm -v "${name}:/volume:ro" alpine \
        tar czf - -C /volume . \
        | rclone rcat "$dest"
done
