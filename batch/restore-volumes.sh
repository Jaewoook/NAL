#!/bin/bash
set -eo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") list [volume]
       $(basename "$0") <volume> [backup-file]

  list            Show available backups (optionally filtered to one volume).
  <volume>        Restore a volume from its most recent backup.
  <volume> FILE   Restore a volume from a specific backup file, as shown by
                  'list' (just the filename, without the remote prefix).

Recreates the docker volume if it doesn't already exist. If it does exist,
asks for confirmation before overwriting its contents.

Requires the same rclone setup as backup-volumes.sh (NAL_BACKUP_REMOTE).
EOF
}

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

if [[ $# -lt 1 ]]; then
    usage
    exit 1
fi

list_backups() {
    local filter="${1:-}"
    # `|| true`: a no-matches result makes the pipeline exit non-zero under
    # pipefail, which would otherwise trip `set -e` before callers get a
    # chance to handle "no backups found" themselves.
    if [[ -n "$filter" ]]; then
        rclone lsf "$NAL_BACKUP_REMOTE" --include "${filter}_*.tar.gz" | sort || true
    else
        rclone lsf "$NAL_BACKUP_REMOTE" --include "*.tar.gz" | sort || true
    fi
}

if [[ "$1" == "list" ]]; then
    list_backups "${2:-}"
    exit 0
fi

volume="$1"
file="${2:-}"

if [[ -z "$file" ]]; then
    file="$(list_backups "$volume" | tail -1)"
    if [[ -z "$file" ]]; then
        echo "Error: no backups found for volume '$volume'." >&2
        exit 1
    fi
fi

if docker volume inspect "$volume" &>/dev/null; then
    read -rp "Volume '$volume' already exists; its contents will be overwritten. Continue? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Aborted." >&2
        exit 1
    fi
else
    echo "==> creating volume $volume"
    docker volume create "$volume" >/dev/null
fi

src="${NAL_BACKUP_REMOTE%/}/${file}"
echo "==> restoring $volume <- $src"
rclone cat "$src" | docker run --rm -i -v "${volume}:/volume" alpine \
    tar xzf - -C /volume
