#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICES_DIR="$SCRIPT_DIR/services"

usage() {
    cat <<EOF
Usage: $(basename "$0") <start|stop|restart> [service...]

Start, stop, or restart one or more service stacks under services/*.

  - Pass service names directly to act on them without prompting.
  - Pass "all" as the only service argument to target every service.
  - Pass no service names to pick interactively from a numbered list.

Examples:
  $(basename "$0") start                # interactive picker, then start selection
  $(basename "$0") stop auth db         # stop the auth and db stacks directly
  $(basename "$0") restart all          # restart every discovered service
EOF
}

has_compose_file() {
    local dir="$1"
    [[ -f "$dir/compose.yaml" || -f "$dir/compose.yml" \
        || -f "$dir/docker-compose.yaml" || -f "$dir/docker-compose.yml" ]]
}

discover_services() {
    local dir name
    for dir in "$SERVICES_DIR"/*/; do
        name="$(basename "$dir")"
        has_compose_file "$dir" && echo "$name"
    done | sort
}

prompt_selection() {
    local -a services=("$@")
    local i=1
    echo "Available services:" >&2
    for name in "${services[@]}"; do
        printf '  %2d) %s\n' "$i" "$name" >&2
        i=$((i + 1))
    done
    echo >&2
    read -rp "Select services (space/comma-separated numbers, or 'all'): " reply

    reply="${reply//,/ }"
    if [[ -z "${reply// /}" ]]; then
        echo "Error: no selection made." >&2
        exit 1
    fi
    if [[ "$reply" == "all" ]]; then
        printf '%s\n' "${services[@]}"
        return
    fi

    local -a picked=()
    for token in $reply; do
        if ! [[ "$token" =~ ^[0-9]+$ ]] || (( token < 1 || token > ${#services[@]} )); then
            echo "Error: '$token' is not a valid selection." >&2
            exit 1
        fi
        picked+=("${services[$((token - 1))]}")
    done
    printf '%s\n' "${picked[@]}"
}

run_action() {
    local action="$1" name="$2"
    local dir="$SERVICES_DIR/$name"

    echo "==> ${action} ${name}"
    case "$action" in
        start)   docker compose --project-directory "$dir" up -d ;;
        stop)    docker compose --project-directory "$dir" down ;;
        restart)
            docker compose --project-directory "$dir" down
            docker compose --project-directory "$dir" up -d
            ;;
    esac
}

if ! command -v docker &>/dev/null; then
    echo "Error: docker command is not available. Please install Docker first." >&2
    exit 1
fi

if [[ $# -lt 1 ]]; then
    usage
    exit 1
fi

action="$1"
shift
if [[ "$action" != "start" && "$action" != "stop" && "$action" != "restart" ]]; then
    usage
    exit 1
fi

all_services=()
while IFS= read -r name; do
    all_services+=("$name")
done < <(discover_services)
if [[ ${#all_services[@]} -eq 0 ]]; then
    echo "Error: no services with a compose file found under $SERVICES_DIR." >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    selection_output=$(prompt_selection "${all_services[@]}") || exit 1
    targets=()
    while IFS= read -r name; do
        [[ -n "$name" ]] && targets+=("$name")
    done <<< "$selection_output"
elif [[ "$1" == "all" ]]; then
    targets=("${all_services[@]}")
else
    targets=("$@")
    for name in "${targets[@]}"; do
        if [[ ! -d "$SERVICES_DIR/$name" ]] || ! has_compose_file "$SERVICES_DIR/$name"; then
            echo "Error: '$name' is not a known service under $SERVICES_DIR." >&2
            exit 1
        fi
    done
fi

if [[ ${#targets[@]} -eq 0 ]]; then
    echo "No services selected; nothing to do." >&2
    exit 0
fi

for name in "${targets[@]}"; do
    run_action "$action" "$name"
done
