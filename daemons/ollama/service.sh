#!/bin/bash
set -euo pipefail

LABEL="me.jaewook.nal.ollama"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_PLIST="$SCRIPT_DIR/${LABEL}.plist"
USER_ID="$(id -u)"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
TARGET_PLIST="$LAUNCH_AGENTS_DIR/${LABEL}.plist"
LOG_DIR="$HOME/Library/Logs"
LOG_OUT="$LOG_DIR/${LABEL}.log"
LOG_ERR="$LOG_DIR/${LABEL}.error.log"

usage() {
    cat <<EOF
Usage: $(basename "$0") <install|uninstall|start|stop|restart|status|logs|help>

Manage native host Ollama daemon on macOS via launchd.

Commands:
  install     Configure and register the LaunchAgent with launchd
  uninstall   Unload and remove the LaunchAgent plist
  start       Start the Ollama daemon service
  stop        Stop the Ollama daemon service
  restart     Restart the Ollama daemon service
  status      Show current service status, PID, port reachability, and models
  logs        Tail the stdout and stderr log files
  help        Show this help message
EOF
}

find_ollama() {
    if [[ -x "/opt/homebrew/bin/ollama" ]]; then
        echo "/opt/homebrew/bin/ollama"
    elif command -v ollama >/dev/null 2>&1; then
        command -v ollama
    else
        echo ""
    fi
}

cmd_install() {
    echo "==> Installing $LABEL daemon..."
    local ollama_bin
    ollama_bin="$(find_ollama)"
    if [[ -z "$ollama_bin" ]]; then
        echo "Error: ollama executable not found. Please install via: brew install ollama" >&2
        exit 1
    fi

    mkdir -p "$LAUNCH_AGENTS_DIR"
    mkdir -p "$LOG_DIR"

    # Generate target plist with dynamically resolved home and binary path
    sed -e "s|/opt/homebrew/bin/ollama|$ollama_bin|g" \
        -e "s|/Users/jaewookahn|$HOME|g" \
        "$SOURCE_PLIST" > "$TARGET_PLIST"

    chmod 644 "$TARGET_PLIST"

    # Stop any conflicting instance first
    if launchctl print "gui/$USER_ID/$LABEL" >/dev/null 2>&1; then
        echo "Service already loaded. Booting out existing service..."
        launchctl bootout "gui/$USER_ID/$LABEL" 2>/dev/null || true
    fi

    # Bootstrap service into modern macOS launchd domain
    if launchctl bootstrap "gui/$USER_ID" "$TARGET_PLIST" 2>/dev/null; then
        echo "Service bootstrapped successfully."
    else
        # Fallback to legacy launchctl load
        launchctl load -w "$TARGET_PLIST"
        echo "Service loaded via legacy launchctl."
    fi

    echo "==> $LABEL successfully installed and registered."
    cmd_status
}

cmd_uninstall() {
    echo "==> Uninstalling $LABEL..."
    if launchctl print "gui/$USER_ID/$LABEL" >/dev/null 2>&1; then
        launchctl bootout "gui/$USER_ID/$LABEL" 2>/dev/null || true
    elif [[ -f "$TARGET_PLIST" ]]; then
        launchctl unload -w "$TARGET_PLIST" 2>/dev/null || true
    fi

    if [[ -f "$TARGET_PLIST" ]]; then
        rm -f "$TARGET_PLIST"
        echo "Removed $TARGET_PLIST"
    fi
    echo "==> $LABEL successfully uninstalled."
}

cmd_start() {
    echo "==> Starting $LABEL..."
    if ! launchctl print "gui/$USER_ID/$LABEL" >/dev/null 2>&1; then
        echo "Service not loaded. Running install first..."
        cmd_install
        return
    fi

    launchctl kickstart -k "gui/$USER_ID/$LABEL" 2>/dev/null || launchctl start "$LABEL"
    echo "==> Start command issued."
    sleep 1
    cmd_status
}

cmd_stop() {
    echo "==> Stopping $LABEL..."
    if launchctl print "gui/$USER_ID/$LABEL" >/dev/null 2>&1; then
        launchctl kill SIGTERM "gui/$USER_ID/$LABEL" 2>/dev/null || true
        # Also disable KeepAlive temporarily if needed or wait
        sleep 1
    fi

    # Kill any leftover manual process if running
    local pids
    pids=$(pgrep -f "ollama serve" || true)
    if [[ -n "$pids" ]]; then
        echo "Stopping remaining ollama serve process(es): $pids"
        kill $pids 2>/dev/null || true
    fi
    echo "==> Stop command completed."
}

cmd_restart() {
    echo "==> Restarting $LABEL..."
    if launchctl print "gui/$USER_ID/$LABEL" >/dev/null 2>&1; then
        launchctl kickstart -k "gui/$USER_ID/$LABEL"
    else
        cmd_stop
        cmd_start
    fi
    sleep 1
    cmd_status
}

cmd_status() {
    echo "--------------------------------------------------"
    echo "Service: $LABEL"

    local running=false
    local pid=""

    # Check via launchctl print
    if launchctl print "gui/$USER_ID/$LABEL" >/dev/null 2>&1; then
        pid=$(launchctl print "gui/$USER_ID/$LABEL" 2>/dev/null | awk -F' = ' '/pid/ {print $2}' || true)
        if [[ -n "$pid" && "$pid" != "0" ]]; then
            running=true
        fi
    fi

    # Fallback check via pgrep
    if [[ "$running" == false ]]; then
        pid=$(pgrep -f "ollama serve" | head -n 1 || true)
        if [[ -n "$pid" ]]; then
            running=true
        fi
    fi

    if [[ "$running" == true && -n "$pid" ]]; then
        echo "Status:  RUNNING (PID: $pid)"
        ps -p "$pid" -o %cpu,%mem,time,command | tail -n +2 | while read -r cpu mem time cmd; do
            echo "CPU:     ${cpu}% | Memory: ${mem}% | CPU Time: ${time}"
        done
    else
        echo "Status:  STOPPED"
    fi

    echo -n "Port:    "
    if curl -s -m 2 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
        local version
        version=$(curl -s http://127.0.0.1:11434/api/version | sed -E 's/.*"version":"([^"]+)".*/\1/' || echo "unknown")
        echo "http://0.0.0.0:11434 is REACHABLE (Ollama v$version)"

        echo "Models:"
        local models
        models=$(curl -s http://127.0.0.1:11434/api/tags | grep -o '"name":"[^"]*"' | cut -d'"' -f4 || true)
        if [[ -n "$models" ]]; then
            while IFS= read -r m; do
                echo "  - $m"
            done <<< "$models"
        else
            echo "  (No models currently pulled)"
        fi
    else
        echo "http://127.0.0.1:11434 is NOT reachable"
    fi
    echo "Logs:    $LOG_OUT"
    echo "         $LOG_ERR"
    echo "--------------------------------------------------"
}

cmd_logs() {
    touch "$LOG_OUT" "$LOG_ERR"
    echo "Tailing logs ($LOG_OUT and $LOG_ERR) - press Ctrl+C to exit:"
    tail -n 50 -f "$LOG_OUT" "$LOG_ERR"
}

case "${1:-status}" in
    install)    cmd_install ;;
    uninstall)  cmd_uninstall ;;
    start)      cmd_start ;;
    stop)       cmd_stop ;;
    restart)    cmd_restart ;;
    status)     cmd_status ;;
    logs)       cmd_logs ;;
    help|--help|-h) usage ;;
    *)
        echo "Unknown command: $1" >&2
        usage >&2
        exit 1
        ;;
esac
