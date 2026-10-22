# Server Monitor (`server-monitor`)

A lightweight, zero-dependency, single-binary physical server monitoring and notification daemon written in **Go**.

Designed specifically for physical and home servers running unattended workloads, `server-monitor` detects CPU usage spikes, sudden workload crashes (plunge drops), memory/disk exhaustion, and complete server outages via an outbound dead-man's-switch heartbeat.

Alerts are dispatched across multiple channels including **Telegram** (directly reusing your existing `@for_jaewook_bot`), **Discord**, **Slack**, **SMTP Email**, and **Generic Webhooks**.

---

## Features

- **CPU Usage Spike Detection:**
  - Alerts when CPU utilization exceeds a threshold (e.g., > 85%) sustained for a configurable duration (e.g., 15s) to eliminate transient false alarms.
  - Automatically dispatches a **Recovery notification** once the load settles back to normal.
- **CPU Plunge Drop Detection (Crash / Deadlock Alert):**
  - Detects abrupt plunges in CPU load ($\ge 40\%$ drop within a 15-second window from an active baseline $\ge 50\%$), catching sudden process crashes or pipeline failures.
  - One-shot incident alert with cooldown—no false recovery alarms when your server naturally idles.
- **Server Health & Resource Monitoring:**
  - Real-time telemetry: aggregate CPU %, per-mount disk usage %, RAM usage & available MB, system load averages (1m, 5m, 15m), and system uptime.
  - **Process Attribution:** Automatically inspects and attaches the top CPU-consuming processes (PID, Name, CPU%, Memory%) to alert notifications.
- **Server Aliveness & Outbound Dead-Man's Switch:**
  - Periodically pings an external monitor (e.g. [Healthchecks.io](https://healthchecks.io), [BetterStack](https://betterstack.com), or Uptime Kuma) via HTTP GET/POST.
  - If your physical server suffers a total power outage, kernel panic, or ISP loss, the external service notifies you immediately.
  - Optional scheduled **Health Digest** (e.g. daily "All systems operational" summary) sent directly to your chat.
- **Multi-Track Alerting & Noise Prevention:**
  - Independent track state machines per subsystem (`cpu_spike`, `cpu_plunge`, `memory`, `disk`). A disk warning will never silence or corrupt an ongoing CPU spike alert.
  - Configurable cooldown timers (e.g., 30m) prevent alert storms on long-running incidents.
- **Direct Telegram Bot Reuse (`for_jaewook_bot`):**
  - Seamlessly uses your existing bot token (`BOT_TOKEN`) and chat ID (`DEFAULT_CHAT_ID`) to send messages directly via the Telegram Bot API.
  - Works concurrently without interfering with your bot's incoming command polling (`/ping`, `/cmd`, `/상태`).
- **Single Static Binary & Low Footprint:**
  - Compiles to a standalone static binary with zero CGO dependencies (`CGO_ENABLED=0`).
  - Ultra-low resource consumption: **$< 0.1\%$ CPU** and **$< 8$ MB RAM**.

---

## Architecture

```
+-----------------------------------------------------------------------------------+
|                        Go Binary: server-monitor                                  |
|                                                                                   |
|  +--------------------+       +----------------------+       +-----------------+  |
|  |  Metrics Collector | ----> |   Anomaly Detector   | ----> |  Alert Manager  |  |
|  | (gopsutil samples) |       |  (Spikes, Plunges,   |       | (Independent    |  |
|  |                    |       |   Health Limits)     |       |  Tracks & Cooldown)
|  +--------------------+       +----------------------+       +--------+--------+  |
|                                                                       |           |
|  +--------------------+                                               v           |
|  |  Heartbeat Sender  |                                      +-----------------+  |
|  | (Dead-Man's Ping)  |                                      | Notification    |  |
|  +---------+----------+                                      | Dispatcher      |  |
+------------|-------------------------------------------------+--------+--------+--+
             |                                                          |
             v                                                          v
    +-----------------+                                 +-------------------------------+
    | External Uptime |                                 | Channels:                     |
    | (Healthchecks,  |                                 | - Telegram (for_jaewook_bot)  |
    |  BetterStack)   |                                 | - Discord Webhook             |
    +-----------------+                                 | - Slack Webhook               |
                                                        | - Email (SMTP)                |
                                                        | - Generic Webhook             |
                                                        +-------------------------------+
```

---

## Quick Start

### 1. Build the Binary

```bash
# Build locally
go build -o server-monitor ./cmd/server-monitor

# Or cross-compile for a Linux server from macOS:
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server-monitor ./cmd/server-monitor
```

### 2. Quick One-Off Health Check

Inspect your server's current hardware metrics and process table directly in the terminal:

```bash
./server-monitor check
```

Output:
```text
=== Server Monitor: System Health Check ===
Server:    my-physical-server
Timestamp: 2026-10-22 18:40:00 KST
Uptime:    33d 2h 15m 10s

[System Metrics]
  CPU Utilization:    7.4%
  Memory Utilization: 66.8%
  Disk Utilization:   82.9% (/)
  Load Averages:      2.10 (1m), 2.05 (5m), 1.98 (15m)

[Top Processes by CPU]
  PID     NAME             CPU%     MEM%    
  38101   OrbStack Helper  22.8%    20.5%   
  83995   Storage          5.7%     0.3%    
  60384   iTerm2           5.2%     0.7%    

[Rule Evaluations]
  Status: OK (no alerts triggered)
```

### 3. Test Your Notification Channels

Verify your webhook URLs and bot credentials by sending a test alert:

```bash
# Test all enabled channels
./server-monitor test-alert

# Or test a specific channel
./server-monitor test-alert -channel telegram
```

### 4. Run the 24/7 Monitoring Daemon

```bash
./server-monitor run
```

---

## Using with `for_jaewook_bot` (Telegram)

You can reuse your existing `@for_jaewook_bot` credentials directly. 

Because Telegram allows unlimited concurrent outbound `sendMessage` calls with the same bot token, `server-monitor` can push alerts to your Telegram chat while your existing Node.js bot continues polling and responding to `/ping`, `/cmd`, and `/상태` without any conflict!

### Zero-Config via Environment Variables
If you don't want to maintain a YAML file, export your bot's `.env` variables:

```bash
export BOT_TOKEN="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
export DEFAULT_CHAT_ID="987654321"

# Automatically enables Telegram notifications and sends a test:
./server-monitor test-alert -channel telegram
```

---

## Configuration

`server-monitor` can be configured via a YAML file (`config.yaml`), environment variables, or a combination of both (environment variables take precedence).

Copy the example configuration to get started:
```bash
cp config.example.yaml config.yaml
```

### `config.yaml` Reference

```yaml
server:
  name: "primary-server"
  check_interval_seconds: 5

cpu:
  spike:
    enabled: true
    threshold_percent: 85.0     # Alert if CPU exceeds 85%
    sustained_seconds: 15       # Must stay above 85% for 15s
    cooldown_minutes: 30        # Do not repeat alert for 30m
  plunge_drop:
    enabled: true
    delta_percent: 40.0         # Alert if CPU drops by >= 40%
    from_min_percent: 50.0      # Only if load was previously >= 50%
    window_seconds: 15          # Within a 15-second rolling window
    cooldown_minutes: 15
  floor_drop:
    enabled: false              # Disabled by default for idle servers
    threshold_percent: 5.0
    sustained_seconds: 30
    cooldown_minutes: 30
  top_processes_count: 5

health:
  memory:
    enabled: true
    threshold_percent: 90.0
    sustained_seconds: 15
    cooldown_minutes: 30
  disk:
    enabled: true
    threshold_percent: 85.0
    mount_point: "/"
    cooldown_minutes: 60

alerting:
  notify_on_recovery: true      # Send "RESOLVED" alert when CPU/memory normalizes

heartbeat:
  enabled: true
  url: "https://hc-ping.com/YOUR-UUID-HERE"
  interval_seconds: 60

digest:
  enabled: true
  interval_hours: 24            # Daily health summary

notifications:
  telegram:
    enabled: true
    bot_token: "YOUR_TELEGRAM_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
  discord:
    enabled: false
    webhook_url: "https://discord.com/api/webhooks/..."
  slack:
    enabled: false
    webhook_url: "https://hooks.slack.com/services/..."
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: "user@example.com"
    password: "app-password"
    to_email: "operator@example.com"
  webhook:
    enabled: false
    url: "https://example.com/alerts"
```

### Environment Variable Overrides

Any configuration value can be set via environment variables. Setting a channel token or webhook URL automatically enables that channel:

| Variable | Description |
| :--- | :--- |
| `SERVER_NAME` | Name of the server |
| `CHECK_INTERVAL_SECONDS` | Metric sample interval (default: `5`) |
| `BOT_TOKEN` / `TELEGRAM_BOT_TOKEN` | Telegram Bot Token |
| `DEFAULT_CHAT_ID` / `TELEGRAM_CHAT_ID` | Telegram Chat ID |
| `TELEGRAM_ENABLED` | Explicitly enable/disable Telegram (`true`/`false`) |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `WEBHOOK_URL` | Generic HTTP JSON webhook URL |
| `HEARTBEAT_URL` | Outbound dead-man's-switch ping URL |
| `HEARTBEAT_INTERVAL_SECONDS` | Heartbeat interval in seconds (default: `60`) |
| `CPU_SPIKE_THRESHOLD` | CPU Spike threshold percentage (default: `85.0`) |
| `CPU_SPIKE_SUSTAINED_SECONDS`| Spike sustained duration in seconds (default: `15`) |
| `MEMORY_THRESHOLD` | Memory utilization threshold % (default: `90.0`) |
| `DISK_THRESHOLD` | Disk utilization threshold % (default: `85.0`) |
| `NOTIFY_ON_RECOVERY` | Send alerts on recovery (`true`/`false`) |

---

## Daemon & Service Installation

`server-monitor` includes a built-in generator to install itself as a native system service that restarts automatically on reboot.

### Linux (`systemd`)

Generate and install the systemd service unit:

```bash
# Print the systemd unit file to terminal:
./server-monitor service install -type systemd

# Automatically write to systemd directory and enable:
sudo ./server-monitor service install -type systemd -path /etc/systemd/system/server-monitor.service
sudo systemctl daemon-reload
sudo systemctl enable --now server-monitor

# Check status:
sudo systemctl status server-monitor
```

### macOS (`launchd`)

Install as a background LaunchDaemon / LaunchAgent:

```bash
# Install to ~/Library/LaunchAgents:
./server-monitor service install -type launchd -path ~/Library/LaunchAgents/com.servermonitor.plist
launchctl load ~/Library/LaunchAgents/com.servermonitor.plist
```

---

## CLI Command Reference

```text
Usage:
  server-monitor <command> [flags]

Commands:
  check            Perform a single system health check and print metrics
  test-alert       Send a test alert through configured notification channels
  run              Run the continuous monitoring daemon
  service install  Generate service configuration (systemd unit or launchd plist)

Global Flags:
  -config string   Path to config YAML file (default: "config.yaml")

Command Flags:
  test-alert:
    -channel string  Specific channel to test (telegram, discord, slack, email, webhook)
  service install:
    -type string     Service manager type: "systemd" or "launchd" (auto-detected by default)
    -path string     File path to write service definition (prints to stdout if omitted)
    -user string     User to run service as (default: current user)
```

---

## Development & Testing

Run all unit and integration tests with Go's race detector:

```bash
go test -race -count=1 ./...
```

All network interactions in tests use hermetic in-memory transports (`http.RoundTripper`), guaranteeing 100% offline, deterministic testing with zero network socket requirements.
