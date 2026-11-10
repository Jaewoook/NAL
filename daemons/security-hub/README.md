# NAL Security Hub (`security-hub`)

A zero-dependency, single-binary host-level security hub, CVE vulnerability scanner, and LTS/End-of-Life (EoL) monitor for NAL Docker services (`services/*`), Homebrew packages (`brew`), and macOS host daemons (`daemons/*`).

---

## Features

- **Unified Outdated & Linkage Detection:**
  - Scans all Docker Compose stacks under `services/*` (supporting floating tags like `:latest`/`:main` via OCI Registry v2 digest comparison as well as `.env` and `compose.yml` pinned tags).
  - Scans installed Homebrew formulas (`brew outdated`, `brew info`) and automatically detects broken dynamic library linkages (`brew linkage --test`, e.g., missing `libsimdjson` dylibs).
  - Inspects host daemons (`ollama`, `server-monitor`) and macOS software updates.
- **Vulnerability Scanning (OSV.dev + Trivy):**
  - Checks running versions against OSV.dev / GitHub Security Advisories (GHSAs) and automatically integrates with `trivy image` when installed on the host.
- **LTS / End-of-Life (EoL) Window Tracking:**
  - Tracks lifecycle expiration dates via `endoflife.date` API (PostgreSQL, Authentik, Home Assistant, Gerrit, Node.js, OpenSSL, Python, Go, macOS) and vendor support rules (Cloudflare's 1-year `cloudflared` support window).
  - Flags versions as **Supported**, **Expiring Soon** ($\le 30$ days), or **Expired (EoL)**.
- **Controlled One-Click Web Updates & 60s Dead-Man's Rollback:**
  - Never auto-updates unattended.
  - Pick a specific target version from the web UI, skip unwanted versions, optionally trigger `./batch/backup-volumes.sh` before stateful updates, and pre-pull images before stopping containers.
  - **60-Second Automatic Dead-Man's Rollback:** If a critical-path service (`cloudflare-tunnel`, `nginx-proxy`, `auth`, `db`, `dns`) fails health verification after an update, the daemon automatically restores `compose.yml`/`.env` and re-tags the previous working image digest (`sha256:...`).
- **NAL Account SSO + Local WebAuthn Passkey Fallback:**
  - Authenticates via Authentik OIDC (`https://auth.jaewook.dev`) with a self-contained HMAC-SHA256 session cookie that survives while `auth` or `db` restarts.
  - Supports local WebAuthn Passkey (TouchID / Hardware Key) registration and offline login, plus a CLI break-glass login link (`./security-hub auth login-link`).
- **Resilient Task Logs in `services/db` with Local Spooling:**
  - Streams live task logs over SSE and persists all task logs to `services/db` (`security_hub_db` database).
  - Always writes to a local write-ahead spool (`daemons/security-hub/data/`) first—if PostgreSQL is down or upgrading, logs are served from the local spool and flushed to PostgreSQL automatically once `postgresql` is healthy again.
- **Multi-Server Hub $\rightarrow$ Agent Architecture:**
  - Manage multiple machines from a single Hub dashboard while running lightweight LAN agents (`./security-hub agent`) on remote compute nodes.
  - **Agent Auto-Discovery & Web Approval:** Remote agents automatically announce themselves to the Hub in the background (`-hub http://hub:10311`); new nodes appear in a top-bar banner and can be approved or dismissed with one click.
  - **Test Connection & Live Feedback:** Test agent connectivity, measure round-trip latency, and inspect remote OS info right from the Web UI before saving.
  - Node names auto-detect from the host's system hostname (`os.Hostname()`) by default, or can be explicitly set via `node_name` in `config.yml`, `SECURITY_HUB_NODE_NAME`, or `-name <node-name>`.
  - Dynamically add or remove compute nodes at any time via the Web UI (**⚙ Manage Nodes**) or CLI (`./security-hub node add|list|remove`).
  - **Cross-Platform Agent Service Management:** Install, inspect, and run agents as native background services using `./security-hub agent service <install|uninstall|start|stop|restart|status>` for macOS (launchd) and Linux (systemd).
  - **Graceful Component Auto-Detection:** Automatically skips uninstalled or stopped components on each machine (e.g., if Docker is not installed or stopped on a remote node, only Homebrew, `ollama`, and macOS updates are scanned without error).
- **Asynchronous Live Scan Streaming & Concurrency Guard:**
  - One-click `↻ Scan Now` runs asynchronously in the background while streaming real-time scan progress steps (`[Hub] Scanned 12 local components...`, `[Atlas] Querying remote agent...`) over SSE.
  - Mutex lock concurrency guard prevents concurrent scans from overlapping; simultaneous requests receive HTTP 409 Conflict and automatically hook into the live progress stream.

---

## Configuration & Preparation

`security-hub` reads configuration from `config.yml` in the working directory and supports environment variable overrides (environment variables take precedence).

### 1. Preparation & Secret Generation

Before starting the Hub or any remote Agent, prepare the following secrets and prerequisites:

1. **Generate the `session_secret` (Hub Cookie Signing Key) & `agent_token` (Shared LAN Agent Secret):**
   Use `openssl` (pre-installed on macOS) to generate cryptographically random 32-byte hex tokens:
   ```bash
   # Generate session_secret (for Hub config.yml -> auth.session_secret):
   openssl rand -hex 32

   # Generate agent_token (shared between Hub and remote Agents via X-NAL-Node-Token):
   openssl rand -hex 32
   ```
2. **Prepare `services/db` (PostgreSQL on Hub):**
   - Ensure `services/db/.env` has `SECURITY_HUB_DB_USER` and `SECURITY_HUB_DB_PASS` (matching `database.db_user` and `database.db_pass` in `config.yml`).
   - Ensure `services/db/compose.yml` exposes `127.0.0.1:5432:5432` so the host daemon can reach `postgresql`.
3. **Configure Authentik OIDC Provider (Optional — for NAL Account SSO):**
   - In Authentik (`https://auth.jaewook.dev`), create an **OAuth2/OpenID Provider** and Application named `security-hub`:
     - **Client Type:** `Confidential`
     - **Redirect URI:** `https://securityhub.jaewook.dev/api/auth/oidc/callback` (or `http://localhost:10311/api/auth/oidc/callback` for local access)
   - Copy the **Client ID** and **Client Secret** into `auth.oidc_client_id` and `auth.oidc_client_secret` in `config.yml`.
   - *Note:* Even before Authentik is configured, you can sign in immediately using `./security-hub auth login-link` and register a local hardware/TouchID **Passkey**.
4. **Configure SMTP App Password (Optional — for Email Alerts):**
   - If using Gmail SMTP (`smtp.gmail.com:587`), generate a 16-character **Google App Password** under Google Account $\rightarrow$ Security $\rightarrow$ 2-Step Verification $\rightarrow$ App Passwords, and set `notifications.email.enabled: true`.
5. **LAN Firewall / Static IP Check (For Multi-Node Agents):**
   - Ensure the remote compute node has a static LAN IP (e.g., `192.168.1.x`) and allows incoming TCP connections on port `10247` from the Hub machine on the same subnet.

### 2. Create `config.yml`

Copy the example configuration and fill in the values generated above:

```bash
cd daemons/security-hub
cp config.example.yml config.yml
```

### `config.yml` Reference

```yaml
# Leave node_name empty to auto-detect from system hostname, or set an explicit name
node_name: ""
agent_token: "replace-with-shared-lan-agent-secret"
# Central Hub URL for Agent auto-announcement (leave empty on central Hub)
hub_url: ""
# Agent advertise URL reachable by Hub (leave empty for automatic detection)
agent_advertise_url: ""

web:
  host: "0.0.0.0"
  port: 10311
  public_url: "https://securityhub.jaewook.dev"

auth:
  oidc_issuer: "https://auth.jaewook.dev/application/o/security-hub/"
  oidc_client_id: "security-hub"
  oidc_client_secret: ""
  redirect_url: "https://securityhub.jaewook.dev/api/auth/oidc/callback"
  session_secret: "replace-with-openssl-rand-hex-32"
  session_ttl_hours: 24
  rp_id: "securityhub.jaewook.dev"

database:
  container_name: "postgresql"
  db_name: "security_hub_db"
  db_user: "security_hub"
  db_pass: "security_hub_pass"
  data_dir: "data"

scanner:
  interval_hours: 6
  eol_warning_days: 30
  services_dir: "../../services"
  daemons_dir: ".."

updater:
  batch_dir: "../../batch"
  deadman_timeout_seconds: 60
  critical_services:
    - "cloudflare-tunnel"
    - "nginx-proxy"
    - "auth"
    - "db"
    - "dns"
  stateful_volumes:
    db: "nal_main_db"
    dns: "nal_dns_config"
    iot: "nal_ha_config"
    nginx-proxy: "nginx_proxy_data"
  git:
    enabled: true
    bot_name: "NAL Bot"
    bot_email: "nal-git-system@jaewook.me"
    gpg_sign: true
    gpg_key: "024D4017DFF5360A"

notifications:
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: ""
    password: ""
    from_email: ""
    to_email: ""
```

### Environment Variable Overrides

| Variable | Description |
| :--- | :--- |
| `SECURITY_HUB_NODE_NAME` / `NODE_NAME` | Explicit node name (defaults to system hostname via `os.Hostname()`) |
| `SECURITY_HUB_AGENT_TOKEN` / `NODE_TOKEN` | Shared `X-NAL-Node-Token` secret for Hub $\leftrightarrow$ Agent LAN communication |
| `SECURITY_HUB_URL` / `HUB_URL` | Central Security Hub URL for Agent background auto-announcement (e.g. `http://hub.lan:10311`) |
| `SECURITY_HUB_ADVERTISE_URL` / `AGENT_ADVERTISE_URL` | Explicit agent URL reachable by Hub (e.g. `http://192.168.1.50:10247`) |
| `SECURITY_HUB_HOST` | Bind address (default: `0.0.0.0`) |
| `SECURITY_HUB_PORT` / `PORT` | HTTP listen port (default: `10311` for Hub, `10247` for Agent) |
| `SECURITY_HUB_PUBLIC_URL` | External dashboard URL (e.g., `https://securityhub.jaewook.dev`) |
| `AUTHENTIK_ISSUER` / `OIDC_ISSUER` | Authentik OIDC provider issuer URL |
| `AUTHENTIK_CLIENT_ID` / `OIDC_CLIENT_ID` | Authentik OIDC Client ID |
| `AUTHENTIK_CLIENT_SECRET` / `OIDC_CLIENT_SECRET` | Authentik OIDC Client Secret |
| `SESSION_SECRET` / `NEXTAUTH_SECRET` | HMAC-SHA256 secret used to sign stateless session cookies |
| `SECURITY_HUB_DB_NAME` / `PG_DB` | PostgreSQL database name in `services/db` (default: `security_hub_db`) |
| `SECURITY_HUB_DB_USER` / `PG_USER` | PostgreSQL role in `services/db` (default: `security_hub`) |
| `SECURITY_HUB_DB_PASS` / `PG_PASS` | Password for the `security_hub` PostgreSQL role |
| `SECURITY_HUB_DATA_DIR` | Local write-ahead spool directory (default: `data`) |
| `EMAIL_HOST` / `SMTP_HOST` | SMTP server hostname (default: `smtp.gmail.com`) |
| `EMAIL_PORT` / `SMTP_PORT` | SMTP port (default: `587`) |
| `EMAIL_USERNAME` / `SMTP_USERNAME` | SMTP username |
| `EMAIL_PASSWORD` / `SMTP_PASSWORD` | SMTP password or app password |
| `EMAIL_FROM` / `SMTP_FROM` | Sender email address |
| `EMAIL_TO` / `SMTP_TO` | Recipient email address (setting this automatically enables email alerts) |
| `SECURITY_HUB_GIT_COMMIT_ENABLED` / `GIT_BOT_ENABLED` | Enable/disable automated git commit after healthy Docker update (default: `true`) |
| `SECURITY_HUB_GIT_BOT_NAME` / `GIT_BOT_NAME` | Automated git committer/author name (default: `NAL Bot`) |
| `SECURITY_HUB_GIT_BOT_EMAIL` / `GIT_BOT_EMAIL` | Automated git committer/author email (default: `nal-git-system@jaewook.me`) |
| `SECURITY_HUB_GIT_GPG_SIGN` / `GIT_BOT_GPG_SIGN` | Enable/disable GPG commit signing for automated commits (default: `true`) |
| `SECURITY_HUB_GIT_GPG_KEY` / `GIT_BOT_GPG_KEY` | GPG signing key ID for automated commits (default: `024D4017DFF5360A`) |

---

## Quick Start (Hub)

```bash
cd daemons/security-hub

# 1. Copy & edit configuration
cp config.example.yml config.yml

# 2. Build binary
go build -o security-hub ./cmd/security-hub

# 3. Provision database in services/db (if postgresql is running)
./security-hub db init

# 4. Run a one-off CLI scan
./security-hub scan

# 5. Generate a 5-minute break-glass login link for initial setup
./security-hub auth login-link

# 6. Start the web dashboard & background scanner (default port 10311)
./security-hub run
```

## Multi-Node Setup (Adding Remote Agents)

`security-hub` supports central aggregation across multiple compute nodes via lightweight LAN agents (`./security-hub agent`). Remote agents can register automatically via auto-announcement or be manually configured with connection testing.

### 1. Agent Auto-Announcement & Web Approval (Zero-Touch Registration)

Remote agents can automatically announce themselves to the Hub and maintain a background heartbeat every 30 seconds:

```bash
# On the remote node (auto-detects hostname and network interface):
./security-hub agent \
  -hub "http://<hub-lan-ip>:10311" \
  -token "<shared-lan-secret>" \
  -name "<optional-node-name>" \
  -advertise-url "http://<agent-lan-ip>:10247"
```

Environment variables `SECURITY_HUB_URL` (or `HUB_URL`) and `SECURITY_HUB_ADVERTISE_URL` (or `AGENT_ADVERTISE_URL`) may also be used.

**Pending Node Approval Workflow:**
1. When an agent first announces itself, the Hub registers the device in a **Pending** status to prevent unauthorized nodes from joining.
2. In the Hub web console, a top-bar banner immediately appears: `⚠️ 1 Pending Node(s)`.
3. Clicking the banner (or **⚙ Manage Nodes**) reveals pending registrations displaying device name, detected OS version, and incoming URL.
4. Click **[Approve]** to promote the node to active monitoring and include it in multi-node scans, or **[Dismiss]** to reject the registration.

---

### 2. Manual Agent Addition & "Test Connection"

You can also manually register compute nodes through the Web UI or CLI:

- **Web UI with Connection Testing:**
  1. Open the Web Console and click **⚙ Manage Nodes**.
  2. Enter the remote agent LAN URL (`http://<agent-lan-ip>:10247`) and shared `agent_token`.
  3. Click **⚡ Test Connection**: The Hub securely probes `/api/info` on the agent, reporting round-trip latency (e.g. `12ms`), remote OS version (e.g. `macOS 15.3 (arm64)` or `Linux 6.6.0 (amd64)`), and automatically populates the device name field if left blank.
  4. Click **+ Add / Save Node** to persist the node.

- **CLI Management:**
  ```bash
  # Add node manually:
  ./security-hub node add <node-name> http://<agent-lan-ip>:10247 -token "<shared-lan-secret>"

  # List registered nodes:
  ./security-hub node list

  # Remove node:
  ./security-hub node remove <node-name>
  ```

---

### 3. Background Agent Daemon Service CLI (`agent service`)

To run the remote agent as a persistent system service across reboots, use the built-in cross-platform `agent service` command:

```bash
# Install the background service:
./security-hub agent service install \
  -name "<node-name>" \
  -token "<shared-lan-secret>" \
  -hub "http://<hub-lan-ip>:10311" \
  -advertise-url "http://<agent-lan-ip>:10247" \
  -port 10247

# Manage service lifecycle:
./security-hub agent service status     # View running status and service identifier
./security-hub agent service start      # Start the background daemon
./security-hub agent service stop       # Stop the background daemon
./security-hub agent service restart    # Restart the background daemon
./security-hub agent service uninstall  # Remove service unit definition
```

- **macOS:** Automatically installs to `~/Library/LaunchAgents/me.jaewook.nal.security-hub-agent.plist` with `RunAtLoad`, `KeepAlive`, and stdout/stderr logging in the working directory.
- **Linux:** Automatically installs to `/etc/systemd/system/security-hub-agent.service` with `Restart=always`, `RestartSec=5s`, and whitespace-safe quoting for `ExecStart` arguments.
- A custom service unit path may be specified using the `-path <filepath>` flag.

---

### 4. Real-Time Scan Progress & Concurrency Lock

In the Web Console:
- Clicking **↻ Scan Now** dispatches an asynchronous background scan across the Hub and all approved LAN agents.
- **Live Progress Streaming:** The scan button dynamically updates to **⟳ Scanning...** (disabled), and a real-time progress pill (`#scan-progress-pill`) streams each phase of execution (e.g., `[Hub] Scanned 14 local components...`, `[Atlas] Querying remote agent...`, `Scan complete: 28 items...`) over SSE via `/api/tasks/<task_id>/stream`.
- **Concurrency Mutex Guard:** The backend prevents simultaneous scans. If another user or background trigger starts a scan while one is already running, the server responds with HTTP 409 Conflict, and the frontend seamlessly connects to the ongoing scan's live stream.
- Upon completion, the progress pill cleanly hides, the button returns to **↻ Scan Now**, and the dashboard metrics update automatically.
