# NAL Security Hub (`system-updater`)

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
  - Supports local WebAuthn Passkey (TouchID / Hardware Key) registration and offline login, plus a CLI break-glass login link (`./system-updater auth login-link`).
- **Resilient Task Logs in `services/db` with Local Spooling:**
  - Streams live task logs over SSE and persists all task logs to `services/db` (`system_updater` database).
  - Always writes to a local write-ahead spool (`daemons/system-updater/data/`) first—if PostgreSQL is down or upgrading, logs are served from the local spool and flushed to PostgreSQL automatically once `postgresql` is healthy again.
- **Multi-Server Hub $\rightarrow$ Agent Architecture:**
  - Manage multiple machines from a single Hub dashboard while running lightweight LAN agents (`./system-updater agent`) on remote compute nodes.
  - Node names auto-detect from the host's system hostname (`os.Hostname()`) by default, or can be explicitly set via `node_name` in `config.yml`, `UPDATER_NODE_NAME`, or `-name <node-name>`.
  - Dynamically add or remove compute nodes at any time via the Web UI (**⚙ Manage Nodes**) or CLI (`./system-updater node add|list|remove`).
  - **Graceful Component Auto-Detection:** Automatically skips uninstalled or stopped components on each machine (e.g., if Docker is not installed or stopped on a remote node, only Homebrew, `ollama`, and macOS updates are scanned without error).

---

## Configuration & Preparation

`system-updater` reads configuration from `config.yml` in the working directory and supports environment variable overrides (environment variables take precedence).

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
   - Ensure `services/db/.env` has `SYSTEM_UPDATER_DB_USER` and `SYSTEM_UPDATER_DB_PASS` (matching `database.db_user` and `database.db_pass` in `config.yml`).
   - Ensure `services/db/compose.yml` exposes `127.0.0.1:5432:5432` so the host daemon can reach `postgresql`.
3. **Configure Authentik OIDC Provider (Optional — for NAL Account SSO):**
   - In Authentik (`https://auth.jaewook.dev`), create an **OAuth2/OpenID Provider** and Application named `system-updater`:
     - **Client Type:** `Confidential`
     - **Redirect URI:** `https://updater.jaewook.dev/api/auth/oidc/callback` (or `http://localhost:10311/api/auth/oidc/callback` for local access)
   - Copy the **Client ID** and **Client Secret** into `auth.oidc_client_id` and `auth.oidc_client_secret` in `config.yml`.
   - *Note:* Even before Authentik is configured, you can sign in immediately using `./system-updater auth login-link` and register a local hardware/TouchID **Passkey**.
4. **Configure SMTP App Password (Optional — for Email Alerts):**
   - If using Gmail SMTP (`smtp.gmail.com:587`), generate a 16-character **Google App Password** under Google Account $\rightarrow$ Security $\rightarrow$ 2-Step Verification $\rightarrow$ App Passwords, and set `notifications.email.enabled: true`.
5. **LAN Firewall / Static IP Check (For Multi-Node Agents):**
   - Ensure the remote compute node has a static LAN IP (e.g., `192.168.1.x`) and allows incoming TCP connections on port `10247` from the Hub machine on the same subnet.

### 2. Create `config.yml`

Copy the example configuration and fill in the values generated above:

```bash
cd daemons/system-updater
cp config.example.yml config.yml
```

### `config.yml` Reference

```yaml
# Leave node_name empty to auto-detect from system hostname, or set an explicit name
node_name: ""
agent_token: "replace-with-shared-lan-agent-secret"

web:
  host: "0.0.0.0"
  port: 10311
  public_url: "https://updater.jaewook.dev"

auth:
  oidc_issuer: "https://auth.jaewook.dev/application/o/system-updater/"
  oidc_client_id: "system-updater"
  oidc_client_secret: ""
  redirect_url: "https://updater.jaewook.dev/api/auth/oidc/callback"
  session_secret: "replace-with-openssl-rand-hex-32"
  session_ttl_hours: 24
  rp_id: "updater.jaewook.dev"
  rp_origin: "https://updater.jaewook.dev"

database:
  dsn: "postgres://system_updater:system_updater_pass@127.0.0.1:5432/system_updater?sslmode=disable"
  container_name: "postgresql"
  db_name: "system_updater"
  db_user: "system_updater"
  db_pass: "system_updater_pass"
  data_dir: "data"

scanner:
  interval_hours: 6
  eol_warning_days: 30
  services_dir: "../../services"
  daemons_dir: ".."

updater:
  batch_dir: "../../batch"
  deadman_timeout_seconds: 60
  external_probe_url: "https://auth.jaewook.dev"
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
| `UPDATER_NODE_NAME` / `NODE_NAME` | Explicit node name (defaults to system hostname via `os.Hostname()`) |
| `UPDATER_AGENT_TOKEN` / `NODE_TOKEN` | Shared `X-NAL-Node-Token` secret for Hub $\leftrightarrow$ Agent LAN communication |
| `UPDATER_HOST` | Bind address (default: `0.0.0.0`) |
| `UPDATER_PORT` / `PORT` | HTTP listen port (default: `10311` for Hub, `10247` for Agent) |
| `UPDATER_PUBLIC_URL` | External dashboard URL (e.g., `https://updater.jaewook.dev`) |
| `AUTHENTIK_ISSUER` / `OIDC_ISSUER` | Authentik OIDC provider issuer URL |
| `AUTHENTIK_CLIENT_ID` / `OIDC_CLIENT_ID` | Authentik OIDC Client ID |
| `AUTHENTIK_CLIENT_SECRET` / `OIDC_CLIENT_SECRET` | Authentik OIDC Client Secret |
| `SESSION_SECRET` / `NEXTAUTH_SECRET` | HMAC-SHA256 secret used to sign stateless session cookies |
| `SYSTEM_UPDATER_DB_NAME` / `PG_DB` | PostgreSQL database name in `services/db` (default: `system_updater`) |
| `SYSTEM_UPDATER_DB_USER` / `PG_USER` | PostgreSQL role in `services/db` (default: `system_updater`) |
| `SYSTEM_UPDATER_DB_PASS` / `PG_PASS` | Password for the `system_updater` PostgreSQL role |
| `UPDATER_DATA_DIR` | Local write-ahead spool directory (default: `data`) |
| `EMAIL_HOST` / `SMTP_HOST` | SMTP server hostname (default: `smtp.gmail.com`) |
| `EMAIL_PORT` / `SMTP_PORT` | SMTP port (default: `587`) |
| `EMAIL_USERNAME` / `SMTP_USERNAME` | SMTP username |
| `EMAIL_PASSWORD` / `SMTP_PASSWORD` | SMTP password or app password |
| `EMAIL_FROM` / `SMTP_FROM` | Sender email address |
| `EMAIL_TO` / `SMTP_TO` | Recipient email address (setting this automatically enables email alerts) |

---

## Quick Start (Hub)

```bash
cd daemons/system-updater

# 1. Copy & edit configuration
cp config.example.yml config.yml

# 2. Build binary
go build -o system-updater ./cmd/system-updater

# 3. Provision database in services/db (if postgresql is running)
./system-updater db init

# 4. Run a one-off CLI scan
./system-updater scan

# 5. Generate a 5-minute break-glass login link for initial setup
./system-updater auth login-link

# 6. Start the web dashboard & background scanner (default port 10311)
./system-updater run
```

## Multi-Node Setup (Adding Remote Agents)

1. **On the Remote Compute Node:**
   ```bash
   cd daemons/system-updater
   go build -o system-updater ./cmd/system-updater
   ./system-updater agent -name <node-name> -port 10247 -token "<shared-lan-secret>"
   ```
2. **On the Hub — via Web UI or CLI:**
   - **Web UI:** Click **⚙ Manage Nodes** $\rightarrow$ Enter `<node-name>`, `http://<agent-lan-ip>:10247`, and `<shared-lan-secret>`.
   - **CLI:**
     ```bash
     ./system-updater node add <node-name> http://<agent-lan-ip>:10247 -token "<shared-lan-secret>"
     ./system-updater node list
     ```
