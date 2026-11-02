# NAL System Updater (`system-updater`)

A zero-dependency, single-binary host-level system updater, CVE vulnerability scanner, and LTS/End-of-Life (EoL) monitor for NAL Docker services (`services/*`), Homebrew packages (`brew`), and macOS host daemons (`daemons/*`).

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

## Quick Start (Hub)

```bash
cd daemons/system-updater

# 1. Build binary
go build -o system-updater ./cmd/system-updater

# 2. Provision database in services/db (if postgresql is running)
./system-updater db init

# 3. Run a one-off CLI scan
./system-updater scan

# 4. Generate a 5-minute break-glass login link for initial setup
./system-updater auth login-link

# 5. Start the web dashboard & background scanner (default port 10246)
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
