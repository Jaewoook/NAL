# Apache Guacamole Remote Desktop Gateway

Clientless HTML5 remote desktop gateway providing browser-based VNC access to Apple Mac Studio (**Atlas**) at `https://remote.jaewook.dev` with Authentik SSO, Fast User Switching, and automatic 1-click desktop launch.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       External Client Browser         |
                      +---------------------------------------+
                                          |
                                          | HTTPS / WebSockets (WSS)
                                          v
                      +---------------------------------------+
                      | Cloudflare Tunnel (*.jaewook.dev)     |
                      +---------------------------------------+
                                          |
                                          | Ingress (remote.jaewook.dev)
                                          v
+-----------------------------------------------------------------------------+
| Mac Mini Host (Axis)                                                        |
|                                                                             |
|   +-----------------------+           +---------------------------------+   |
|   |  Nginx Proxy Manager  | --------> |  guacamole-web (Tomcat :8080)   |   |
|   |  (WebSockets enabled) |           |  (ROOT webapp context)          |   |
|   +-----------------------+           +---------------------------------+   |
|                                            |                     |          |
|                                     Guacamole Protocol    OIDC Token Validation
|                                            |                     |          |
|                                            v                     v          |
|                                       +----------+      +---------------+   |
|                                       |  guacd   |      | Authentik SSO |   |
|                                       |  (:4822) |      | (auth.jaewook)|   |
|                                       +----------+      +---------------+   |
|                                            |                                |
|                                            | PostgreSQL                     |
|                                            v                                |
|                                       +----------------+                    |
|                                       | postgresql :5432|                   |
|                                       | (guacamole_db) |                    |
|                                       +----------------+                    |
+-----------------------------------------------------------------------------+
                                             |
                                             | Native macOS VNC (Port 5900)
                                             | Home LAN (Private & Headless)
                                             v
+-----------------------------------------------------------------------------+
| Apple Mac Studio (Atlas)                                                    |
|                                                                             |
|   +---------------------------------------------------------------------+   |
|   | macOS Screen Sharing (`screensharingd` on port 5900)                |   |
|   |                                                                     |   |
|   |   +-------------------------+     +-----------------------------+   |   |
|   |   | User: jaewook           |     | User: friend                |   |   |
|   |   | (Interactive Desktop)   |     | (Interactive Desktop)       |   |   |
|   |   +-------------------------+     +-----------------------------+   |   |
|   |                ^                               ^                    |   |
|   |                +----- Fast User Switching -----+                    |   |
|   +---------------------------------------------------------------------+   |
|                                                                             |
|   +---------------------------------------------------------------------+   |
|   | Background Local LLM Server (Ollama / vLLM launchd daemon)          |   |
|   | User: atlas (Completely isolated, runs 24/7 Metal GPU inference)   |   |
|   +---------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------+
```

### Key Highlights
1. **Zero External Open Ports:** No raw VNC (5900) or Guacamole (8080) ports are exposed to the WAN. All traffic is tunneled through Cloudflare Zero Trust and Nginx Proxy Manager.
2. **Authentik OIDC Single Sign-On:** Users authenticate against `https://auth.jaewook.dev`. Guacamole automatically provisions accounts on login.
3. **1-Click Auto-Connect:** Guacamole auto-connects straight into the user's macOS desktop session when they only have access to a single connection.
4. **Fast User Switching:** Multiple users (`jaewook`, `friend`) can log into macOS without terminating each other's desktop state or background jobs.
5. **LLM Daemon Isolation:** The local LLM engine runs under the dedicated `atlas` daemon account via `launchd` and Metal GPU acceleration, remaining completely uninterrupted regardless of GUI login/logout actions.

---

## 1. Prerequisites & Environment Setup

### Step 1.1: Database Credentials (`services/db/.env`)
Ensure PostgreSQL has the Guacamole credentials configured:
```dotenv
GUACAMOLE_DB_NAME=guacamole_db
GUACAMOLE_DB_USER=guacamole
GUACAMOLE_DB_PASS=<your_secure_password>
```

If the PostgreSQL container is already running with an existing data volume, execute the provisioning script manually:
```bash
# From repository root:
docker exec -i postgresql /bin/bash < services/db/init/40-guacamole.sh
```
This script will:
- Create the `guacamole` role and `guacamole_db` database.
- Execute the Guacamole 1.5.5 relational schema (`40-guacamole-schema.sql.inc`).
- Bootstrap the `jaewook` user with `ADMINISTER` system permissions.

### Step 1.2: Remote Stack Environment (`services/remote/.env`)
Copy the environment template:
```bash
cp services/remote/.env.example services/remote/.env
```
Ensure values match your deployment:
```dotenv
GUACAMOLE_DB_NAME=guacamole_db
GUACAMOLE_DB_USER=guacamole
GUACAMOLE_DB_PASS=<your_secure_password>

GUACAMOLE_OIDC_CLIENT_ID=nal-guacamole
OPENID_AUTHORIZATION_ENDPOINT=https://auth.jaewook.dev/application/o/authorize/
OPENID_JWKS_ENDPOINT=https://auth.jaewook.dev/application/o/guacamole/jwks/
OPENID_ISSUER=https://auth.jaewook.dev/application/o/guacamole/
OPENID_REDIRECT_URI=https://remote.jaewook.dev/
```

---

## 2. Authentik SSO Configuration

Guacamole uses the OpenID Connect implicit/PKCE flow to authenticate tokens via Authentik's public JWKS endpoint.

1. Navigate to **Authentik Admin Console** (`https://auth.jaewook.dev`) -> **Applications** -> **Providers**.
2. Click **Create** -> Choose **OAuth2/OpenID Provider**:
   - **Name:** `NAL Remote Desktop`
   - **Authentication flow:** default-authentication-flow
   - **Authorization flow:** default-provider-authorization-implicit-consent (or explicit)
   - **Client type:** `Public` (*Important: Guacamole OIDC extension runs client-side; do NOT use Confidential*)
   - **Client ID:** `nal-guacamole`
   - **Redirect URIs:** `https://remote.jaewook.dev/`
   - **Signing Key:** Select your Authentik self-signed or Let's Encrypt certificate.
   - **Scopes:** `openid`, `email`, `profile`
   - **Subject mode:** `Based on the User's username`
3. Click **Finish**.
4. Navigate to **Applications** -> **Applications** -> Click **Create**:
   - **Name:** `Remote Desktop`
   - **Slug:** `guacamole`
   - **Provider:** `NAL Remote Desktop`
   - **Launch URL:** `https://remote.jaewook.dev/`

---

## 3. Nginx Proxy Manager Configuration

Guacamole requires full WebSocket pass-through for low-latency interactive streaming.

1. Open **Nginx Proxy Manager** (`https://nginx.jaewook.dev`).
2. Navigate to **Hosts** -> **Proxy Hosts** -> **Add Proxy Host**:
   - **Domain Names:** `remote.jaewook.dev`
   - **Scheme:** `http`
   - **Forward Hostname / IP:** `guacamole-web`
   - **Forward Port:** `8080`
   - **Cache Assets:** `OFF`
   - **Block Common Exploits:** `ON`
   - **Websockets Support:** `ON` (*Mandatory: failure to enable degrades performance to HTTP polling*)
3. Under the **SSL** tab:
   - Select SSL Certificate (`*.jaewook.dev` or Cloudflare Origin Cert).
   - **Force SSL:** `ON`
   - **HTTP/2 Support:** `ON`
   - **HSTS Enabled:** `ON`
4. Click **Save**.

---

## 4. macOS Host Configuration on Atlas

Configure Screen Sharing on the Mac Studio:

1. Open **System Settings** -> **General** -> **Sharing**.
2. Enable **Screen Sharing** (or **Remote Management**).
3. Click the `(i)` info icon next to Screen Sharing:
   - **Allow access for:** `Only these users` -> Add `jaewook` and `friend`.
   - Under **Computer Settings**:
     - Check *"Anyone may request permission to control display"*.
     - Check *"VNC viewers may control screen with password"* (optional if using macOS user authentication).
4. Verify accounts:
   - Ensure the macOS local user `jaewook` exists on Atlas with standard/admin permissions.
   - Ensure the macOS local user `friend` exists on Atlas.
   - Ensure the dedicated service user `atlas` runs the background Ollama/vLLM daemon via `launchd`.

---

## 5. Adding Guacamole Connections & Auto-Connect

1. Log in to `https://remote.jaewook.dev`.
2. Authentik will authenticate your session. Because the database script bootstrapped `jaewook`, you will have administrator rights.
3. Click your username in the top right -> **Settings** -> **Connections** -> **New Connection**:
   - **Name:** `Atlas (Jaewook)`
   - **Location:** `ROOT`
   - **Protocol:** `VNC`
4. In the **Parameters** section:
   - **Network -> Hostname:** IP address of Atlas or `atlas.home.jaewook.me`
   - **Network -> Port:** `5900`
   - **Authentication -> Username:** `jaewook`
   - **Authentication -> Password:** `<macOS account password for jaewook>`
   - **Display -> Color depth:** `True color (24-bit)`
   - **Performance:** Leave auto-detect or configure cursor rendering to local.
5. Save the connection.
6. Under **Settings** -> **Users** -> Click `jaewook`:
   - Under **Connections**, check `Atlas (Jaewook)`.
   - Save.

> **Auto-Connect Behavior:** When a user is permitted to access exactly **one** connection, Apache Guacamole automatically launches that desktop upon login without displaying the intermediate connection list.

---

## 6. Onboarding Additional Users (e.g. `friend`)

To grant access to a friend or family member after initial deployment:

1. Have the user sign in once to `https://remote.jaewook.dev` via Authentik.
   - Guacamole will dynamically provision their entity in `guacamole_db` under their Authentik username (e.g. `friend`).
2. Log in as `jaewook` -> **Settings** -> **Connections** -> **New Connection**:
   - **Name:** `Atlas (Friend)`
   - **Protocol:** `VNC`
   - **Hostname:** Atlas IP / `atlas.home.jaewook.me`
   - **Port:** `5900`
   - **Username:** `friend`
   - **Password:** `<macOS account password for friend>`
3. Navigate to **Settings** -> **Users** -> Click `friend`:
   - Under **Connections**, check **only** `Atlas (Friend)`.
   - Ensure system permissions (Administrator, User management) remain **unchecked**.
4. When `friend` logs into `https://remote.jaewook.dev`, they will immediately auto-connect to their personal macOS desktop session on Atlas.
5. If `jaewook` and `friend` access Atlas at different times or switch, macOS **Fast User Switching** retains both desktop environments seamlessly.

---

## 7. Headless Display Resolution Management

Apple Silicon Macs running without a physical monitor connected may initialize the display framebuffer to a default resolution (1024x768 or 1280x720).

If higher resolutions (1080p, 1440p, 4K) or HiDPI scaling are needed:
1. **Hardware Virtual Dummy Plug:** Plug an inexpensive HDMI dummy display emulator ($6) into Atlas's HDMI port. This tricks macOS into activating full 4K @ 60Hz GPU display outputs.
2. **Software Virtual Display (BetterDisplay):**
   - Install BetterDisplay (`brew install --cask betterdisplay`) on Atlas.
   - Enable virtual display creation at startup to generate virtual 16:9 displays at 1920x1080 or 2560x1440 with HiDPI support.
