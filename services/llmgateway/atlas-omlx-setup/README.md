# Atlas oMLX Host Daemon & Ingress Firewall Setup

This directory contains the host configuration files for running **oMLX** bare-metal on **Atlas** (Apple Silicon M5 Max Mac Studio, 64GB Unified Memory).

## Architecture & Security Model

- **Atlas**: Dedicated ML inference node running `omlx` bare-metal on port `8000`.
- **Axis (`182.168.0.2`)**: Primary control plane node (Mac Mini) running the LLM Gateway and orchestrators.
- **Network Ingress Policy**: Port `8000` on Atlas is strictly restricted to Axis (`182.168.0.2`) via macOS Packet Filter (`pfctl`). All other inbound traffic to port 8000 is blocked at the packet filter level.
- **Service Management**: Managed as a system-level macOS `launchd` daemon with automatic boot start and process supervision (`KeepAlive: true`).

---

## Prerequisites on Atlas

1. **Verify oMLX Installation**:
   Ensure `omlx` is installed (typically in `/opt/homebrew/bin/omlx` on Apple Silicon):
   ```bash
   which omlx
   ```
   If installed at a different path (e.g. `/usr/local/bin/omlx` or inside a virtualenv), update `ai.omlx.server.plist` accordingly.

2. **Create Log Directory**:
   Create `/var/log/omlx` for daemon stdout and stderr logging:
   ```bash
   sudo mkdir -p /var/log/omlx
   sudo chmod 755 /var/log/omlx
   ```

---

## 1. launchd Service Daemon Setup

The plist file `ai.omlx.server.plist` configures `omlx serve --host 0.0.0.0 --port 8000` as a system daemon.

### Installation

1. Copy the plist file to `/Library/LaunchDaemons/`:
   ```bash
   sudo cp ai.omlx.server.plist /Library/LaunchDaemons/ai.omlx.server.plist
   ```

2. Set standard ownership and permissions:
   ```bash
   sudo chown root:wheel /Library/LaunchDaemons/ai.omlx.server.plist
   sudo chmod 644 /Library/LaunchDaemons/ai.omlx.server.plist
   ```

3. Bootstrap the daemon via `launchctl`:
   ```bash
   sudo launchctl bootstrap system /Library/LaunchDaemons/ai.omlx.server.plist
   ```

### Managing the Service

- **Check status**:
  ```bash
  sudo launchctl print system/ai.omlx.server
  ```
- **Stop / Unload daemon**:
  ```bash
  sudo launchctl bootout system/ai.omlx.server
  ```
- **Inspect Logs**:
  ```bash
  tail -f /var/log/omlx/omlx.log
  tail -f /var/log/omlx/omlx.err.log
  ```

---

## 2. Ingress Firewall (`pfctl`) Setup

The firewall configuration `pf-omlx.conf` enforces that port `8000` only accepts incoming TCP packets from Axis (`182.168.0.2`):

```pf
# Atlas oMLX Ingress Filter: Only permit Axis (182.168.0.2)
block in proto tcp from any to any port 8000
pass in quick proto tcp from 182.168.0.2 to any port 8000
```

### Enable Rules Immediately

To test and load the rules with `pfctl`:

```bash
# Enable pf and load pf-omlx.conf
sudo pfctl -ef pf-omlx.conf
```

To verify loaded rules:
```bash
sudo pfctl -sr
```

### Persistent Configuration Across Reboots

To ensure the rule persists across macOS reboots:

1. Copy the configuration file:
   ```bash
   sudo cp pf-omlx.conf /etc/pf.anchors/omlx.conf
   sudo chmod 644 /etc/pf.anchors/omlx.conf
   ```

2. Reference the anchor in `/etc/pf.conf`:
   Add the anchor declaration after the default anchors in `/etc/pf.conf`:
   ```pf
   anchor "omlx"
   load anchor "omlx" from "/etc/pf.anchors/omlx.conf"
   ```

3. Test and reload `/etc/pf.conf`:
   ```bash
   sudo pfctl -vnf /etc/pf.conf
   sudo pfctl -ef /etc/pf.conf
   ```

---

## 3. Verification

1. **Verify from Axis (`182.168.0.2`)**:
   From Axis, verify connectivity to Atlas oMLX server:
   ```bash
   curl -I http://<atlas-ip>:8000/v1/models
   ```
   Should return `HTTP/1.1 200 OK`.

2. **Verify Ingress Rejection from Other Hosts**:
   From any host other than `182.168.0.2`, attempt to connect:
   ```bash
   curl --connect-timeout 3 http://<atlas-ip>:8000/v1/models
   ```
   The connection should time out or be dropped by the packet filter.
