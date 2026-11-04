# Atlas oMLX Host Daemon & Ingress Firewall Setup

This directory contains the host configuration files for running **oMLX** bare-metal on **Atlas** (Apple Silicon M5 Max Mac Studio, 64GB Unified Memory).

## Architecture & Security Model

- **Atlas**: Dedicated ML inference node running `omlx` natively bare-metal on port `8000`.
- **Axis (`192.168.0.2`)**: Primary control plane node (Mac Mini) running the AI Gateway and orchestrators.
- **Service Management**: Managed as a native macOS user **LaunchAgent** (`~/Library/LaunchAgents/ai.omlx.server.plist`) with automatic supervision (`KeepAlive: true`).
- **Network Ingress Policy**: Port `8000` on Atlas is strictly restricted to Axis (`192.168.0.2`) via macOS Packet Filter (`pfctl`). All other inbound traffic to port 8000 is blocked at the kernel network filter level.

---

## 1. Quick Start: Service Lifecycle Management

The included [`service.sh`](./service.sh) script manages the LaunchAgent lifecycle:

```bash
# Check daemon status, port 8000 reachability, and loaded models
./daemons/omlx/service.sh status

# Register, configure, and bootstrap the LaunchAgent
./daemons/omlx/service.sh install

# Start, Stop, or Restart the service
./daemons/omlx/service.sh start
./daemons/omlx/service.sh stop
./daemons/omlx/service.sh restart

# Tail stdout and stderr logs in real time
./daemons/omlx/service.sh logs

# Unregister and remove the LaunchAgent
./daemons/omlx/service.sh uninstall
```

---

## 2. Manual Setup (Without `service.sh`)

If configuring macOS `launchd` manually without the helper script:

1. **Prerequisites**:
   Ensure `omlx` is installed on Atlas (typically via Homebrew):
   ```bash
   which omlx  # Expects /opt/homebrew/bin/omlx
   ```

2. **Create User Log and LaunchAgent Directories**:
   ```bash
   mkdir -p ~/Library/Logs/omlx ~/Library/LaunchAgents
   ```

3. **Generate User Plist**:
   Substitute placeholder paths and copy the plist to your user `LaunchAgents`:
   ```bash
   sed -e "s|__OMLX_BIN__|$(which omlx)|g" \
       -e "s|__HOME__|$HOME|g" \
       ai.omlx.server.plist > ~/Library/LaunchAgents/ai.omlx.server.plist

   chmod 644 ~/Library/LaunchAgents/ai.omlx.server.plist
   ```

4. **Bootstrap the LaunchAgent**:
   Load the service into the user GUI domain:
   ```bash
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.omlx.server.plist
   ```

5. **Service Management**:
   - **Check status**:
     ```bash
     launchctl print gui/$(id -u)/ai.omlx.server
     ```
   - **Kickstart / Start immediately**:
     ```bash
     launchctl kickstart -k gui/$(id -u)/ai.omlx.server
     ```
   - **Stop / Unload**:
     ```bash
     launchctl bootout gui/$(id -u)/ai.omlx.server
     ```
   - **View logs**:
     ```bash
     tail -f ~/Library/Logs/omlx/omlx.log
     tail -f ~/Library/Logs/omlx/omlx.err.log
     ```

---

## 3. Ingress Firewall (`pfctl`) Setup

> [!NOTE]
> Configuring the host packet filter (`pfctl`) to restrict port 8000 to Axis is a one-time network configuration requiring administrative privileges (`sudo`).

The configuration `pf-omlx.conf` enforces that port `8000` only accepts incoming TCP packets from Axis (`192.168.0.2`):

```pf
# Atlas oMLX Ingress Filter: Only permit Axis (192.168.0.2)
block in proto tcp from any to any port 8000
pass in quick proto tcp from 192.168.0.2 to any port 8000
```

### Enable Rules Immediately
```bash
# Enable pf and load pf-omlx.conf
sudo pfctl -ef pf-omlx.conf

# Verify active filter rules
sudo pfctl -sr
```

### Persistent Across macOS Reboots
To ensure the packet filter rules reload automatically upon host reboot:

1. Copy the configuration file:
   ```bash
   sudo cp pf-omlx.conf /etc/pf.anchors/omlx.conf
   sudo chmod 644 /etc/pf.anchors/omlx.conf
   ```

2. Reference the anchor in `/etc/pf.conf`:
   Add after existing anchor declarations in `/etc/pf.conf`:
   ```pf
   anchor "omlx"
   load anchor "omlx" from "/etc/pf.anchors/omlx.conf"
   ```

3. Test and reload `/etc/pf.conf`:
   ```bash
   sudo pfctl -vnf /etc/pf.conf
   sudo pfctl -ef /etc/pf.conf
   ```

4. **Install Boot Daemon for Persistent pfctl**:
   Install `ai.omlx.pfctl.plist` to reload rules at system boot:
   ```bash
   sudo cp ai.omlx.pfctl.plist /Library/LaunchDaemons/ai.omlx.pfctl.plist
   sudo chown root:wheel /Library/LaunchDaemons/ai.omlx.pfctl.plist
   sudo chmod 644 /Library/LaunchDaemons/ai.omlx.pfctl.plist
   sudo launchctl bootstrap system /Library/LaunchDaemons/ai.omlx.pfctl.plist
   ```

---

## 4. Verification

1. **Verify from Axis (`192.168.0.2`)**:
   From Axis, test connectivity to the Atlas oMLX inference endpoint:
   ```bash
   curl -I http://<atlas-ip>:8000/v1/models
   ```
   Should return `HTTP/1.1 200 OK`.

2. **Verify Ingress Rejection from Other Hosts**:
   From any host other than `192.168.0.2`, attempt to connect:
   ```bash
   curl --connect-timeout 3 http://<atlas-ip>:8000/v1/models
   ```
   The connection should time out or immediately drop at the packet filter.
