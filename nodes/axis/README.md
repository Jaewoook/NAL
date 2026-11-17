# Axis (`k3s` Control Plane) Setup on macOS

Provisioning suite for running **Axis** (`NAL-Axis.local`, Apple Mac Mini M2, 16 GB RAM) as the `k3s` Kubernetes control plane inside a declarative, headless **Lima (`vz`)** Ubuntu 24.04 ARM64 VM bridged directly onto Axis's wired Ethernet NIC (`en0`).

> [!IMPORTANT]
> Why Lima bridged instead of OrbStack Kubernetes: OrbStack's built-in Kubernetes is single-node only, and OrbStack already uses `192.168.0.2` for your existing Docker Compose services (`nginx-proxy`, `technitium-dns`). Bridging a separate `vz` VM onto `en0` gives the `k3s` node its own LAN IP (on the same L2 subnet as **Aegis**) with zero port conflicts during migration.

## Configuration

Copy [`.env.example`](./.env.example) to `.env` if you want to customize resources, pin a router-reserved IP, or disable bundled `traefik`/`servicelb`:

```sh
cp nodes/axis/.env.example nodes/axis/.env
```

*(Recommended: start with `AXIS_MEMORY=6GiB` while Docker stacks stay up on 16 GB Axis, and lower OrbStack's cap if needed—e.g. `orb config set memory_mib 8192`, down from `12288`—so both VMs fit cleanly within 16 GB; raise VM memory once services migrate into Kubernetes. Also reserve the VM's `lima0` MAC address cleanly in your router DHCP settings and pin it in `AXIS_NODE_IP`.)*

## Step 1: One-Time Host Bootstrap (`lima` + `socket_vmnet`)

Installs `lima` via Homebrew, builds root-owned `/opt/socket_vmnet` from `lima-vm/socket_vmnet`, configures `~/.lima/_config/networks.yaml` (`mode: bridged` on `en0`), and installs `/etc/sudoers.d/lima`:

```sh
./nodes/axis/setup.sh bootstrap
```

## Step 2: Bring Up VM + `k3s server`

Creates and boots the Ubuntu 24.04 ARM64 VM, installs `k3s server` bound to the bridged `lima0` interface (`--flannel-iface=lima0`), forwards API port `6443` locally to `127.0.0.1` (avoiding macOS `vmnet` bridged hairpin limits), merges context `nal` into `~/.kube/config`, and enables `launchd` autostart:

```sh
./nodes/axis/setup.sh up
```

Verify local `kubectl` access on Axis:

```sh
kubectl get nodes -o wide
```

## Step 3: Join Aegis (`nodes/aegis`)

Print exact `K3S_URL`, `K3S_TOKEN`, and `K3S_VERSION` values for `nodes/aegis/.env`:

```sh
./nodes/axis/setup.sh join-info
```

Paste them into `nodes/aegis/.env`, then run:

```sh
./nodes/aegis/setup.sh join
```

## Operations

```sh
./nodes/axis/setup.sh status      # VM state, lima0 IP/MAC, memory, and k3s nodes
./nodes/axis/setup.sh k3s         # Re-apply /etc/rancher/k3s/config.yaml or k3s version
./nodes/axis/setup.sh kubeconfig  # Refresh ~/.kube/config context
./nodes/axis/setup.sh autostart   # Apply AXIS_AUTOSTART_MODE (login | boot | none)
./nodes/axis/setup.sh stop        # Shut down the Lima VM
./nodes/axis/setup.sh destroy     # Delete the VM and its disk
```

### Changing the Static IP After Initial Setup

If you add or change the router static DHCP reservation for `lima0` after `axis-k3s` is already up:

1. Run `./nodes/axis/setup.sh status` to confirm the `lima0` MAC address, reserve the IP on your router, and set `AXIS_NODE_IP` in `nodes/axis/.env`.
2. Restart the VM and reconcile `k3s` + `~/.kube/config`:
   ```sh
   ./nodes/axis/setup.sh stop && ./nodes/axis/setup.sh up
   ```
3. Re-run `./nodes/axis/setup.sh join-info` so `K3S_URL` reflects the new IP before joining worker nodes (or update `K3S_URL` on already-joined workers).

*(Tip: set `AXIS_AUTOSTART_MODE=boot` and run `./nodes/axis/setup.sh autostart` if you want the VM to start on macOS boot before a GUI login.)*
