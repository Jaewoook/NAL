# Aegis (Raspberry Pi 3B+) Setup & Recovery

Provisioning scripts for **Aegis** (Raspberry Pi 3B+, 1 GB RAM, wired Ethernet), run directly from your MacBook so the Pi can be rebuilt cleanly after any microSD/OS reset.

## Prerequisites

1. Flash **Raspberry Pi OS Lite (64-bit)** onto the microSD card (no Imager OS customization needed—Step 0 handles SSH and account creation).
2. Keep the flashed microSD card mounted on your MacBook (`/Volumes/bootfs` or `/Volumes/boot`).
3. Create your local config:
   ```sh
   cp nodes/aegis/.env.example nodes/aegis/.env
   ```
   Edit `nodes/aegis/.env` with `AEGIS_USER` and `AEGIS_PASSWORD` (or `AEGIS_PASSWORD_HASH`, or leave both blank to be prompted securely).

## Step 0: Prepare the Flashed SD Card (Before First Boot)

With the flashed SD card still plugged into your MacBook:

```sh
./nodes/aegis/setup.sh sd --eject
```

This writes directly to the mounted boot partition (auto-detecting `/Volumes/bootfs` or `/Volumes/boot`, or override with `--boot-dir`):
* Creates an empty `ssh` file to enable SSH on first boot.
* Writes `userconf.txt` (`<username>:<$6$-sha512-hash>`) from `.env` (`AEGIS_USER` and `AEGIS_PASSWORD` / `AEGIS_PASSWORD_HASH`).
* Pre-applies `config.txt` (`gpu_mem=16`, `disable-wifi`, `disable-bt`) and `cmdline.txt` (memory cgroups) so initial system options are active from boot #1.
* Ejects the SD card safely when `--eject` is passed.

Insert the SD card into Aegis, plug in wired Ethernet, and power it on.

## Step 1: Prepare the Host over SSH (Immediate after First Boot)

Run this once Aegis boots (if you didn't set the hostname in Raspberry Pi Imager, the fresh OS boots as `raspberrypi.local` first—Step 1 will rename it to `aegis` and automatically switch over on reboot):

```sh
./nodes/aegis/setup.sh prep --host raspberrypi.local --refresh-host-key
```

*(Omit `--host raspberrypi.local` if Aegis is already reachable as `AEGIS_HOST` in `.env`. Pass `--refresh-host-key` after any re-flash so your MacBook clears the previous SSH host key.)*

This connects over SSH and idempotently:
* Confirms `aarch64` / Debian-based OS, configures system locale (`en_US.UTF-8`), and sets hostname to `aegis`.
* Installs `curl`, `ca-certificates`, and `iptables` (plus `zram-tools` on legacy Bookworm) with apt lock timeout handling.
* Ensures `config.txt` and `cmdline.txt` cgroups match your `.env` settings.
* Enables compressed in-RAM `zram` swap (`rpi-swap` on Trixie+, `zramswap` on Bookworm) without disk swapfile wear, and puts `systemd-journald` into volatile 32 MB RAM mode to protect the microSD card.
* Disables `systemd-resolved`'s local port `53` stub listener (if active) and repoints `/etc/resolv.conf` so Technitium DNS can bind port `53` later.
* Reboots Aegis, waits for it to go down and come back online, and prints a status check.

*(Pass `--no-reboot` if you want to reboot manually later.)*

## Step 2: Join `k3s` Cluster (Once Axis Is Ready)

Once Axis's `k3s` server is running, set `K3S_URL`, `K3S_TOKEN`, and optionally `K3S_VERSION` (recommended to pin to Axis's k3s version) in `nodes/aegis/.env` (or pass `--k3s-url` / `--k3s-token` / `--k3s-version` on the CLI) and run:

```sh
./nodes/aegis/setup.sh join
```

This writes `/etc/rancher/k3s/config.yaml` and installs `k3s-agent` with:
* Node name: `aegis`
* Taint: `role=edge:NoSchedule` (blocks heavy pods from scheduling onto the 1 GB Pi accidentally)
* Labels: `hardware=rpi3b`, `nal.role=edge`
* Kubelet log caps (`10Mi` × 2 files) and full eviction guard (`memory.available<120Mi` plus standard disk/inode thresholds)

> [!NOTE]
> `node-taint` and `node-label` in `/etc/rancher/k3s/config.yaml` only apply when a node first registers. If you change them after initial join, update the existing node via `kubectl taint` / `kubectl label` on Axis.

To verify token acceptance and node readiness from Axis once joined:
```sh
kubectl get nodes -o wide
```

## Check Live Status Anytime

```sh
./nodes/aegis/setup.sh status
```
