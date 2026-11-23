# Atlas Host Provisioning (`nodes/atlas`)

Host-level configuration for **Atlas** (Apple Mac Studio M5 Max, 128 GB Unified Memory).

## Persistent VRAM Limit (`vram.sh`)

macOS resets `iogpu.wired_limit_mb` back to the system default (`0`) on every reboot. [`vram.sh`](./vram.sh) installs a root `LaunchDaemon` (`/Library/LaunchDaemons/me.jaewook.atlas.vram.plist`) from [`me.jaewook.atlas.vram.plist`](./me.jaewook.atlas.vram.plist) so Atlas allocates **`122880` MB (120 GiB)** of GPU-wired memory immediately and across reboots, independent of whichever inference engine (`omlx`, etc.) is running.

### Configuration (Optional)

Copy [`.env.example`](./.env.example) to `.env` if you want to customize the default limit:

```sh
cp nodes/atlas/.env.example nodes/atlas/.env
```

### Usage

```sh
# Install persistent LaunchDaemon (122880 MB) and remove any legacy com.vram.limit daemon
./nodes/atlas/vram.sh install

# Install with a custom limit in MB
./nodes/atlas/vram.sh install --mb 114688

# Check live sysctl value, LaunchDaemon status, and legacy daemon warnings
./nodes/atlas/vram.sh status

# Apply temporarily without touching LaunchDaemons (resets on reboot)
./nodes/atlas/vram.sh apply

# Remove LaunchDaemon and reset iogpu.wired_limit_mb to 0 (macOS default)
./nodes/atlas/vram.sh uninstall
```

### Legacy Migration (`com.vram.limit`)

Running `./nodes/atlas/vram.sh install` automatically detects, boots out, and deletes any leftover `com.vram.limit` LaunchDaemon (`/Library/LaunchDaemons/com.vram.limit.plist`) from the retired `daemons/ollama` setup before registering `me.jaewook.atlas.vram`.

### Verification

After running `./nodes/atlas/vram.sh install` (and after rebooting Atlas), verify with:

```sh
sysctl iogpu.wired_limit_mb
./nodes/atlas/vram.sh status
```

`iogpu.wired_limit_mb` should report `122880`.
