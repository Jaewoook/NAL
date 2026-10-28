# Ollama Native Host Daemon (`me.jaewook.nal.ollama`)

Host-level daemon for managing Ollama directly on macOS with Apple Silicon (M2) Metal GPU acceleration.

## Why Native?

Docker on macOS runs inside a Linux lightweight virtual machine that lacks Apple Silicon GPU (Metal) passthrough. Running Ollama inside Docker restricts inference to CPU emulation (~0.45 tokens/sec). Running Ollama natively on macOS host achieves **18 to 80+ tokens/sec** using the M2 GPU and Unified Memory.

## Service Specification

* **Launchd Identifier:** `me.jaewook.nal.ollama`
* **Agent Plist:** `~/Library/LaunchAgents/me.jaewook.nal.ollama.plist`
* **Program:** `/opt/homebrew/bin/ollama serve`
* **Environment Configuration:**
  * `OLLAMA_HOST=0.0.0.0:11434` (accessible to host, LAN, and Docker containers via `host.docker.internal`)
  * `OLLAMA_ORIGINS=*` (allows cross-origin requests from web clients)
  * `OLLAMA_FLASH_ATTENTION=1` (optimized attention mechanism for Apple Silicon)
  * `OLLAMA_KV_CACHE_TYPE=q8_0` (optimized KV cache quantization)
  * `OLLAMA_KEEP_ALIVE=24h` (keeps loaded models warm in unified memory)
* **Logs:**
  * `~/Library/Logs/me.jaewook.nal.ollama.log`
  * `~/Library/Logs/me.jaewook.nal.ollama.error.log`

## Management Commands

Use the [`service.sh`](./service.sh) script to control the daemon lifecycle:

```bash
# Check daemon status, PID, port reachability, and installed models
./daemons/ollama/service.sh status

# Register and start the launchd service
./daemons/ollama/service.sh install

# Stop / Start / Restart the daemon
./daemons/ollama/service.sh stop
./daemons/ollama/service.sh start
./daemons/ollama/service.sh restart

# Follow daemon logs in real time
./daemons/ollama/service.sh logs

# Unregister and remove the launchd service
./daemons/ollama/service.sh uninstall
```
