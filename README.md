# Network Attached Laboratory (NAL) Server

A set of configurations for homelab servers. All sensitive data are ignored/masked. Currently all configurations are written in compose config format, with plans to migrate to Kubernetes in the future.
 
## Hardware Specifications

All infrastructure is running on the following hardwares.

### Apple Mac Mini

- Processor: Apple M2
- RAM: 16GM
- Storage: 256GB SSD
- Network: 1Gbps wired connection

### Synology DS925+

- Processor: AMD Ryzen V1500B
- RAM: 4GB
- Storage: 32TB HDD
- Network: 1Gbps wired connection

## Get Started

Setup docker environment by running the command:

```sh
./setup-docker-env.sh
```

Start, stop, or restart one or more services with:

```sh
./manage-services.sh start   # interactive picker
./manage-services.sh stop auth db
./manage-services.sh restart all
```

## Services

> fqdn:
>
> - jaewook.dev
> - home.jaewook.me (Inaccessible from outside)

| Service          | Endpoint | Description | Status |
| ---------------- | :------: | ----------- | :----: |
| VPN              | N/A | Wireguard VPN Proxy | Stable |
| DDNS             | N/A | Cloudflare DDNS Daemon | Stable |
| Tunnel           | N/A | Cloudflare Tunnel Daemon | Stable |
| Proxy            | <ul><li>https://nginx.jaewook.dev</li><ul>   | Nginx web management console | Stable |
| Virt             | <ul><li>https://docker.jaewook.dev</li></ul> | Docker stack management console | Stable |
| LLM              | <ul><li>https://llm.home.jaewook.me</li></ul> | On-premise LLM service | Experimental |
| Auth             | <ul><li>https://auth.jaewook.dev</li></ul> | Authenticate/Authorize + LDAP | Stable |
| DB               | N/A | Shared PostgreSQL database server | Work in progress |
| Homebrew NAL Tap | <ul><li>https://homebrew-nal.jaewook.dev</li></ul> | [Homebrew tap](https://github.com/Jaewoook/homebrew-nal) registry | Stable |
| DNS              | <ul><li>https://dns.home.jaewook.me</li></ul> | Technitium DNS server for local network | Stable |
| Code Review      | | Gerrit code review system | Experimental |
| Docker Registry  | | Private docker image registry | Planned |

Future work: Technitium (DNS) supports OIDC SSO login for its web console,
which could integrate with the authentik (Auth) instance once it's actually
live/configured — not implemented yet.

## Networks

**Externally created networks**

| Name              | Description                                        | Status  |
| ----------------- | -------------------------------------------------- | :-----: |
| nginx_network     | Nginx uses this network to proxy other services    | Stable  |
| db_network        | Shared network for services to reach the DB server | Work in progress |
| ~~nextcloud-aio~~ | ~~All of the Nextcloud services use this network~~ | Deleted |

`nginx_network` is created with a fixed subnet (`172.22.0.0/16`) and gateway
(`172.22.0.1`), with dynamically-assigned addresses restricted to the
`172.22.1.0/24` range. Services that pin a static IP (e.g. nginx-proxy,
portainer, ollama) use `172.22.0.0/24`, so they never collide with an
auto-assigned one.

## Volumes and data

Bind mount is not used for security reason. All data are stored in docker volume and the volume is listed in docker compose configuration file.

**Externally created volumes**

| Name                    | Description              | Status  |
| ----------------------- | ------------------------ | :-----: |
| nginx_proxy_data        | Nginx configuration data | Stable  |
| nginx_proxy_letsencrypt | Nginx SSL/TLS data       | Staable |
| nal_main_db             | Shared PostgreSQL data (all databases/roles) | Work in progress |
| nal_dns_config          | Technitium DNS Server configuration/zone data | Work in progress |

**Backups**

Docker has no undo for `docker volume rm`, `docker volume prune`, or
`docker network prune` — they permanently delete data that isn't attached to
a running container, including volumes marked `external: true`. Avoid running
those commands on this host. Networks are cheap to recover (`./setup-docker-env.sh`
recreates them, including nginx_network's fixed subnet), but volume contents
are not, so they're backed up separately:

```sh
# one-time setup: install rclone and configure a remote (rclone config),
# then set NAL_BACKUP_REMOTE to that remote:path, e.g.:
export NAL_BACKUP_REMOTE="b2:my-bucket/nal"

./batch/backup-volumes.sh              # back up every named volume on this host
./batch/backup-volumes.sh nal_main_db  # back up just one

./batch/restore-volumes.sh list                 # show available backups
./batch/restore-volumes.sh nal_main_db          # restore the latest backup
./batch/restore-volumes.sh nal_main_db <file>   # restore a specific one
```

Recovery after a full wipe: `./setup-docker-env.sh` (networks + empty
volumes) → `./batch/restore-volumes.sh <volume>` for each volume that had
data → `./manage-services.sh start all`.

## Daemons (Host-Level Background Services)

Unlike Docker services running inside the container virtualization layer, daemons run natively on the physical Mac mini host to monitor hardware, OS metrics, and external reachability directly.

| Daemon | Path | Description | Management |
| :--- | :--- | :--- | :--- |
| **Server Monitor** | [`daemons/server-monitor`](./daemons/server-monitor) | Real-time CPU spike & drop anomaly detection, host health telemetry, dead-man's-switch aliveness heartbeat, and multi-channel alerting (Telegram, Discord, Slack, Email, Webhook). | macOS `launchd` / CLI |

**Quick Commands:**
```sh
# One-off system health inspection
./daemons/server-monitor/server-monitor check

# Test notification channel (e.g. Telegram)
./daemons/server-monitor/server-monitor test-alert -channel telegram

# Run continuous monitoring daemon directly
./daemons/server-monitor/server-monitor run

# Install as an automatic macOS background service (launchd)
./daemons/server-monitor/server-monitor service install -type launchd -path ~/Library/LaunchAgents/me.jaewook.nal.servermonitor.plist
launchctl load ~/Library/LaunchAgents/me.jaewook.nal.servermonitor.plist
```

## Batch Tasks

### [*prune-docker.sh*](./batch/prune-docker.sh)

This script will delete builder cache and dangling images to free up disk space.

### [*backup-volumes.sh*](./batch/backup-volumes.sh) / [*restore-volumes.sh*](./batch/restore-volumes.sh)

Back up docker volumes to (and restore them from) a remote/cloud destination
via `rclone`. See the Backups section above.
