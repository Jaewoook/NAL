# Network Attached Laboratory (NAL) Server

A set of configurations for my home server. All sensitive data is stored in docker volume so this repository does not have private files. Since there is only one server running, all of this configurations are written in docker compose.

## Server Information

> fqdn:
>
> - home.jaewook.me
> - jaewook.dev

- Apple M2 Mac mini
- 16GM RAM
- 256GB Internal SSD
- 1Gbps internet connected

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

| Service         | Endpoint | Description | Status |
| --------------- | :------: | ----------- | :----: |
| VPN             | N/A | Wireguard VPN Proxy | Stable |
| DDNS            | N/A | Cloudflare DDNS Updater | Stable |
| Tunnel          | N/A | Cloudflare Tunnel Daemon | Stable |
| Proxy           | <ul><li>https://nginx.home.jaewook.me</li><ul>   | Nginx web management console | Stable |
| Virt            | <ul><li>https://docker.home.jaewook.me</li></ul> | Docker stack management console | Stable |
| LLM             | <ul><li>https://llm.home.jaewook.me</li></ul> | On-premise LLM service | Stable |
| Auth            | | Authenticate/Authorize + LDAP Server (authentik) | Work in progress |
| DB              | N/A | Shared PostgreSQL database server | Work in progress |
| DNS             | | DNS Service | Planned |
| Code Review     | | Gerrit code review system | Experimental |
| Docker Registry | | Private docker image registry | Planned |
| ~~Storage~~     | ~~<ul><li>https://status.drive.home.jaewook.me</li><li>https://drive.home.jaewook.me</li></ul>~~ | ~~Personal NAS solution~~ | Deleted |
| ~~Metrics~~     | ~~<ul><li>https://status.home.jaewook.me</li></ul>~~ | ~~Metrics for server~~ | Deleted |

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

## Batch Tasks

### [*prune-docker.sh*](./batch/prune-docker.sh)

This script will delete builder cache and dangling images to free up disk space.

### [*backup-volumes.sh*](./batch/backup-volumes.sh) / [*restore-volumes.sh*](./batch/restore-volumes.sh)

Back up docker volumes to (and restore them from) a remote/cloud destination
via `rclone`. See the Backups section above.
