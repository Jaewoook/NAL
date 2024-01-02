# Network Attached Laboratory (NAL) Server

A set of configurations for my home server. All sensitive data is stored in docker volume so this repository does not have private files. Since there is only one server running, all of this configurations are written in docker compose.

## Server Information

> server fqdn: home.jaewook.me

- Apple M2 Mac mini
- 16GM RAM
- 256GB Internal SSD
- 500Mbps internet connected

## Services

| Service name        | Service URL                                      |
|---------------------|:------------------------------------------------:|
| nginx-proxy-manager | <ul><li>https://nginx.home.jaewook.me</li><ul>   |
| netdata             | <ul><li>https://status.home.jaewook.me</li></ul> |
| portainer           | <ul><li>https://docker.home.jaewook.me</li></ul> |
| nextcloud           | <ul><li>https://status.drive.home.jaewook.me</li><li>https://drive.home.jaewook.me</li></ul> |
| wireguard           | X |
| cloudflare-ddns     | X |
| dduksangbot         | X |

## Networks

| Name | Description |
|------|-------------|
| nginx_network | Nginx uses this network to proxy other services |
| nextcloud-aio | All of the Nextcloud services use this network |

## Volumes and data

For security reasons, I don't use bind mount. All data is stored in docker volume and the volume is listed in docker compose configuration file.

## Batch Tasks

### *prune-docker.sh*

This script will delete builder cache and dangling images to free up space.
