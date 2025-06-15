# Network Attached Laboratory (NAL) Server

A set of configurations for my home server. All sensitive data is stored in docker volume so this repository does not have private files. Since there is only one server running, all of this configurations are written in docker compose.

## Server Information

> fqdn: home.jaewook.me

- Apple M2 Mac mini
- 16GM RAM
- 256GB Internal SSD
- 500Mbps internet connected

## Get Started

Setup docker environment by running the command:

```sh
./setup-docker-env.sh
```

## Services

| Service name | Endpoint | Description | Availability |
|-----------------|:---:|---|:---:|
| VPN             | X | Wireguard VPN Proxy | Yes |
| DDNS            | X | Cloudflare DDNS Updater | Yes |
| Proxy           | <ul><li>https://nginx.home.jaewook.me</li><ul>   | Nginx web management console | Yes |
| Virt            | <ul><li>https://docker.home.jaewook.me</li></ul> | Docker stack management console | Yes |
| Metrics         | <ul><li>https://status.home.jaewook.me</li></ul> | Metrics for server | Need maintenance |
| LDAP            | | LDAP Server | Planned |
| DNS             | | DNS Service | Planned |
| Code Review     | | Gerrit code review system | Experimental |
| Docker Registry | | Private docker image registry | Planned |
| Storage         | <ul><li>https://status.drive.home.jaewook.me</li><li>https://drive.home.jaewook.me</li></ul> | Personal NAS solution | No |


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
