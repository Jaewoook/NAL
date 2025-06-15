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

**Externally created networks**

| Name | Description | Status |
|------|-------------|:------:|
| nginx_network | Nginx uses this network to proxy other services | Current |
| nextcloud-aio | All of the Nextcloud services use this network | Obsolete |

## Volumes and data

Bind mount is not used for security reason. All data are stored in docker volume and the volume is listed in docker compose configuration file.

**Externally created volumes**

| Name | Description | Status |
|------|-------------|:------:|
| nginx_proxy_data | Nginx configuration data | Current |
| nginx_proxy_letsencrypt | Nginx SSL/TLS data | Current |

## Batch Tasks

### *prune-docker.sh*

This script will delete builder cache and dangling images to free up space.
