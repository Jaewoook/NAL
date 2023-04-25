# Network Attached Laboratory Server

A set of configurations for my home server. All sensitive data is stored in docker volume so this repository does not have private files. Since there is only one server running, all of this configurations are written in docker compose.

## Server Information

> server fqdn: home.jaewook.me

- Apple M2 Mac mini
- 16GM RAM
- 256GB Internal SSD
- 500Mbps internet connected

## Services

- cloudflare-ddns
- nginx-proxy-manager
  - service urls:
    - https://nginx.home.jaewook.me
- netdata
  - service url: https://status.home.jaewook.me
- portainer
  - service url: https://docker.home.jaewook.me
- nextcloud
  - service urls:
    - https://status.drive.home.jaewook.me
    - https://drive.home.jaewook.me
- dduksangbot
- for_jaewook_bot

## Networks

| name | description |
|------|-------------|
| nginx_network | Nginx uses this network to proxy other services |
| nextcloud-aio | All of the Nextcloud services use this network |
