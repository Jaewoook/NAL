#!/bin/bash

echo "Setting up NAL docker environment..."

# Check if docker command is available
if ![ command -v docker &>/dev/null ]; then
    echo "Error: docker command is not available. Please install Docker first."
    exit 1
fi

echo "Setting up networks..."
# Check if nginx_network exists
if ! docker network ls | grep -q "nginx_network"; then
    echo "Creating nginx_network..."
    docker network create nginx_network \
    --subnet=172.22.0.0/16 \
    --gateway=172.22.0.1 \
    --ip-range=172.22.1.0/24
else
    echo "nginx_network already exists, skipping creation."
fi

# Check if db_network exists
if ! docker network ls | grep -q "db_network"; then
    echo "Creating db_network..."
    docker network create db_network
else
    echo "db_network already exists, skipping creation."
fi

echo "Setting up volumes..."
# Check if nginx_volume exists
if ! docker volume ls | grep -q "nginx_proxy_data"; then
    echo "Creating nginx_proxy_data..."
    docker volume create nginx_proxy_data
else
    echo "nginx_proxy_data already exists, skipping creation."
fi

if ! docker volume ls | grep -q "nginx_proxy_letsencrypt"; then
    echo "Creating nginx_proxy_letsencrypt..."
    docker volume create nginx_proxy_letsencrypt
else
    echo "nginx_proxy_letsencrypt already exists, skipping creation."
fi

if ! docker volume ls | grep -q "git-volume"; then
    echo "Creating git-volume..."
    docker volume create git-volume
else
    echo "git-volume already exists, skipping creation."
fi

if ! docker volume ls | grep -q "nal_main_db"; then
    echo "Creating nal_main_db..."
    docker volume create nal_main_db
else
    echo "nal_main_db already exists, skipping creation."
fi

if ! docker volume ls | grep -q "nal_dns_config"; then
    echo "Creating nal_dns_config..."
    docker volume create nal_dns_config
else
    echo "nal_dns_config already exists, skipping creation."
fi

if ! docker volume ls | grep -q "nal_ha_config"; then
    echo "Creating nal_ha_config..."
    docker volume create nal_ha_config
else
    echo "nal_ha_config already exists, skipping creation."
fi

if ! docker volume ls | grep -q "nal_matter_hub_data"; then
    echo "Creating nal_matter_hub_data..."
    docker volume create nal_matter_hub_data
else
    echo "nal_matter_hub_data already exists, skipping creation."
fi
echo "Done."
