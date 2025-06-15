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
    docker network create nginx_network
else
    echo "nginx_network already exists, skipping creation."
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
echo "Done."
