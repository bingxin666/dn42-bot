# Docker Deployment Guide

This guide explains how to deploy the DN42 bot using Docker.

## Prerequisites

Before running the containers, you must create configuration files:

1. **Server**: Copy `server/config.example.py` to `server/config.py` and customize it
2. **Agent**: Copy `agent/agent_config.example.json` to `agent/agent_config.json` and customize it

**Important**: Never commit your actual config files (`config.py` and `agent_config.json`) to version control as they contain sensitive information!

## Building Images

### Server Image

```bash
cd server
docker build -t dn42-bot-server:latest .
```

### Agent Image

```bash
cd agent
docker build -t dn42-bot-agent:latest .
```

## Running Containers

### Server Container

Run the container:

```bash
docker run -d \
  --name dn42-bot-server \
  -v $(pwd)/server/config.py:/app/config.py:ro \
  -v dn42-bot-server-data:/app/data \
  -p 3443:3443 \
  dn42-bot-server:latest
```

### Agent Container

Run the container with necessary privileges:

```bash
docker run -d \
  --name dn42-bot-agent \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --device /dev/net/tun \
  -v $(pwd)/agent/agent_config.json:/app/agent_config.json:ro \
  -v /etc/wireguard:/etc/wireguard:ro \
  -p 54321:54321 \
  dn42-bot-agent:latest
```

**Note:** The agent requires elevated privileges for WireGuard tunnel management and network operations.

## Docker Compose

You can use Docker Compose to manage both services:

```yaml
version: '3.8'

services:
  server:
    build: ./server
    container_name: dn42-bot-server
    volumes:
      - ./server/config.py:/app/config.py:ro
      - server-data:/app/data
    ports:
      - "3443:3443"
    restart: unless-stopped

  agent:
    build: ./agent
    container_name: dn42-bot-agent
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun
    volumes:
      - ./agent/agent_config.json:/app/agent_config.json:ro
      - /etc/wireguard:/etc/wireguard:ro
    ports:
      - "54321:54321"
    restart: unless-stopped

volumes:
  server-data:
```

## Using Pre-built Images from GitHub Container Registry

After GitHub Actions builds the images, you can pull them directly:

```bash
# Pull server image
docker pull ghcr.io/<your-github-username>/dn42-bot/server:latest

# Pull agent image
docker pull ghcr.io/<your-github-username>/dn42-bot/agent:latest
```

Replace `<your-github-username>` with the actual GitHub repository owner name.

## Notes

- **TCPing**: The tcping tool is not included in the base images. You can either:
  - Install it manually in the container: `docker exec -it dn42-bot-agent bash -c "wget -O /usr/local/bin/tcping https://github.com/nodeseeker/tcping/releases/latest/download/tcping-linux-amd64 && chmod +x /usr/local/bin/tcping"`
  - Or mount a pre-installed tcping binary as a volume: `-v /path/to/tcping:/usr/local/bin/tcping:ro`

- **Config Files**: Always mount your config files as read-only (`:ro`) for security

- **Persistent Data**: Use volumes for any data that needs to persist (databases, logs, etc.)
