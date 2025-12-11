# 通过 Docker 部署 Telegram DN42 机器人

## Server

Docker Compose 示例：

```yaml
version: '3.8'

services:
  server:
    image: ghcr.io/bingxin666/dn42-bot/server:latest
    container_name: dn42-bot-server
    volumes:
      - ./config.py:/app/config.py:ro
      - ./data:/app/data
      - ./cache:/app/cache
    restart: unless-stopped
```

`config.py` 文件请参考 `server/config.example.py` 进行修改。

## Agent

Docker Compose 示例：

```yaml
version: "3.8"

services:
  agent:
    image: ghcr.io/bingxin666/dn42-bot/agent:latest
    container_name: dn42-agent
    dns:
      - 172.20.0.53
      - 1.1.1.1
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    restart: unless-stopped
    volumes:
      - /etc/wireguard:/etc/wireguard
      - /etc/bird/dn42_peers:/etc/bird/dn42_peers
      - /etc/bird/config:/etc/bird/config
      - /var/run/bird/bird.ctl:/var/run/bird/bird.ctl # 修改为你的 bird.ctl 路径
      - ./agent_config.json:/app/agent_config.json:ro
```