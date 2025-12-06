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
    network_mode: host           # 共享宿主机网络，便于操作 WireGuard/路由
    cap_add:
      - NET_ADMIN                # 操作网络接口所需
    restart: unless-stopped
    volumes:
      - /etc/wireguard:/etc/wireguard
      - /etc/bird/dn42_peers:/etc/bird/dn42_peers
      - /var/run/bird/bird.ctl:/var/run/bird/bird.ctl # 修改为你的 bird.ctl 路径
      - ./agent_config.json:/app/agent_config.json:ro
```