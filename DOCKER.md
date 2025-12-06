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

TODO