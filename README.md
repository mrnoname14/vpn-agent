# VPN Health Agent

Lightweight HTTP service monitor for VPN servers.

## Install
```bash
curl -sSL https://raw.githubusercontent.com/mrnoname14/vpn-agent/main/install.sh | bash -s YOUR_TOKEN
```

Or auto-generate token:
```bash
curl -sSL https://raw.githubusercontent.com/mrnoname14/vpn-agent/main/install.sh | bash
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | / | No | Basic info |
| GET | /health | Yes | All services status |
| GET | /health/{service} | Yes | Single service status |
| POST | /restart/{service} | Yes | Restart service |
| POST | /restart-all | Yes | Restart all stopped |
| GET | /info | Yes | Server info |
| POST | /update | Yes | Self-update |

## Auth

Add header: X-Agent-Token: YOUR_TOKEN
