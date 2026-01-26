# VPN Key Agent v3.4.0

Lightweight agent for managing VPN keys on servers.

## Changes in v3.3.0

- ❌ Removed `IPBlocker` (duplicate detection moved to API fingerprint)
- ❌ Removed `ConnectionTracker` (simplified to metrics only)
- ✅ Cleaner codebase (~400 lines removed)
- ✅ Same key management functionality

## Features

- HTTP API for key management (VLESS, TUIC, Shadowsocks, WireGuard, Hysteria2)
- WebSocket connection to Central Manager
- Heartbeat with metrics (CPU, RAM, connections)
- Service health monitoring

## Installation

```bash
# On VPN server
curl -fsSL https://raw.githubusercontent.com/mrnoname14/vpn-agent/main/install.sh | bash
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VPN_AGENT_TOKEN` | Authentication token |
| `CENTRAL_MANAGER_URL` | WebSocket URL (optional) |
| `VPN_SERVER_ID` | Server ID in database |

## Usage

```bash
# HTTP only
python vpn_agent.py

# WebSocket + HTTP
python vpn_agent.py --websocket
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Status |
| `/health` | GET | All services health |
| `/info` | GET | Server metrics |
| `/keys/vless` | POST | Add VLESS key |
| `/keys/vless/<uuid>` | DELETE | Delete VLESS key |
| `/keys/tuic` | POST | Add TUIC key |
| `/keys/hysteria2` | POST | Add Hysteria2 key |
| `/keys/shadowsocks` | POST | Add Shadowsocks key |
| `/keys/wireguard` | POST | Add WireGuard key |
| `/restart/<service>` | POST | Restart service |

## Releases

- v3.4.0 - Simplified (removed IPBlocker, ConnectionTracker)
- v3.2.2 - All protocol parsing
- v3.0.1 - WebSocket support
- v2.0.4 - Multi-domain support
