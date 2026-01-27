#!/usr/bin/env python3
"""
VPN Key Agent v3.5.0 (Sync Support)

Changes from v3.4.0:
- Added GET endpoints for all protocols (for sync)
- /keys/tuic GET - list TUIC users
- /keys/hysteria2 GET - list Hysteria2 users
- /keys/shadowsocks GET - list Shadowsocks keys
- /keys/wireguard GET - list WireGuard peers

Features:
- WebSocket connection to Central Manager
- HTTP API for key management
- Heartbeat with metrics (CPU, RAM, connections)
- Key management for all 5 protocols
- Full key listing for sync operations

Usage:
  python vpn_agent.py                    # HTTP mode only
  python vpn_agent.py --websocket        # WebSocket + HTTP mode
"""

import subprocess
import os
import sys
import time
import json
import yaml
import uuid
import base64
import secrets
import re
import threading
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from functools import wraps
from flask import Flask, jsonify, request

__version__ = "3.5.0"

# ==================== Configuration ====================

API_TOKEN = os.environ.get("VPN_AGENT_TOKEN", "")
CENTRAL_MANAGER_URL = os.environ.get("CENTRAL_MANAGER_URL", "")
SERVER_ID = int(os.environ.get("VPN_SERVER_ID", "0"))

# Config paths
XRAY_CONFIG = "/usr/local/etc/xray/config.json"
TUIC_CONFIG = "/etc/tuic/config.json"
TUIC_CONFIG_D2 = "/etc/tuic/config2.json"
SS_CONFIG = "/etc/outline/config.yml"
WG_CONFIG = "/etc/wireguard/wg0.conf"
HYSTERIA_CONFIG = "/etc/hysteria/config.yaml"
HYSTERIA_CONFIG_D2 = "/etc/hysteria/config2.yaml"

TUIC_CONFIGS = [TUIC_CONFIG, TUIC_CONFIG_D2]
HYSTERIA_CONFIGS = [HYSTERIA_CONFIG, HYSTERIA_CONFIG_D2]
TUIC_SERVICES = ["tuic", "tuic2"]
HYSTERIA_SERVICES = ["hysteria", "hysteria2"]

VPN_SERVICES = ["hysteria", "hysteria2", "tuic", "tuic2", "xray", "shadowsocks", "wg-quick@wg0", "AdGuardHome"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("vpn-agent")

app = Flask(__name__)

# ==================== Metrics ====================

def get_server_metrics() -> dict:
    """Get server metrics for heartbeat."""
    info = {"version": __version__}
    try:
        with open("/proc/loadavg") as f:
            load = [float(x) for x in f.read().split()[:3]]
            info["cpu_percent"] = round(load[0] * 100, 1)
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if parts[0] in ["MemTotal:", "MemAvailable:"]:
                    meminfo[parts[0][:-1]] = int(parts[1])
            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)
            if total:
                info["ram_percent"] = round((total - available) / total * 100, 1)
    except:
        pass
    
    # Count active connections via ss
    info["active_connections"] = _count_active_connections()
    return info


def _count_active_connections() -> int:
    """Count active VPN connections via ss."""
    ports = [443, 8443, 8444, 8388, 51820]
    total = 0
    try:
        for port in ports:
            result = subprocess.run(
                ["ss", "-tn", "state", "established", f"sport = :{port}"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.strip().split('\n')[1:]
            total += len([l for l in lines if l.strip()])
    except:
        pass
    return total

# ==================== Helpers ====================

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_TOKEN:
            return jsonify({"error": "Agent not configured"}), 503
        if request.headers.get("X-Agent-Token") != API_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def is_valid_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except:
        return False


def restart_service_sync(service: str, timeout: int = 30) -> dict:
    try:
        subprocess.run(["systemctl", "restart", service], capture_output=True, text=True, timeout=timeout)
        time.sleep(2)
        result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=5)
        return {"success": result.stdout.strip() == "active", "status": result.stdout.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


def read_json_config(path: str) -> dict:
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error(f"Error reading {path}: {e}")
        return {}


def write_json_config(path: str, data: dict):
    if os.path.exists(path):
        with open(path, 'r') as f:
            with open(f"{path}.bak", 'w') as b:
                b.write(f.read())
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def read_yaml_config(path: str) -> dict:
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error(f"Error reading {path}: {e}")
        return {}


def write_yaml_config(path: str, data: dict):
    if os.path.exists(path):
        with open(path, 'r') as f:
            with open(f"{path}.bak", 'w') as b:
                b.write(f.read())
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False)

# ==================== Command Handler ====================

def handle_command(command: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Handle command from Central Manager."""
    logger.info(f"Command: {command}")
    
    if command == "restart_service":
        service = data.get("service")
        if service and service in VPN_SERVICES:
            result = restart_service_sync(service)
            return {"success": result.get("success", False), "service": service, **result}
        return {"success": False, "error": f"Invalid service: {service}"}
    
    elif command == "ping":
        return {"success": True, "pong": True, "version": __version__}
    
    else:
        return {"success": False, "error": f"Unknown command: {command}"}

# ==================== VLESS Endpoints ====================

@app.route("/keys/vless", methods=["GET"])
@require_token
def list_vless_keys():
    """List all VLESS clients."""
    try:
        config = read_json_config(XRAY_CONFIG)
        for i in config.get("inbounds", []):
            if i.get("protocol") == "vless":
                clients = i.get("settings", {}).get("clients", [])
                return jsonify({
                    "protocol": "vless",
                    "count": len(clients),
                    "clients": [{"uuid": c.get("id"), "flow": c.get("flow")} for c in clients]
                })
        return jsonify({"protocol": "vless", "count": 0, "clients": []})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/vless", methods=["POST"])
@require_token
def add_vless_key():
    data = request.get_json() or {}
    client_uuid = data.get("uuid") or str(uuid.uuid4())
    flow = data.get("flow", "xtls-rprx-vision")
    if not is_valid_uuid(client_uuid):
        return jsonify({"error": "Invalid UUID format"}), 400
    try:
        config = read_json_config(XRAY_CONFIG)
        vless_inbound = next((i for i in config.get("inbounds", []) if i.get("protocol") == "vless"), None)
        if not vless_inbound:
            return jsonify({"error": "VLESS inbound not found"}), 500
        clients = vless_inbound.get("settings", {}).get("clients", [])
        for c in clients:
            if c.get("id") == client_uuid:
                return jsonify({"success": True, "uuid": client_uuid, "flow": c.get("flow"), "existed": True})
        clients.append({"id": client_uuid, "flow": flow, "email": client_uuid})
        vless_inbound["settings"]["clients"] = clients
        write_json_config(XRAY_CONFIG, config)
        return jsonify({"success": True, "uuid": client_uuid, "flow": flow, "restart": restart_service_sync("xray")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/vless/<client_uuid>", methods=["DELETE"])
@require_token
def delete_vless_key(client_uuid: str):
    try:
        config = read_json_config(XRAY_CONFIG)
        vless_inbound = next((i for i in config.get("inbounds", []) if i.get("protocol") == "vless"), None)
        if not vless_inbound:
            return jsonify({"error": "VLESS inbound not found"}), 500
        clients = vless_inbound.get("settings", {}).get("clients", [])
        new_clients = [c for c in clients if c.get("id") != client_uuid]
        if len(new_clients) == len(clients):
            return jsonify({"error": "UUID not found"}), 404
        vless_inbound["settings"]["clients"] = new_clients
        write_json_config(XRAY_CONFIG, config)
        return jsonify({"success": True, "deleted_uuid": client_uuid, "restart": restart_service_sync("xray")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== TUIC Endpoints ====================

@app.route("/keys/tuic", methods=["GET"])
@require_token
def list_tuic_keys():
    """List all TUIC users. Use ?domain_index=0 or ?domain_index=1"""
    domain_index = request.args.get("domain_index", 0, type=int)
    if domain_index < 0 or domain_index >= len(TUIC_CONFIGS):
        return jsonify({"error": "Invalid domain_index"}), 400
    try:
        config = read_json_config(TUIC_CONFIGS[domain_index])
        users = config.get("users", {})
        return jsonify({
            "protocol": "tuic",
            "domain_index": domain_index,
            "count": len(users),
            "users": users  # {uuid: password}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/tuic", methods=["POST"])
@require_token
def add_tuic_key():
    data = request.get_json() or {}
    user_uuid = data.get("uuid") or str(uuid.uuid4())
    password = data.get("password") or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=')
    domain_index = data.get("domain_index", 0)
    if not is_valid_uuid(user_uuid) or domain_index < 0 or domain_index >= len(TUIC_CONFIGS):
        return jsonify({"error": "Invalid params"}), 400
    try:
        config = read_json_config(TUIC_CONFIGS[domain_index])
        users = config.get("users", {})
        if user_uuid in users:
            return jsonify({"success": True, "uuid": user_uuid, "password": users[user_uuid], "existed": True})
        users[user_uuid] = password
        config["users"] = users
        write_json_config(TUIC_CONFIGS[domain_index], config)
        return jsonify({"success": True, "uuid": user_uuid, "password": password, "domain_index": domain_index, "restart": restart_service_sync(TUIC_SERVICES[domain_index])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/tuic/<user_uuid>", methods=["DELETE"])
@require_token
def delete_tuic_key(user_uuid: str):
    domain_index = request.args.get("domain_index", 0, type=int)
    if domain_index < 0 or domain_index >= len(TUIC_CONFIGS):
        return jsonify({"error": "Invalid domain_index"}), 400
    try:
        config = read_json_config(TUIC_CONFIGS[domain_index])
        users = config.get("users", {})
        if user_uuid not in users:
            return jsonify({"error": "UUID not found"}), 404
        del users[user_uuid]
        config["users"] = users
        write_json_config(TUIC_CONFIGS[domain_index], config)
        return jsonify({"success": True, "deleted_uuid": user_uuid, "restart": restart_service_sync(TUIC_SERVICES[domain_index])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== Hysteria2 Endpoints ====================

@app.route("/keys/hysteria2", methods=["GET"])
@require_token
def list_hysteria2_keys():
    """List all Hysteria2 users. Use ?domain_index=0 or ?domain_index=1"""
    domain_index = request.args.get("domain_index", 0, type=int)
    if domain_index < 0 or domain_index >= len(HYSTERIA_CONFIGS):
        return jsonify({"error": "Invalid domain_index"}), 400
    try:
        config = read_yaml_config(HYSTERIA_CONFIGS[domain_index])
        auth = config.get("auth", {})
        if auth.get("type") == "userpass":
            users = auth.get("userpass", {})
        else:
            users = {}
        return jsonify({
            "protocol": "hysteria2",
            "domain_index": domain_index,
            "count": len(users),
            "users": users  # {username: password}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/hysteria2", methods=["POST"])
@require_token
def add_hysteria2_key():
    data = request.get_json() or {}
    username = data.get("username") or f"user{int(time.time())}"
    password = data.get("password") or secrets.token_urlsafe(16)
    domain_index = data.get("domain_index", 0)
    if domain_index < 0 or domain_index >= len(HYSTERIA_CONFIGS):
        return jsonify({"error": "Invalid domain_index"}), 400
    try:
        config = read_yaml_config(HYSTERIA_CONFIGS[domain_index])
        auth = config.get("auth", {})
        if auth.get("type") == "password":
            config["auth"] = {"type": "userpass", "userpass": {"legacy": auth.get("password", ""), username: password}}
        elif auth.get("type") == "userpass":
            userpass = auth.get("userpass", {})
            if username in userpass:
                return jsonify({"success": True, "username": username, "password": userpass[username], "existed": True})
            userpass[username] = password
            config["auth"]["userpass"] = userpass
        else:
            config["auth"] = {"type": "userpass", "userpass": {username: password}}
        write_yaml_config(HYSTERIA_CONFIGS[domain_index], config)
        return jsonify({"success": True, "username": username, "password": password, "domain_index": domain_index, "restart": restart_service_sync(HYSTERIA_SERVICES[domain_index])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/hysteria2/<username>", methods=["DELETE"])
@require_token
def delete_hysteria2_key(username: str):
    domain_index = request.args.get("domain_index", 0, type=int)
    if domain_index < 0 or domain_index >= len(HYSTERIA_CONFIGS):
        return jsonify({"error": "Invalid domain_index"}), 400
    try:
        config = read_yaml_config(HYSTERIA_CONFIGS[domain_index])
        auth = config.get("auth", {})
        if auth.get("type") != "userpass":
            return jsonify({"error": "Not in userpass mode"}), 400
        userpass = auth.get("userpass", {})
        if username not in userpass:
            return jsonify({"error": "Username not found"}), 404
        del userpass[username]
        config["auth"]["userpass"] = userpass
        write_yaml_config(HYSTERIA_CONFIGS[domain_index], config)
        return jsonify({"success": True, "deleted_username": username, "restart": restart_service_sync(HYSTERIA_SERVICES[domain_index])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== Shadowsocks Endpoints ====================

@app.route("/keys/shadowsocks", methods=["GET"])
@require_token
def list_shadowsocks_keys():
    """List all Shadowsocks keys."""
    try:
        config = read_yaml_config(SS_CONFIG)
        keys = config.get("keys", [])
        return jsonify({
            "protocol": "shadowsocks",
            "count": len(keys),
            "keys": [{"id": k.get("id"), "port": k.get("port"), "cipher": k.get("cipher")} for k in keys]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/shadowsocks", methods=["POST"])
@require_token
def add_shadowsocks_key():
    data = request.get_json() or {}
    key_id = data.get("id") or f"user{int(time.time())}"
    port = data.get("port", 8388)
    cipher = data.get("cipher", "chacha20-ietf-poly1305")
    secret = data.get("secret") or secrets.token_urlsafe(32)
    try:
        config = read_yaml_config(SS_CONFIG)
        keys = config.get("keys", [])
        for k in keys:
            if k.get("id") == key_id:
                return jsonify({"success": True, "id": key_id, "secret": k.get("secret"), "existed": True})
        keys.append({"id": key_id, "port": port, "cipher": cipher, "secret": secret})
        config["keys"] = keys
        write_yaml_config(SS_CONFIG, config)
        return jsonify({"success": True, "id": key_id, "port": port, "cipher": cipher, "secret": secret, "restart": restart_service_sync("shadowsocks")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/shadowsocks/<key_id>", methods=["DELETE"])
@require_token
def delete_shadowsocks_key(key_id: str):
    try:
        config = read_yaml_config(SS_CONFIG)
        keys = config.get("keys", [])
        new_keys = [k for k in keys if k.get("id") != key_id]
        if len(new_keys) == len(keys):
            return jsonify({"error": "Key ID not found"}), 404
        config["keys"] = new_keys
        write_yaml_config(SS_CONFIG, config)
        return jsonify({"success": True, "deleted_id": key_id, "restart": restart_service_sync("shadowsocks")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== WireGuard Endpoints ====================

@app.route("/keys/wireguard", methods=["GET"])
@require_token
def list_wireguard_keys():
    """List all WireGuard peers."""
    try:
        with open(WG_CONFIG, 'r') as f:
            config_content = f.read()
        
        # Parse peers
        peers = []
        peer_blocks = re.findall(r'\[Peer\](.*?)(?=\[|\Z)', config_content, re.DOTALL)
        for block in peer_blocks:
            public_key = re.search(r'PublicKey\s*=\s*(\S+)', block)
            allowed_ips = re.search(r'AllowedIPs\s*=\s*(\S+)', block)
            if public_key:
                peers.append({
                    "public_key": public_key.group(1),
                    "allowed_ips": allowed_ips.group(1) if allowed_ips else None
                })
        
        return jsonify({
            "protocol": "wireguard",
            "count": len(peers),
            "peers": peers
        })
    except FileNotFoundError:
        return jsonify({"protocol": "wireguard", "count": 0, "peers": []})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/wireguard", methods=["POST"])
@require_token
def add_wireguard_key():
    data = request.get_json() or {}
    try:
        with open(WG_CONFIG, 'r') as f:
            config_content = f.read()
        if data.get("public_key"):
            public_key, private_key = data["public_key"], data.get("private_key", "")
        else:
            result = subprocess.run(["wg", "genkey"], capture_output=True, text=True)
            private_key = result.stdout.strip()
            result = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True)
            public_key = result.stdout.strip()
        if public_key in config_content:
            match = re.search(rf'PublicKey\s*=\s*{re.escape(public_key)}[\s\S]*?AllowedIPs\s*=\s*(\S+)', config_content)
            return jsonify({"success": True, "public_key": public_key, "private_key": private_key, "client_ip": match.group(1).replace('/32', '') if match else None, "existed": True})
        ips = re.findall(r'AllowedIPs\s*=\s*10\.66\.66\.(\d+)/32', config_content)
        used = set(int(ip) for ip in ips)
        client_ip = next(f"10.66.66.{i}" for i in range(2, 255) if i not in used)
        with open(WG_CONFIG, 'a') as f:
            f.write(f"\n[Peer]\nPublicKey = {public_key}\nAllowedIPs = {client_ip}/32\n")
        subprocess.run(["wg", "syncconf", "wg0", "/dev/stdin"], input=subprocess.run(["wg-quick", "strip", "wg0"], capture_output=True, text=True).stdout, capture_output=True, text=True)
        return jsonify({"success": True, "public_key": public_key, "private_key": private_key, "client_ip": client_ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/wireguard/<path:public_key>", methods=["DELETE"])
@require_token
def delete_wireguard_key(public_key: str):
    try:
        with open(WG_CONFIG, 'r') as f:
            config_content = f.read()
        if public_key not in config_content:
            return jsonify({"error": "Public key not found"}), 404
        pattern = rf'\[Peer\]\s*\n(?:.*\n)*?PublicKey\s*=\s*{re.escape(public_key)}\s*\n(?:.*\n)*?(?=\[|$)'
        new_content = re.sub(pattern, '', config_content)
        with open(WG_CONFIG, 'w') as f:
            f.write(new_content)
        subprocess.run(["wg", "syncconf", "wg0", "/dev/stdin"], input=subprocess.run(["wg-quick", "strip", "wg0"], capture_output=True, text=True).stdout, capture_output=True, text=True)
        return jsonify({"success": True, "deleted_public_key": public_key})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== Health & Info Endpoints ====================

def get_service_status(service: str) -> dict:
    try:
        result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=5)
        return {"service": service, "status": result.stdout.strip()}
    except Exception as e:
        return {"service": service, "status": "error", "error": str(e)}


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "VPN Key Agent", "version": __version__, "status": "running"})


@app.route("/health", methods=["GET"])
@require_token
def health_all():
    services = {}
    all_healthy = True
    for svc in VPN_SERVICES:
        status = get_service_status(svc)
        services[svc] = status
        if status["status"] != "active":
            all_healthy = False
    return jsonify({"healthy": all_healthy, "services": services})


@app.route("/health/<service>", methods=["GET"])
@require_token
def health_service(service: str):
    if service not in VPN_SERVICES:
        return jsonify({"error": f"Unknown service: {service}"}), 404
    return jsonify(get_service_status(service))


@app.route("/restart/<service>", methods=["POST"])
@require_token
def restart(service: str):
    if service not in VPN_SERVICES:
        return jsonify({"error": f"Unknown service: {service}"}), 404
    result = restart_service_sync(service)
    return jsonify({"service": service, **result}), 200 if result.get("success") else 500


@app.route("/info", methods=["GET"])
@require_token
def server_info():
    return jsonify(get_server_metrics())

# ==================== WebSocket Mode ====================

async def websocket_loop():
    """WebSocket loop - connects to Central Manager."""
    import aiohttp
    
    if not CENTRAL_MANAGER_URL or not SERVER_ID:
        logger.warning("WebSocket disabled: CENTRAL_MANAGER_URL or VPN_SERVER_ID not set")
        return
    
    logger.info(f"WebSocket connecting to {CENTRAL_MANAGER_URL}")
    
    while True:
        try:
            ws_url = f"{CENTRAL_MANAGER_URL}/{SERVER_ID}?token={API_TOKEN}"
            
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url, heartbeat=20) as ws:
                    logger.info("Connected to Central Manager")
                    
                    await ws.send_json({"agent_version": __version__, "server_id": SERVER_ID})
                    
                    msg = await ws.receive_json()
                    if msg.get("type") == "welcome":
                        logger.info(f"Registered: {msg.get('server_name')}")
                    
                    last_heartbeat = time.time()
                    
                    while True:
                        now = time.time()
                        
                        # Heartbeat every 30s
                        if now - last_heartbeat >= 30:
                            metrics = get_server_metrics()
                            await ws.send_json({"type": "heartbeat", "agent_version": __version__, **metrics})
                            last_heartbeat = now
                        
                        # Check commands
                        try:
                            msg = await asyncio.wait_for(ws.receive_json(), timeout=5)
                            if msg.get("type") == "command":
                                result = handle_command(msg.get("command"), msg.get("data", {}))
                                await ws.send_json({"type": "command_result", "command": msg.get("command"), "result": result})
                        except asyncio.TimeoutError:
                            pass
                        except Exception as e:
                            if "close" in str(e).lower():
                                raise
                            
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            logger.info("Reconnecting in 10s...")
            await asyncio.sleep(10)


def run_websocket_in_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(websocket_loop())


# ==================== Main ====================

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8080
    websocket_mode = "--websocket" in sys.argv or bool(CENTRAL_MANAGER_URL)
    
    if not API_TOKEN:
        print("WARNING: VPN_AGENT_TOKEN not set!")
    
    print(f"VPN Key Agent v{__version__} starting on port {port}")
    print(f"WebSocket: {'enabled' if websocket_mode else 'disabled'}")
    
    if websocket_mode:
        ws_thread = threading.Thread(target=run_websocket_in_thread, daemon=True)
        ws_thread.start()
        logger.info("WebSocket thread started")
    
    app.run(host="0.0.0.0", port=port, threaded=True)
