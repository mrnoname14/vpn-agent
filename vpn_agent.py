#!/usr/bin/env python3
"""
VPN Key Agent v3.9.7
Extended VPN Health Agent with key management for multi-user support.

New Endpoints:
  POST   /keys/vless          - Add VLESS client (UUID)
  DELETE /keys/vless/{uuid}   - Remove VLESS client
  POST   /keys/tuic           - Add TUIC user (UUID:password)
  DELETE /keys/tuic/{uuid}    - Remove TUIC user
  POST   /keys/shadowsocks    - Add Shadowsocks key
  DELETE /keys/shadowsocks/{id} - Remove Shadowsocks key
  POST   /keys/wireguard      - Add WireGuard peer
  DELETE /keys/wireguard/{pubkey} - Remove WireGuard peer
  POST   /keys/hysteria2      - Add Hysteria2 user
  DELETE /keys/hysteria2/{username} - Remove Hysteria2 user
  GET    /keys/{protocol}     - List all keys for protocol
  POST   /restart-self        - Restart the agent itself
  GET    /traffic             - Server network traffic stats

Original Endpoints (from v1.3):
  GET  /              - basic info (no auth)
  GET  /health        - status of all VPN services
  GET  /health/{svc}  - status of specific service
  POST /restart/{svc} - restart a service
  POST /restart-all   - restart all stopped services
  GET  /info          - server info (uptime, load, memory, disk)

v3.9.7 Changes:
  - Added real cpu_percent to /info endpoint (from /proc/stat, auto-scales with any core count)
  - Replaces broken load_avg * 100 calculation in backend

v3.9.6 Changes:
  - Added GET /traffic endpoint - returns server network traffic (bytes in/out from /proc/net/dev)

v3.9.5 Changes:
  - Fixed Shadowsocks: changed config path from /etc/outline/config.yml to /etc/shadowsocks-rust/config.json
  - Shadowsocks now uses JSON format and shadowsocks-rust multi-user mode (users array)
  - Updated SS endpoints to use 'name'/'password' instead of 'id'/'secret'

v3.9.4 Changes:
  - Added /restart-self endpoint for remote agent restart via API

v3.9.3 Changes:
  - Added system key protection (legacy keys cannot be deleted)
  - System keys are hidden from list endpoints
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
from functools import wraps
from flask import Flask, jsonify, request

__version__ = "3.9.7"

app = Flask(__name__)

API_TOKEN = os.environ.get("VPN_AGENT_TOKEN", "")

# Config paths
XRAY_CONFIG = "/usr/local/etc/xray/config.json"
TUIC_CONFIG = "/etc/tuic/config.json"
TUIC_CONFIG_D2 = "/etc/tuic/config-d2.json"  # Second domain
SS_CONFIG = "/etc/shadowsocks-rust/config.json"
WG_CONFIG = "/etc/wireguard/wg0.conf"
HYSTERIA_CONFIG = "/etc/hysteria/config.yaml"
HYSTERIA_CONFIG_D2 = "/etc/hysteria/config-d2.yaml"  # Second domain

# Multi-domain config mapping
TUIC_CONFIGS = [TUIC_CONFIG, TUIC_CONFIG_D2]
HYSTERIA_CONFIGS = [HYSTERIA_CONFIG, HYSTERIA_CONFIG_D2]

# Services for each domain
TUIC_SERVICES = ["tuic", "tuic-d2"]  # tuic for D1, tuic-d2 for D2
HYSTERIA_SERVICES = ["hysteria", "hysteria-d2"]  # hysteria for D1, hysteria-d2 for D2

# Services to restart after config changes
SERVICE_MAP = {
    "vless": "xray",
    "tuic": "tuic",
    "shadowsocks": "shadowsocks",
    "wireguard": "wg-quick@wg0",
    "hysteria2": "hysteria",
}

VPN_SERVICES = [
    "hysteria",
    "hysteria-d2",
    "tuic",
    "tuic-d2",
    "xray",
    "shadowsocks",
    "AdGuardHome",
]

# System key protection
TUIC_SYSTEM_UUIDS = {"00000000-0000-0000-0000-000000000000"}
HYSTERIA_SYSTEM_USERS = {"legacy"}

def _is_tuic_system_key(uuid_str):
    return uuid_str.lower() in TUIC_SYSTEM_UUIDS

def _is_hysteria_system_key(username):
    return username.lower() in HYSTERIA_SYSTEM_USERS


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_TOKEN:
            return jsonify({"error": "Agent not configured (no token)"}), 503
        token = request.headers.get("X-Agent-Token", "")
        if token != API_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def is_valid_uuid(uuid_string: str) -> bool:
    """Validate UUID format (must be valid hex characters)."""
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, AttributeError):
        return False


def restart_service_sync(service: str, timeout: int = 30) -> dict:
    """Restart a service and return status."""
    try:
        result = subprocess.run(
            ["systemctl", "restart", service],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip() or "Restart failed"}
        
        time.sleep(2)
        
        # Check if active
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=5
        )
        status = result.stdout.strip()
        return {"success": status == "active", "status": status}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Restart timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def read_json_config(path: str) -> dict:
    """Read JSON config file."""
    with open(path, 'r') as f:
        return json.load(f)


def write_json_config(path: str, data: dict):
    """Write JSON config file with backup."""
    # Backup
    backup_path = f"{path}.bak"
    if os.path.exists(path):
        with open(path, 'r') as f:
            backup_data = f.read()
        with open(backup_path, 'w') as f:
            f.write(backup_data)
    
    # Write new config
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def read_yaml_config(path: str) -> dict:
    """Read YAML config file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def write_yaml_config(path: str, data: dict):
    """Write YAML config file with backup."""
    backup_path = f"{path}.bak"
    if os.path.exists(path):
        with open(path, 'r') as f:
            backup_data = f.read()
        with open(backup_path, 'w') as f:
            f.write(backup_data)
    
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False)


# ==================== VLESS (xray) ====================

@app.route("/keys/vless", methods=["POST"])
@require_token
def add_vless_key():
    """Add VLESS client to xray config."""
    data = request.get_json() or {}
    client_uuid = data.get("uuid") or str(uuid.uuid4())
    flow = data.get("flow", "xtls-rprx-vision")
    
    # Validate UUID format
    if not is_valid_uuid(client_uuid):
        return jsonify({"error": "Invalid UUID format", "uuid": client_uuid}), 400
    
    try:
        config = read_json_config(XRAY_CONFIG)
        
        # Find VLESS inbound
        vless_inbound = None
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless":
                vless_inbound = inbound
                break
        
        if not vless_inbound:
            return jsonify({"error": "VLESS inbound not found in config"}), 500
        
        # Check if UUID already exists
        clients = vless_inbound.get("settings", {}).get("clients", [])
        for client in clients:
            if client.get("id") == client_uuid:
                return jsonify({"error": "UUID already exists", "uuid": client_uuid}), 409
        
        # Add new client
        new_client = {"id": client_uuid, "flow": flow}
        clients.append(new_client)
        vless_inbound["settings"]["clients"] = clients
        
        write_json_config(XRAY_CONFIG, config)
        
        # Restart xray
        restart_result = restart_service_sync("xray")
        
        return jsonify({
            "success": True,
            "uuid": client_uuid,
            "flow": flow,
            "restart": restart_result,
            "total_clients": len(clients)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/vless/<client_uuid>", methods=["DELETE"])
@require_token
def delete_vless_key(client_uuid: str):
    """Remove VLESS client from xray config."""
    try:
        config = read_json_config(XRAY_CONFIG)
        
        vless_inbound = None
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless":
                vless_inbound = inbound
                break
        
        if not vless_inbound:
            return jsonify({"error": "VLESS inbound not found"}), 500
        
        clients = vless_inbound.get("settings", {}).get("clients", [])
        original_count = len(clients)
        
        # Remove client
        clients = [c for c in clients if c.get("id") != client_uuid]
        
        if len(clients) == original_count:
            return jsonify({"error": "UUID not found"}), 404
        
        vless_inbound["settings"]["clients"] = clients
        write_json_config(XRAY_CONFIG, config)
        
        restart_result = restart_service_sync("xray")
        
        return jsonify({
            "success": True,
            "deleted_uuid": client_uuid,
            "restart": restart_result,
            "total_clients": len(clients)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/vless", methods=["GET"])
@require_token
def list_vless_keys():
    """List all VLESS clients."""
    try:
        config = read_json_config(XRAY_CONFIG)
        
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless":
                clients = inbound.get("settings", {}).get("clients", [])
                return jsonify({
                    "protocol": "vless",
                    "count": len(clients),
                    "clients": [{"uuid": c.get("id"), "flow": c.get("flow")} for c in clients]
                })
        
        return jsonify({"error": "VLESS inbound not found"}), 500
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== TUIC ====================

@app.route("/keys/tuic", methods=["POST"])
@require_token
def add_tuic_key():
    """Add TUIC user. Supports domain_index for multi-domain setups."""
    data = request.get_json() or {}
    user_uuid = data.get("uuid") or str(uuid.uuid4())
    password = data.get("password") or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=')
    domain_index = data.get("domain_index", 0)
    
    # Validate UUID format
    if not is_valid_uuid(user_uuid):
        return jsonify({"error": "Invalid UUID format", "uuid": user_uuid}), 400
    
    # Validate domain_index
    if domain_index < 0 or domain_index >= len(TUIC_CONFIGS):
        return jsonify({"error": f"Invalid domain_index: {domain_index}"}), 400
    
    config_path = TUIC_CONFIGS[domain_index]
    service_name = TUIC_SERVICES[domain_index]
    
    try:
        config = read_json_config(config_path)
        
        users = config.get("users", {})
        
        if user_uuid in users:
            return jsonify({"error": "UUID already exists", "uuid": user_uuid}), 409
        
        users[user_uuid] = password
        config["users"] = users
        
        write_json_config(config_path, config)
        
        restart_result = restart_service_sync(service_name)
        
        return jsonify({
            "success": True,
            "uuid": user_uuid,
            "password": password,
            "domain_index": domain_index,
            "restart": restart_result,
            "total_users": len(users)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/tuic/<user_uuid>", methods=["DELETE"])
@require_token
def delete_tuic_key(user_uuid: str):
    """Remove TUIC user. Supports domain_index query param for multi-domain setups."""
    domain_index = request.args.get("domain_index", 0, type=int)

    # PROTECTION: Cannot delete system keys
    if _is_tuic_system_key(user_uuid):
        return jsonify({"error": "Cannot delete system key", "uuid": user_uuid}), 403
    
    # Validate domain_index
    if domain_index < 0 or domain_index >= len(TUIC_CONFIGS):
        return jsonify({"error": f"Invalid domain_index: {domain_index}"}), 400
    
    config_path = TUIC_CONFIGS[domain_index]
    service_name = TUIC_SERVICES[domain_index]
    
    try:
        config = read_json_config(config_path)
        
        users = config.get("users", {})
        
        if user_uuid not in users:
            return jsonify({"error": "UUID not found"}), 404
        
        del users[user_uuid]
        config["users"] = users
        
        write_json_config(config_path, config)
        
        restart_result = restart_service_sync(service_name)
        
        return jsonify({
            "success": True,
            "deleted_uuid": user_uuid,
            "domain_index": domain_index,
            "restart": restart_result,
            "total_users": len(users)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/tuic", methods=["GET"])
@require_token
def list_tuic_keys():
    """List all TUIC users. Supports domain_index query param."""
    domain_index = request.args.get("domain_index", 0, type=int)
    
    # Validate domain_index
    if domain_index < 0 or domain_index >= len(TUIC_CONFIGS):
        return jsonify({"error": f"Invalid domain_index: {domain_index}"}), 400
    
    config_path = TUIC_CONFIGS[domain_index]
    
    try:
        config = read_json_config(config_path)
        users = config.get("users", {})
        
        # Filter out system keys
        filtered = {k: v for k, v in users.items() if not _is_tuic_system_key(k)}
        
        return jsonify({
            "protocol": "tuic",
            "domain_index": domain_index,
            "count": len(filtered),
            "users": filtered
        })
        
    except FileNotFoundError:
        return jsonify({
            "protocol": "tuic",
            "domain_index": domain_index,
            "count": 0,
            "users": {},
            "error": f"Config not found: {config_path}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== Shadowsocks ====================

@app.route("/keys/shadowsocks", methods=["POST"])
@require_token
def add_shadowsocks_key():
    """Add Shadowsocks user (shadowsocks-rust multi-user mode)."""
    data = request.get_json() or {}
    user_name = data.get("name") or data.get("id") or f"user{int(time.time())}"
    password = data.get("password") or data.get("secret") or secrets.token_urlsafe(32)
    
    try:
        config = read_json_config(SS_CONFIG)
        
        users = config.get("users", [])
        
        # Check if name exists
        for user in users:
            if user.get("name") == user_name:
                return jsonify({"error": "User already exists", "name": user_name}), 409
        
        new_user = {
            "name": user_name,
            "password": password
        }
        users.append(new_user)
        config["users"] = users
        
        write_json_config(SS_CONFIG, config)
        
        restart_result = restart_service_sync("shadowsocks")
        
        return jsonify({
            "success": True,
            "name": user_name,
            "password": password,
            "restart": restart_result,
            "total_users": len(users)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/shadowsocks/<user_name>", methods=["DELETE"])
@require_token
def delete_shadowsocks_key(user_name: str):
    """Remove Shadowsocks user."""
    try:
        config = read_json_config(SS_CONFIG)
        
        users = config.get("users", [])
        original_count = len(users)
        
        users = [u for u in users if u.get("name") != user_name]
        
        if len(users) == original_count:
            return jsonify({"error": "User not found"}), 404
        
        config["users"] = users
        write_json_config(SS_CONFIG, config)
        
        restart_result = restart_service_sync("shadowsocks")
        
        return jsonify({
            "success": True,
            "deleted_name": user_name,
            "restart": restart_result,
            "total_users": len(users)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/shadowsocks", methods=["GET"])
@require_token
def list_shadowsocks_keys():
    """List all Shadowsocks users."""
    try:
        config = read_json_config(SS_CONFIG)
        users = config.get("users", [])
        
        return jsonify({
            "protocol": "shadowsocks",
            "count": len(users),
            "users": users
        })
        
    except FileNotFoundError:
        return jsonify({
            "protocol": "shadowsocks",
            "count": 0,
            "users": [],
            "error": f"Config not found: {SS_CONFIG}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== WireGuard ====================

def generate_wireguard_keypair():
    """Generate WireGuard keypair."""
    result = subprocess.run(["wg", "genkey"], capture_output=True, text=True)
    private_key = result.stdout.strip()
    
    result = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True)
    public_key = result.stdout.strip()
    
    return private_key, public_key


def get_next_wg_ip(config_content: str) -> str:
    """Get next available WireGuard IP address."""
    # Find all existing IPs
    ips = re.findall(r'AllowedIPs\s*=\s*10\.66\.66\.(\d+)/32', config_content)
    used = set(int(ip) for ip in ips)
    
    # Server uses .1, clients start from .2
    for i in range(2, 255):
        if i not in used:
            return f"10.66.66.{i}"
    
    raise Exception("No available IP addresses in WireGuard subnet")


@app.route("/keys/wireguard", methods=["POST"])
@require_token
def add_wireguard_key():
    """Add WireGuard peer."""
    data = request.get_json() or {}
    
    try:
        # Read current config
        with open(WG_CONFIG, 'r') as f:
            config_content = f.read()
        
        # Generate or use provided keys
        if data.get("public_key"):
            public_key = data["public_key"]
            private_key = data.get("private_key", "")  # Client keeps private key
        else:
            private_key, public_key = generate_wireguard_keypair()
        
        # Check if public key already exists
        if public_key in config_content:
            return jsonify({"error": "Public key already exists"}), 409
        
        # Get next available IP
        client_ip = data.get("client_ip") or get_next_wg_ip(config_content)
        
        # Add peer section
        peer_section = f"""
[Peer]
# Added by VPN Agent
PublicKey = {public_key}
AllowedIPs = {client_ip}/32
"""
        
        # Append to config
        with open(WG_CONFIG, 'a') as f:
            f.write(peer_section)
        
        # Reload WireGuard (wg syncconf is faster than restart)
        result = subprocess.run(
            ["wg", "syncconf", "wg0", "/dev/stdin"],
            input=subprocess.run(["wg-quick", "strip", "wg0"], capture_output=True, text=True).stdout,
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            # Fallback to restart
            restart_result = restart_service_sync("wg-quick@wg0")
        else:
            restart_result = {"success": True, "method": "syncconf"}
        
        return jsonify({
            "success": True,
            "public_key": public_key,
            "private_key": private_key,  # Only if we generated it
            "client_ip": client_ip,
            "restart": restart_result
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/wireguard/<path:public_key>", methods=["DELETE"])
@require_token
def delete_wireguard_key(public_key: str):
    """Remove WireGuard peer by public key."""
    try:
        with open(WG_CONFIG, 'r') as f:
            config_content = f.read()
        
        if public_key not in config_content:
            return jsonify({"error": "Public key not found"}), 404
        
        # Remove peer section
        # Pattern: [Peer] followed by lines until next [Peer] or end
        pattern = rf'\[Peer\]\s*\n(?:.*\n)*?PublicKey\s*=\s*{re.escape(public_key)}\s*\n(?:.*\n)*?(?=\[|$)'
        new_content = re.sub(pattern, '', config_content)
        
        with open(WG_CONFIG, 'w') as f:
            f.write(new_content)
        
        # Reload
        result = subprocess.run(
            ["wg", "syncconf", "wg0", "/dev/stdin"],
            input=subprocess.run(["wg-quick", "strip", "wg0"], capture_output=True, text=True).stdout,
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            restart_result = restart_service_sync("wg-quick@wg0")
        else:
            restart_result = {"success": True, "method": "syncconf"}
        
        return jsonify({
            "success": True,
            "deleted_public_key": public_key,
            "restart": restart_result
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/wireguard", methods=["GET"])
@require_token
def list_wireguard_keys():
    """List all WireGuard peers."""
    try:
        with open(WG_CONFIG, 'r') as f:
            config_content = f.read()
        
        # Parse peers
        peers = []
        peer_blocks = re.findall(r'\[Peer\](.*?)(?=\[|$)', config_content, re.DOTALL)
        
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
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== Hysteria2 ====================

@app.route("/keys/hysteria2", methods=["POST"])
@require_token
def add_hysteria2_key():
    """Add Hysteria2 user (userpass mode). Supports domain_index for multi-domain setups."""
    data = request.get_json() or {}
    username = data.get("username") or f"user{int(time.time())}"
    password = data.get("password") or secrets.token_urlsafe(16)
    domain_index = data.get("domain_index", 0)
    
    # Validate domain_index
    if domain_index < 0 or domain_index >= len(HYSTERIA_CONFIGS):
        return jsonify({"error": f"Invalid domain_index: {domain_index}"}), 400
    
    config_path = HYSTERIA_CONFIGS[domain_index]
    service_name = HYSTERIA_SERVICES[domain_index]
    
    try:
        config = read_yaml_config(config_path)
        
        auth = config.get("auth", {})
        
        # Check current auth type
        if auth.get("type") == "password":
            # Need to convert to userpass mode
            old_password = auth.get("password", "")
            config["auth"] = {
                "type": "userpass",
                "userpass": {
                    "legacy": old_password,  # Keep old password as legacy user
                    username: password
                }
            }
        elif auth.get("type") == "userpass":
            userpass = auth.get("userpass", {})
            filtered = {k: v for k, v in userpass.items() if not _is_hysteria_system_key(k)}
            if username in userpass:
                return jsonify({"error": "Username already exists", "username": username}), 409
            userpass[username] = password
            config["auth"]["userpass"] = userpass
        else:
            # First user
            config["auth"] = {
                "type": "userpass",
                "userpass": {
                    username: password
                }
            }
        
        write_yaml_config(config_path, config)
        
        restart_result = restart_service_sync(service_name)
        
        userpass = config["auth"].get("userpass", {})
        
        return jsonify({
            "success": True,
            "username": username,
            "password": password,
            "domain_index": domain_index,
            "restart": restart_result,
            "total_users": len(userpass)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/hysteria2/<username>", methods=["DELETE"])
@require_token
def delete_hysteria2_key(username: str):
    """Remove Hysteria2 user. Supports domain_index query param for multi-domain setups."""
    domain_index = request.args.get("domain_index", 0, type=int)

    # PROTECTION: Cannot delete system keys
    if _is_hysteria_system_key(username):
        return jsonify({"error": "Cannot delete system key", "username": username}), 403
    
    # Validate domain_index
    if domain_index < 0 or domain_index >= len(HYSTERIA_CONFIGS):
        return jsonify({"error": f"Invalid domain_index: {domain_index}"}), 400
    
    config_path = HYSTERIA_CONFIGS[domain_index]
    service_name = HYSTERIA_SERVICES[domain_index]
    
    try:
        config = read_yaml_config(config_path)
        
        auth = config.get("auth", {})
        
        if auth.get("type") != "userpass":
            return jsonify({"error": "Hysteria2 not in userpass mode"}), 400
        
        userpass = auth.get("userpass", {})
        
        if username not in userpass:
            return jsonify({"error": "Username not found"}), 404
        
        del userpass[username]
        config["auth"]["userpass"] = userpass
        
        write_yaml_config(config_path, config)
        
        restart_result = restart_service_sync(service_name)
        
        return jsonify({
            "success": True,
            "deleted_username": username,
            "domain_index": domain_index,
            "restart": restart_result,
            "total_users": len(userpass)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/hysteria2", methods=["GET"])
@require_token
def list_hysteria2_keys():
    """List all Hysteria2 users. Supports domain_index query param."""
    domain_index = request.args.get("domain_index", 0, type=int)
    
    # Validate domain_index
    if domain_index < 0 or domain_index >= len(HYSTERIA_CONFIGS):
        return jsonify({"error": f"Invalid domain_index: {domain_index}"}), 400
    
    config_path = HYSTERIA_CONFIGS[domain_index]
    
    try:
        config = read_yaml_config(config_path)
        
        auth = config.get("auth", {})
        
        if auth.get("type") == "password":
            # Single password mode
            return jsonify({
                "protocol": "hysteria2",
                "domain_index": domain_index,
                "mode": "password",
                "count": 1,
                "users": {"default": auth.get("password", "")}
            })
        elif auth.get("type") == "userpass":
            userpass = auth.get("userpass", {})
            filtered = {k: v for k, v in userpass.items() if not _is_hysteria_system_key(k)}
            return jsonify({
                "protocol": "hysteria2",
                "domain_index": domain_index,
                "mode": "userpass",
                "count": len(filtered),
                "users": filtered
            })
        else:
            return jsonify({
                "protocol": "hysteria2",
                "domain_index": domain_index,
                "mode": "unknown",
                "count": 0,
                "users": {}
            })
        
    except FileNotFoundError:
        return jsonify({
            "protocol": "hysteria2",
            "domain_index": domain_index,
            "count": 0,
            "users": {},
            "error": f"Config not found: {config_path}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== Original Health Endpoints ====================

def get_service_status(service: str) -> dict:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=5
        )
        status = result.stdout.strip()
        info = {"service": service, "status": status}
        
        if status == "active":
            result = subprocess.run(
                ["systemctl", "show", service, "--property=ActiveEnterTimestamp"],
                capture_output=True, text=True, timeout=5
            )
            info["since"] = result.stdout.strip().split("=")[-1]
            
            result = subprocess.run(
                ["systemctl", "show", service, "--property=MemoryCurrent"],
                capture_output=True, text=True, timeout=5
            )
            mem = result.stdout.strip().split("=")[-1]
            if mem and mem not in ["[not set]", ""]:
                try:
                    info["memory_mb"] = round(int(mem) / 1024 / 1024, 1)
                except:
                    pass
        return info
    except subprocess.TimeoutExpired:
        return {"service": service, "status": "timeout", "error": "Command timed out"}
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
    return jsonify({"healthy": all_healthy, "services": services, "timestamp": int(time.time())})


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


@app.route("/restart-all", methods=["POST"])
@require_token
def restart_all():
    results = []
    for svc in VPN_SERVICES:
        status = get_service_status(svc)
        if status["status"] != "active":
            result = restart_service_sync(svc)
            results.append({"service": svc, **result})
    return jsonify({
        "restarted": [r["service"] for r in results if r.get("success")],
        "failed": [r["service"] for r in results if not r.get("success")],
        "details": results,
    })


@app.route("/restart-self", methods=["POST"])
@require_token
def restart_self():
    """
    Restart the VPN Agent itself.
    Uses systemd to restart, response sent before restart.
    """
    try:
        # Start restart in background so we can respond first
        subprocess.Popen(
            ["bash", "-c", "sleep 1 && systemctl restart vpn-agent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return jsonify({
            "success": True,
            "message": "Agent restart initiated",
            "version": __version__,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def _read_cpu_times():
    """Read total and idle CPU times from /proc/stat. Works with any number of cores."""
    with open("/proc/stat") as f:
        line = f.readline()  # First line = aggregated across all CPUs
    parts = line.split()
    # user, nice, system, idle, iowait, irq, softirq, steal
    times = [int(x) for x in parts[1:9]]
    idle = times[3] + times[4]  # idle + iowait
    total = sum(times)
    return total, idle


def _get_cpu_percent(interval=0.5):
    """Get real CPU usage % via two /proc/stat samples. Auto-scales with any core count."""
    try:
        t1, i1 = _read_cpu_times()
        time.sleep(interval)
        t2, i2 = _read_cpu_times()
        total_diff = t2 - t1
        idle_diff = i2 - i1
        if total_diff == 0:
            return 0.0
        return round((1.0 - idle_diff / total_diff) * 100, 1)
    except Exception:
        return 0.0


@app.route("/info", methods=["GET"])
@require_token
def server_info():
    info = {"version": __version__}
    try:
        # Real CPU % (auto-scales with any number of cores)
        info["cpu_percent"] = _get_cpu_percent()
        with open("/proc/uptime") as f:
            info["uptime_hours"] = round(float(f.read().split()[0]) / 3600, 1)
        with open("/proc/loadavg") as f:
            info["load_avg"] = [float(x) for x in f.read().split()[:3]]
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if parts[0] in ["MemTotal:", "MemAvailable:"]:
                    meminfo[parts[0][:-1]] = int(parts[1])
            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)
            if total:
                info["memory_total_mb"] = round(total / 1024)
                info["memory_used_mb"] = round((total - available) / 1024)
                info["memory_percent"] = round((total - available) / total * 100, 1)
        result = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            parts = result.stdout.strip().split("\n")[1].split()
            info["disk_total"] = parts[1]
            info["disk_used"] = parts[2]
            info["disk_percent"] = parts[4]
    except Exception as e:
        info["error"] = str(e)
    return jsonify(info)


# ==================== Traffic Stats ====================

def _get_main_interface():
    """Find main network interface (eth0, ens3, etc). Skip lo and docker."""
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]  # Skip headers
        for line in lines:
            iface = line.split(":")[0].strip()
            if iface in ("lo",) or iface.startswith(("docker", "br-", "veth")):
                continue
            return iface
    except Exception:
        pass
    return "eth0"  # fallback


def _parse_proc_net_dev(interface):
    """Read bytes_in/bytes_out from /proc/net/dev for given interface."""
    with open("/proc/net/dev") as f:
        for line in f:
            if interface + ":" in line:
                parts = line.split(":")[1].split()
                return int(parts[0]), int(parts[8])  # bytes_recv, bytes_sent
    return None, None


def _format_bytes(b):
    """Format bytes to human readable."""
    if b is None:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


@app.route("/traffic", methods=["GET"])
@require_token
def traffic_stats():
    """
    Get server network traffic from /proc/net/dev.
    Returns total bytes in/out since last server reboot.
    Safe read-only operation - no config changes.
    """
    try:
        interface = _get_main_interface()
        bytes_in, bytes_out = _parse_proc_net_dev(interface)

        if bytes_in is None:
            return jsonify({"error": f"Interface {interface} not found"}), 404

        return jsonify({
            "interface": interface,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "bytes_in_human": _format_bytes(bytes_in),
            "bytes_out_human": _format_bytes(bytes_out),
            "bytes_total": bytes_in + bytes_out,
            "bytes_total_human": _format_bytes(bytes_in + bytes_out),
            "timestamp": int(time.time()),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    if not API_TOKEN:
        print("WARNING: VPN_AGENT_TOKEN not set!")
    print(f"VPN Key Agent v{__version__} starting on port {port}")
    app.run(host="0.0.0.0", port=port, threaded=True)
