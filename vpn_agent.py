#!/usr/bin/env python3
"""
VPN Key Agent v3.2.0
Enterprise VPN Agent with WebSocket connection to Central Manager.

Features:
- WebSocket connection to Central Manager (primary)
- HTTP fallback for key management
- Real-time connection tracking for ALL 5 protocols:
  * VLESS (xray) - via access.log parsing
  * WireGuard - via wg show command
  * Hysteria2 - via trafficStats API
  * TUIC - via ss port monitoring
  * Shadowsocks - via ss port monitoring
- Batch event sending for efficiency
- Heartbeat with metrics and connection counts
- IP blocking for duplicate detection (iptables)

Run modes:
- WebSocket mode: Agent connects to Central Manager, sends events
- HTTP mode: Flask server for key management commands

Usage:
  python vpn_agent.py                    # HTTP mode only (legacy)
  python vpn_agent.py --websocket        # WebSocket + HTTP mode
  
Environment:
  VPN_AGENT_TOKEN        - Authentication token
  CENTRAL_MANAGER_URL    - WebSocket URL (ws://api.example.com/...)
  VPN_SERVER_ID          - Server ID in database
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
from dataclasses import dataclass, field
from functools import wraps
from collections import deque
from flask import Flask, jsonify, request

__version__ = "3.2.1"

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

XRAY_ACCESS_LOG = "/var/log/xray/access.log"

# Hysteria2 trafficStats API
HYSTERIA_API_URL = "http://127.0.0.1:9999"
HYSTERIA_API_SECRET = os.environ.get("HYSTERIA_API_SECRET", "agent_stats_token_2024")

# Port mapping for protocols (for ss-based tracking)
PROTOCOL_PORTS = {
    "vless": 443,
    "hysteria2": 8443,
    "tuic": 8444,
    "shadowsocks": 8388,
    "wireguard": 51820,
}

# IP block duration (seconds)
IP_BLOCK_DURATION = 1800  # 30 minutes

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("vpn-agent")

app = Flask(__name__)

# ==================== IP Blocking ====================

class IPBlocker:
    """Manages IP blocking via iptables for duplicate detection."""
    
    CHAIN_NAME = "VPN_BLOCK"
    
    def __init__(self):
        self._blocked_ips: Dict[str, float] = {}  # ip -> unblock_time
        self._lock = threading.Lock()
        self._setup_chain()
    
    def _setup_chain(self):
        """Create iptables chain if not exists."""
        try:
            # Check if chain exists
            result = subprocess.run(
                ["iptables", "-L", self.CHAIN_NAME, "-n"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                # Create chain
                subprocess.run(["iptables", "-N", self.CHAIN_NAME], capture_output=True)
                # Add chain to INPUT
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-j", self.CHAIN_NAME],
                    capture_output=True
                )
                logger.info(f"Created iptables chain: {self.CHAIN_NAME}")
        except Exception as e:
            logger.error(f"Failed to setup iptables chain: {e}")
    
    def block_ip(self, ip: str, duration: int = IP_BLOCK_DURATION) -> bool:
        """Block IP for specified duration."""
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP: {ip}")
            return False
        
        try:
            with self._lock:
                # Add iptables rule
                result = subprocess.run(
                    ["iptables", "-A", self.CHAIN_NAME, "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    self._blocked_ips[ip] = time.time() + duration
                    logger.info(f"Blocked IP: {ip} for {duration}s")
                    return True
                else:
                    logger.error(f"Failed to block IP {ip}: {result.stderr}")
                    return False
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP."""
        if not self._is_valid_ip(ip):
            return False
        
        try:
            with self._lock:
                # Remove iptables rule
                result = subprocess.run(
                    ["iptables", "-D", self.CHAIN_NAME, "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True
                )
                
                if ip in self._blocked_ips:
                    del self._blocked_ips[ip]
                
                if result.returncode == 0:
                    logger.info(f"Unblocked IP: {ip}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False
    
    def cleanup_expired(self):
        """Remove expired blocks."""
        now = time.time()
        expired = [ip for ip, unblock_time in self._blocked_ips.items() if now >= unblock_time]
        for ip in expired:
            self.unblock_ip(ip)
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of blocked IPs with remaining time."""
        now = time.time()
        with self._lock:
            return [
                {"ip": ip, "remaining_seconds": int(unblock_time - now)}
                for ip, unblock_time in self._blocked_ips.items()
                if unblock_time > now
            ]
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except:
            return False


ip_blocker = IPBlocker()

# ==================== Connection Tracking ====================

@dataclass
class ConnectionEvent:
    event_type: str
    protocol: str
    key_id: str
    client_ip: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self):
        return {"event_type": self.event_type, "protocol": self.protocol, "key_id": self.key_id, 
                "client_ip": self.client_ip, "timestamp": self.timestamp.isoformat()}


class ConnectionTracker:
    """Tracks active VPN connections by parsing logs."""
    
    def __init__(self):
        self._active: Dict[str, str] = {}
        self._event_queue: deque = deque(maxlen=1000)
        self._log_positions: Dict[str, int] = {}
        self._lock = threading.Lock()
    
    def get_pending_events(self) -> List[ConnectionEvent]:
        with self._lock:
            events = list(self._event_queue)
            self._event_queue.clear()
            return events
    
    def track_connection(self, protocol: str, key_id: str, client_ip: str):
        conn_key = f"{protocol}:{key_id}"
        with self._lock:
            if conn_key not in self._active or self._active[conn_key] != client_ip:
                self._active[conn_key] = client_ip
                self._event_queue.append(ConnectionEvent("connect", protocol, key_id, client_ip))
                logger.info(f"Connect: {protocol} {key_id[:8]}... from {client_ip}")
    
    def get_active_count(self) -> int:
        with self._lock:
            return len(self._active)
    
    def get_active_by_protocol(self) -> Dict[str, int]:
        with self._lock:
            counts = {}
            for conn_key in self._active:
                protocol = conn_key.split(":")[0]
                counts[protocol] = counts.get(protocol, 0) + 1
            return counts
    
    def parse_xray_log(self):
        if not os.path.exists(XRAY_ACCESS_LOG):
            return
        try:
            with open(XRAY_ACCESS_LOG, 'r') as f:
                last_pos = self._log_positions.get(XRAY_ACCESS_LOG, 0)
                f.seek(0, 2)
                current_size = f.tell()
                if current_size < last_pos:
                    last_pos = 0
                f.seek(last_pos)
                for line in f:
                    match = re.search(r'from:(\d+\.\d+\.\d+\.\d+):\d+.*?email:([a-f0-9-]{36})', line, re.IGNORECASE)
                    if match:
                        self.track_connection("vless", match.group(2), match.group(1))
                self._log_positions[XRAY_ACCESS_LOG] = f.tell()
        except Exception as e:
            logger.error(f"Error parsing xray log: {e}")
    
    def parse_wireguard(self):
        try:
            result = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split('\t')
                if len(parts) >= 5:
                    public_key, endpoint, latest_handshake = parts[0], parts[2], int(parts[4]) if parts[4].isdigit() else 0
                    if endpoint != "(none)" and latest_handshake > 0 and time.time() - latest_handshake < 180:
                        self.track_connection("wireguard", public_key, endpoint.split(':')[0])
        except Exception:
            pass
    
    def parse_hysteria2(self):
        """Parse Hysteria2 trafficStats API to get active connections."""
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{HYSTERIA_API_URL}/online",
                headers={"Authorization": HYSTERIA_API_SECRET}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                # Response format: {"username1": {"tx": 123, "rx": 456}, ...}
                for username, stats in data.items():
                    # We don't have IP from API, but we can track the connection
                    # For now, use a placeholder - we'll get real IP from ss
                    self.track_connection("hysteria2", username, "api")
        except Exception as e:
            if "urlopen" not in str(e.__class__.__name__).lower():
                logger.debug(f"Hysteria2 API error: {e}")
    
    def parse_port_connections(self, protocol: str, port: int) -> List[Dict[str, Any]]:
        """
        Parse active connections on a port using ss command.
        Returns list of {"client_ip": "x.x.x.x", "connected_at": timestamp}
        """
        connections = []
        try:
            # Get established connections to this port
            result = subprocess.run(
                ["ss", "-tn", "state", "established", f"sport = :{port}"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                # Format: "0      0      [::ffff:109.107.181.93]:8443   [::ffff:185.154.73.227]:59648"
                parts = line.split()
                if len(parts) >= 4:
                    peer = parts[3]
                    # Extract IP from peer address
                    # Handle both IPv4 and IPv6-mapped IPv4
                    if "::ffff:" in peer:
                        # IPv6-mapped IPv4: [::ffff:185.154.73.227]:59648
                        ip_match = re.search(r'::ffff:(\d+\.\d+\.\d+\.\d+)', peer)
                    else:
                        # Plain IPv4: 185.154.73.227:59648
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', peer)
                    
                    if ip_match:
                        client_ip = ip_match.group(1)
                        connections.append({
                            "client_ip": client_ip,
                            "connected_at": time.time()
                        })
        except Exception as e:
            logger.debug(f"Error parsing port {port} connections: {e}")
        
        return connections
    
    def get_connection_counts(self) -> Dict[str, int]:
        """
        Get connection counts for all protocols using ss.
        Used for detecting anomalies (more connections than keys).
        """
        counts = {}
        for protocol, port in PROTOCOL_PORTS.items():
            connections = self.parse_port_connections(protocol, port)
            counts[protocol] = len(connections)
        return counts
    
    def scan_all(self):
        # Protocols with key_id tracking
        self.parse_xray_log()      # VLESS - from access.log
        self.parse_wireguard()      # WireGuard - from wg show
        self.parse_hysteria2()      # Hysteria2 - from API
        
        # Note: TUIC and Shadowsocks don't provide key_id in connections
        # We track total connection counts for anomaly detection
        
        # Cleanup expired IP blocks
        ip_blocker.cleanup_expired()


tracker = ConnectionTracker()

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
    with open(path, 'r') as f:
        return json.load(f)

def write_json_config(path: str, data: dict):
    if os.path.exists(path):
        with open(path, 'r') as f:
            with open(f"{path}.bak", 'w') as b:
                b.write(f.read())
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def read_yaml_config(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def write_yaml_config(path: str, data: dict):
    if os.path.exists(path):
        with open(path, 'r') as f:
            with open(f"{path}.bak", 'w') as b:
                b.write(f.read())
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False)

def get_server_metrics() -> dict:
    info = {"version": __version__}
    try:
        with open("/proc/loadavg") as f:
            info["load_avg"] = [float(x) for x in f.read().split()[:3]]
            info["cpu_percent"] = round(info["load_avg"][0] * 100, 1)
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
    info["active_connections"] = tracker.get_active_count()
    info["connections_by_protocol"] = tracker.get_active_by_protocol()
    info["blocked_ips"] = len(ip_blocker.get_blocked_ips())
    # Real connection counts from ss (for all protocols)
    info["connection_counts"] = tracker.get_connection_counts()
    return info

# ==================== Command Handler ====================

def handle_command(command: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Handle command from Central Manager."""
    logger.info(f"Handling command: {command} with data: {data}")
    
    if command == "block_ip":
        ip = data.get("ip")
        duration = data.get("duration", IP_BLOCK_DURATION)
        if ip:
            success = ip_blocker.block_ip(ip, duration)
            return {"success": success, "ip": ip, "duration": duration}
        return {"success": False, "error": "No IP provided"}
    
    elif command == "unblock_ip":
        ip = data.get("ip")
        if ip:
            success = ip_blocker.unblock_ip(ip)
            return {"success": success, "ip": ip}
        return {"success": False, "error": "No IP provided"}
    
    elif command == "get_blocked_ips":
        return {"success": True, "blocked_ips": ip_blocker.get_blocked_ips()}
    
    elif command == "restart_service":
        service = data.get("service")
        if service and service in VPN_SERVICES:
            result = restart_service_sync(service)
            return {"success": result.get("success", False), "service": service, **result}
        return {"success": False, "error": f"Invalid service: {service}"}
    
    elif command == "ping":
        return {"success": True, "pong": True, "version": __version__}
    
    else:
        logger.warning(f"Unknown command: {command}")
        return {"success": False, "error": f"Unknown command: {command}"}

# ==================== Key Management Endpoints ====================

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

@app.route("/keys/vless", methods=["GET"])
@require_token
def list_vless_keys():
    try:
        config = read_json_config(XRAY_CONFIG)
        for i in config.get("inbounds", []):
            if i.get("protocol") == "vless":
                clients = i.get("settings", {}).get("clients", [])
                return jsonify({"protocol": "vless", "count": len(clients), "clients": [{"uuid": c.get("id"), "flow": c.get("flow")} for c in clients]})
        return jsonify({"error": "VLESS inbound not found"}), 500
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

# ==================== IP Blocking Endpoints ====================

@app.route("/block-ip", methods=["POST"])
@require_token
def block_ip_endpoint():
    """Block an IP address."""
    data = request.get_json() or {}
    ip = data.get("ip")
    duration = data.get("duration", IP_BLOCK_DURATION)
    
    if not ip:
        return jsonify({"error": "IP required"}), 400
    
    success = ip_blocker.block_ip(ip, duration)
    return jsonify({"success": success, "ip": ip, "duration": duration})

@app.route("/unblock-ip", methods=["POST"])
@require_token
def unblock_ip_endpoint():
    """Unblock an IP address."""
    data = request.get_json() or {}
    ip = data.get("ip")
    
    if not ip:
        return jsonify({"error": "IP required"}), 400
    
    success = ip_blocker.unblock_ip(ip)
    return jsonify({"success": success, "ip": ip})

@app.route("/blocked-ips", methods=["GET"])
@require_token
def get_blocked_ips_endpoint():
    """Get list of blocked IPs."""
    return jsonify({"blocked_ips": ip_blocker.get_blocked_ips()})

# ==================== Health & Info Endpoints ====================

def get_service_status(service: str) -> dict:
    try:
        result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=5)
        status = result.stdout.strip()
        info = {"service": service, "status": status}
        if status == "active":
            result = subprocess.run(["systemctl", "show", service, "--property=ActiveEnterTimestamp"], capture_output=True, text=True, timeout=5)
            info["since"] = result.stdout.strip().split("=")[-1]
        return info
    except Exception as e:
        return {"service": service, "status": "error", "error": str(e)}

@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "VPN Key Agent", "version": __version__, "status": "running", "websocket_enabled": bool(CENTRAL_MANAGER_URL)})

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
    return jsonify({"restarted": [r["service"] for r in results if r.get("success")], "failed": [r["service"] for r in results if not r.get("success")]})

@app.route("/info", methods=["GET"])
@require_token
def server_info():
    return jsonify(get_server_metrics())

@app.route("/connections", methods=["GET"])
@require_token
def get_connections():
    """Get current active connections."""
    return jsonify({
        "total": tracker.get_active_count(),
        "by_protocol": tracker.get_active_by_protocol(),
    })

@app.route("/events", methods=["GET"])
@require_token
def get_pending_events():
    """Get and clear pending connection events (for HTTP polling fallback)."""
    events = tracker.get_pending_events()
    return jsonify({
        "count": len(events),
        "events": [e.to_dict() for e in events],
    })

# ==================== WebSocket Mode ====================

async def websocket_loop():
    """Main WebSocket loop - connects to Central Manager and sends events."""
    import aiohttp
    
    if not CENTRAL_MANAGER_URL or not SERVER_ID:
        logger.warning("WebSocket mode disabled: CENTRAL_MANAGER_URL or VPN_SERVER_ID not set")
        return
    
    logger.info(f"Starting WebSocket mode: connecting to {CENTRAL_MANAGER_URL}")
    
    while True:
        try:
            # Build WebSocket URL
            ws_url = f"{CENTRAL_MANAGER_URL}/{SERVER_ID}?token={API_TOKEN}"
            
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url, heartbeat=20) as ws:
                    logger.info("Connected to Central Manager")
                    
                    # Send handshake
                    await ws.send_json({"agent_version": __version__, "server_id": SERVER_ID})
                    
                    # Wait for welcome
                    msg = await ws.receive_json()
                    if msg.get("type") == "welcome":
                        logger.info(f"Registered as: {msg.get('server_name')}")
                    
                    # Main loop
                    last_heartbeat = time.time()
                    last_scan = time.time()
                    
                    while True:
                        now = time.time()
                        
                        # Scan logs every 5 seconds
                        if now - last_scan >= 5:
                            tracker.scan_all()
                            last_scan = now
                            
                            # Send pending events
                            events = tracker.get_pending_events()
                            if events:
                                await ws.send_json({
                                    "type": "events",
                                    "events": [e.to_dict() for e in events],
                                })
                        
                        # Send heartbeat every 30 seconds
                        if now - last_heartbeat >= 30:
                            metrics = get_server_metrics()
                            await ws.send_json({
                                "type": "heartbeat",
                                "agent_version": __version__,
                                **metrics,
                            })
                            last_heartbeat = now
                        
                        # Check for incoming commands
                        try:
                            msg = await asyncio.wait_for(ws.receive_json(), timeout=1)
                            if msg.get("type") == "command":
                                command = msg.get("command")
                                data = msg.get("data", {})
                                result = handle_command(command, data)
                                # Send response
                                await ws.send_json({
                                    "type": "command_result",
                                    "command": command,
                                    "result": result,
                                })
                        except asyncio.TimeoutError:
                            pass
                        except Exception as e:
                            if "close" in str(e).lower():
                                raise
                            
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            logger.info("Reconnecting in 10 seconds...")
            await asyncio.sleep(10)


def run_websocket_in_thread():
    """Run WebSocket loop in separate thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(websocket_loop())
    except Exception as e:
        logger.error(f"WebSocket thread error: {e}")


# ==================== Main ====================

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8080
    websocket_mode = "--websocket" in sys.argv or bool(CENTRAL_MANAGER_URL)
    
    if not API_TOKEN:
        print("WARNING: VPN_AGENT_TOKEN not set!")
    
    print(f"VPN Key Agent v{__version__} starting on port {port}")
    print(f"WebSocket mode: {'enabled' if websocket_mode else 'disabled'}")
    print(f"IP blocking: enabled (iptables chain: {IPBlocker.CHAIN_NAME})")
    
    if websocket_mode:
        # Start WebSocket in background thread
        ws_thread = threading.Thread(target=run_websocket_in_thread, daemon=True)
        ws_thread.start()
        logger.info("WebSocket thread started")
    
    # Start Flask HTTP server (for key management commands)
    app.run(host="0.0.0.0", port=port, threaded=True)
