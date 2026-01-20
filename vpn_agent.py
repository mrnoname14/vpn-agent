#!/usr/bin/env python3
"""
VPN Health Agent v1.2.1
Lightweight HTTP service monitor for VPN servers.

Runs on each VPN server, provides health API and restart capabilities.
Install: curl -sSL https://raw.githubusercontent.com/mrnoname14/vpn-agent/main/install.sh | bash -s YOUR_TOKEN

Endpoints:
  GET  /              - basic info (no auth)
  GET  /health        - status of all VPN services
  GET  /health/{svc}  - status of specific service
  POST /restart/{svc} - restart a service
  POST /restart-all   - restart all stopped services
  GET  /info          - server info (uptime, load, memory, disk)
  POST /update        - self-update from GitHub
"""

import subprocess
import os
import sys
import time
import threading
from functools import wraps
from flask import Flask, jsonify, request

__version__ = "1.2.1"

app = Flask(__name__)

# Security token from environment
API_TOKEN = os.environ.get("VPN_AGENT_TOKEN", "")

# VPN services to monitor
VPN_SERVICES = [
    "hysteria",
    "tuic",
    "xray",
    "shadowsocks",
    "wg-quick@wg0",
    "AdGuardHome",
]

# GitHub raw URL for self-update
GITHUB_RAW_URL = os.environ.get(
    "VPN_AGENT_UPDATE_URL",
    "https://raw.githubusercontent.com/mrnoname14/vpn-agent/main/vpn_agent.py"
)


def require_token(f):
    """Token authentication decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_TOKEN:
            return jsonify({"error": "Agent not configured (no token)"}), 503
        
        token = request.headers.get("X-Agent-Token", "")
        if token != API_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def get_service_status(service: str) -> dict:
    """Get status of a systemd service."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=5
        )
        status = result.stdout.strip()
        info = {"service": service, "status": status}
        
        if status == "active":
            # Uptime
            result = subprocess.run(
                ["systemctl", "show", service, "--property=ActiveEnterTimestamp"],
                capture_output=True,
                text=True,
                timeout=5
            )
            info["since"] = result.stdout.strip().split("=")[-1]
            
            # Memory
            result = subprocess.run(
                ["systemctl", "show", service, "--property=MemoryCurrent"],
                capture_output=True,
                text=True,
                timeout=5
            )
            mem = result.stdout.strip().split("=")[-1]
            if mem and mem not in ["[not set]", ""]:
                try:
                    info["memory_mb"] = round(int(mem) / 1024 / 1024, 1)
                except (ValueError, TypeError):
                    pass
        
        return info
        
    except subprocess.TimeoutExpired:
        return {"service": service, "status": "timeout", "error": "Command timed out"}
    except Exception as e:
        return {"service": service, "status": "error", "error": str(e)}


def restart_service(service: str) -> dict:
    """Restart a systemd service."""
    try:
        result = subprocess.run(
            ["systemctl", "restart", service],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return {
                "service": service,
                "success": False,
                "error": result.stderr.strip() or "Restart failed"
            }
        
        time.sleep(2)
        status = get_service_status(service)
        
        return {
            "service": service,
            "success": status["status"] == "active",
            "status": status["status"],
        }
        
    except subprocess.TimeoutExpired:
        return {"service": service, "success": False, "error": "Restart timed out"}
    except Exception as e:
        return {"service": service, "success": False, "error": str(e)}


def delayed_restart():
    """Restart agent after delay (runs in background thread)."""
    time.sleep(2)
    subprocess.run(["systemctl", "restart", "vpn-agent"])


@app.route("/", methods=["GET"])
def index():
    """Basic info (no auth)."""
    return jsonify({
        "service": "VPN Health Agent",
        "version": __version__,
        "status": "running",
    })


@app.route("/health", methods=["GET"])
@require_token
def health_all():
    """Get status of all VPN services."""
    services = {}
    all_healthy = True
    
    for svc in VPN_SERVICES:
        status = get_service_status(svc)
        services[svc] = status
        if status["status"] != "active":
            all_healthy = False
    
    return jsonify({
        "healthy": all_healthy,
        "services": services,
        "timestamp": int(time.time()),
    })


@app.route("/health/<service>", methods=["GET"])
@require_token
def health_service(service: str):
    """Get status of specific service."""
    if service not in VPN_SERVICES:
        return jsonify({"error": f"Unknown service: {service}"}), 404
    return jsonify(get_service_status(service))


@app.route("/restart/<service>", methods=["POST"])
@require_token
def restart(service: str):
    """Restart a service."""
    if service not in VPN_SERVICES:
        return jsonify({"error": f"Unknown service: {service}"}), 404
    
    result = restart_service(service)
    return jsonify(result), 200 if result.get("success") else 500


@app.route("/restart-all", methods=["POST"])
@require_token
def restart_all():
    """Restart all stopped services."""
    results = []
    
    for svc in VPN_SERVICES:
        status = get_service_status(svc)
        if status["status"] != "active":
            results.append(restart_service(svc))
    
    return jsonify({
        "restarted": [r["service"] for r in results if r.get("success")],
        "failed": [r["service"] for r in results if not r.get("success")],
        "details": results,
    })


@app.route("/info", methods=["GET"])
@require_token
def server_info():
    """Get server info."""
    info = {"version": __version__}
    
    try:
        # Uptime
        with open("/proc/uptime") as f:
            info["uptime_hours"] = round(float(f.read().split()[0]) / 3600, 1)
        
        # Load
        with open("/proc/loadavg") as f:
            info["load_avg"] = [float(x) for x in f.read().split()[:3]]
        
        # Memory
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
        
        # Disk
        result = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            parts = result.stdout.strip().split("\n")[1].split()
            info["disk_total"] = parts[1]
            info["disk_used"] = parts[2]
            info["disk_percent"] = parts[4]
        
    except Exception as e:
        info["error"] = str(e)
    
    return jsonify(info)


@app.route("/update", methods=["POST"])
@require_token
def self_update():
    """Self-update from GitHub."""
    try:
        # Download new version
        result = subprocess.run(
            ["curl", "-sSL", "-o", "/tmp/vpn_agent_new.py", GITHUB_RAW_URL],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return jsonify({"success": False, "error": f"Download failed: {result.stderr}"}), 500
        
        # Verify it's valid Python
        result = subprocess.run(
            ["python3", "-m", "py_compile", "/tmp/vpn_agent_new.py"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return jsonify({"success": False, "error": "Invalid Python file"}), 500
        
        # Replace file
        subprocess.run(["cp", "/tmp/vpn_agent_new.py", "/opt/vpn_agent.py"], check=True)
        
        # Restart in background after delay (so we can return response)
        thread = threading.Thread(target=delayed_restart)
        thread.daemon = True
        thread.start()
        
        return jsonify({"success": True, "message": "Update complete, agent restarting in 2 seconds..."})
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    
    if not API_TOKEN:
        print("WARNING: VPN_AGENT_TOKEN not set! Agent will reject all authenticated requests.")
    
    app.run(host="0.0.0.0", port=port, threaded=True)
