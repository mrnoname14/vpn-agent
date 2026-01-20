#!/usr/bin/env python3
"""
VPN Health Agent v1.3.0
Lightweight HTTP service monitor for VPN servers.

Endpoints:
  GET  /              - basic info (no auth)
  GET  /health        - status of all VPN services
  GET  /health/{svc}  - status of specific service
  POST /restart/{svc} - restart a service
  POST /restart-all   - restart all stopped services
  GET  /info          - server info (uptime, load, memory, disk)
"""

import subprocess
import os
import sys
import time
from functools import wraps
from flask import Flask, jsonify, request

__version__ = "1.3.0"

app = Flask(__name__)

API_TOKEN = os.environ.get("VPN_AGENT_TOKEN", "")

VPN_SERVICES = [
    "hysteria",
    "tuic",
    "xray",
    "shadowsocks",
    "wg-quick@wg0",
    "AdGuardHome",
]


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


def restart_service(service: str) -> dict:
    try:
        result = subprocess.run(
            ["systemctl", "restart", service],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return {"service": service, "success": False, "error": result.stderr.strip() or "Restart failed"}
        
        time.sleep(2)
        status = get_service_status(service)
        return {"service": service, "success": status["status"] == "active", "status": status["status"]}
    except subprocess.TimeoutExpired:
        return {"service": service, "success": False, "error": "Restart timed out"}
    except Exception as e:
        return {"service": service, "success": False, "error": str(e)}


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "VPN Health Agent", "version": __version__, "status": "running"})


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
    result = restart_service(service)
    return jsonify(result), 200 if result.get("success") else 500


@app.route("/restart-all", methods=["POST"])
@require_token
def restart_all():
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
    info = {"version": __version__}
    try:
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


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    if not API_TOKEN:
        print("WARNING: VPN_AGENT_TOKEN not set!")
    app.run(host="0.0.0.0", port=port, threaded=True)
