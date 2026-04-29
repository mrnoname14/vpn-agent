#!/usr/bin/env python3
"""
VPN Key Agent v4.5.2
Extended VPN Health Agent with key management for multi-user support.

v4.5.2 Changes (Session 19 hotfix #2 — heal partial drift):
  - add_vless_key(): 409 "already exists" only when UUID is in ALL VLESS
    inbounds. If UUID is in vless-in but missing from vless-vision-in
    (or vice versa), agent now ADDs the UUID to the missing inbound
    instead of refusing with 409. Inherited bug from v4.4.4 made the
    drift_monitor unable to heal partial drift through the agent —
    it kept getting 409 even when the secondary inbound was missing
    the UUID.
  - delete_vless_key() unaffected (already iterates all inbounds).

v4.5.1 Changes (Session 19 hotfix — xray gRPC adu storm fix):
  - xray_sync_config_to_live(): added idempotent guard via `xray api lsi`.
    Before: every /reload re-issued `adu` for every UUID, even ones already
    in xray runtime. Repeated adu of same UUID can drive xray-core 26.3.27
    internal user index into an inconsistent state — handshake validation
    starts behaving randomly, both VLESS channels stop accepting their
    legitimate users until the xray process is restarted.
    Now: lsi snapshot first, adu only for UUIDs not already in runtime.
    Drops typical /reload from O(N_users) gRPC writes to O(0) on a healthy
    server, removes the storm pattern entirely.
  - Same guard applies to both vless-in (xray-vless on :10085) and
    vless-vision-in (xray-vision on :10086) in split layout.

v4.5.0 Changes (Session 19 — split xray layout):
  - Added support for two independent xray processes:
      xray-vless.service   /etc/xray-vless/config.json    127.0.0.1:10085
      xray-vision.service  /etc/xray-vision/config.json   127.0.0.1:10086
    Each VLESS inbound (vless-in / vless-vision-in) now lives in its own
    xray process — restart of one no longer drops the other channel.
  - Layout detection: `systemctl is-active xray-vless` (5s cache).
    Active → split layout. Otherwise legacy single xray.service path.
  - VLESS POST/DELETE/list iterate the tag→config/grpc binding so writes
    land in the right config and adu/rmu hits the right gRPC endpoint.
  - VPN_SERVICES, /reload, /restart/{svc}, /health are layout-aware.
  - `/restart/xray` in split layout fans out to both xray-vless and
    xray-vision (backward-compat for unmodified backend callers).
  - Legacy single-xray servers behave exactly as before — no changes
    needed on the 10 servers we haven't migrated yet.

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
  GET    /check-ipv4          - Check IPv4/IPv6 configuration

Original Endpoints (from v1.3):
  GET  /              - basic info (no auth)
  GET  /health        - status of all VPN services
  GET  /health/{svc}  - status of specific service
  POST /restart/{svc} - restart a service
  POST /restart-all   - restart all stopped services
  GET  /info          - server info (uptime, load, memory, disk)


v4.4.3 Changes:
  - DEL-sync: DELETE /keys/vless?no_restart=true now queues the UUID in
    /var/lib/vpn-agent/pending_xray_rmu.json; /reload (xray) consumes the
    queue via gRPC rmu. Previously the UUID was removed from config.json
    but stayed alive in the xray process until the next full restart —
    revoked/migrated clients kept working until then. Two-way sync now.
  - xray_sync_config_to_live() does ADD-sync + DEL-sync in one pass.
  - Requires xray config with api+StatsService for future phase-2 work
    (inactive-user alerts), but StatsService is NOT needed for v4.4.3.

v4.4.2 Changes:
  - /reload (xray) now calls xray_sync_config_to_live() which uses gRPC
    AddUser for every VLESS client in config.json. Fixes phantom-users
    from the prior no_restart=True + /reload-noop combination.

v4.4.0 Changes:
  - Xray gRPC API for zero-downtime user management (no more systemctl restart for VLESS!)
  - add_vless_key() uses xray api adu (add user to inbound via gRPC) - 0 sec downtime
  - delete_vless_key() uses xray api rmu (remove user from inbound via gRPC) - 0 sec downtime
  - /reload endpoint: xray handled via grpc-api-noop (keys already added/removed inline)
  - Config file still updated as backup (survives xray restart/reboot)
  - Fallback: if gRPC API fails, falls back to systemctl restart
  - Requires: api section + tag "vless-in" in xray config.json + port 10085 on localhost

v4.2.3 Changes:
  - Removed AdGuardHome from VPN_SERVICES health check (AdGuard removed from all servers)
  - Phase 2.97: AdGuard caused 3-7s delays on YouTube/Instagram, DNS now direct

v4.2.2 Changes:
  - IPv4 check: replaced curl https://google.com with ping -4 1.1.1.1
  - Fixes false IPv4 alerts caused by AdGuard DoH cold-start DNS latency
  - ping tests raw IPv4 connectivity without DNS dependency (5ms vs 3-5sec)

v4.2.1 Changes:
  - Removed shadowsocks from VPN_SERVICES health check (service stopped intentionally, DPI risk)
  - SS keys/config endpoints still work — only monitoring disabled

v4.2.0 Changes:
  - SS 2022 support: user passwords now generated as base64(16 bytes) for AEAD-2022 ciphers
  - Required for 2022-blake3-aes-128-gcm multi-user mode (EIH)
  - No change to API interface — same name/password fields

v4.1.3 Changes:
  - CPU metrics: rolling 60-second average instead of 0.5s instant sample
  - Background thread samples /proc/stat every 5s, /info returns smooth average
  - Fixes spiky CPU readings in admin panel (7% → 70% → 7%)

v4.3.0 Changes:
  - CRITICAL FIX: Xray does NOT support SIGHUP — it kills the process silently!
  - SIGHUP was sending kill signal to xray since v3.9.8, causing 3-5 min VLESS outages
  - With Restart=on-failure in systemd, xray stayed dead until next key operation
  - FIX: Removed xray (and shadowsocks) from SIGHUP_SUPPORTED → uses systemctl restart
  - FIX: install.sh now sets Restart=always for xray systemd service
  - Result: VLESS restarts cleanly in 2-3 sec instead of dying for 3-5 minutes

v4.1.2 Changes:
  - Added GET /check-ipv4 endpoint: checks gai.conf, sysctl IPv6, and IPv4 connectivity
  - Used by health monitoring to detect IPv6 misconfigurations that break Hysteria2/TUIC

v4.1.1 Changes:
  - Hysteria2 debounce delay increased: 30s → 120s (2 min) to reduce restart frequency
  - Expected result: ~15 restarts/day → 3-5 restarts/day

v4.1.0 Changes:
  - Hysteria2 debounce restart: same as TUIC — config written immediately, ONE restart after 30s
  - REMOVED hysteria/hysteria-d2 from SIGHUP_SUPPORTED (SIGHUP kills Hysteria2 process!)
  - /reload endpoint: hysteria/hysteria-d2 now use debounce instead of SIGHUP
  - Result: 43 restarts/day → 2-5 restarts/day, zero connection drops during key ops

v4.0.0 Changes:
  - TUIC debounce restart: config changes are batched, restart fires 30s after last change
  - Result: 200 key ops/day = 1-2 TUIC restarts instead of 200
  - New users get TUIC within 30s max; existing users lose connection only on restart
  - /reload endpoint: tuic/tuic-d2 now use debounce instead of immediate restart

v3.9.9 Changes:
  - SIGHUP hot reload for shadowsocks and hysteria2 (in addition to xray)
  - hot_reload_service(service) — universal SIGHUP for all supported services
  - /reload endpoint now uses SIGHUP for xray, shadowsocks, hysteria, hysteria-d2
  - TUIC still uses systemctl restart (no SIGHUP support)
  - Result: adding/removing keys causes ZERO connection drops for existing users

v3.9.8 Changes:
  - Added no_restart flag to all /keys/* endpoints (POST body or GET query param)
  - Added POST /reload endpoint for batch reload after multiple key operations
  - hot_reload_xray() uses SIGHUP instead of systemctl restart (no connection drops)
  - Fixes 10-min VPN outage caused by parallel key ops each triggering full restart

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
import threading
from functools import wraps
from flask import Flask, jsonify, request

__version__ = "4.5.2"

app = Flask(__name__)

API_TOKEN = os.environ.get("VPN_AGENT_TOKEN", "")

# Config paths
XRAY_CONFIG = "/usr/local/etc/xray/config.json"

# Xray gRPC API address (localhost only, configured in xray config.json api section)
XRAY_GRPC_ADDR = "127.0.0.1:10085"
XRAY_INBOUND_TAG = "vless-in"

# v4.4.4 — multi-VLESS-inbound support.
#
# Servers running Session 17 architecture have TWO VLESS inbounds:
#   - "vless-in"        → XHTTP transport on main IP (channel №1)
#   - "vless-vision-in" → Vision transport on reserved IP (channel №2)
#
# The agent iterates all known tags so a new user is added to BOTH inbounds,
# and a deleted user is removed from BOTH. Backwards compatible: if a server
# has only the legacy "vless-in" inbound, the second iteration is a no-op.
#
# Flow semantics differ per transport:
#   - XHTTP+Reality (vless-in)        → flow = ""
#   - TCP+Reality+Vision (vless-vision-in) → flow = "xtls-rprx-vision"
# We honor the caller-provided flow for vless-in (allows legacy callers to
# still request specific flow) and force xtls-rprx-vision for Vision inbound.
XRAY_INBOUND_TAGS = ["vless-in", "vless-vision-in"]
INBOUND_FLOW_OVERRIDE = {
    "vless-vision-in": "xtls-rprx-vision",
}

# v4.5.0 — split-xray layout detection.
#
# Split layout: two independent xray processes, one per VLESS inbound.
#   vless-in        → xray-vless.service   /etc/xray-vless/config.json    127.0.0.1:10085
#   vless-vision-in → xray-vision.service  /etc/xray-vision/config.json   127.0.0.1:10086
#
# Single layout (legacy): one xray.service with both inbounds in one config.
#   vless-in, vless-vision-in → /usr/local/etc/xray/config.json  127.0.0.1:10085
#
# Detection runs `systemctl is-active xray-vless` and caches the answer
# briefly — every gRPC call hits this path, so we don't want to fork
# systemctl on every request, and we don't want to cache for so long
# that a freshly-migrated server takes minutes for the agent to notice.
_LAYOUT_CACHE = {"value": None, "ts": 0.0}
_LAYOUT_CACHE_TTL_SEC = 5.0

XRAY_SPLIT_VLESS_CONFIG = "/etc/xray-vless/config.json"
XRAY_SPLIT_VISION_CONFIG = "/etc/xray-vision/config.json"
XRAY_SPLIT_VLESS_GRPC = "127.0.0.1:10085"
XRAY_SPLIT_VISION_GRPC = "127.0.0.1:10086"
XRAY_SPLIT_VLESS_SERVICE = "xray-vless"
XRAY_SPLIT_VISION_SERVICE = "xray-vision"

# (config_path, grpc_addr, service_name) per tag, valid only in split layout.
_TAG_BINDING_SPLIT = {
    "vless-in": (XRAY_SPLIT_VLESS_CONFIG, XRAY_SPLIT_VLESS_GRPC, XRAY_SPLIT_VLESS_SERVICE),
    "vless-vision-in": (XRAY_SPLIT_VISION_CONFIG, XRAY_SPLIT_VISION_GRPC, XRAY_SPLIT_VISION_SERVICE),
}


def xray_layout() -> str:
    """Return 'split' if xray-vless.service is active, else 'single'.

    Cached briefly to avoid per-request systemctl forks while still
    picking up a layout change quickly after migration.
    """
    now = time.time()
    if _LAYOUT_CACHE["value"] and now - _LAYOUT_CACHE["ts"] < _LAYOUT_CACHE_TTL_SEC:
        return _LAYOUT_CACHE["value"]
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "xray-vless"],
            capture_output=True, text=True, timeout=3,
        )
        layout = "split" if r.stdout.strip() == "active" else "single"
    except Exception:
        layout = "single"
    _LAYOUT_CACHE["value"] = layout
    _LAYOUT_CACHE["ts"] = now
    return layout


def _binding_for_tag(tag: str) -> tuple:
    """(config_path, grpc_addr, service_name) for an inbound tag."""
    if xray_layout() == "split" and tag in _TAG_BINDING_SPLIT:
        return _TAG_BINDING_SPLIT[tag]
    return (XRAY_CONFIG, XRAY_GRPC_ADDR, "xray")


def xray_config_paths() -> list:
    """All xray config files in current layout (in tag order)."""
    if xray_layout() == "split":
        return [XRAY_SPLIT_VLESS_CONFIG, XRAY_SPLIT_VISION_CONFIG]
    return [XRAY_CONFIG]


def xray_services_for_layout() -> list:
    """Services that systemd manages for xray in current layout."""
    if xray_layout() == "split":
        return [XRAY_SPLIT_VLESS_SERVICE, XRAY_SPLIT_VISION_SERVICE]
    return ["xray"]


def _iter_vless_locations() -> list:
    """Yield (config_path, inbound_dict, grpc_addr, service_name) for every
    VLESS inbound in current layout — abstracts single-vs-split for callers
    that need to read or mutate every VLESS inbound."""
    out = []
    for path in xray_config_paths():
        try:
            cfg = read_json_config(path)
        except Exception as e:
            app.logger.warning(f"[XRAY-CFG] read failed {path}: {e}")
            continue
        for inb in cfg.get("inbounds", []):
            if inb.get("protocol") != "vless":
                continue
            tag = inb.get("tag", "vless-in")
            _cfg, grpc_addr, svc = _binding_for_tag(tag)
            out.append((path, inb, grpc_addr, svc))
    return out


def _flow_for_inbound(tag: str, requested_flow: str) -> str:
    """Resolve VLESS flow for a given inbound tag.

    Vision inbound *requires* xtls-rprx-vision regardless of caller intent.
    XHTTP inbound uses the caller's requested flow (default empty)."""
    return INBOUND_FLOW_OVERRIDE.get(tag, requested_flow)


def _list_vless_inbound_tags(config: dict) -> list:
    """Return tags of all VLESS inbounds present in config.json, in order.

    Filters XRAY_INBOUND_TAGS by what's actually configured. Legacy servers
    with only vless-in get [vless-in]; Session 17 servers get both."""
    present = []
    for inbound in config.get("inbounds", []):
        if inbound.get("protocol") != "vless":
            continue
        tag = inbound.get("tag")
        if tag and tag not in present:
            present.append(tag)
    # Preserve XRAY_INBOUND_TAGS order for known tags; append unknown ones at end
    ordered = [t for t in XRAY_INBOUND_TAGS if t in present]
    extras = [t for t in present if t not in XRAY_INBOUND_TAGS]
    return ordered + extras

# Persistent file tracking UUIDs that were removed from config.json
# via DELETE /keys/vless with no_restart=true but not yet removed from
# the live xray process via gRPC rmu. Processed on /reload (xray).
# See xray_sync_config_to_live() for details. v4.4.3+.
XRAY_PENDING_RMU_FILE = "/var/lib/vpn-agent/pending_xray_rmu.json"

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

_VPN_SERVICES_BASE = [
    "hysteria",
    "hysteria-d2",
    "tuic",
    "tuic-d2",
    # "shadowsocks",  # Disabled: SS stopped intentionally (DPI risk 6/10)
    # "AdGuardHome",  # Removed Phase 2.97: caused 3-7s delays on YouTube/Instagram
]


def vpn_services() -> list:
    """List of services to health-check / restart-all on this server.

    v4.5.0 — xray entry depends on layout: split layout reports both
    xray-vless and xray-vision so /health surfaces them independently;
    single layout reports legacy `xray`.
    """
    return _VPN_SERVICES_BASE + xray_services_for_layout()

# ==================== TUIC DEBOUNCE RESTART ====================
# TUIC does not support SIGHUP, so we batch config changes and
# restart once after 30s of inactivity instead of on every key op.
# This means 200 migrations/day = 1-2 restarts instead of 200.

TUIC_DEBOUNCE_DELAY = 30  # seconds

# {service_name: threading.Timer}
_tuic_timers: dict = {}
_tuic_timers_lock = threading.Lock()


def _do_tuic_restart(service: str):
    """Actually restart TUIC. Called by debounce timer."""
    with _tuic_timers_lock:
        _tuic_timers.pop(service, None)
    app.logger.warning(f"[TUIC-DEBOUNCE] Restarting {service} after debounce delay")
    result = restart_service_sync(service)
    app.logger.warning(f"[TUIC-DEBOUNCE] {service} restart result: {result}")


def schedule_tuic_restart(service: str):
    """
    Schedule a debounced restart for a TUIC service.
    If called multiple times within TUIC_DEBOUNCE_DELAY seconds,
    only ONE restart fires — 30s after the LAST call.
    """
    with _tuic_timers_lock:
        # Cancel existing timer if pending
        existing = _tuic_timers.get(service)
        if existing:
            existing.cancel()
            app.logger.info(f"[TUIC-DEBOUNCE] Reset timer for {service}")

        # Schedule new restart
        timer = threading.Timer(TUIC_DEBOUNCE_DELAY, _do_tuic_restart, args=[service])
        timer.daemon = True
        timer.start()
        _tuic_timers[service] = timer
        app.logger.info(f"[TUIC-DEBOUNCE] Scheduled restart for {service} in {TUIC_DEBOUNCE_DELAY}s")


# ==================== END TUIC DEBOUNCE ====================


# ==================== HYSTERIA DEBOUNCE RESTART ====================
# Hysteria2 does NOT support SIGHUP — the process dies on HUP signal.
# Same debounce approach as TUIC: write config immediately, restart
# once after 30s of inactivity. 43 restarts/day → 2-5 restarts/day.

HYSTERIA_DEBOUNCE_DELAY = 120  # seconds (2 min)

_hysteria_timers: dict = {}
_hysteria_timers_lock = threading.Lock()


def _do_hysteria_restart(service: str):
    """Actually restart Hysteria. Called by debounce timer."""
    with _hysteria_timers_lock:
        _hysteria_timers.pop(service, None)
    app.logger.warning(f"[HYSTERIA-DEBOUNCE] Restarting {service} after debounce delay")
    result = restart_service_sync(service)
    app.logger.warning(f"[HYSTERIA-DEBOUNCE] {service} restart result: {result}")


def schedule_hysteria_restart(service: str):
    """
    Schedule a debounced restart for a Hysteria service.
    If called multiple times within HYSTERIA_DEBOUNCE_DELAY seconds,
    only ONE restart fires — 30s after the LAST call.
    """
    with _hysteria_timers_lock:
        existing = _hysteria_timers.get(service)
        if existing:
            existing.cancel()
            app.logger.info(f"[HYSTERIA-DEBOUNCE] Reset timer for {service}")

        timer = threading.Timer(HYSTERIA_DEBOUNCE_DELAY, _do_hysteria_restart, args=[service])
        timer.daemon = True
        timer.start()
        _hysteria_timers[service] = timer
        app.logger.info(f"[HYSTERIA-DEBOUNCE] Scheduled restart for {service} in {HYSTERIA_DEBOUNCE_DELAY}s")


# ==================== END HYSTERIA DEBOUNCE ====================

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
    """Restart a service and return status.

    v4.5.0 — when the caller asks to restart legacy `xray` on a split-layout
    server we fan out to both xray-vless and xray-vision sequentially.
    Sequential (not parallel) so the brief SO_REUSEPORT-less downtime is
    isolated to one channel at a time. Backend code that still says
    `xray` keeps working.
    """
    if service == "xray" and xray_layout() == "split":
        results = {}
        for svc in (XRAY_SPLIT_VLESS_SERVICE, XRAY_SPLIT_VISION_SERVICE):
            results[svc] = restart_service_sync(svc, timeout=timeout)
        all_ok = all(r.get("success") for r in results.values())
        return {
            "success": all_ok,
            "method": "split-fanout",
            "services": results,
        }

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


# Services that support SIGHUP hot reload (no connection drops)
# v4.3.0: EMPTIED — xray dies on SIGHUP (verified 2026-04-07), shadowsocks removed from stack
SIGHUP_SUPPORTED = set()

# Systemd service name → process name for pkill
SERVICE_PROCESS_MAP = {
    "xray": "xray",
    "shadowsocks": "ssserver",
    "hysteria": "hysteria",
    "hysteria-d2": "hysteria",
}


def hot_reload_service(service: str) -> dict:
    """
    Hot reload a service via SIGHUP — no connection drops, no restart.
    Existing tunnels stay alive, new config applied instantly.
    Falls back to full restart only if SIGHUP fails.
    Supported: xray, shadowsocks, hysteria, hysteria-d2.
    """
    process_name = SERVICE_PROCESS_MAP.get(service)
    if not process_name:
        # Not in map — use full restart
        return restart_service_sync(service)
    
    try:
        result = subprocess.run(
            ["pkill", "-HUP", "-x", process_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            time.sleep(0.3)
            check = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=5
            )
            if check.stdout.strip() == "active":
                return {"success": True, "method": "sighup"}
        # SIGHUP failed — fall back to full restart
        return restart_service_sync(service)
    except Exception as e:
        return restart_service_sync(service)


def hot_reload_xray() -> dict:
    """Hot reload xray (backward compat)."""
    return hot_reload_service("xray")


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



def _xray_api_lsi_uuids(grpc_addr: str, tag: str) -> tuple:
    """v4.5.1 — return (uuids_set, ok_flag) of UUIDs currently in xray runtime
    for the given inbound tag at the given gRPC endpoint.

    `xray api lsi` returns the live inbound table (config-loaded clients
    + runtime-added clients via gRPC adu — both sources unified). We use
    this set as an idempotent guard before issuing adu in sync paths:
    if the UUID is already there, skip the adu entirely. This stops the
    "adu storm" pattern that was driving xray-core 26.3.27 user index
    into inconsistent state on /reload.

    Returns ({set of uuid strings}, True) on success, (empty set, False)
    on any error so callers can choose to fall back to unconditional adu.
    """
    try:
        result = subprocess.run(
            ["xray", "api", "lsi", "-s", grpc_addr],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode != 0:
            return (set(), False)
        data = json.loads(result.stdout)
        uuids = set()
        for inb in data.get("inbounds", []):
            if inb.get("tag") != tag:
                continue
            clients = inb.get("proxySettings", {}).get("clients", [])
            for cl in clients:
                uid = (cl.get("account") or {}).get("id")
                if uid:
                    uuids.add(uid)
        return (uuids, True)
    except Exception as e:
        app.logger.warning(f"[XRAY-SYNC] lsi failed for {tag}@{grpc_addr}: {e}")
        return (set(), False)


def _xray_api_adu_to_tag(client_uuid: str, tag: str, flow: str) -> dict:
    """Internal: gRPC adu for a SPECIFIC inbound tag. Returns ok/already/error.

    Idempotent: 'already exists' is treated as success (user already present).
    v4.5.0 — gRPC address is resolved per tag via _binding_for_tag, so split
    layout sends vless-vision-in to :10086 instead of :10085.
    """
    email = f"{client_uuid}@vless"
    _cfg_path, grpc_addr, _svc = _binding_for_tag(tag)
    add_json = json.dumps({
        "inbounds": [{
            "tag": tag,
            "protocol": "vless",
            "port": 1,
            "settings": {
                "clients": [{"id": client_uuid, "email": email, "flow": flow, "level": 0}],
                "decryption": "none"
            }
        }]
    })
    tmp_path = f"/tmp/xray_adu_{client_uuid[:8]}_{tag}.json"
    try:
        with open(tmp_path, "w") as f:
            f.write(add_json)
        result = subprocess.run(
            ["xray", "api", "adu", "-s", grpc_addr, tmp_path],
            capture_output=True, text=True, timeout=5
        )
        out = (result.stdout + result.stderr).lower()
        if "result: ok" in out or "added 1" in out:
            return {"success": True, "tag": tag, "state": "added"}
        if "already exists" in out:
            return {"success": True, "tag": tag, "state": "already_exists"}
        return {"success": False, "tag": tag, "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "tag": tag, "error": str(e)}
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def xray_api_add_user(client_uuid: str, flow: str = "") -> dict:
    """Add VLESS user via xray gRPC API to ALL configured VLESS inbounds.

    v4.4.4 — multi-inbound: iterates over all VLESS inbound tags present in
    config.json and adds the user to each via gRPC `adu`. Per-inbound flow is
    resolved by `_flow_for_inbound` (Vision inbounds force xtls-rprx-vision
    regardless of caller intent; XHTTP inbounds use caller's `flow`).

    Returns success=True only if at least the PRIMARY inbound (first tag)
    succeeded. Per-inbound results are surfaced in `details` for observability.
    Falls back to xray restart if PRIMARY add fails (preserves v4.4.3 semantics).

    Default flow is empty string — required for XHTTP+Reality.
    v4.5.0 — discovers VLESS inbounds across all xray configs in current
    layout (one in single, two in split), so users get added to both
    channels regardless of which xray process owns each.
    """
    locations = _iter_vless_locations()
    if not locations:
        # No VLESS inbounds at all — degenerate config. Fall back to restart.
        app.logger.warning("[XRAY-GRPC] no VLESS inbounds — falling back to restart")
        return restart_service_sync("xray")

    # Build ordered tag list (preserve XRAY_INBOUND_TAGS order so vless-in
    # is always primary). _iter_vless_locations already deduplicates per
    # (config, inbound) pair.
    seen = set()
    tags = []
    for _path, inb, _grpc, _svc in locations:
        t = inb.get("tag", "vless-in")
        if t in seen:
            continue
        seen.add(t)
        tags.append(t)
    tags = [t for t in XRAY_INBOUND_TAGS if t in tags] + \
           [t for t in tags if t not in XRAY_INBOUND_TAGS]

    details = []
    primary_ok = False
    for idx, tag in enumerate(tags):
        per_tag_flow = _flow_for_inbound(tag, flow)
        res = _xray_api_adu_to_tag(client_uuid, tag, per_tag_flow)
        details.append(res)
        if idx == 0:
            primary_ok = res.get("success", False)

    if primary_ok:
        added_to = [d["tag"] for d in details if d.get("success")]
        app.logger.info(
            f"[XRAY-GRPC] Added user {client_uuid[:8]}... to {added_to}"
        )
        return {"success": True, "method": "grpc-api", "details": details}

    # Primary failed — log and fall back to restart of the primary's service.
    primary_tag = tags[0]
    _cfg, _grpc, primary_service = _binding_for_tag(primary_tag)
    app.logger.warning(
        f"[XRAY-GRPC] adu to primary tag '{primary_tag}' failed for "
        f"{client_uuid[:8]}: {details[0]} — restarting {primary_service}"
    )
    return restart_service_sync(primary_service)


def _pending_rmu_read() -> list:
    """Read pending-rmu UUID list. Returns [] if file missing/corrupt."""
    try:
        with open(XRAY_PENDING_RMU_FILE) as f:
            data = json.load(f)
            if isinstance(data, list):
                return [u for u in data if isinstance(u, str) and u]
    except FileNotFoundError:
        return []
    except Exception as e:
        app.logger.warning(f"[XRAY-SYNC] pending_rmu read failed: {e}")
    return []


def _pending_rmu_write(uuids: list) -> None:
    """Atomically overwrite pending-rmu file."""
    try:
        os.makedirs(os.path.dirname(XRAY_PENDING_RMU_FILE), exist_ok=True)
        tmp = XRAY_PENDING_RMU_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(uuids, f)
        os.replace(tmp, XRAY_PENDING_RMU_FILE)
    except Exception as e:
        app.logger.error(f"[XRAY-SYNC] pending_rmu write failed: {e}")


def _pending_rmu_append(client_uuid: str) -> None:
    """Add one UUID to pending-rmu list (dedup)."""
    uuids = _pending_rmu_read()
    if client_uuid not in uuids:
        uuids.append(client_uuid)
        _pending_rmu_write(uuids)


def xray_sync_config_to_live() -> dict:
    """
    Two-way sync between config.json and the live xray process.

    Called from /reload after batch key operations.

    ADD-sync (v4.4.2+): ensures every VLESS client in config.json is
    present in live xray. POST /keys/vless with no_restart=True skips
    the inline adu, so without this sync the user would never reach
    live xray. Idempotent: gRPC adu returns "already exists" for
    clients already in live.

    DEL-sync (v4.4.3+): processes the pending-rmu file populated by
    DELETE /keys/vless with no_restart=true (which previously removed
    the UUID from config.json but left a phantom user in live xray,
    letting revoked/migrated clients continue working until the next
    full xray restart). On /reload we iterate the pending list and
    call gRPC rmu for each UUID; successful + "not found" results
    both clear the entry. Persisted on disk so the list survives
    agent restarts between DELETE and /reload.

    Never modifies config files. Never restarts xray.
    v4.5.0 — iterates all xray config files in current layout. In split
    layout each VLESS inbound has its own (config, gRPC endpoint) pair, so
    adu/rmu hit the right xray process automatically.
    """
    # v4.5.0 — sync each VLESS inbound INDEPENDENTLY across all configs.
    # Was: read one XRAY_CONFIG and one XRAY_GRPC_ADDR. Now: walk every
    # config returned by _iter_vless_locations() so split layout (two
    # files, two gRPC ports) is handled transparently.
    locations = _iter_vless_locations()
    # per_inbound_clients: [(tag, grpc_addr, [(uid, flow), ...])]
    per_inbound_clients = []
    for _path, inb, grpc_addr, _svc in locations:
        tag = inb.get("tag")
        if not tag:
            continue
        clients = []
        for cl in inb.get("settings", {}).get("clients", []):
            uid = cl.get("id")
            if not uid:
                continue
            # Vision forces xtls-rprx-vision; XHTTP uses whatever's in config.
            cl_flow = _flow_for_inbound(tag, cl.get("flow", ""))
            clients.append((uid, cl_flow))
        per_inbound_clients.append((tag, grpc_addr, clients))

    if not per_inbound_clients:
        app.logger.warning("[XRAY-SYNC] no VLESS inbounds discovered in any config")
        return {"success": False, "method": "sync-config-to-live",
                "error": "no VLESS inbounds"}

    total_clients_seen = sum(len(cs) for _, _, cs in per_inbound_clients)
    added = 0
    already = 0
    errors = 0
    skipped_lsi = 0  # v4.5.1 — counted separately for visibility
    for tag, grpc_addr, clients in per_inbound_clients:
        # v4.5.1 — idempotent guard: snapshot runtime UUIDs once, skip adu
        # for any UUID already present. Eliminates the "adu storm" that
        # corrupted xray-core 26.3.27 user index. If lsi fails (e.g. xray
        # restarting) fall back to unconditional adu — old behavior.
        existing_uuids, lsi_ok = _xray_api_lsi_uuids(grpc_addr, tag)
        if lsi_ok:
            app.logger.info(
                f"[XRAY-SYNC] lsi tag={tag} grpc={grpc_addr} "
                f"runtime_count={len(existing_uuids)} config_count={len(clients)}"
            )
        for uid, flow in clients:
            if lsi_ok and uid in existing_uuids:
                # Already in runtime — skip adu. Counts as "already" for
                # the response payload (backwards-compatible signal).
                already += 1
                skipped_lsi += 1
                continue
            email = f"{uid}@vless"
            add_payload = {
                "inbounds": [{
                    "tag": tag,
                    "protocol": "vless",
                    "port": 1,
                    "settings": {
                        "clients": [{"id": uid, "email": email, "flow": flow, "level": 0}],
                        "decryption": "none",
                    },
                }]
            }
            tmp_path = f"/tmp/xray_sync_{uid[:8]}_{tag}.json"
            try:
                with open(tmp_path, "w") as f:
                    f.write(json.dumps(add_payload))
                result = subprocess.run(
                    ["xray", "api", "adu", "-s", grpc_addr, tmp_path],
                    capture_output=True, text=True, timeout=5,
                )
                out = (result.stdout + result.stderr).lower()
                if "already exists" in out:
                    already += 1
                elif "result: ok" in out or "added 1" in out:
                    added += 1
                else:
                    errors += 1
                    app.logger.warning(
                        f"[XRAY-SYNC] adu failed for {uid[:8]} tag={tag} "
                        f"grpc={grpc_addr}: {result.stdout.strip()} "
                        f"{result.stderr.strip()}"
                    )
            except Exception as e:
                errors += 1
                app.logger.error(f"[XRAY-SYNC] exception for {uid[:8]} tag={tag}: {e}")
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    # ---- DEL-sync: remove phantom users from ALL VLESS inbounds ----
    # v4.5.0 — was: single XRAY_GRPC_ADDR. Now: per-tag grpc_addr so split
    # layout removes vless-vision-in users via :10086.
    # A UUID stays in `still_pending` only if AT LEAST ONE tag returned a
    # hard error (not "not found"). 'not found' on a tag is acceptable.
    sync_tags_with_addr = [(tag, grpc_addr) for tag, grpc_addr, _ in per_inbound_clients]
    pending = _pending_rmu_read()
    removed = 0
    not_in_live = 0
    rmu_errors = 0
    still_pending: list = []
    for uid in pending:
        email = f"{uid}@vless"
        per_uid_hard_error = False
        per_uid_any_removed = False
        for tag, grpc_addr in sync_tags_with_addr:
            try:
                result = subprocess.run(
                    ["xray", "api", "rmu", "-s", grpc_addr,
                     "-tag", tag, email],
                    capture_output=True, text=True, timeout=5,
                )
                out = (result.stdout + result.stderr).lower()
                if "removed 1" in out:
                    per_uid_any_removed = True
                elif "not found" in out:
                    pass  # already gone — acceptable
                else:
                    per_uid_hard_error = True
                    app.logger.warning(
                        f"[XRAY-SYNC] rmu failed for {uid[:8]} tag={tag} "
                        f"grpc={grpc_addr}: {result.stdout.strip()} "
                        f"{result.stderr.strip()}"
                    )
            except Exception as e:
                per_uid_hard_error = True
                app.logger.error(f"[XRAY-SYNC] rmu exception for {uid[:8]} tag={tag}: {e}")

        if per_uid_hard_error:
            rmu_errors += 1
            still_pending.append(uid)
        elif per_uid_any_removed:
            removed += 1
        else:
            not_in_live += 1

    # Keep only UUIDs that failed — they will be retried on the next /reload.
    # Successful + "not found" are cleared.
    _pending_rmu_write(still_pending)

    inbound_summary = ",".join(
        f"{t}({len(c)}@{g})" for t, g, c in per_inbound_clients
    )
    app.logger.info(
        f"[XRAY-SYNC] layout={xray_layout()} inbounds=[{inbound_summary}] "
        f"total_clients={total_clients_seen} already={already} "
        f"skipped_lsi={skipped_lsi} added={added} add_errors={errors} | "
        f"del pending={len(pending)} removed={removed} "
        f"not_in_live={not_in_live} rmu_errors={rmu_errors}"
    )
    return {
        "success": errors == 0 and rmu_errors == 0,
        "method": "sync-config-to-live",
        "version": __version__,
        "layout": xray_layout(),
        "total": total_clients_seen,
        "inbounds": [
            {"tag": t, "grpc": g, "clients": len(c)}
            for t, g, c in per_inbound_clients
        ],
        "already_in_live": already,
        "skipped_via_lsi": skipped_lsi,
        "added_to_live": added,
        "errors": errors,
        "pending_rmu": len(pending),
        "removed_from_live": removed,
        "not_in_live": not_in_live,
        "rmu_errors": rmu_errors,
    }


def _xray_api_rmu_from_tag(client_uuid: str, tag: str) -> dict:
    """Internal: gRPC rmu from a SPECIFIC inbound tag.

    'not found' is treated as success (user already absent — same end state).
    v4.5.0 — gRPC address is resolved per tag (split layout sends
    vless-vision-in to :10086).
    """
    email = f"{client_uuid}@vless"
    _cfg_path, grpc_addr, _svc = _binding_for_tag(tag)
    try:
        result = subprocess.run(
            ["xray", "api", "rmu", "-s", grpc_addr, "-tag", tag, email],
            capture_output=True, text=True, timeout=5
        )
        out = (result.stdout + result.stderr).lower()
        if "removed 1" in out:
            return {"success": True, "tag": tag, "state": "removed"}
        if "not found" in out:
            return {"success": True, "tag": tag, "state": "not_found"}
        return {"success": False, "tag": tag, "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "tag": tag, "error": str(e)}


def xray_api_remove_user(client_uuid: str) -> dict:
    """Remove VLESS user via xray gRPC API from ALL configured VLESS inbounds.

    v4.4.4 — multi-inbound: removes user from every VLESS inbound. 'not found'
    on a tag is acceptable (same end state). Considers operation successful if
    primary tag (first) returned removed/not_found, even if a secondary tag
    errored — degraded but the channel №1 user is gone.

    Falls back to xray restart only on hard failure of the primary tag.
    v4.5.0 — discovers VLESS inbounds across all xray configs in current
    layout (split or single).
    """
    locations = _iter_vless_locations()
    if not locations:
        app.logger.warning("[XRAY-GRPC] no VLESS inbounds — falling back to restart")
        return restart_service_sync("xray")

    seen = set()
    tags = []
    for _path, inb, _grpc, _svc in locations:
        t = inb.get("tag", "vless-in")
        if t in seen:
            continue
        seen.add(t)
        tags.append(t)
    tags = [t for t in XRAY_INBOUND_TAGS if t in tags] + \
           [t for t in tags if t not in XRAY_INBOUND_TAGS]

    details = []
    primary_ok = False
    for idx, tag in enumerate(tags):
        res = _xray_api_rmu_from_tag(client_uuid, tag)
        details.append(res)
        if idx == 0:
            primary_ok = res.get("success", False)

    if primary_ok:
        removed_from = [d["tag"] for d in details if d.get("success")]
        app.logger.info(
            f"[XRAY-GRPC] Removed user {client_uuid[:8]}... from {removed_from}"
        )
        return {"success": True, "method": "grpc-api", "details": details}

    primary_tag = tags[0]
    _cfg, _grpc, primary_service = _binding_for_tag(primary_tag)
    app.logger.warning(
        f"[XRAY-GRPC] rmu from primary tag '{primary_tag}' failed for "
        f"{client_uuid[:8]}: {details[0]} — restarting {primary_service}"
    )
    return restart_service_sync(primary_service)


# ==================== VLESS (xray) ====================

@app.route("/keys/vless", methods=["POST"])
@require_token
def add_vless_key():
    """Add VLESS client to xray config (all VLESS inbounds).

    v4.4.4 — multi-inbound aware. Adds the UUID to EVERY VLESS inbound in
    config.json (legacy single-inbound servers + Session-17 dual-inbound
    servers). Per-inbound flow is resolved by `_flow_for_inbound`:
      - vless-in            → caller-provided flow (default "")
      - vless-vision-in     → "xtls-rprx-vision" (forced — Vision splitting
                              cannot work without it)

    Backwards compatible: response payload preserves `flow` field as the
    flow used for the PRIMARY inbound (matches v4.4.3 callers' expectations).

    UUID-already-exists check is done across ALL inbounds; we return 409
    only if it exists in the PRIMARY inbound (so re-add to a server that
    has the user only in vless-in but missing from vless-vision-in is NOT
    treated as an error — instead it heals the missing inbound).

    NOTE: default flow is "" for XHTTP+Reality (current setup).
    Legacy VLESS+Reality+TCP used flow="xtls-rprx-vision" — callers needing
    that mode must pass it explicitly in request body.
    """
    data = request.get_json() or {}
    client_uuid = data.get("uuid") or str(uuid.uuid4())
    flow = data.get("flow", "")

    # Validate UUID format
    if not is_valid_uuid(client_uuid):
        return jsonify({"error": "Invalid UUID format", "uuid": client_uuid}), 400

    try:
        # v4.5.0 — read every xray config in current layout, mutate the
        # in-memory dict per file, and write each file back. Single layout
        # touches one file; split layout touches two.
        configs_by_path = {}
        for path in xray_config_paths():
            try:
                configs_by_path[path] = read_json_config(path)
            except FileNotFoundError:
                continue
            except Exception as e:
                return jsonify({"error": f"read {path} failed: {e}"}), 500

        if not configs_by_path:
            return jsonify({"error": "no xray config found"}), 500

        # Locate every VLESS inbound across all configs (preserve order:
        # vless-in must be primary so legacy 409-on-primary semantics hold).
        # entries: [(path, inbound_dict, tag)]
        entries = []
        for path, cfg in configs_by_path.items():
            for inb in cfg.get("inbounds", []):
                if inb.get("protocol") != "vless":
                    continue
                entries.append((path, inb, inb.get("tag", "vless-in")))

        if not entries:
            return jsonify({"error": "VLESS inbound not found in config"}), 500

        # Sort so vless-in is primary.
        def _tag_priority(tag):
            try:
                return XRAY_INBOUND_TAGS.index(tag)
            except ValueError:
                return len(XRAY_INBOUND_TAGS)

        entries.sort(key=lambda e: _tag_priority(e[2]))
        primary_path, primary_inbound, primary_tag = entries[0]

        # v4.5.2 — 409 only if UUID is in ALL VLESS inbounds (truly already
        # there). If it's missing from at least one inbound, fall through
        # and let the per-inbound idempotent add (below) heal that inbound.
        # Was: 409 fired as soon as UUID was in PRIMARY (vless-in), which
        # blocked drift_monitor / sync_keys_to_server from healing
        # partial drift on vless-vision-in (or any secondary inbound).
        in_all_inbounds = all(
            any(c.get("id") == client_uuid for c in inb.get("settings", {}).get("clients", []))
            for _path, inb, _tag in entries
        )
        if in_all_inbounds:
            return jsonify({"error": "UUID already exists", "uuid": client_uuid}), 409

        # Add new client to each VLESS inbound (idempotent per inbound).
        added_to = []
        touched_paths = set()
        for path, inbound, tag in entries:
            clients = inbound.get("settings", {}).get("clients", [])
            if any(c.get("id") == client_uuid for c in clients):
                continue  # already there — skip silently
            client_flow = _flow_for_inbound(tag, flow)
            clients.append({"id": client_uuid, "flow": client_flow})
            inbound.setdefault("settings", {})["clients"] = clients
            added_to.append(tag)
            touched_paths.add(path)

        for path in touched_paths:
            write_json_config(path, configs_by_path[path])

        # Add user via gRPC API (zero downtime) or skip if no_restart.
        # xray_api_add_user is layout- and multi-inbound aware (v4.5.0).
        no_restart = data.get("no_restart", False)
        restart_result = (
            {"success": True, "method": "skipped"}
            if no_restart else xray_api_add_user(client_uuid, flow)
        )

        return jsonify({
            "success": True,
            "uuid": client_uuid,
            "flow": flow,
            "layout": xray_layout(),
            "added_to_inbounds": added_to,
            "restart": restart_result,
            "total_clients": len(primary_inbound.get("settings", {}).get("clients", []))
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/vless/<client_uuid>", methods=["DELETE"])
@require_token
def delete_vless_key(client_uuid: str):
    """Remove VLESS client from xray config (all VLESS inbounds).

    v4.4.4 — multi-inbound aware. Removes UUID from EVERY VLESS inbound it
    appears in. 404 returned only if UUID is not present in ANY inbound (so
    a partial-drift situation where UUID is in vless-in but missing from
    vless-vision-in still successfully removes from vless-in).
    """
    try:
        # v4.5.0 — same per-config iteration as POST.
        configs_by_path = {}
        for path in xray_config_paths():
            try:
                configs_by_path[path] = read_json_config(path)
            except FileNotFoundError:
                continue
            except Exception as e:
                return jsonify({"error": f"read {path} failed: {e}"}), 500

        if not configs_by_path:
            return jsonify({"error": "no xray config found"}), 500

        entries = []
        for path, cfg in configs_by_path.items():
            for inb in cfg.get("inbounds", []):
                if inb.get("protocol") != "vless":
                    continue
                entries.append((path, inb, inb.get("tag", "vless-in")))

        if not entries:
            return jsonify({"error": "VLESS inbound not found"}), 500

        def _tag_priority(tag):
            try:
                return XRAY_INBOUND_TAGS.index(tag)
            except ValueError:
                return len(XRAY_INBOUND_TAGS)

        entries.sort(key=lambda e: _tag_priority(e[2]))

        # Remove UUID from each inbound, track removals + final primary count.
        removed_from = []
        primary_count = 0
        touched_paths = set()
        for idx, (path, inbound, tag) in enumerate(entries):
            clients = inbound.get("settings", {}).get("clients", [])
            before = len(clients)
            clients = [c for c in clients if c.get("id") != client_uuid]
            after = len(clients)
            inbound.setdefault("settings", {})["clients"] = clients
            if after < before:
                removed_from.append(tag)
                touched_paths.add(path)
            if idx == 0:
                primary_count = after

        if not removed_from:
            return jsonify({"error": "UUID not found"}), 404

        for path in touched_paths:
            write_json_config(path, configs_by_path[path])

        no_restart = request.args.get("no_restart", "false").lower() == "true"
        if no_restart:
            # UUID removed from config but still in live xray.
            # Queue gRPC rmu for the next /reload (xray_sync_config_to_live).
            # See XRAY_PENDING_RMU_FILE docstring. v4.4.3+.
            _pending_rmu_append(client_uuid)
            restart_result = {"success": True, "method": "queued-for-sync"}
        else:
            restart_result = xray_api_remove_user(client_uuid)

        return jsonify({
            "success": True,
            "deleted_uuid": client_uuid,
            "layout": xray_layout(),
            "removed_from_inbounds": removed_from,
            "restart": restart_result,
            "total_clients": primary_count
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/keys/vless", methods=["GET"])
@require_token
def list_vless_keys():
    """List VLESS clients.

    v4.4.4 — multi-inbound aware. Returns:
      - top-level `clients` / `count` / `flow`: from PRIMARY inbound (vless-in)
        → backwards-compatible with v4.4.3 callers (existing backend code that
        compares by `clients[*].uuid` keeps working without change).
      - `inbounds`: per-inbound breakdown for new callers — each entry has
        {tag, count, clients[]} so backend can audit Vision separately.

    On legacy single-inbound servers, `inbounds` will have just one entry
    (vless-in) and the response shape is structurally a superset of v4.4.3.
    v4.5.0 — reads every xray config in current layout.
    """
    try:
        entries = []  # (tag, inbound_dict)
        for path in xray_config_paths():
            try:
                cfg = read_json_config(path)
            except FileNotFoundError:
                continue
            for inb in cfg.get("inbounds", []):
                if inb.get("protocol") != "vless":
                    continue
                entries.append((inb.get("tag", ""), inb))

        if not entries:
            return jsonify({"error": "VLESS inbound not found"}), 500

        # Sort so vless-in is primary (index 0).
        def _tag_priority(tag):
            try:
                return XRAY_INBOUND_TAGS.index(tag)
            except ValueError:
                return len(XRAY_INBOUND_TAGS)

        entries.sort(key=lambda e: _tag_priority(e[0]))

        per_inbound = []
        for tag, inbound in entries:
            clients = inbound.get("settings", {}).get("clients", [])
            per_inbound.append({
                "tag": tag,
                "count": len(clients),
                "clients": [
                    {"uuid": c.get("id"), "flow": c.get("flow")}
                    for c in clients
                ],
            })

        primary = per_inbound[0]
        return jsonify({
            "protocol": "vless",
            "layout": xray_layout(),
            "count": primary["count"],
            "clients": primary["clients"],
            "inbounds": per_inbound,
        })

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
        
        no_restart = data.get("no_restart", False)
        if no_restart:
            restart_result = {"success": True, "method": "skipped"}
        else:
            schedule_tuic_restart(service_name)
            restart_result = {"success": True, "method": "debounced", "delay_seconds": TUIC_DEBOUNCE_DELAY}
        
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
        
        no_restart = request.args.get("no_restart", "false").lower() == "true"
        if no_restart:
            restart_result = {"success": True, "method": "skipped"}
        else:
            schedule_tuic_restart(service_name)
            restart_result = {"success": True, "method": "debounced", "delay_seconds": TUIC_DEBOUNCE_DELAY}
        
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
    # SS 2022 requires base64-encoded 16-byte PSK (not urlsafe!)
    password = data.get("password") or data.get("secret") or base64.b64encode(secrets.token_bytes(16)).decode()
    
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
        
        no_restart = data.get("no_restart", False)
        restart_result = {"success": True, "method": "skipped"} if no_restart else restart_service_sync("shadowsocks")
        
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
        
        no_restart = request.args.get("no_restart", "false").lower() == "true"
        restart_result = {"success": True, "method": "skipped"} if no_restart else restart_service_sync("shadowsocks")
        
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
        
        no_restart = data.get("no_restart", False)
        if no_restart:
            restart_result = {"success": True, "method": "skipped"}
        else:
            schedule_hysteria_restart(service_name)
            restart_result = {"success": True, "method": "debounced", "delay_seconds": HYSTERIA_DEBOUNCE_DELAY}
        
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
        
        no_restart = request.args.get("no_restart", "false").lower() == "true"
        if no_restart:
            restart_result = {"success": True, "method": "skipped"}
        else:
            schedule_hysteria_restart(service_name)
            restart_result = {"success": True, "method": "debounced", "delay_seconds": HYSTERIA_DEBOUNCE_DELAY}
        
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


# ==================== IPv4 Configuration Check ====================

@app.route("/check-ipv4", methods=["GET"])
@require_token
def check_ipv4_config():
    """
    Check IPv4/IPv6 configuration on this server.
    Detects misconfigurations that cause Hysteria2/TUIC to fail
    (Go ignores gai.conf/sysctl, needs GODEBUG=netdns=cgo).
    """
    result = {
        "ipv4_priority": False,
        "ipv6_disabled": False,
        "ipv4_works": False,
    }

    # Check 1: gai.conf has IPv4 priority
    try:
        with open("/etc/gai.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("precedence") and "::ffff:0:0/96" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        val = int(parts[2])
                        if val >= 100:
                            result["ipv4_priority"] = True
                    break
    except Exception as e:
        result["gai_error"] = str(e)

    # Check 2: IPv6 disabled via sysctl
    try:
        out = subprocess.run(
            ["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"],
            capture_output=True, text=True, timeout=5
        )
        result["ipv6_disabled"] = out.stdout.strip() == "1"
    except Exception as e:
        result["sysctl_error"] = str(e)

    # Check 3: IPv4 connectivity (ping — no DNS dependency)
    # Previous method (curl https://google.com) caused false alerts because
    # AdGuard DoH upstream needs TLS handshake after idle (~3sec), and
    # curl 5sec timeout wasn't always enough (DNS + TLS + HTTP).
    # Ping by IP tests raw IPv4 connectivity reliably in <100ms.
    try:
        out = subprocess.run(
            ["ping", "-4", "-c", "1", "-W", "3", "1.1.1.1"],
            capture_output=True, text=True, timeout=5
        )
        result["ipv4_works"] = out.returncode == 0
        # Extract ping time if available
        if out.returncode == 0 and "time=" in out.stdout:
            match = re.search(r"time=([\d.]+)", out.stdout)
            if match:
                result["ipv4_ping_ms"] = float(match.group(1))
    except Exception as e:
        result["ipv4_error"] = str(e)

    return jsonify(result)


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
    for svc in vpn_services():
        status = get_service_status(svc)
        services[svc] = status
        if status["status"] != "active":
            all_healthy = False
    return jsonify({
        "healthy": all_healthy,
        "services": services,
        "xray_layout": xray_layout(),
        "timestamp": int(time.time()),
    })


@app.route("/health/<service>", methods=["GET"])
@require_token
def health_service(service: str):
    known = set(vpn_services())
    # Backward compat: accept "xray" on split layout (returns aggregate).
    if service == "xray" and xray_layout() == "split":
        agg = {svc: get_service_status(svc) for svc in xray_services_for_layout()}
        all_active = all(s["status"] == "active" for s in agg.values())
        return jsonify({
            "service": "xray",
            "status": "active" if all_active else "degraded",
            "components": agg,
        })
    if service not in known:
        return jsonify({"error": f"Unknown service: {service}"}), 404
    return jsonify(get_service_status(service))


@app.route("/restart/<service>", methods=["POST"])
@require_token
def restart(service: str):
    known = set(vpn_services())
    # Backward compat: legacy callers say "xray" on split layout —
    # restart_service_sync fans out automatically.
    if service == "xray" and xray_layout() == "split":
        result = restart_service_sync("xray")
        return jsonify({"service": "xray", **result}), 200 if result.get("success") else 500
    if service not in known:
        return jsonify({"error": f"Unknown service: {service}"}), 404
    result = restart_service_sync(service)
    return jsonify({"service": service, **result}), 200 if result.get("success") else 500


@app.route("/restart-all", methods=["POST"])
@require_token
def restart_all():
    results = []
    for svc in vpn_services():
        status = get_service_status(svc)
        if status["status"] != "active":
            result = restart_service_sync(svc)
            results.append({"service": svc, **result})
    return jsonify({
        "restarted": [r["service"] for r in results if r.get("success")],
        "failed": [r["service"] for r in results if not r.get("success")],
        "details": results,
    })


@app.route("/reload", methods=["POST"])
@require_token
def reload_services():
    """
    Reload/restart specified services after batch key operations.
    Call this ONCE after all key add/delete operations instead of
    restarting after each individual key change.
    
    Body: {"services": ["xray", "shadowsocks", "tuic", "tuic-d2", "hysteria", "hysteria-d2"]}
    Xray uses SIGHUP (hot reload, no connection drops).
    Other services use systemctl restart.
    """
    data = request.get_json() or {}
    services = data.get("services", [])
    
    if not services:
        return jsonify({"error": "No services specified"}), 400
    
    # Validate all services. v4.5.0 — accept legacy "xray" alias on
    # split layout (backend may still send it before the protocol map
    # ships in the next release).
    allowed = set(vpn_services())
    if xray_layout() == "split":
        allowed.add("xray")
    invalid = [s for s in services if s not in allowed]
    if invalid:
        return jsonify({"error": f"Unknown services: {invalid}"}), 400

    results = {}
    for service in services:
        if service in SIGHUP_SUPPORTED:
            results[service] = hot_reload_service(service)
        elif service in ("tuic", "tuic-d2"):
            # Debounced restart — batches multiple /reload calls
            schedule_tuic_restart(service)
            results[service] = {"success": True, "method": "debounced", "delay_seconds": TUIC_DEBOUNCE_DELAY}
        elif service in ("hysteria", "hysteria-d2"):
            # Debounced restart — Hysteria2 does NOT support SIGHUP (process dies)
            schedule_hysteria_restart(service)
            results[service] = {"success": True, "method": "debounced", "delay_seconds": HYSTERIA_DEBOUNCE_DELAY}
        elif service in ("xray", XRAY_SPLIT_VLESS_SERVICE, XRAY_SPLIT_VISION_SERVICE):
            # Sync config.json → live xray via gRPC AddUser.
            # Previously this was a no-op under the assumption that users
            # were added inline via gRPC during the /keys/vless POST. That
            # assumption was WRONG when the POST carried no_restart=True
            # (the backend always does this for batching): the agent
            # skipped the inline xray_api_add_user and the user never
            # reached the live xray process — only config.json. The
            # "already exists" response for in-live users makes this
            # idempotent and safe to call from every /reload.
            results[service] = xray_sync_config_to_live()
        else:
            results[service] = restart_service_sync(service)
    
    all_ok = all(r.get("success") for r in results.values())
    return jsonify({
        "success": all_ok,
        "results": results,
    }), 200 if all_ok else 500


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


# ==================== CPU Monitoring (rolling average) ====================
# Background thread samples CPU every 5 seconds, keeps 60-second rolling average.
# This prevents spiky readings from 0.5s instant samples (7% → 70% → 7%).

_cpu_samples = []  # List of (timestamp, cpu_percent) tuples
_cpu_samples_lock = threading.Lock()
CPU_SAMPLE_INTERVAL = 5    # seconds between samples
CPU_WINDOW_SECONDS = 60    # rolling average window


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


def _cpu_sampler_thread():
    """Background thread: samples CPU every 5s, stores in rolling buffer."""
    prev_total, prev_idle = _read_cpu_times()
    while True:
        time.sleep(CPU_SAMPLE_INTERVAL)
        try:
            cur_total, cur_idle = _read_cpu_times()
            total_diff = cur_total - prev_total
            idle_diff = cur_idle - prev_idle
            prev_total, prev_idle = cur_total, cur_idle
            
            if total_diff == 0:
                cpu_pct = 0.0
            else:
                cpu_pct = round((1.0 - idle_diff / total_diff) * 100, 1)
            
            now = time.time()
            with _cpu_samples_lock:
                _cpu_samples.append((now, cpu_pct))
                # Remove samples older than window
                cutoff = now - CPU_WINDOW_SECONDS
                while _cpu_samples and _cpu_samples[0][0] < cutoff:
                    _cpu_samples.pop(0)
        except Exception:
            pass


def _get_cpu_percent(interval=0.5):
    """Get CPU usage % as rolling average over last 60 seconds.
    Falls back to instant sample if no data yet (first 5 seconds after start)."""
    with _cpu_samples_lock:
        if _cpu_samples:
            avg = sum(s[1] for s in _cpu_samples) / len(_cpu_samples)
            return round(avg, 1)
    
    # Fallback: instant sample (only on first call before thread populates data)
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


# Start CPU sampler thread
_cpu_thread = threading.Thread(target=_cpu_sampler_thread, daemon=True)
_cpu_thread.start()


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
