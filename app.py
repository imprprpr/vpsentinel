#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from secure_files import transactional, config_transaction
import sys
import time
import json
import socket
import sqlite3
import asyncio
import logging
import threading
import hmac
import hashlib
import secrets
import ipaddress
from typing import List, Optional, Any, Literal
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Response, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, field_validator, Field
import requests

import sentinel_core
import sub_engine
import transit_mgr
import custom_node_mgr
import notification
import ip_audit
import speedtest_mgr
import auth_mgr
import traffic_mgr
import mesh_mgr
import bot_mgr
import clean_ip_mgr
import cert_sync_mgr

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('SentinelAPI')

app = FastAPI(title='VPSentinel Control Center', docs_url=None, redoc_url=None, openapi_url=None)

from paths import BASE_DIR, STATIC_PATH
METACUBEXD_PATH = os.path.join(STATIC_PATH, 'metacubexd')
NUXT_PATH = os.path.join(METACUBEXD_PATH, '_nuxt')

monitor = sentinel_core.SystemMonitor()
cfg_mgr = sentinel_core.ConfigManager()
auth = auth_mgr.AuthManager(cfg_mgr)

# Cloudflare official edge ranges are trusted by default.
# Loopback networks are NOT trusted by default to eliminate header spoofing risks;
# operators deploying local reverse proxies (e.g., nginx/caddy) must explicitly configure security.trusted_proxy_cidrs.
LOOPBACK_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8', strict=False),
    ipaddress.ip_network('::1/128', strict=False)
]

CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network('173.245.48.0/20', strict=False),
    ipaddress.ip_network('103.21.244.0/22', strict=False),
    ipaddress.ip_network('103.22.200.0/22', strict=False),
    ipaddress.ip_network('103.31.4.0/22', strict=False),
    ipaddress.ip_network('141.101.64.0/18', strict=False),
    ipaddress.ip_network('108.162.192.0/18', strict=False),
    ipaddress.ip_network('190.93.240.0/20', strict=False),
    ipaddress.ip_network('188.114.96.0/20', strict=False),
    ipaddress.ip_network('197.234.240.0/22', strict=False),
    ipaddress.ip_network('198.41.128.0/17', strict=False),
    ipaddress.ip_network('162.158.0.0/15', strict=False),
    ipaddress.ip_network('104.16.0.0/13', strict=False),
    ipaddress.ip_network('104.24.0.0/14', strict=False),
    ipaddress.ip_network('172.64.0.0/13', strict=False),
    ipaddress.ip_network('131.0.72.0/22', strict=False),
    ipaddress.ip_network('2400:cb00::/32', strict=False),
    ipaddress.ip_network('2606:4700::/32', strict=False),
    ipaddress.ip_network('2803:f800::/32', strict=False),
    ipaddress.ip_network('2405:b500::/32', strict=False),
    ipaddress.ip_network('2405:8100::/32', strict=False),
    ipaddress.ip_network('2a06:98c0::/29', strict=False),
    ipaddress.ip_network('2c0f:f248::/32', strict=False)
]

DEFAULT_TRUSTED_PROXY_NETWORKS = list(CLOUDFLARE_NETWORKS)

def is_ip_in_networks(ip_str: str, networks: List[Any]) -> bool:
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    for net in networks:
        if ip_obj in net:
            return True
    return False

def is_cloudflare_peer(peer_ip: str) -> bool:
    return is_ip_in_networks(peer_ip, CLOUDFLARE_NETWORKS)

def is_trusted_peer(peer_ip: str, custom_cidrs: Optional[List[str]] = None) -> bool:
    if not peer_ip:
        return False
    networks = list(DEFAULT_TRUSTED_PROXY_NETWORKS)
    if custom_cidrs:
        for cidr in custom_cidrs:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    return is_ip_in_networks(peer_ip, networks)

def _has_proxy_headers(headers) -> bool:
    if not headers:
        return False
    target = {'x-forwarded-for', 'cf-connecting-ip', 'x-real-ip'}
    if hasattr(headers, 'items'):
        for k, v in headers.items():
            if str(k).lower() in target and v:
                return True
    elif hasattr(headers, 'get'):
        for k in target:
            if headers.get(k):
                return True
    return False

_loopback_proxy_warned = False

def resolve_client_ip(request: Request, custom_cidrs: Optional[List[str]] = None) -> str:
    global _loopback_proxy_warned
    peer_ip = request.client.host if request.client else ""
    if not is_trusted_peer(peer_ip, custom_cidrs):
        if is_ip_in_networks(peer_ip, LOOPBACK_NETWORKS):
            headers = getattr(request, 'headers', {})
            if _has_proxy_headers(headers) and not _loopback_proxy_warned:
                _loopback_proxy_warned = True
                logger.warning(
                    f"Detected reverse proxy headers from loopback peer {peer_ip}, but loopback is not configured "
                    f"in security.trusted_proxy_cidrs. Visitor IP is falling back to {peer_ip}. "
                    f"Configure 'trusted_proxy_cidrs': ['127.0.0.1'] in config.json to restore original client IPs."
                )
        return peer_ip

    headers = getattr(request, 'headers', {})

    # 1. CF-Connecting-IP is strictly accepted ONLY when peer is an authentic Cloudflare edge node
    if is_cloudflare_peer(peer_ip):
        cf_ip = headers.get('cf-connecting-ip') if hasattr(headers, 'get') else None
        if not cf_ip and hasattr(headers, 'items'):
            for k, v in headers.items():
                if k.lower() == 'cf-connecting-ip':
                    cf_ip = v
                    break
        if cf_ip and cf_ip.strip():
            return cf_ip.strip()

    # 2. X-Forwarded-For: traverse right-to-left to find the first untrusted upstream hop
    xfwd = headers.get('x-forwarded-for') if hasattr(headers, 'get') else None
    if not xfwd and hasattr(headers, 'items'):
        for k, v in headers.items():
            if k.lower() == 'x-forwarded-for':
                xfwd = v
                break

    if xfwd:
        hops = [h.strip() for h in xfwd.split(',') if h.strip()]
        for hop in reversed(hops):
            if not is_trusted_peer(hop, custom_cidrs):
                return hop

    return peer_ip

def mask_token(token: str, head: int = 4, tail: int = 4) -> str:
    if not token:
        return ""
    if len(token) <= head + tail:
        return "****"
    if head == 0:
        return f"****{token[-tail:]}"
    return f"{token[:head]}****{token[-tail:]}"

def redact_notifications(notifications: dict) -> dict:
    if not isinstance(notifications, dict):
        return {}
    redacted = json.loads(json.dumps(notifications))
    tg = redacted.get('telegram', {})
    if isinstance(tg, dict) and tg.get('bot_token'):
        tg['bot_token'] = mask_token(tg['bot_token'], head=0, tail=4)
    dc = redacted.get('discord', {})
    if isinstance(dc, dict) and dc.get('webhook_url'):
        dc['webhook_url'] = mask_token(dc['webhook_url'], head=8, tail=4)
    bark = redacted.get('bark', {})
    if isinstance(bark, dict) and bark.get('bark_key'):
        bark['bark_key'] = mask_token(bark['bark_key'], head=0, tail=4)
    cw = redacted.get('custom_webhook', {})
    if isinstance(cw, dict) and cw.get('url'):
        cw['url'] = mask_token(cw['url'], head=8, tail=4)
    return redacted

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)

class UpdatePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)

class SecuritySettingsRequest(BaseModel):
    auth_enabled: Optional[bool] = None
    secret_path: Optional[str] = None
    enable_host_guard: Optional[bool] = None
    regenerate_sub_token: Optional[bool] = None

@app.exception_handler(OSError)
async def persistence_error(request: Request, exc: OSError):
    logger.error('Operation failed: %s', type(exc).__name__)
    return JSONResponse(status_code=503, content={'detail': 'Storage or system operation failed; changes were not confirmed'})

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Host Guard: Reject raw IP scans on public interface
    if not auth.check_host_guard(request):
        return Response(status_code=404, content=b"", headers={"Server": "nginx/1.22.1"})

    if request.method not in ('GET', 'HEAD', 'OPTIONS') and request.cookies.get('sentinel_session'):
        origin = request.headers.get('origin')
        if origin:
            from urllib.parse import urlsplit
            if urlsplit(origin).netloc != request.headers.get('host'):
                return JSONResponse(status_code=403, content={'detail': 'Cross-origin cookie mutation rejected'})
    cfg = cfg_mgr.load()
    trusted_cidrs = cfg.get("security", {}).get("trusted_proxy_cidrs", [])
    request.state.client_ip = resolve_client_ip(request, trusted_cidrs)

    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    response.headers["Server"] = "nginx/1.22.1"
    return response

def check_admin(request: Request):
    sec = auth.get_security_config()
    if sec.get('auth_enabled', True) and sec.get('must_change_password', False) and request.url.path not in ('/api/auth/update-password', '/api/auth/logout'):
        raise HTTPException(status_code=403, detail='Change the initial administrator password first')
    if not auth.is_request_authenticated(request):
        raise HTTPException(status_code=401, detail="Administrator authentication required")

def check_setup_allowed(request: Request):
    cfg = cfg_mgr.load()
    if cfg.get('initialized', False):
        check_admin(request)
        return
    peer_ip = request.client.host if request.client else ""
    resolved_ip = getattr(request.state, "client_ip", peer_ip)
    headers = getattr(request, 'headers', {})
    has_proxy = _has_proxy_headers(headers)
    # Direct unproxied localhost access ONLY is exempt from admin auth during uninitialized setup
    if peer_ip in ("127.0.0.1", "::1", "localhost") and resolved_ip in ("127.0.0.1", "::1", "localhost") and not has_proxy:
        return
    check_admin(request)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await asyncio.wait_for(connection.send_json(message), timeout=5)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Runtime state
runtime_state = {
    'status': 'healthy', # healthy, warning, critical, healing
    'last_healed': 'Never',
    'heal_count': 0,
    'heal_in_progress': False,
    'logs': [
        {'time': time.strftime("%H:%M:%S"), 'level': 'INFO', 'msg': 'Oracle Sentinel System initialized.'},
        {'time': time.strftime("%H:%M:%S"), 'level': 'INFO', 'msg': 'Sidecar monitoring active on port 20540.'}
    ]
}

def log_event(msg: str, level='INFO'):
    entry = {'time': time.strftime("%H:%M:%S"), 'level': level, 'msg': msg}
    runtime_state['logs'].append(entry)
    if len(runtime_state['logs']) > 100:
        runtime_state['logs'].pop(0)
    logger.info(f'[{level}] {msg}')
    return entry

async def broadcast_log(msg: str, level='INFO'):
    entry = log_event(msg, level)
    await ws_manager.broadcast({'type': 'log', 'data': entry})

_managed_tasks = set()

def create_managed_task(coro):
    task = asyncio.create_task(coro)
    _managed_tasks.add(task)
    task.add_done_callback(_managed_tasks.discard)
    return task

@app.on_event('shutdown')
async def shutdown_event():
    from edt_optimizer import Optimizer
    Optimizer.stop.set()
    for owner in (traffic_mgr.TrafficManager, mesh_mgr.MeshManager, cert_sync_mgr.CertSyncManager):
        event = getattr(owner, '_stop_event', None)
        if event: event.set()
    bot = bot_mgr.get_bot_instance()
    bot.stop()
    tasks = list(_managed_tasks)
    for task in tasks: task.cancel()
    if tasks: await asyncio.gather(*tasks, return_exceptions=True)
    for socket in list(ws_manager.active_connections):
        await socket.close(code=1001)
    ws_manager.active_connections.clear()

@app.on_event('startup')
async def startup_event():
    from edt_optimizer import Optimizer
    Optimizer.start_scheduler()
    create_managed_task(background_monitor_loop())
    traffic_mgr.TrafficManager.start_background_collector(cfg_mgr.load, interval_sec=60)
    mesh_mgr.MeshManager.start_background_poller(interval_sec=60)
    cert_sync_mgr.CertSyncManager.start_background_poller(cfg_mgr.load)
    bot = bot_mgr.get_bot_instance(
        get_state_func=monitor.get_full_state,
        get_config_func=cfg_mgr.load,
        run_healing_func=run_healing_routine
    )
    bot.start()

def retry_pending_dns():
    cfg = cfg_mgr.load()
    mon = cfg.get('monitor', {})
    address = mon.get('last_reip_new_ip')
    if not mon.get('dns_sync_pending') or not address:
        return False
    dns = sentinel_core.dns_settings(cfg)
    if not dns.get('record_name'):
        return False
    if sentinel_core.get_dns_provider(cfg).update_dns_record(dns['record_name'], address):
        def clear(current):
            if current.get('monitor', {}).get('last_reip_new_ip') == address:
                current['monitor']['dns_sync_pending'] = False
        cfg_mgr.update(clear)
        return True
    return False


def confirmed_inbound_failure(cfg):
    url = cfg.get('monitor', {}).get('inbound_probe_url')
    if not url:
        return False
    from net_policy import open_secure, read_json
    import urllib.request
    token = cfg.get('monitor', {}).get('inbound_probe_token', '')
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token})
    with open_secure(request) as response:
        result = read_json(response)
    return result.get('inbound_reachable') is False and result.get('target_ip') == monitor.get_public_ip() and abs(time.time() - float(result.get('timestamp', 0))) < 120


async def background_monitor_loop():
    logger.info('Starting background probe & monitor task...')
    loop = asyncio.get_running_loop()
    while True:
        try:
            cfg = cfg_mgr.load()
            if cfg.get('monitor', {}).get('dns_sync_pending'):
                await asyncio.to_thread(retry_pending_dns)
            state = await loop.run_in_executor(None, monitor.get_full_state)
            
            if not runtime_state['heal_in_progress']:
                runtime_state['status'] = state['health']

            payload = {
                'type': 'telemetry',
                'state': state,
                'speedtest': speedtest_mgr.speedtest_mgr.get_status(),
                'sentinel': {
                    'status': runtime_state['status'],
                    'last_healed': runtime_state['last_healed'],
                    'heal_count': runtime_state['heal_count'],
                    'auto_heal': cfg.get('monitor', {}).get('auto_heal_enabled', False)
                }
            }
            await ws_manager.broadcast(payload)

            # Auto-healing condition check
            if cfg.get('monitor', {}).get('auto_heal_enabled', False) and not runtime_state['heal_in_progress']:
                loss_thresh = float(cfg.get('monitor', {}).get('loss_threshold', 75.0))
                consec_limit = int(cfg.get('monitor', {}).get('consecutive_failures', 3))
                auto_heal_mode = cfg.get('monitor', {}).get('auto_heal_mode', 'notify_only')
                
                # P1-9: If local uplink network is down, do not trigger false positive Re-IP
                if state['probes'].get('network_down'):
                    monitor.consecutive_failures = 0
                    await broadcast_log('Local uplink network is unreachable (network_down). Skipping Re-IP evaluation.', 'WARN')
                elif state['probes']['loss_pct'] >= loss_thresh:
                    monitor.consecutive_failures += 1
                    await broadcast_log(
                        f'Outbound probe loss threshold exceeded: {state["probes"]["loss_pct"]}% loss '
                        f'({monitor.consecutive_failures}/{consec_limit})',
                        'WARN'
                    )
                    if monitor.consecutive_failures >= consec_limit:
                        if auto_heal_mode == 'reip_auto' and not cfg.get('monitor', {}).get('dns_sync_pending') and await asyncio.to_thread(confirmed_inbound_failure, cfg):
                            await broadcast_log('Triggering automated Re-IP self-healing routine!', 'WARN')
                            await asyncio.to_thread(notification.NotificationManager.broadcast,
                                cfg,
                                title="GFW Block Detected / 节点探针阻断告警",
                                message=f"[GFW Block] Loss rate reached {state['probes']['loss_pct']}% across domestic probes.\nConsecutive failures: {monitor.consecutive_failures}/{consec_limit}.\nInitiating recovery sequence...",
                                level="WARN"
                            )
                            create_managed_task(run_healing_routine('AUTO'))
                        else:
                            await broadcast_log(
                                f'Outbound probe failure confirmed ({state["probes"]["loss_pct"]}% loss). '
                                f'Mode is notify_only: skipping automated Re-IP.',
                                'WARN'
                            )
                            await asyncio.to_thread(notification.NotificationManager.broadcast,
                                cfg,
                                title="GFW Block Alert / 探针阻断告警 (仅通知)",
                                message=f"[GFW Block] Loss rate reached {state['probes']['loss_pct']}%. Consecutive failures: {monitor.consecutive_failures}/{consec_limit}.\nMode is notify_only, manual review recommended.",
                                level="WARN"
                            )
                            monitor.consecutive_failures = 0
                else:
                    if monitor.consecutive_failures > 0:
                        monitor.consecutive_failures = 0

            interval = cfg.get('monitor', {}).get('interval_sec', 15)
            await asyncio.sleep(interval)
        except Exception as e:
            logger.error(f'Monitor loop error: {e}')
            await asyncio.sleep(5)

class SettingsModel(BaseModel):
    cf_token: Optional[str] = None
    cf_zone: Optional[str] = None
    cf_record: Optional[str] = None
    auto_heal: Optional[bool] = None
    auto_heal_mode: Optional[Literal['notify_only', 'reip_auto']] = None
    reip_cooldown_hours: Optional[int] = Field(default=None, ge=0, le=720)
    provider_type: Optional[Literal['auto', 'oracle', 'lightsail', 'hetzner', 'azure', 'hook', 'generic']] = None
    provider_hook: Optional[str] = None
    lightsail: Optional[dict] = None
    hetzner: Optional[dict] = None
    azure: Optional[dict] = None
    notifications_enabled: Optional[bool] = None
    tg_enabled: Optional[bool] = None
    tg_token: Optional[str] = None
    tg_chat_id: Optional[str] = None
    discord_enabled: Optional[bool] = None
    discord_webhook: Optional[str] = None
    bark_enabled: Optional[bool] = None
    bark_key: Optional[str] = None
    custom_webhook_enabled: Optional[bool] = None
    custom_webhook_url: Optional[str] = None
    secret_path: Optional[str] = None
    enable_host_guard: Optional[bool] = None

@app.get('/api/mesh/telemetry')
async def mesh_telemetry(request: Request):
    expected = auth.get_security_config().get('mesh_token', '')
    supplied = request.headers.get('authorization', '').removeprefix('Bearer ').strip()
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail='Mesh telemetry token required')
    state = await asyncio.to_thread(monitor.get_full_state)
    return {'state': {key: state.get(key) for key in ('public_ip', 'metrics', 'warp')}}


@app.get('/api/status')
async def get_status(request: Request):
    check_admin(request)
    cfg = cfg_mgr.load()
    loop = asyncio.get_running_loop()
    state = await loop.run_in_executor(None, monitor.get_full_state)
    return {
        'state': state,
        'sentinel': {
            'status': runtime_state['status'],
            'last_healed': runtime_state['last_healed'],
            'heal_count': runtime_state['heal_count'],
            'auto_heal': cfg.get('monitor', {}).get('auto_heal_enabled', False)
        },
        'logs': runtime_state['logs'][-30:]
    }

@app.get('/api/settings')
def get_settings(request: Request):
    check_admin(request)
    cfg = cfg_mgr.load()
    token = cfg.get('cloudflare', {}).get('api_token', '')
    masked_token = f'{token[:4]}****{token[-4:]}' if len(token) > 8 else ('' if not token else '****')
    
    # Check OCI status
    oci_mgr = sentinel_core.OracleManager(cfg.get('oci', {}).get('config_path')) if cfg.get('provider', {}).get('type') == 'oracle' else None
    oci_status = {
        'ready': oci_mgr is not None and oci_mgr.client is not None,
        'instance_id': (oci_mgr.instance_id if oci_mgr else ''),
        'vnic_id': (oci_mgr.vnic_id if oci_mgr else ''),
        'compartment_id': (oci_mgr.compartment_id if oci_mgr else ''),
        'region': (oci_mgr.region if oci_mgr else ''),
        'error': oci_mgr.init_error if oci_mgr else ''
    }

    notify_cfg = cfg.get('notifications', {})
    sec_cfg = auth.get_security_config()

    ls_cfg = cfg.get('lightsail', {})
    hz_cfg = cfg.get('hetzner', {})
    az_cfg = cfg.get('azure', {})

    return {
        'provider': cfg.get('provider', {'type': 'auto', 'hook_cmd': ''}),
        'lightsail': {
            'region': ls_cfg.get('region', 'us-east-1'),
            'instance_name': ls_cfg.get('instance_name', ''),
            'access_key_id': f"{ls_cfg.get('access_key_id', '')[:4]}****" if ls_cfg.get('access_key_id') else '',
            'has_secret': bool(ls_cfg.get('secret_access_key'))
        },
        'hetzner': {
            'server_id': hz_cfg.get('server_id', ''),
            'ip_type': hz_cfg.get('ip_type', 'primary'),
            'has_token': bool(hz_cfg.get('api_token'))
        },
        'azure': {
            'subscription_id': az_cfg.get('subscription_id', ''),
            'resource_group': az_cfg.get('resource_group', ''),
            'vm_name': az_cfg.get('vm_name', ''),
            'nic_name': az_cfg.get('nic_name', ''),
            'tenant_id': az_cfg.get('tenant_id', ''),
            'client_id': f"{az_cfg.get('client_id', '')[:4]}****" if az_cfg.get('client_id') else '',
            'has_secret': bool(az_cfg.get('client_secret'))
        },
        'cloudflare': {
            'token_set': bool(token),
            'masked_token': masked_token,
            'zone_name': cfg.get('cloudflare', {}).get('zone_name', ''),
            'record_name': cfg.get('cloudflare', {}).get('record_name', '')
        },
        'oci': oci_status,
        'monitor': cfg.get('monitor', {}),
        'security': {
            'auth_enabled': sec_cfg.get('auth_enabled', True),
            'admin_username': sec_cfg.get('admin_username', 'admin'),
            'secret_path': sec_cfg.get('secret_path', '/sentinel'),
            'enable_host_guard': sec_cfg.get('enable_host_guard', True),
            'sub_token': sec_cfg.get('sub_token', '')
        },
        'notifications': redact_notifications(notify_cfg)
    }

@app.post('/api/settings')
@transactional
def update_settings(data: SettingsModel, request: Request):
    check_admin(request)
    cfg = cfg_mgr.load()
    if data.cf_token:
        cfg['cloudflare']['api_token'] = data.cf_token
    if data.cf_zone is not None:
        cfg['cloudflare']['zone_name'] = data.cf_zone
    if data.cf_record is not None:
        cfg['cloudflare']['record_name'] = data.cf_record
    if data.auto_heal is not None:
        cfg.setdefault('monitor', {})['auto_heal_enabled'] = data.auto_heal
    if data.auto_heal_mode is not None:
        cfg.setdefault('monitor', {})['auto_heal_mode'] = data.auto_heal_mode
    if data.reip_cooldown_hours is not None:
        cfg.setdefault('monitor', {})['reip_cooldown_hours'] = data.reip_cooldown_hours

    if 'provider' not in cfg:
        cfg['provider'] = {}
    if data.provider_type:
        cfg['provider']['type'] = data.provider_type
    if data.provider_hook is not None:
        cfg['provider']['hook_cmd'] = data.provider_hook

    if data.lightsail is not None:
        cur_ls = cfg.setdefault('lightsail', {})
        sec_k = data.lightsail.get('secret_access_key', '')
        if not sec_k or '****' in sec_k:
            sec_k = cur_ls.get('secret_access_key', '')
        ak_id = data.lightsail.get('access_key_id', '')
        if not ak_id or '****' in ak_id:
            ak_id = cur_ls.get('access_key_id', '')
        cfg['lightsail'] = {
            'access_key_id': ak_id,
            'secret_access_key': sec_k,
            'region': data.lightsail.get('region') or cur_ls.get('region', 'us-east-1'),
            'instance_name': data.lightsail.get('instance_name') or cur_ls.get('instance_name', '')
        }

    if data.hetzner is not None:
        cur_hz = cfg.setdefault('hetzner', {})
        tok = data.hetzner.get('api_token', '')
        if not tok or '****' in tok:
            tok = cur_hz.get('api_token', '')
        cfg['hetzner'] = {
            'api_token': tok,
            'server_id': data.hetzner.get('server_id') or cur_hz.get('server_id', ''),
            'ip_type': data.hetzner.get('ip_type') or cur_hz.get('ip_type', 'primary')
        }

    if data.azure is not None:
        cur_az = cfg.setdefault('azure', {})
        csec = data.azure.get('client_secret', '')
        if not csec or '****' in csec:
            csec = cur_az.get('client_secret', '')
        cid = data.azure.get('client_id', '')
        if not cid or '****' in cid:
            cid = cur_az.get('client_id', '')
        cfg['azure'] = {
            'subscription_id': data.azure.get('subscription_id') or cur_az.get('subscription_id', ''),
            'resource_group': data.azure.get('resource_group') or cur_az.get('resource_group', ''),
            'vm_name': data.azure.get('vm_name') or cur_az.get('vm_name', ''),
            'nic_name': data.azure.get('nic_name') or cur_az.get('nic_name', ''),
            'client_id': cid,
            'client_secret': csec,
            'tenant_id': data.azure.get('tenant_id') or cur_az.get('tenant_id', '')
        }

    sec = cfg.setdefault('security', {})
    if data.secret_path is not None:
        sec['secret_path'] = data.secret_path.strip() or '/sentinel'
    if data.enable_host_guard is not None:
        sec['enable_host_guard'] = data.enable_host_guard

    notifications = cfg.setdefault('notifications', {})
    if data.notifications_enabled is not None:
        notifications['enabled'] = data.notifications_enabled
    mappings = {'telegram': {'enabled': 'tg_enabled', 'bot_token': 'tg_token', 'chat_id': 'tg_chat_id'},
                'discord': {'enabled': 'discord_enabled', 'webhook_url': 'discord_webhook'},
                'bark': {'enabled': 'bark_enabled', 'bark_key': 'bark_key'},
                'custom_webhook': {'enabled': 'custom_webhook_enabled', 'url': 'custom_webhook_url'}}
    for channel, fields in mappings.items():
        section = notifications.setdefault(channel, {})
        for field, attribute in fields.items():
            value = getattr(data, attribute)
            if value is not None and not (isinstance(value, str) and '****' in value):
                section[field] = value

    cfg_mgr.save(cfg)
    log_event('System configuration updated successfully.')
    return {'status': 'ok'}

@app.post('/api/notifications/test')
async def test_notifications(request: Request, data: Optional[dict] = None):
    check_admin(request)
    cfg = cfg_mgr.load()
    if data and 'notifications' in data:
        cfg['notifications'] = data['notifications']
    
    results = await asyncio.to_thread(notification.NotificationManager.broadcast,
        cfg,
        title="Probe Alert Test / 告警测试",
        message="Universal Sentinel notification channel test successful! All systems operational.\n全能哨兵消息推送测试成功，节点状态良好。",
        level="SUCCESS"
    )
    return {'status': 'ok', 'results': results}

@app.post('/api/settings/test-cf')
def test_cf_token(data: dict, request: Request):
    check_admin(request)
    token = data.get('token') or cfg_mgr.load().get('cloudflare', {}).get('api_token')
    cf = sentinel_core.get_dns_provider({'dns': {'type': 'cloudflare', 'api_token': token}})
    ok, msg = cf.verify_token()
    return {'success': ok, 'message': msg}

# --- Authentication & Security Endpoints ---

@app.post('/api/auth/login')
def login(req: LoginRequest, request: Request, response: Response):
    client_ip = getattr(request.state, "client_ip", "") or (request.client.host if request.client else "unknown")
    ok, token_or_msg = auth.authenticate_admin(req.username, req.password, client_ip=client_ip)
    if not ok:
        raise HTTPException(status_code=401, detail=token_or_msg)
    
    # Set HttpOnly session cookie
    response.set_cookie(
        key="sentinel_session",
        value=token_or_msg,
        max_age=86400 * 30,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/"
    )
    sec = auth.get_security_config()
    return {
        "success": True,
        "token": token_or_msg,
        "sub_token": sec.get("sub_token", ""),
        "secret_path": sec.get("secret_path", "/sentinel"),
        "username": req.username,
        "must_change_password": sec.get("must_change_password", False)
    }

@app.get('/api/auth/check')
def check_auth(request: Request):
    sec = auth.get_security_config()
    authenticated = auth.is_request_authenticated(request)
    return {
        "authenticated": authenticated,
        "auth_enabled": sec.get("auth_enabled", True),
        "username": sec.get("admin_username", "admin") if authenticated else None,
        "sub_token": sec.get("sub_token", "") if authenticated else None,
        "secret_path": sec.get("secret_path", "/sentinel"),
        "must_change_password": sec.get("must_change_password", False) if authenticated else False
    }

@app.post('/api/auth/logout')
async def logout(request: Request, response: Response):
    if auth.is_privileged_request(request):
        await asyncio.to_thread(auth.revoke_sessions)
    response.delete_cookie(key="sentinel_session", path="/")
    return {"success": True}

@app.post('/api/auth/update-password')
def update_password(req: UpdatePasswordRequest, request: Request, response: Response):
    check_admin(request)
    sec = auth.get_security_config()
    current_user = sec.get("admin_username", "admin")
    client_ip = getattr(request.state, "client_ip", "") or (request.client.host if request.client else "unknown")
    ok, _ = auth.authenticate_admin(current_user, req.old_password, client_ip=client_ip)
    if not ok:
        raise HTTPException(status_code=400, detail="原密码输入错误")
    
    if not auth.update_password(req.new_password):
        raise HTTPException(status_code=400, detail="新密码长度必须为 12–1024 位")
    
    _, new_token = auth.authenticate_admin(current_user, req.new_password, client_ip=client_ip)
    response.set_cookie(
        key="sentinel_session",
        value=new_token,
        max_age=86400 * 30,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/"
    )
    return {"success": True, "message": "管理员密码已更新"}

@app.post('/api/auth/update-security')
def update_security(req: SecuritySettingsRequest, request: Request):
    check_admin(request)
    sec = auth.update_security_settings(req.model_dump(exclude_unset=True))
    return {"success": True, "security": sec}

# --- Web Onboarding / Setup Wizard Endpoints ---

class SetupSaveModel(BaseModel):
    provider_type: Literal['auto', 'oracle', 'lightsail', 'hetzner', 'azure', 'hook', 'generic'] = 'auto'
    provider_hook: Optional[str] = ''
    oci_config_text: Optional[str] = ''
    oci_key_path: Optional[str] = ''
    lightsail: Optional[dict] = None
    hetzner: Optional[dict] = None
    azure: Optional[dict] = None
    cf_token: Optional[str] = ''
    cf_zone: Optional[str] = ''
    cf_record: Optional[str] = ''
    auto_heal: bool = True
    provision_nodes: bool = True
    notifications: Optional[dict] = None

class ProviderTestModel(BaseModel):
    provider_type: str
    provider_hook: Optional[str] = ''
    oci_config_text: Optional[str] = ''
    oci_key_path: Optional[str] = ''
    lightsail: Optional[dict] = None
    hetzner: Optional[dict] = None
    azure: Optional[dict] = None

@app.get('/api/setup/status')
def setup_status(request: Request):
    cfg = cfg_mgr.load()
    is_init = cfg.get('initialized', False) or bool(cfg.get('cloudflare', {}).get('api_token'))
    is_authed = auth.is_request_authenticated(request)

    # P0-1: If already initialized and unauthenticated, restrict access to configuration
    if is_init and not is_authed:
        return {
            'initialized': True
        }

    cloud_info = sentinel_core.get_cloud_info()
    pub_ip = monitor.get_public_ip()
    ls_cfg = cfg.get('lightsail', {})
    hz_cfg = cfg.get('hetzner', {})
    az_cfg = cfg.get('azure', {})
    notif_cfg = redact_notifications(cfg.get('notifications', {}))
    return {
        'initialized': is_init,
        'cloud_info': cloud_info,
        'public_ip': pub_ip,
        'config': {
            'provider': cfg.get('provider', {}),
            'lightsail': {
                'region': ls_cfg.get('region', 'us-east-1'),
                'instance_name': ls_cfg.get('instance_name', ''),
                'access_key_id': f"{ls_cfg.get('access_key_id', '')[:4]}****" if ls_cfg.get('access_key_id') else '',
                'has_secret': bool(ls_cfg.get('secret_access_key'))
            },
            'hetzner': {
                'server_id': hz_cfg.get('server_id', ''),
                'ip_type': hz_cfg.get('ip_type', 'primary'),
                'has_token': bool(hz_cfg.get('api_token'))
            },
            'azure': {
                'subscription_id': az_cfg.get('subscription_id', ''),
                'resource_group': az_cfg.get('resource_group', ''),
                'vm_name': az_cfg.get('vm_name', ''),
                'nic_name': az_cfg.get('nic_name', ''),
                'tenant_id': az_cfg.get('tenant_id', ''),
                'client_id': f"{az_cfg.get('client_id', '')[:4]}****" if az_cfg.get('client_id') else '',
                'has_secret': bool(az_cfg.get('client_secret'))
            },
            'cloudflare': {
                'zone_name': cfg.get('cloudflare', {}).get('zone_name', ''),
                'record_name': cfg.get('cloudflare', {}).get('record_name', '')
            },
            'notifications': notif_cfg
        }
    }

@app.post('/api/provider/test')
def test_provider_endpoint(data: ProviderTestModel, request: Request):
    check_setup_allowed(request)
    ptype = data.provider_type
    try:
        if ptype == 'oracle':
            prov = sentinel_core.OracleCloudProvider(config_path=data.oci_key_path)
            ok, msg = prov.test_connection()
            return {'success': ok, 'message': msg}
        elif ptype == 'lightsail':
            ls = data.lightsail or {}
            cfg = cfg_mgr.load().get('lightsail', {})
            ak = ls.get('access_key_id') or cfg.get('access_key_id', '')
            sk = ls.get('secret_access_key') or cfg.get('secret_access_key', '')
            reg = ls.get('region') or cfg.get('region', 'us-east-1')
            inst = ls.get('instance_name') or cfg.get('instance_name', '')
            prov = sentinel_core.LightsailCloudProvider(
                access_key_id=ak,
                secret_access_key=sk,
                region=reg,
                instance_name=inst
            )
            ok, msg = prov.test_connection()
            return {'success': ok, 'message': msg}
        elif ptype == 'hetzner':
            hz = data.hetzner or {}
            cfg = cfg_mgr.load().get('hetzner', {})
            tok = hz.get('api_token') or cfg.get('api_token', '')
            sid = hz.get('server_id') or cfg.get('server_id', '')
            ipt = hz.get('ip_type') or cfg.get('ip_type', 'primary')
            prov = sentinel_core.HetznerCloudProvider(
                api_token=tok,
                server_id=sid,
                ip_type=ipt
            )
            ok, msg = prov.test_connection()
            return {'success': ok, 'message': msg}
        elif ptype == 'azure':
            az = data.azure or {}
            cfg = cfg_mgr.load().get('azure', {})
            sub = az.get('subscription_id') or cfg.get('subscription_id', '')
            rg = az.get('resource_group') or cfg.get('resource_group', '')
            vm = az.get('vm_name') or cfg.get('vm_name', '')
            nic = az.get('nic_name') or cfg.get('nic_name', '')
            cid = az.get('client_id') or cfg.get('client_id', '')
            csec = az.get('client_secret') or cfg.get('client_secret', '')
            tid = az.get('tenant_id') or cfg.get('tenant_id', '')
            prov = sentinel_core.AzureCloudProvider(
                subscription_id=sub,
                resource_group=rg,
                vm_name=vm,
                nic_name=nic,
                client_id=cid,
                client_secret=csec,
                tenant_id=tid
            )
            ok, msg = prov.test_connection()
            return {'success': ok, 'message': msg}
        elif ptype == 'hook':
            cmd = data.provider_hook or cfg_mgr.load().get('provider', {}).get('hook_cmd', '')
            prov = sentinel_core.CustomHookProvider(hook_cmd=cmd)
            ok, msg = prov.test_connection()
            return {'success': ok, 'message': msg}
        elif ptype == 'auto':
            cfg = cfg_mgr.load()
            prov = sentinel_core.get_cloud_provider(cfg)
            ok, msg = prov.test_connection()
            return {'success': ok, 'message': f'Auto-detected ({prov.get_name()}): {msg}'}
        else:
            prov = sentinel_core.GenericProvider()
            ok, msg = prov.test_connection()
            return {'success': ok, 'message': msg}
    except Exception as e:
        return {'success': False, 'message': str(e)}

@app.post('/api/setup/verify-cf')
def verify_cf(data: dict, request: Request):
    check_setup_allowed(request)
    token = data.get('token', '').strip()
    if not token:
        return {'success': False, 'message': 'API Token 不能为空'}
    cf = sentinel_core.get_dns_provider({'dns': {'type': 'cloudflare', 'api_token': token}})
    ok, zones, msg = cf.list_zones()
    return {'success': ok, 'zones': zones, 'message': msg}

@app.post('/api/setup/generate-key')
def generate_key(request: Request):
    check_setup_allowed(request)
    try:
        pub_key, key_path = sentinel_core.generate_rsa_keypair()
        return {'success': True, 'public_key': pub_key, 'key_path': key_path}
    except Exception as e:
        return {'success': False, 'message': str(e)}

@app.post('/api/setup/save')
def complete_setup(data: SetupSaveModel, request: Request):
    check_setup_allowed(request)
    with config_transaction():
        cfg = cfg_mgr.load()
        cfg['initialized'] = True
        cfg['provider'] = {
            'type': data.provider_type,
            'hook_cmd': data.provider_hook or ''
        }
        if data.cf_token:
            cfg['cloudflare']['api_token'] = data.cf_token
        if data.cf_zone:
            cfg['cloudflare']['zone_name'] = data.cf_zone
        if data.cf_record:
            cfg['cloudflare']['record_name'] = data.cf_record
    
        cfg['monitor']['auto_heal_enabled'] = data.auto_heal
    
        # If OCI config provided
        if data.provider_type == 'oracle' and data.oci_config_text:
            key_path = data.oci_key_path or os.path.join(sentinel_core.OCI_DIR, 'oci_api_key.pem')
            try:
                cfg_path = sentinel_core.save_oci_config(data.oci_config_text, key_path)
                cfg['oci']['config_path'] = cfg_path
                cfg['oci']['auth_method'] = 'config_file'
            except Exception as e:
                logger.warning(f"Error saving OCI config: {e}")

        if data.lightsail:
            cur_ls = cfg.setdefault('lightsail', {})
            sec_k = data.lightsail.get('secret_access_key', '')
            if not sec_k or '****' in sec_k:
                sec_k = cur_ls.get('secret_access_key', '')
            ak_id = data.lightsail.get('access_key_id', '')
            if not ak_id or '****' in ak_id:
                ak_id = cur_ls.get('access_key_id', '')
            cfg['lightsail'] = {
                'access_key_id': ak_id,
                'secret_access_key': sec_k,
                'region': data.lightsail.get('region') or cur_ls.get('region', 'us-east-1'),
                'instance_name': data.lightsail.get('instance_name') or cur_ls.get('instance_name', '')
            }

        if data.hetzner:
            cur_hz = cfg.setdefault('hetzner', {})
            tok = data.hetzner.get('api_token', '')
            if not tok or '****' in tok:
                tok = cur_hz.get('api_token', '')
            cfg['hetzner'] = {
                'api_token': tok,
                'server_id': data.hetzner.get('server_id') or cur_hz.get('server_id', ''),
                'ip_type': data.hetzner.get('ip_type') or cur_hz.get('ip_type', 'primary')
            }

        if data.azure:
            cur_az = cfg.setdefault('azure', {})
            csec = data.azure.get('client_secret', '')
            if not csec or '****' in csec:
                csec = cur_az.get('client_secret', '')
            cid = data.azure.get('client_id', '')
            if not cid or '****' in cid:
                cid = cur_az.get('client_id', '')
            cfg['azure'] = {
                'subscription_id': data.azure.get('subscription_id') or cur_az.get('subscription_id', ''),
                'resource_group': data.azure.get('resource_group') or cur_az.get('resource_group', ''),
                'vm_name': data.azure.get('vm_name') or cur_az.get('vm_name', ''),
                'nic_name': data.azure.get('nic_name') or cur_az.get('nic_name', ''),
                'client_id': cid,
                'client_secret': csec,
                'tenant_id': data.azure.get('tenant_id') or cur_az.get('tenant_id', '')
            }

        if data.notifications:
            cfg['notifications'] = data.notifications

        cfg_mgr.save(cfg)

    # Optionally provision 3x-ui inbounds
    if data.provision_nodes and data.cf_record:
        try:
            script_path = os.path.join(BASE_DIR, 'scripts')
            if script_path not in sys.path:
                sys.path.insert(0, script_path)
            import node_provisioner
            node_provisioner.provision_nodes(domain=data.cf_record)
        except Exception as e:
            logger.warning(f"Auto-provision nodes warning: {e}")

    log_event('Web 初始化向导配置已完成，Sentinel 引擎已全面接管自愈守护！', 'INFO')
    return {'success': True, 'message': 'Setup completed successfully'}

class QuickStartRequest(BaseModel):
    outbound_mode: Literal['edgetunnel', 'native'] = 'edgetunnel'
    admin_password: Optional[str] = Field(default=None, min_length=12, max_length=1024)
    pages_domain: Optional[str] = None
    pages_uuid: Optional[str] = None
    worker_domain: Optional[str] = None
    worker_uuid: Optional[str] = None

@app.post('/api/setup/quick-start')
def quick_start_setup(data: QuickStartRequest, request: Request):
    check_setup_allowed(request)
    with config_transaction():
        cfg = cfg_mgr.load()
        cfg['initialized'] = True
        cfg.setdefault('provider', {})['type'] = 'auto'
        cfg.setdefault('monitor', {})['auto_heal_enabled'] = True

        sec = cfg.setdefault('security', {})
        if data.admin_password and 12 <= len(data.admin_password.strip()) <= 1024:
            sec['admin_password_hash'] = auth.hash_password(data.admin_password.strip())
            sec['session_secret'] = secrets.token_hex(32)
            sec['must_change_password'] = False

        if not sec.get('sub_token'):
            sec['sub_token'] = secrets.token_hex(16)
        sub_token = sec['sub_token']

        if data.outbound_mode == 'edgetunnel':
            edt = cfg.setdefault('edgetunnel', {})
            edt['enabled'] = True
            if data.pages_domain:
                edt['pages_domain'] = clean_ip_mgr.sanitize_domain(data.pages_domain)
            if data.pages_uuid:
                clean_uuid = clean_ip_mgr.validate_uuid(data.pages_uuid)
                if not clean_uuid: raise HTTPException(status_code=422, detail='Invalid Pages UUID')
                edt['pages_uuid'] = clean_uuid
            if data.worker_domain:
                edt['worker_domain'] = clean_ip_mgr.sanitize_domain(data.worker_domain)
            if data.worker_uuid:
                clean_w_uuid = clean_ip_mgr.validate_uuid(data.worker_uuid)
                if not clean_w_uuid: raise HTTPException(status_code=422, detail='Invalid Worker UUID')
                edt['worker_uuid'] = clean_w_uuid
            clean_ip_mgr.CleanIPManager.refresh_clean_ips(active_test=False)
        else:
            cfg.setdefault('edgetunnel', {})['enabled'] = False
            try:
                script_path = os.path.join(BASE_DIR, 'scripts')
                if script_path not in sys.path:
                    sys.path.insert(0, script_path)
                import node_provisioner
                node_provisioner.provision_nodes()
            except Exception as e:
                logger.warning(f"Native nodes auto-provision note: {e}")

        cfg_mgr.save(cfg)

    log_event('Web 极速向导配置已完成，系统已就绪！', 'INFO')
    return {
        'success': True,
        'message': 'Quick start setup completed successfully',
        'sub_token': sub_token,
        'urls': {
            'clash': f'/sub/clash?token={sub_token}',
            'singbox': f'/sub/singbox?token={sub_token}',
            'v2ray': f'/sub/v2ray?token={sub_token}'
        }
    }

# --- Subscription Engine Endpoints ---

@app.api_route('/sub/clash', methods=['GET', 'HEAD'])
def get_clash_sub(request: Request):
    if not auth.verify_subscription_access(request):
        raise HTTPException(status_code=403, detail="订阅 Token 无效或未提供，拒绝访问")
    yaml_content = sub_engine.SubEngine.generate_clash_yaml()
    headers = {
        'Content-Disposition': 'inline; filename="oracle_sentinel_clash.yaml"',
        'subscription-userinfo': 'upload=1073741824; download=5368709120; total=1073741824000; expire=0',
        'profile-update-interval': '24'
    }
    return Response(content=yaml_content, media_type='text/yaml; charset=utf-8', headers=headers)

@app.api_route('/sub/v2ray', methods=['GET', 'HEAD'])
@app.api_route('/sub/base64', methods=['GET', 'HEAD'])
@app.api_route('/sub/shadowrocket', methods=['GET', 'HEAD'])
def get_v2ray_sub(request: Request):
    if not auth.verify_subscription_access(request):
        raise HTTPException(status_code=403, detail="订阅 Token 无效或未提供，拒绝访问")
    b64_content = sub_engine.SubEngine.generate_v2ray_base64()
    headers = {
        'Content-Disposition': 'inline; filename="oracle_nodes.txt"',
        'subscription-userinfo': 'upload=1073741824; download=5368709120; total=1073741824000; expire=0',
        'profile-update-interval': '24'
    }
    return Response(content=b64_content, media_type='text/plain; charset=utf-8', headers=headers)

@app.api_route('/sub/singbox', methods=['GET', 'HEAD'])
def get_singbox_sub(request: Request):
    if not auth.verify_subscription_access(request):
        raise HTTPException(status_code=403, detail="订阅 Token 无效或未提供，拒绝访问")
    json_content = sub_engine.SubEngine.generate_singbox_json()
    headers = {
        'Content-Disposition': 'inline; filename="singbox_config.json"',
        'profile-update-interval': '24'
    }
    return Response(content=json_content, media_type='application/json; charset=utf-8', headers=headers)

@app.get('/api/sub/rules')
def get_sub_rules(request: Request):
    check_admin(request)
    return sub_engine.SubEngine.get_rules_config()

@app.post('/api/sub/rules')
def set_sub_rules(rules: dict, request: Request):
    check_admin(request)
    sub_engine.SubEngine.save_rules_config(rules)
    log_event('Subscription routing rules updated successfully.')
    return {'status': 'ok', 'rules': rules}

# --- Transit / Relay Endpoints ---

class TransitCreateModel(BaseModel):
    name: str
    host: str
    hy2_port: int = 20443
    reality_port: int = 28443
    trojan_port: int = 22083

    @field_validator('host')
    @classmethod
    def validate_host(cls, value):
        from validation import host
        return host(value)

    @field_validator('hy2_port', 'reality_port', 'trojan_port')
    @classmethod
    def validate_ports(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

@app.get('/api/transits')
def list_transits(request: Request):
    check_admin(request)
    return transit_mgr.TransitManager.get_transits()

@app.post('/api/transits')
def create_transit(item: TransitCreateModel, request: Request):
    check_admin(request)
    res = transit_mgr.TransitManager.add_transit(
        name=item.name,
        host=item.host,
        hy2_port=item.hy2_port,
        reality_port=item.reality_port,
        trojan_port=item.trojan_port
    )
    log_event(f'Added new transit relay node: {item.name} ({item.host})')
    return {'status': 'ok', 'transit': res}

@app.delete('/api/transits/{transit_id}')
def delete_transit(transit_id: str, request: Request):
    check_admin(request)
    transit_mgr.TransitManager.delete_transit(transit_id)
    log_event(f'Removed transit relay node ID: {transit_id}')
    return {'status': 'ok'}

@app.post('/api/transits/{transit_id}/toggle')
def toggle_transit(transit_id: str, data: dict, request: Request):
    check_admin(request)
    enabled = data.get('enabled', True)
    transit_mgr.TransitManager.toggle_transit(transit_id, enabled)
    return {'status': 'ok'}

@app.get('/scripts/setup-relay.sh')
def get_relay_script():
    domain = sub_engine.SubEngine.get_server_domain()
    script = transit_mgr.TransitManager.generate_realm_script(domain)
    return Response(content=script, media_type='text/x-shellscript')

# --- Custom Standalone Nodes Endpoints ---

@app.get('/api/custom-nodes')
def list_custom_nodes(request: Request):
    check_admin(request)
    return custom_node_mgr.CustomNodeManager.get_custom_nodes()

@app.post('/api/custom-nodes')
def create_custom_node(item: dict, request: Request):
    check_admin(request)
    try:
        res = custom_node_mgr.CustomNodeManager.add_custom_node(item)
        log_event(f'Added custom node: {res.get("name")} ({res.get("server")}:{res.get("port")})')
        return {'status': 'ok', 'node': res}
    except Exception as e:
        logger.error(f'Failed to add custom node: {e}')
        raise HTTPException(status_code=400, detail=str(e))

@app.delete('/api/custom-nodes/{node_id}')
def delete_custom_node(node_id: str, request: Request):
    check_admin(request)
    custom_node_mgr.CustomNodeManager.delete_custom_node(node_id)
    log_event(f'Removed custom node ID: {node_id}')
    return {'status': 'ok'}

@app.post('/api/custom-nodes/{node_id}/toggle')
def toggle_custom_node(node_id: str, data: dict, request: Request):
    check_admin(request)
    enabled = data.get('enabled', True)
    custom_node_mgr.CustomNodeManager.toggle_custom_node(node_id, enabled)
    return {'status': 'ok'}

# --- EdgeTunnel (EDT) Integration API ---
@app.get('/api/edt/config')
def get_edt_config(request: Request):
    check_admin(request)
    cfg = cfg_mgr.load()
    edt = cfg.get('edgetunnel', {})
    clean_ips = clean_ip_mgr.CleanIPManager.get_clean_ips()
    return {
        'status': 'ok',
        'edgetunnel': {
            'enabled': bool(edt.get('enabled', False)),
            'pages_domain': edt.get('pages_domain', ''),
            'worker_domain': edt.get('worker_domain', ''),
            'uuid': edt.get('uuid', ''),
            'pages_uuid': edt.get('pages_uuid', ''),
            'worker_uuid': edt.get('worker_uuid', ''),
            'path': edt.get('path', '/?ed=2048'),
            'proxy_ip': edt.get('proxy_ip', ''),
            'benchmark': edt.get('benchmark', 'cloudflare'),
            'clean_ips': clean_ips,
            'auto_refresh_clean_ips': bool(edt.get('auto_refresh_clean_ips', True)),
            'enable_fallback_group': bool(edt.get('enable_fallback_group', True)),
            'candidates': edt.get('optimizer', {}).get('candidates', []),
            'sources': edt.get('optimizer', {}).get('sources', []),
            'interval_sec': edt.get('optimizer', {}).get('interval_sec', 3600)
        }
    }

@app.post('/api/edt/config')
@transactional
def save_edt_config(data: dict, request: Request):
    check_admin(request)
    from edt_optimizer import validate_candidate, endpoints
    from validation import https_url
    proposed = dict(cfg_mgr.load().get('edgetunnel', {}))
    proposed.update({k: data[k] for k in ('enabled', 'pages_domain', 'worker_domain', 'uuid', 'pages_uuid', 'worker_uuid', 'path', 'proxy_ip', 'benchmark') if k in data})
    try:
        for name in ('pages_domain', 'worker_domain'):
            if name in data:
                if not isinstance(data[name], str):
                    raise ValueError('Endpoint domains must be strings')
                proposed[name] = clean_ip_mgr.sanitize_domain(data[name])
        if proposed.get('benchmark', 'cloudflare') not in ('cloudflare', 'wikimedia'):
            raise ValueError('Unsupported benchmark target')
        if proposed.get('enabled'): endpoints(proposed)
        candidates = [validate_candidate(v) for v in data.get('candidates', [])]
        sources = [https_url(v) for v in data.get('sources', [])]
        if len(candidates) > 24 or len(sources) > 3: raise ValueError('At most 24 candidates and 3 sources')
        interval = int(data.get('interval_sec', 3600))
        if not 900 <= interval <= 86400: raise ValueError('Refresh interval must be 900–86400 seconds')
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    cfg = cfg_mgr.load()
    if 'edgetunnel' not in cfg:
        cfg['edgetunnel'] = {}

    edt = cfg['edgetunnel']
    opt = edt.setdefault('optimizer', {})
    for key, value in (('candidates', candidates), ('sources', sources), ('interval_sec', interval)):
        if key in data: opt[key] = value
    for k in ('enabled', 'pages_domain', 'worker_domain', 'uuid', 'pages_uuid', 'worker_uuid', 'path', 'proxy_ip', 'benchmark', 'auto_refresh_clean_ips', 'enable_fallback_group'):
        if k in data:
            val = data[k]
            if k in ('pages_domain', 'worker_domain') and isinstance(val, str):
                val = clean_ip_mgr.sanitize_domain(val)
            edt[k] = val

    cfg_mgr.save(cfg)
    if 'clean_ips' in data and isinstance(data['clean_ips'], dict):
        clean_ip_mgr.CleanIPManager.save_clean_ips(data['clean_ips'])

    log_event('EdgeTunnel configuration updated.')
    return {'status': 'ok', 'message': 'EdgeTunnel configuration saved successfully'}

@app.post('/api/edt/refresh-clean-ips')
def refresh_edt_clean_ips(request: Request):
    check_admin(request)
    try:
        from edt_optimizer import Optimizer
        started = Optimizer.start()
        return {'status': 'started' if started else 'running', 'optimizer': Optimizer.status(),
                'clean_ips': clean_ip_mgr.CleanIPManager.get_clean_ips()}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

@app.get('/api/edt/optimizer')
def edt_optimizer_status(request: Request):
    check_admin(request)
    from edt_optimizer import Optimizer
    return Optimizer.status()

class EdtAgentRegistration(BaseModel):
    isp: Literal['telecom', 'unicom', 'mobile']
    region: str = Field(min_length=1, max_length=64)

@app.post('/api/edt/agents')
def register_edt_agent(data: EdtAgentRegistration, request: Request):
    check_admin(request)
    token = secrets.token_urlsafe(32)
    agent = {'id': secrets.token_hex(8), 'isp': data.isp, 'region': data.region,
             'token_hash': hashlib.sha256(token.encode()).hexdigest()}
    def save(cfg):
        agents = cfg.setdefault('edgetunnel', {}).setdefault('optimizer', {}).setdefault('agents', [])
        if len(agents) >= 12: raise ValueError('At most 12 probes')
        agents.append(agent)
    try: cfg_mgr.update(save)
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc))
    return {'id': agent['id'], 'token': token}

@app.delete('/api/edt/agents/{agent_id}')
def revoke_edt_agent(agent_id: str, request: Request):
    check_admin(request)
    def remove(cfg):
        opt = cfg.setdefault('edgetunnel', {}).setdefault('optimizer', {})
        opt['agents'] = [a for a in opt.get('agents', []) if a['id'] != agent_id]
        opt.get('reports', {}).pop(agent_id, None)
        opt.get('tasks', {}).pop(agent_id, None)
    cfg_mgr.update(remove)
    return {'status': 'ok'}

def check_edt_agent(request):
    from edt_optimizer import authenticate_agent
    token = request.headers.get('authorization', '').removeprefix('Bearer ')
    if len(token) > 128: raise HTTPException(status_code=401, detail='Invalid probe credential')
    try: return authenticate_agent(token)
    except ValueError: raise HTTPException(status_code=401, detail='Invalid probe credential')

@app.get('/api/edt/probe/task')
@transactional
def get_edt_probe_task(request: Request):
    agent = check_edt_agent(request)
    from edt_optimizer import Optimizer
    opt = cfg_mgr.load().get('edgetunnel', {}).get('optimizer', {})
    old = opt.get('tasks', {}).get(agent['id'])
    if old and old['expires_at'] > time.time():
        if old.get('reported'): raise HTTPException(status_code=409, detail='Next task available after current task expires')
        return old
    try: task = Optimizer.task()
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc))
    def save(cfg):
        current = cfg.setdefault('edgetunnel', {}).setdefault('optimizer', {})
        if not any(a['id'] == agent['id'] for a in current.get('agents', [])):
            raise HTTPException(status_code=401, detail='Probe revoked')
        current.setdefault('tasks', {})[agent['id']] = task
    cfg_mgr.update(save)
    return task

class EdtProbeRow(BaseModel):
    ip: str = Field(max_length=45)
    success_rate: float = Field(ge=0, le=1, allow_inf_nan=False)
    latency_ms: Optional[float] = Field(default=None, ge=0, le=120000, allow_inf_nan=False)
    jitter_ms: Optional[float] = Field(default=None, ge=0, le=120000, allow_inf_nan=False)
    download_mbps: Optional[float] = Field(default=None, ge=0, le=100000, allow_inf_nan=False)

class EdtProbeReport(BaseModel):
    task_id: str = Field(max_length=64)
    results: List[EdtProbeRow] = Field(min_length=1, max_length=24)

@app.post('/api/edt/probe/report')
def report_edt_probe(data: EdtProbeReport, request: Request):
    agent = check_edt_agent(request)
    from edt_optimizer import Optimizer
    task = cfg_mgr.load().get('edgetunnel', {}).get('optimizer', {}).get('tasks', {}).get(agent['id'])
    if not task or task['id'] != data.task_id or task['expires_at'] < time.time():
        raise HTTPException(status_code=409, detail='Task expired; request a new task')
    rows = [r.model_dump() for r in data.results]
    if len({r['ip'] for r in rows}) != len(rows) or {r['ip'] for r in rows} != set(task['candidates']):
        raise HTTPException(status_code=422, detail='Report must cover each task candidate exactly once')
    if any(r['success_rate'] > 0 and any(r[k] is None for k in ('latency_ms','jitter_ms','download_mbps')) for r in rows):
        raise HTTPException(status_code=422, detail='Successful measurements need latency, jitter and throughput')
    try: Optimizer.store(rows, agent['isp'], task['fingerprint'], agent['id'], data.task_id)
    except ValueError as exc: raise HTTPException(status_code=409, detail=str(exc))
    return {'status': 'ok'}

@app.get('/api/edt/status')
def get_edt_status(request: Request):
    check_admin(request)
    endpoints = mesh_mgr.MeshManager.get_serverless_endpoints()
    results = []
    for ep in endpoints:
        probe = mesh_mgr.MeshManager.probe_serverless_endpoint(ep['domain'])
        ep_res = dict(ep)
        ep_res['last_status'] = probe
        results.append(ep_res)
    return {'status': 'ok', 'endpoints': results}

@app.get('/api/services')
def get_services(request: Request):
    check_admin(request)
    xui_base_path = '/'
    xui_port = 20530
    db_path = '/etc/x-ui/x-ui.db'
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT value FROM settings WHERE key = 'webBasePath'")
            r = c.fetchone()
            if r and r[0]: xui_base_path = r[0].strip()
            c.execute("SELECT value FROM settings WHERE key = 'webPort'")
            r = c.fetchone()
            if r and r[0]: xui_port = int(r[0])
            conn.close()
        except Exception as e:
            logger.warning(f"Error querying x-ui.db settings: {e}")

    def is_listening(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            res = s.connect_ex(('127.0.0.1', port))
            s.close()
            return res == 0
        except Exception:
            return False

    services = [
        {
            "id": "kuma-status",
            "name": "Uptime Kuma 探针状态大屏",
            "category": "dashboard",
            "proto": "https",
            "port": 3001,
            "path": "/status/services",
            "badge": "16 Probes",
            "desc": "实时监测甲骨文美西核心、日本绿云原生机、云端套件与全球 AI 节点（OpenAI/Anthropic）连通率与毫秒级延迟。",
            "running": is_listening(3001)
        },
        {
            "id": "xui",
            "name": "3x-ui 核心节点面板",
            "category": "admin",
            "proto": "https",
            "port": xui_port,
            "path": xui_base_path,
            "badge": "Xray Core",
            "desc": "VLESS-Reality / Hysteria 2 / Trojan 原生节点配置、公私钥证书管理与实时流量审计。",
            "running": is_listening(xui_port)
        },
        {
            "id": "kuma-admin",
            "name": "Uptime Kuma 运维后台",
            "category": "admin",
            "proto": "https",
            "port": 3001,
            "path": "/",
            "badge": "Telemetry",
            "desc": "探针目标增删、心跳频率调整、Telegram / Discord / Bark 即时阻断告警通道配置。",
            "running": is_listening(3001)
        },
        {
            "id": "substore",
            "name": "Sub-Store 订阅大脑",
            "category": "admin",
            "proto": "https",
            "port": 3000,
            "path": "/?api=/api",
            "badge": "Subscription",
            "desc": "节点清洗过滤、多机场聚合、正则批量重命名与 Clash / Sing-box / Surge 跨平台分流规则转换。",
            "running": is_listening(3000)
        },
        {
            "id": "alist",
            "name": "Alist 全网盘挂载中心",
            "category": "admin",
            "proto": "https",
            "port": 5244,
            "path": "/",
            "badge": "WebDAV 4K",
            "desc": "聚合挂载阿里云盘、夸克、百度网盘、OneDrive，支持 4K WebDAV 原画免下载高速串流播放。",
            "running": is_listening(5244)
        }
    ]
    return {
        "status": "ok",
        "services": services,
        "xui_base_path": xui_base_path,
        "xui_port": xui_port
    }

class HealTriggerModel(BaseModel):
    force: Optional[bool] = False

# --- Healing Sequence ---

async def run_healing_routine(trigger_source='MANUAL', force=False) -> dict:
    if runtime_state['heal_in_progress']:
        return {'ok': False, 'error': 'Healing routine already in progress', 'duration_sec': 0.0, 'new_ip': '', 'dns_ok': False}

    cfg = cfg_mgr.load()
    mon_cfg = cfg.get('monitor', {})
    now = time.time()
    t_start = now

    # P1-7: Rolling 24-hour quota and cooldown checks
    reip_history = [t for t in mon_cfg.get('reip_history', []) if (now - t) < 86400]
    mr = mon_cfg.get('max_reip_per_day')
    max_reip = 2 if mr is None else int(mr)
    ch = mon_cfg.get('reip_cooldown_hours')
    cooldown_hours = 24 if ch is None else int(ch)
    cooldown_sec = cooldown_hours * 3600
    last_reip = mon_cfg.get('last_reip_timestamp') or 0

    if not force:
        if len(reip_history) >= max_reip:
            msg = f"Daily Re-IP quota exceeded ({len(reip_history)}/{max_reip} in last 24h). Trigger aborted."
            logger.warning(msg)
            await broadcast_log(f'[WARN] {msg}', 'WARN')
            await asyncio.to_thread(notification.NotificationManager.broadcast,
                cfg,
                title="Re-IP Quota Exceeded / 换IP已达每日上限",
                message=msg,
                level="WARN"
            )
            monitor.consecutive_failures = 0
            return {'ok': False, 'error': msg, 'duration_sec': 0.0, 'new_ip': '', 'dns_ok': False}

        if trigger_source == 'AUTO' and (now - last_reip) < cooldown_sec:
            rem_h = round((cooldown_sec - (now - last_reip)) / 3600, 1)
            msg = f"Auto Re-IP suppressed by cooldown circuit breaker. Last Re-IP cooldown has {rem_h}h remaining ({cooldown_hours}h window)."
            logger.warning(msg)
            await broadcast_log(f'[WARN] {msg}', 'WARN')
            await asyncio.to_thread(notification.NotificationManager.broadcast,
                cfg,
                title="Re-IP Cooldown Active / 换IP保护中",
                message=msg,
                level="WARN"
            )
            monitor.consecutive_failures = 0
            return {'ok': False, 'error': msg, 'duration_sec': 0.0, 'new_ip': '', 'dns_ok': False}

    import uuid
    operation_id = uuid.uuid4().hex
    def reserve(current):
        operation = current.setdefault('monitor', {}).get('healing_operation', {})
        if operation.get('phase') in ('changing_ip', 'allocated', 'uncertain') or (operation.get('phase') == 'preflight' and time.time() - operation.get('started_at', 0) < 600):
            raise RuntimeError('A previous IP operation needs reconciliation before another attempt')
        current['monitor']['healing_operation'] = {'id': operation_id, 'phase': 'preflight', 'started_at': now}
    runtime_state['heal_in_progress'] = True
    try:
        await asyncio.to_thread(cfg_mgr.update, reserve)
    except Exception as exc:
        runtime_state['heal_in_progress'] = False
        return {'ok': False, 'error': str(exc), 'new_ip': '', 'duration_sec': 0, 'dns_ok': False}
    runtime_state['status'] = 'healing'

    prov_name = 'uninitialized'
    try:
        old_ip = await asyncio.to_thread(monitor.get_public_ip)
        await broadcast_log(f'[HEAL STEP 1/5] Initiated {trigger_source} Re-IP rebirth routine (current IP: {old_ip})...', 'WARN')
        await asyncio.sleep(1)

        cf_token = sentinel_core.dns_settings(cfg).get('api_token')
        cf_zone = sentinel_core.dns_settings(cfg).get('zone_name', '')
        cf_record = sentinel_core.dns_settings(cfg).get('record_name', '')

        cloud_prov = await asyncio.to_thread(sentinel_core.get_cloud_provider, cfg)
        prov_name = cloud_prov.get_name()
        loop = asyncio.get_running_loop()

        # P1-10 Pre-flight check before releasing current IP
        await broadcast_log(f'[HEAL PRE-FLIGHT] Validating credentials and connectivity for {prov_name}...')
        conn_ok, conn_msg = await loop.run_in_executor(None, cloud_prov.test_connection)
        if not conn_ok:
            err_msg = f"Pre-flight provider validation failed: {conn_msg}. Aborting IP rebirth to prevent instance isolation."
            logger.error(err_msg)
            await broadcast_log(f'[ERROR] {err_msg}', 'ERROR')
            await asyncio.to_thread(notification.NotificationManager.broadcast,
                cfg,
                title="Healing Pre-Flight Failed / 自动修复预检失败",
                message=err_msg,
                level="ERROR"
            )
            runtime_state['status'] = 'warning'
            dt = round(time.time() - t_start, 1)
            return {'ok': False, 'error': err_msg, 'duration_sec': dt, 'new_ip': '', 'dns_ok': False}

        def mark_changing(current):
            mon = current.setdefault('monitor', {})
            mon['healing_operation'].update(phase='changing_ip', old_ip=old_ip)
            hist = [t for t in mon.get('reip_history', []) if time.time() - t < 86400]
            mon['reip_history'] = hist + [int(time.time())]
            mon['last_reip_timestamp'] = int(time.time())
        await asyncio.to_thread(cfg_mgr.update, mark_changing)
        # Step 2: IP swap via Provider
        await broadcast_log(f'[HEAL STEP 2/5] Initiating IP rebirth via provider: {prov_name}...')
        new_ip = await loop.run_in_executor(None, cloud_prov.change_public_ip)
        def mark_allocated(current):
            mon = current.setdefault('monitor', {})
            mon['healing_operation'].update(phase='allocated', new_ip=new_ip)
            mon['last_reip_new_ip'] = new_ip
            mon['dns_sync_pending'] = bool(cf_record)
        await asyncio.to_thread(cfg_mgr.update, mark_allocated)
        await broadcast_log(f'[HEAL STEP 3/5] Fresh Public IP acquired: {new_ip}', 'INFO')
        await asyncio.sleep(1)

        # Step 3: Cloudflare DNS update
        dns_ok = False
        if cf_record and (cf_token or sentinel_core.dns_settings(cfg).get('type') == 'webhook'):
            await broadcast_log(f'[HEAL STEP 4/5] Updating Cloudflare DNS: {cf_record} -> {new_ip}...')
            cf_mgr = sentinel_core.get_dns_provider(cfg, cf_zone)
            try:
                dns_res = await loop.run_in_executor(None, cf_mgr.update_dns_record, cf_record, new_ip)
                dns_ok = bool(dns_res)
                if dns_ok:
                    await broadcast_log('[OK] [HEAL STEP 4/5] Cloudflare DNS record updated successfully!')
                else:
                    await broadcast_log('[WARN] [HEAL STEP 4/5] Cloudflare DNS update returned False/empty.', 'WARN')
            except Exception as cf_err:
                logger.warning(f"Cloudflare DNS update error: {cf_err}")
                await broadcast_log(f'[WARN] [HEAL STEP 4/5] Cloudflare DNS update failed: {cf_err}', 'WARN')
        else:
            await broadcast_log('[WARN] [HEAL STEP 4/5] Cloudflare token not set; skipping DNS update.', 'WARN')

        # Step 4: Verification (P1-10)
        await broadcast_log('[HEAL STEP 5/5] Verifying edge routing, external egress IP & health state...')
        actual_ip = await loop.run_in_executor(None, monitor.get_public_ip)
        ip_matched = (actual_ip == new_ip) if actual_ip and actual_ip != '127.0.0.1' else False
        dns_required = bool(cf_record)
        dns_matched = (not dns_required) or dns_ok

        # Update persistent history and Re-IP state in config atomically
        def _record_reip(c):
            mon = c.setdefault('monitor', {})
            hist = [t for t in mon.get('reip_history', []) if (time.time() - t) < 86400]
            # Attempt quota was already reserved before the destructive operation.
            mon['reip_history'] = hist
            mon['last_reip_timestamp'] = int(time.time())
            mon['last_reip_old_ip'] = old_ip
            mon['last_reip_new_ip'] = new_ip
            mon['dns_sync_pending'] = not dns_matched
            mon['healing_operation']['phase'] = 'completed'
            return True

        cfg_mgr.update(_record_reip)

        runtime_state['last_healed'] = time.strftime('%Y-%m-%d %H:%M:%S')
        runtime_state['heal_count'] += 1
        monitor.consecutive_failures = 0
        dt = round(time.time() - t_start, 1)

        is_success = ip_matched and dns_matched
        if is_success:
            runtime_state['status'] = 'healthy'
            await broadcast_log(f'[OK] Rebirth completed and verified in {dt}s! Server is now operational on IP: {new_ip}')
            await asyncio.to_thread(notification.NotificationManager.broadcast,
                cfg,
                title="IP Swapped & Restored / 节点IP重生命名成功",
                message=f"[OK] Rebirth routine succeeded and verified!\nProvider: {prov_name}\nNew IP: {new_ip}\nCloudflare DNS: {cf_record} -> {new_ip}\nDuration: {dt}s",
                level="SUCCESS"
            )
            return {'ok': True, 'new_ip': new_ip, 'error': '', 'duration_sec': dt, 'dns_ok': dns_ok}
        else:
            runtime_state['status'] = 'warning'
            warn_msg = (
                f"[WARN] Rebirth executed in {dt}s (new IP: {new_ip}), but verification flagged issues: "
                f"egress IP match: {ip_matched} (actual {actual_ip}), DNS ok: {dns_ok}."
            )
            await broadcast_log(warn_msg, 'WARN')
            await asyncio.to_thread(notification.NotificationManager.broadcast,
                cfg,
                title="IP Swapped with Verification Warning / 节点换IP完成但需复核",
                message=warn_msg,
                level="WARN"
            )
            return {'ok': False, 'new_ip': new_ip, 'error': warn_msg, 'duration_sec': dt, 'dns_ok': dns_ok}

    except Exception as e:
        def mark_uncertain(current):
            operation = current.setdefault('monitor', {}).get('healing_operation', {})
            operation['phase'] = 'uncertain' if operation.get('phase') in ('changing_ip', 'allocated') else 'preflight_failed'
        await asyncio.to_thread(cfg_mgr.update, mark_uncertain)
        logger.error(f'Healing routine failed: {e}', exc_info=True)
        await broadcast_log(f'[ERROR] Healing failed: {str(e)}', 'ERROR')
        runtime_state['status'] = 'warning'
        dt = round(time.time() - t_start, 1)

        await asyncio.to_thread(notification.NotificationManager.broadcast,
            cfg,
            title="Healing Routine Failed / 自动修复失败",
            message=f"[FAILED] Rebirth routine failed for provider {prov_name}: {str(e)}",
            level="ERROR"
        )
        return {'ok': False, 'new_ip': '', 'error': str(e), 'duration_sec': dt, 'dns_ok': False}
    finally:
        runtime_state['heal_in_progress'] = False

@app.post('/api/heal/reconcile')
def reconcile_healing(request: Request, decision: dict):
    check_admin(request)
    if decision.get('acknowledge_manual_verification') is not True:
        raise HTTPException(status_code=422, detail='Confirm the cloud instance and address attachment were manually verified')
    def reconcile(cfg):
        operation = cfg.setdefault('monitor', {}).get('healing_operation', {})
        if operation.get('phase') not in ('uncertain', 'changing_ip', 'allocated'):
            raise ValueError('No uncertain operation to reconcile')
        operation['phase'] = 'manually_reconciled'
        operation['reconciled_at'] = int(time.time())
    cfg_mgr.update(reconcile)
    return {'success': True}

@app.post('/api/heal/trigger')
def trigger_healing(request: Request, body: Optional[HealTriggerModel] = None):
    check_admin(request)
    if runtime_state['heal_in_progress']:
        raise HTTPException(status_code=409, detail='Healing is already in progress')
    force = body.force if body else False
    create_managed_task(run_healing_routine('MANUAL', force=force))
    return {'status': 'initiated', 'message': f'Re-IP rebirth sequence started (force={force})'}

@app.get('/api/ip/audit')
async def get_ip_audit(request: Request, force: bool = False):
    if not auth.verify_subscription_access(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    if force:
        check_admin(request)
    loop = asyncio.get_running_loop()
    report = await loop.run_in_executor(None, ip_audit.auditor.audit, force)
    return JSONResponse(
        content=report,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    )

class SpeedtestRequest(BaseModel):
    mode: Optional[str] = 'full'

@app.post('/api/speedtest/run')
def trigger_speedtest(request: Request, req: Optional[SpeedtestRequest] = None):
    check_admin(request)
    mode = req.mode if req and req.mode else 'full'
    started = speedtest_mgr.speedtest_mgr.start_benchmark(mode=mode)
    if not started:
        raise HTTPException(status_code=409, detail='已有网络测速任务正在执行中，请稍候')
    mode_name = '全带宽与三网压测' if mode == 'full' else '国内三网低延迟探测'
    log_event(f'网络测速任务已发起 ({mode_name})', 'INFO')
    return {'status': 'started', 'message': f'测速任务已启动 ({mode_name})'}

@app.get('/api/speedtest/status')
def get_speedtest_status(request: Request):
    check_admin(request)
    return speedtest_mgr.speedtest_mgr.get_status()

@app.websocket('/ws/live')
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get("sentinel_session")
    origin = websocket.headers.get('origin')
    from urllib.parse import urlsplit
    if auth.get_security_config().get('must_change_password', False) or not auth.verify_session_token(token) or (origin and urlsplit(origin).netloc != websocket.headers.get('host')) or len(ws_manager.active_connections) >= 64:
        await websocket.close(code=1008)
        return
    await ws_manager.connect(websocket)
    try:
        cfg = cfg_mgr.load()
        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, monitor.get_full_state)
        await websocket.send_json({
            'type': 'initial',
            'state': state,
            'speedtest': speedtest_mgr.speedtest_mgr.get_status(),
            'sentinel': {
                'status': runtime_state['status'],
                'last_healed': runtime_state['last_healed'],
                'heal_count': runtime_state['heal_count'],
                'auto_heal': cfg.get('monitor', {}).get('auto_heal_enabled', False)
            },
            'logs': runtime_state['logs'][-30:]
        })
        while True:
            data = await asyncio.wait_for(websocket.receive_text(), timeout=90)
            if len(data) > 64:
                await websocket.close(code=1009)
                break
            if data == 'ping':
                await websocket.send_text('pong')
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        ws_manager.disconnect(websocket)

# --- Traffic Auditing & Quota Endpoints ---

@app.get('/api/traffic/stats')
def get_traffic_stats(request: Request):
    check_admin(request)
    return traffic_mgr.TrafficManager.get_traffic_stats()

class TrafficConfigModel(BaseModel):
    monthly_limit_gb: Optional[float] = Field(default=None, ge=0, le=10000000)
    alert_threshold_pct: Optional[int] = Field(default=None, ge=1, le=100)
    reset_day: Optional[int] = Field(default=None, ge=1, le=28)

@app.post('/api/traffic/config')
def set_traffic_config(data: TrafficConfigModel, request: Request):
    check_admin(request)
    success = traffic_mgr.TrafficManager.set_quota_config(
        monthly_limit_gb=data.monthly_limit_gb,
        alert_threshold_pct=data.alert_threshold_pct,
        reset_day=data.reset_day
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save traffic quota config")
    log_event(f'Updated traffic billing quota: limit={data.monthly_limit_gb}GB, threshold={data.alert_threshold_pct}%, reset_day={data.reset_day}')
    return {'status': 'ok', 'config': traffic_mgr.TrafficManager.get_quota_config()}

# --- Sentinel Mesh Cluster Endpoints ---

class MeshNodeModel(BaseModel):
    name: str
    host: str
    api_token: Optional[str] = ''
    location: Optional[str] = 'Global'
    tag: Optional[str] = 'REMOTE'
    enabled: Optional[bool] = True

    telemetry_token: Optional[str] = ''
    @field_validator('host')
    @classmethod
    def validate_host(cls, value):
        from validation import https_url
        return https_url(value if '://' in value else 'https://' + value)

@app.get('/api/mesh/overview')
def get_mesh_overview(request: Request):
    check_admin(request)
    return mesh_mgr.MeshManager.get_mesh_overview(local_state_func=monitor.get_full_state)

@app.get('/api/mesh/nodes')
def get_mesh_nodes(request: Request):
    check_admin(request)
    return mesh_mgr.MeshManager.get_nodes()

@app.post('/api/mesh/nodes')
def add_mesh_node(node: MeshNodeModel, request: Request):
    check_admin(request)
    created = mesh_mgr.MeshManager.add_node(
        name=node.name,
        host=node.host,
        api_token=node.api_token or '',
        location=node.location or 'Global',
        tag=node.tag or 'REMOTE',
        enabled=node.enabled if node.enabled is not None else True,
        telemetry_token=node.telemetry_token or ''
    )
    def _probe_new():
        stat = mesh_mgr.MeshManager.probe_remote_node(created)
        with mesh_mgr.MeshManager._lock:
            mesh_mgr.MeshManager._node_cache[created['id']] = stat
    threading.Thread(target=_probe_new, daemon=True).start()
    log_event(f'Added new Sentinel Mesh node: {node.name} ({node.host})')
    return {'status': 'ok', 'node': created}

@app.put('/api/mesh/nodes/{node_id}')
def update_mesh_node(node_id: str, node: MeshNodeModel, request: Request):
    check_admin(request)
    updated = mesh_mgr.MeshManager.update_node(node_id, node.dict(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Node not found")
    log_event(f'Updated Sentinel Mesh node: {node_id}')
    return {'status': 'ok', 'node': updated}

@app.delete('/api/mesh/nodes/{node_id}')
def delete_mesh_node(node_id: str, request: Request):
    check_admin(request)
    deleted = mesh_mgr.MeshManager.delete_node(node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Node not found")
    log_event(f'Removed Sentinel Mesh node ID: {node_id}')
    return {'status': 'ok', 'deleted_id': node_id}

@app.post('/api/mesh/refresh')
def refresh_mesh(request: Request):
    check_admin(request)
    mesh_mgr.MeshManager.refresh_all_nodes()
    return mesh_mgr.MeshManager.get_mesh_overview(local_state_func=monitor.get_full_state)

# --- Distributed Certificate Sync Endpoints ---

class CertConfigModel(BaseModel):
    enabled: Optional[bool] = None
    role: Optional[str] = None  # 'disabled', 'master', 'edge'
    master_url: Optional[str] = None
    sync_token: Optional[str] = None
    cert_dir: Optional[str] = None
    poll_interval_hours: Optional[int] = None
    auto_reload_services: Optional[List[str]] = None
    post_sync_hook: Optional[str] = None
    verify_ssl: Optional[bool] = None

class CertSyncNowModel(BaseModel):
    force: Optional[bool] = False

def verify_cert_key_access(request: Request) -> bool:
    """
    P0-2: Strict security authentication for downloading sensitive TLS private key bundles (/api/cert/bundle).
    Only allows:
    1. Active administrator authenticated session.
    2. Explicit cert_sync.sync_token Bearer header or token query param.
    Strictly forbids sub_token: subscription clients must never have access to private TLS keys.
    """
    if auth.is_privileged_request(request):
        return True

    cfg = cfg_mgr.load()
    sync_cfg = cert_sync_mgr.CertSyncManager.get_sync_config(cfg)
    sync_token = sync_cfg.get('sync_token', '').strip()
    if not sync_token:
        return False

    req_token = ''
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        req_token = auth_header[7:].strip()

    if not req_token:
        return False

    return hmac.compare_digest(req_token, sync_token)

def verify_cert_access(request: Request) -> bool:
    """Verifies that the request has permission to access certificate sync endpoints."""
    return verify_cert_key_access(request)

@app.get('/api/cert/info')
def get_cert_info(request: Request):
    check_admin(request)
    cfg = cfg_mgr.load()
    sync_cfg = cert_sync_mgr.CertSyncManager.get_sync_config(cfg)
    cert_dir = sync_cfg.get('cert_dir')
    local_info = cert_sync_mgr.CertManager.get_local_cert_info(cert_dir)
    return {
        'status': 'ok',
        'config': sync_cfg,
        'certificate': local_info
    }

@app.get('/api/cert/status')
def get_cert_status(request: Request):
    if not verify_cert_access(request):
        raise HTTPException(status_code=401, detail="Invalid certificate sync authorization")
    cfg = cfg_mgr.load()
    sync_cfg = cert_sync_mgr.CertSyncManager.get_sync_config(cfg)
    cert_dir = sync_cfg.get('cert_dir')
    info = cert_sync_mgr.CertManager.get_local_cert_info(cert_dir)
    if not info.get('exists'):
        return {
            'status': 'no_cert',
            'fingerprint': '',
            'domains': [],
            'issuer': 'N/A',
            'valid_to': '',
            'days_left': 0,
            'bundle_updated_at': 0
        }
    return {
        'status': 'ok',
        'fingerprint': info.get('fingerprint', ''),
        'domains': info.get('domains', []),
        'issuer': info.get('issuer', 'Unknown'),
        'valid_to': info.get('valid_to', ''),
        'days_left': info.get('days_left', 0),
        'bundle_updated_at': int(os.path.getmtime(info['fullchain_path'])) if os.path.exists(info.get('fullchain_path', '')) else 0
    }

@app.get('/api/cert/bundle')
def get_cert_bundle(request: Request, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    if not verify_cert_key_access(request):
        raise HTTPException(status_code=401, detail="Invalid certificate sync authorization")
    cfg = cfg_mgr.load()
    sync_cfg = cert_sync_mgr.CertSyncManager.get_sync_config(cfg)
    cert_dir = sync_cfg.get('cert_dir')
    try:
        bundle = cert_sync_mgr.CertManager.read_cert_bundle(cert_dir)
        return {
            'status': 'ok',
            **bundle
        }
    except Exception as e:
        logger.error(f"Failed to read certificate bundle: {e}")
        raise HTTPException(status_code=404, detail=f"Certificate bundle not available: {e}")

@app.post('/api/cert/config')
def save_cert_config(model: CertConfigModel, request: Request):
    check_admin(request)
    data = model.model_dump(exclude_unset=True) if hasattr(model, 'model_dump') else model.dict(exclude_unset=True)
    updated = cert_sync_mgr.CertSyncManager.update_sync_config(data)
    log_event(f"Updated certificate sync configuration (role: {updated.get('role')})")
    return {'status': 'ok', 'config': updated}

@app.post('/api/cert/sync-now')
async def trigger_cert_sync_now(model: CertSyncNowModel, request: Request):
    check_admin(request)
    cfg = cfg_mgr.load()
    sync_cfg = cert_sync_mgr.CertSyncManager.get_sync_config(cfg)
    role = sync_cfg.get('role', 'disabled')

    if role == 'edge':
        res = await asyncio.to_thread(cert_sync_mgr.CertSyncManager.perform_edge_sync, force=bool(model.force))
        await broadcast_log(f"Edge certificate sync: {res.get('status')} - {res.get('message')}")
        return res
    elif role == 'master':
        # Master node local reload
        services = sync_cfg.get('auto_reload_services', ['x-ui', 'vpsentinel', 'nginx'])
        hook = sync_cfg.get('post_sync_hook', '')
        reload_results = await asyncio.to_thread(cert_sync_mgr.CertSyncAgent.reload_downstream_services, services=services, hook_path=hook)
        await broadcast_log(f"Master certificate reloaded downstream services: {len(reload_results)} services")
        return {
            'success': all(item.get('success') for item in reload_results),
            'status': 'reloaded' if all(item.get('success') for item in reload_results) else 'reload_failed',
            'role': 'master',
            'message': 'Master node reloaded downstream services successfully',
            'reloaded': reload_results
        }
    else:
        return {
            'success': False,
            'status': 'disabled',
            'message': 'Certificate sync is disabled on this node. Please set role to Master or Edge.'
        }

# --- Interactive Bot Endpoints ---

@app.get('/api/bot/status')
def get_bot_status(request: Request):
    check_admin(request)
    bot = bot_mgr.get_bot_instance(
        get_state_func=monitor.get_full_state,
        get_config_func=cfg_mgr.load,
        run_healing_func=run_healing_routine
    )
    return bot.get_status()

# Mount static folder and dedicated metacubexd app
if os.path.exists(STATIC_PATH):
    app.mount('/static', StaticFiles(directory=STATIC_PATH), name='static')
if os.path.exists(METACUBEXD_PATH):
    app.mount('/metacubexd', StaticFiles(directory=METACUBEXD_PATH, html=True), name='metacubexd')
if os.path.exists(NUXT_PATH):
    app.mount('/_nuxt', StaticFiles(directory=NUXT_PATH), name='nuxt')

@app.get('/dash')
def dash_redirect():
    dash_index = os.path.join(METACUBEXD_PATH, 'index.html')
    if os.path.exists(dash_index):
        return FileResponse(dash_index)
    return HTMLResponse('<h1>Dashboard UI not found</h1>', status_code=404)

DECOY_HTML = """<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; padding-top: 50px; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>"""

@app.api_route('/', methods=['GET', 'HEAD'])
def root():
    # Public root is a stealth decoy Nginx welcome page
    return HTMLResponse(content=DECOY_HTML, status_code=200, headers={"Server": "nginx/1.22.1"})

@app.api_route('/sentinel', methods=['GET', 'HEAD'])
@app.api_route('/sentinel/', methods=['GET', 'HEAD'])
def serve_sentinel_ui():
    index_file = os.path.join(STATIC_PATH, 'index.html')
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse('<h1>Sentinel UI not found</h1>', status_code=404)

@app.api_route('/{path_slug}', methods=['GET', 'HEAD'])
@app.api_route('/{path_slug}/', methods=['GET', 'HEAD'])
def serve_custom_path_ui(path_slug: str):
    sec = auth.get_security_config()
    configured = sec.get("secret_path", "/sentinel").strip('/')
    if path_slug == configured:
        index_file = os.path.join(STATIC_PATH, 'index.html')
        if os.path.exists(index_file):
            return FileResponse(index_file)
    return Response(status_code=404, content=b"")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=20540)
