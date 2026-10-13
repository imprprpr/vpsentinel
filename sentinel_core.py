#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Oracle Sentinel - Core Engine & Multi-Cloud Provider Abstraction
# ==============================================================================

import os
from secure_files import atomic_write, transactional
import sys
import time
import json
import socket
import logging
import platform
import subprocess
import threading
import tempfile
import copy
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Tuple, Dict, Any, Optional
import requests
import psutil

# Conditional OCI import for cross-cloud compatibility
try:
    import oci
    HAS_OCI = True
except ImportError:
    HAS_OCI = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('SentinelCore')

from paths import BASE_DIR, CONFIG_PATH, OCI_DIR, get_config_path
METADATA_INSTANCE_URL = 'http://169.254.169.254/opc/v2/instance/'
METADATA_VNICS_URL = 'http://169.254.169.254/opc/v2/vnics/'

DEFAULT_CONFIG = {
    'provider': {
        'type': 'auto',          # 'auto', 'oracle', 'lightsail', 'hetzner', 'azure', 'hook', 'generic'
        'hook_cmd': ''
    },
    'lightsail': {
        'access_key_id': '',
        'secret_access_key': '',
        'region': 'us-east-1',
        'instance_name': ''
    },
    'hetzner': {
        'api_token': '',
        'server_id': '',
        'ip_type': 'primary'     # 'primary' or 'floating'
    },
    'azure': {
        'subscription_id': '',
        'resource_group': '',
        'vm_name': '',
        'nic_name': '',
        'client_id': '',
        'client_secret': '',
        'tenant_id': ''
    },
    'cloudflare': {
        'api_token': '',
        'zone_name': '',
        'record_name': ''
    },
    'oci': {
        'auth_method': 'config_file',
        'config_path': os.path.join(OCI_DIR, 'config')
    },
    'monitor': {
        'interval_sec': 15,
        'loss_threshold': 75.0,
        'consecutive_failures': 3,
        'auto_heal_enabled': False,
        'auto_heal_mode': 'notify_only',
        'reip_cooldown_hours': 24,
        'max_reip_per_day': 2,
        'last_reip_timestamp': 0,
        'reip_history': []
    },
    'notifications': {
        'enabled': False,
        'telegram': {
            'enabled': False,
            'bot_token': '',
            'chat_id': ''
        },
        'discord': {
            'enabled': False,
            'webhook_url': ''
        },
        'bark': {
            'enabled': False,
            'bark_key': ''
        },
        'custom_webhook': {
            'enabled': False,
            'url': ''
        }
    },
    'rules_config': {
        'adblock': True,
        'ai_group': True,
        'media_group': True,
        'auto_test': True,
        'direct_cn': True,
        'hy2_hop': False
    },
    'security': {
        'auth_enabled': True,
        'admin_username': 'admin',
        'admin_password_hash': '',
        'secret_path': '/sentinel',
        'sub_token': '',
        'enable_host_guard': True,
        'allowed_hosts': [],
        'trusted_proxy_cidrs': []
    },
    'transits': [],
    'edgetunnel': {
        'enabled': False,
        'pages_domain': '',
        'worker_domain': '',
        'uuid': '',
        'path': '/?ed=2048',
        'proxy_ip': '',
        'clean_ips': {
            'telecom': ['ct.v6.rocks', '162.159.192.1'],
            'unicom': ['cu.v6.rocks', '162.159.193.1'],
            'mobile': ['cm.v6.rocks', '162.159.195.1'],
            'anycast': ['cloudflare.com', '104.16.80.1']
        },
        'auto_refresh_clean_ips': True,
        'enable_fallback_group': True
    },
    'cert_sync': {
        'enabled': False,
        'role': 'disabled',
        'master_url': '',
        'sync_token': '',
        'cert_dir': '/etc/vpsentinel/cert',
        'poll_interval_hours': 12,
        'auto_reload_services': ['x-ui', 'vpsentinel', 'nginx'],
        'post_sync_hook': '',
        'verify_ssl': True,
        'last_sync_time': 0,
        'last_fingerprint': '',
        'last_sync_status': 'never',
        'last_sync_message': ''
    }
}

def _deep_merge_dict(base, override):
    merged = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and k in merged and isinstance(merged[k], dict):
            merged[k] = _deep_merge_dict(merged[k], v)
        else:
            merged[k] = copy.deepcopy(v)
    return merged

GENERIC_PROVIDER = 'Generic VPS / Dedicated Server'
CLOUD_INFO_TTL = 300.0

_cached_cloud_info = None
_cached_cloud_info_ts = 0.0
_cloud_info_lock = threading.Lock()


def invalidate_cloud_info_cache():
    global _cached_cloud_info, _cached_cloud_info_ts
    with _cloud_info_lock:
        _cached_cloud_info = None
        _cached_cloud_info_ts = 0.0


def _detect_cloud_info():
    arch = platform.machine()
    dmi_str = ""
    for df in [
        '/sys/class/dmi/id/product_name',
        '/sys/class/dmi/id/sys_vendor',
        '/sys/class/dmi/id/chassis_asset_tag',
        '/sys/class/dmi/id/board_vendor',
        '/sys/class/dmi/id/bios_vendor'
    ]:
        if os.path.exists(df):
            try:
                with open(df, 'r', encoding='utf-8', errors='ignore') as f:
                    dmi_str += f.read() + " "
            except Exception:
                pass

    res = None
    if 'OracleCloud' in dmi_str:
        res = {'provider': 'Oracle Cloud', 'region': 'OCI Global', 'arch': arch}
    elif 'Amazon' in dmi_str or 'EC2' in dmi_str:
        res = {'provider': 'AWS (Lightsail / EC2)', 'region': 'AWS', 'arch': arch}
    elif 'Microsoft' in dmi_str or 'Azure' in dmi_str or '7783-7084-3265-9085-8269-3286-77' in dmi_str:
        res = {'provider': 'Microsoft Azure', 'region': 'Azure Global', 'arch': arch}
    elif 'Hetzner' in dmi_str:
        res = {'provider': 'Hetzner Cloud', 'region': 'Hetzner', 'arch': arch}
    elif 'Alibaba' in dmi_str or 'Aliyun' in dmi_str:
        res = {'provider': 'Alibaba Cloud (阿里云)', 'region': 'Aliyun', 'arch': arch}
    elif 'Tencent' in dmi_str:
        res = {'provider': 'Tencent Cloud (腾讯云)', 'region': 'Tencent', 'arch': arch}
    elif 'DigitalOcean' in dmi_str:
        res = {'provider': 'DigitalOcean', 'region': 'DO', 'arch': arch}

    if not res:
        # Metadata service check (Oracle)
        try:
            r = requests.get(METADATA_INSTANCE_URL, headers={'Authorization': 'Bearer Oracle'}, timeout=1)
            if r.status_code == 200:
                reg = r.json().get('canonicalRegionName', 'Oracle Cloud')
                res = {'provider': 'Oracle Cloud', 'region': reg, 'arch': arch}
        except Exception:
            pass

    if not res:
        # Metadata service check (Azure)
        try:
            r = requests.get(
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                headers={'Metadata': 'true'},
                timeout=1
            )
            if r.status_code == 200:
                data = r.json()
                reg = data.get('compute', {}).get('location', 'Azure Global')
                res = {'provider': 'Microsoft Azure', 'region': reg, 'arch': arch}
        except Exception:
            pass

    if not res:
        # Metadata service check (Hetzner)
        try:
            r = requests.get('http://169.254.169.254/hetzner/v1/metadata', timeout=1)
            if r.status_code == 200:
                res = {'provider': 'Hetzner Cloud', 'region': 'Hetzner Global', 'arch': arch}
        except Exception:
            pass

    if not res:
        # Metadata service check (AWS IMDS)
        try:
            r = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone', timeout=1)
            if r.status_code == 200:
                res = {'provider': 'AWS (Lightsail / EC2)', 'region': r.text.strip(), 'arch': arch}
        except Exception:
            pass

    if not res:
        res = {'provider': GENERIC_PROVIDER, 'region': 'Global', 'arch': arch}
    return res


def get_cloud_info(use_cache: bool = True):
    """
    Auto-detects host virtualization, cloud provider, and CPU architecture.
    """
    global _cached_cloud_info, _cached_cloud_info_ts
    if not use_cache:
        return _detect_cloud_info()

    now = time.time()
    if _cached_cloud_info is not None:
        is_generic = _cached_cloud_info.get('provider') == GENERIC_PROVIDER
        # Positive results are cached permanently; generic fallback is cached for CLOUD_INFO_TTL seconds
        if not is_generic or (now - _cached_cloud_info_ts) < CLOUD_INFO_TTL:
            return dict(_cached_cloud_info)

    with _cloud_info_lock:
        now = time.time()
        if _cached_cloud_info is not None:
            is_generic = _cached_cloud_info.get('provider') == GENERIC_PROVIDER
            if not is_generic or (now - _cached_cloud_info_ts) < CLOUD_INFO_TTL:
                return dict(_cached_cloud_info)

        res = _detect_cloud_info()
        _cached_cloud_info = dict(res)
        _cached_cloud_info_ts = time.time()
        return res


def get_active_config_path() -> str:
    env_cfg = os.environ.get('VPSENTINEL_CONFIG_PATH')
    if env_cfg:
        return env_cfg
    mod_cfg = getattr(sys.modules.get('sentinel_core', None), 'CONFIG_PATH', None)
    return mod_cfg or get_config_path()


class ConfigManager:
    _lock = threading.RLock()
    _cached_cfg = None
    _cached_fingerprint = None  # (mtime_ns, size, inode)

    @classmethod
    def load(cls):
        with cls._lock:
            cfg_path = get_active_config_path()
            if os.path.exists(cfg_path):
                try:
                    st = os.stat(cfg_path)
                    current_fp = (os.path.abspath(cfg_path), st.st_mtime_ns, st.st_size, st.st_ino)
                    if cls._cached_cfg is not None and cls._cached_fingerprint == current_fp:
                        return copy.deepcopy(cls._cached_cfg)
                    with open(cfg_path, 'r', encoding='utf-8') as f:
                        cfg = json.load(f)
                        merged = _deep_merge_dict(DEFAULT_CONFIG, cfg)
                        if cls._cached_fingerprint is not None and cls._cached_fingerprint != current_fp:
                            invalidate_cloud_info_cache()
                        cls._cached_cfg = merged
                        cls._cached_fingerprint = current_fp
                        return copy.deepcopy(merged)
                except Exception as e:
                    logger.error(f'Error reading {cfg_path}: {e}')
                    if cls._cached_cfg is not None and cls._cached_fingerprint and cls._cached_fingerprint[0] == os.path.abspath(cfg_path):
                        logger.warning('Falling back to last valid cached configuration')
                        return copy.deepcopy(cls._cached_cfg)
            else:
                cls._cached_cfg = None
                cls._cached_fingerprint = None
                invalidate_cloud_info_cache()
            return copy.deepcopy(DEFAULT_CONFIG)

    @classmethod
    @transactional
    def save(cls, cfg):
        with cls._lock:
            cfg_path = get_active_config_path()
            try:
                atomic_write(cfg_path, json.dumps(cfg, indent=2, ensure_ascii=False))
                try:
                    st = os.stat(cfg_path)
                    cls._cached_cfg = _deep_merge_dict(DEFAULT_CONFIG, cfg)
                    cls._cached_fingerprint = (os.path.abspath(cfg_path), st.st_mtime_ns, st.st_size, st.st_ino)
                except Exception:
                    cls._cached_cfg = None
                    cls._cached_fingerprint = None
                invalidate_cloud_info_cache()
                return True
            except Exception as e:
                logger.error(f'Error saving {cfg_path}: {e}')
                raise OSError('Configuration could not be persisted') from e

    @classmethod
    def invalidate_cache(cls):
        with cls._lock:
            cls._cached_cfg = None
            cls._cached_fingerprint = None
        invalidate_cloud_info_cache()

    @classmethod
    @transactional
    def update(cls, mutator):
        """Atomically reads, mutates, and saves config under a single lock."""
        with cls._lock:
            cfg = cls.load()
            try:
                should_save = mutator(cfg)
            except Exception as e:
                logger.error(f"Config mutator failed: {e}")
                raise
            if should_save is False:
                return False
            return cls.save(cfg)

    @classmethod
    @transactional
    def update_key(cls, key, value):
        with cls._lock:
            cfg = cls.load()
            cfg[key] = value
            return cls.save(cfg)

class SystemMonitor:
    UPLINK_TARGETS = [
        ('1.1.1.1', 443),
        ('8.8.8.8', 53),
        ('9.9.9.9', 443)
    ]

    def __init__(self):
        self.probes = [
            {'name': 'AliDNS', 'host': '223.5.5.5', 'port': 53},
            {'name': 'DNSPod', 'host': '119.29.29.29', 'port': 53},
            {'name': 'Baidu', 'host': 'www.baidu.com', 'port': 80},
            {'name': 'Tencent', 'host': 'www.qq.com', 'port': 80}
        ]
        self.last_net_io = psutil.net_io_counters()
        self.last_net_time = time.time()
        self.consecutive_failures = 0
        self._state_lock = threading.RLock()
        self._state_cache = None
        self._state_cache_time = 0.0
        self._cache_ttl = 5.0

    def check_uplink_alive(self, timeout=1.5) -> bool:
        """Checks global uplink reachability against root/anycast resolvers.
        Returns True if at least one global target is reachable.
        """
        for host, port in self.UPLINK_TARGETS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((host, port))
                s.close()
                return True
            except Exception:
                s.close()
        return False

    def get_public_ip(self):
        providers = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://checkip.amazonaws.com'
        ]
        for url in providers:
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    ip = r.text.strip()
                    if ip and len(ip.split('.')) == 4:
                        return ip
            except Exception:
                continue
        return '127.0.0.1'

    def get_warp_status(self):
        try:
            r = requests.get(
                'https://cloudflare.com/cdn-cgi/trace',
                proxies={'http': 'socks5h://127.0.0.1:40000', 'https': 'socks5h://127.0.0.1:40000'},
                timeout=2
            )
            data = dict(line.split('=', 1) for line in r.text.strip().split('\n') if '=' in line)
            return {
                'active': data.get('warp') in ('on', 'plus'),
                'ip': data.get('ip', 'N/A'),
                'loc': data.get('loc', 'N/A')
            }
        except Exception:
            return {'active': False, 'ip': 'Offline', 'loc': 'N/A'}

    def check_domestic_probes(self):
        total = len(self.probes)
        success = 0
        latencies = []
        details = []

        for p in self.probes:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            t0 = time.time()
            ok = False
            rtt = 0.0
            try:
                s.connect((p['host'], p['port']))
                rtt = round((time.time() - t0) * 1000, 1)
                latencies.append(rtt)
                success += 1
                ok = True
            except Exception:
                pass
            finally:
                s.close()
            details.append({'name': p['name'], 'host': p['host'], 'port': p['port'], 'success': ok, 'rtt_ms': rtt})

        loss = round((total - success) / total * 100, 1) if total else 0.0
        avg_rtt = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

        # P1-9: Uplink liveness vs domestic blockage check
        uplink_alive = True
        network_down = False
        blocked_suspected = False

        if loss >= 75.0 or (total > 0 and success == 0):
            uplink_alive = self.check_uplink_alive()
            if not uplink_alive:
                network_down = True
                blocked_suspected = False
            else:
                network_down = False
                blocked_suspected = True

        return {
            'loss_pct': loss,
            'avg_rtt_ms': avg_rtt,
            'avg_latency': avg_rtt,
            'success_probes': success,
            'total_probes': total,
            'direction': 'outbound',
            'uplink_alive': uplink_alive,
            'network_down': network_down,
            'blocked_suspected': blocked_suspected,
            'details': details
        }

    def check_port_listening(self, port, proto='tcp'):
        proto = proto.lower()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port == port:
                    if proto == 'tcp':
                        if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
                            return True
                    elif proto == 'udp':
                        if conn.type == socket.SOCK_DGRAM:
                            return True
        except Exception:
            pass
        return False

    def get_metrics(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        
        now = time.time()
        curr_io = psutil.net_io_counters()
        dt = max(now - self.last_net_time, 0.1)
        
        rx_bytes_sec = (curr_io.bytes_recv - self.last_net_io.bytes_recv) / dt
        tx_bytes_sec = (curr_io.bytes_sent - self.last_net_io.bytes_sent) / dt
        
        self.last_net_io = curr_io
        self.last_net_time = now

        uptime_seconds = int(time.time() - psutil.boot_time())
        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        mins = (uptime_seconds % 3600) // 60
        uptime_str = f'{days}d {hours}h {mins}m' if days else f'{hours}h {mins}m'

        return {
            'cpu_pct': cpu,
            'mem_pct': mem.percent,
            'mem_used_mb': round(mem.used / (1024 * 1024), 1),
            'mem_total_mb': round(mem.total / (1024 * 1024), 1),
            'rx_speed_kb': round(rx_bytes_sec / 1024, 1),
            'tx_speed_kb': round(tx_bytes_sec / 1024, 1),
            'uptime': uptime_str
        }

    def get_full_state(self, force_refresh: bool = False):
        with self._state_lock:
            return copy.deepcopy(self._collect_full_state(force_refresh))

    def _collect_full_state(self, force_refresh: bool = False):
        now = time.time()
        if not force_refresh and self._state_cache is not None and (now - self._state_cache_time < self._cache_ttl):
            return self._state_cache

        cfg = ConfigManager.load()
        cloud_info = get_cloud_info()
        metrics = self.get_metrics()
        probes = self.check_domestic_probes()
        pub_ip = self.get_public_ip()
        warp = self.get_warp_status()

        domain = (
            cfg.get('dns', {}).get('record_name') or
            cfg.get('cloudflare', {}).get('record_name') or
            (cfg.get('security', {}).get('allowed_hosts', [None])[0] if cfg.get('security', {}).get('allowed_hosts') else '') or
            ''
        )

        nodes = [
            {
                'id': 'vless-reality',
                'name': 'VPS-Reality',
                'proto': 'VLESS-Reality',
                'port': 8443,
                'sni': 'swdist.apple.com',
                'status': 'online' if self.check_port_listening(8443, 'tcp') else 'offline'
            },
            {
                'id': 'hy2',
                'name': 'VPS-Hy2',
                'proto': 'Hysteria 2',
                'port': 443,
                'hop': '20000-40000 (iptables active)',
                'status': 'online' if self.check_port_listening(443, 'udp') else 'offline'
            },
            {
                'id': 'trojan',
                'name': 'VPS-Trojan',
                'proto': 'Trojan-TLS',
                'port': 2083,
                'sni': domain or 'vps.example.com',
                'status': 'online' if self.check_port_listening(2083, 'tcp') else 'offline'
            }
        ]

        loss_thresh = float(cfg.get('monitor', {}).get('loss_threshold', 75.0))
        if probes.get('network_down'):
            health = 'network_down'
        elif probes['loss_pct'] >= loss_thresh:
            health = 'critical'
        elif probes['loss_pct'] > 0:
            health = 'warning'
        else:
            health = 'healthy'

        state = {
            'timestamp': int(time.time()),
            'health': health,
            'public_ip': pub_ip,
            'current_ip': pub_ip,
            'domain': domain,
            'cloud_info': cloud_info,
            'probes': probes,
            'metrics': metrics,
            'nodes': nodes,
            'warp': warp
        }
        self._state_cache = state
        self._state_cache_time = time.time()
        return state

# ==============================================================================
# Multi-Cloud Provider Abstraction
# ==============================================================================

class BaseCloudProvider:
    def change_public_ip(self) -> str:
        raise NotImplementedError("Subclasses must implement change_public_ip()")

    def test_connection(self) -> Tuple[bool, str]:
        return True, f"Provider {self.get_name()} does not require credential pre-validation."

    def get_name(self) -> str:
        return "BaseProvider"

class OracleCloudProvider(BaseCloudProvider):
    def __init__(self, config_path=None):
        self.metadata = self._get_metadata(METADATA_INSTANCE_URL)
        self.vnics_info = self._get_metadata(METADATA_VNICS_URL)
        self.compartment_id = self.metadata.get('compartmentId')
        self.instance_id = self.metadata.get('id')
        self.region = self.metadata.get('canonicalRegionName', 'us-phoenix-1')
        self.vnic_id = self.vnics_info[0].get('vnicId') if self.vnics_info else None
        self.client = None
        self.init_error = None
        
        if not HAS_OCI:
            self.init_error = "OCI Python SDK is not installed."
            return

        try:
            self.client = self._init_client(config_path)
        except Exception as e:
            self.init_error = str(e)
            logger.warning(f'Oracle Client init deferred/failed: {e}')

    def get_name(self) -> str:
        return "Oracle Cloud Infrastructure (OCI)"

    def test_connection(self) -> Tuple[bool, str]:
        if not HAS_OCI:
            return False, "OCI Python SDK is not installed on this system."
        if self.init_error:
            return False, f"OCI Client init failed: {self.init_error}"
        if not self.client:
            return False, "OCI Client is not initialized."
        try:
            if self.vnic_id:
                priv_ips = self.client.list_private_ips(vnic_id=self.vnic_id).data
                return True, f"OCI API connected successfully. VNIC {self.vnic_id} verified with {len(priv_ips)} private IP(s)."
            return True, "OCI client initialized with valid configuration."
        except Exception as e:
            return False, f"OCI API call failed: {e}"

    def _get_metadata(self, url):
        try:
            r = requests.get(url, headers={'Authorization': 'Bearer Oracle'}, timeout=2)
            return r.json()
        except Exception:
            return {}

    def _init_client(self, config_path):
        default_oci_cfg = os.path.expanduser('~/.oci/config')
        target_cfg = config_path or (default_oci_cfg if os.path.exists(default_oci_cfg) else None)
        
        if target_cfg and os.path.exists(target_cfg):
            try:
                config = oci.config.from_file(target_cfg)
                logger.info(f'Using OCI API Key configuration from {target_cfg}')
                return oci.core.VirtualNetworkClient(config)
            except Exception as e:
                logger.warning(f'Failed loading ~/.oci/config: {e}')
        
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        logger.info('Using OCI Instance Principal authentication')
        return oci.core.VirtualNetworkClient(config={}, signer=signer)

    def change_public_ip(self):
        if not self.client:
            raise RuntimeError(f'OCI Client not ready: {self.init_error}')
        if not self.vnic_id:
            raise ValueError('Primary VNIC ID not detected from metadata.')

        logger.info('Querying private IPs on primary VNIC...')
        try:
            priv_ips = self.client.list_private_ips(vnic_id=self.vnic_id).data
        except Exception as e:
            if 'NotAuthorizedOrNotFound' in str(e):
                raise PermissionError(
                    'Oracle IAM Authorization failed. Please grant permission in Oracle Console: '
                    'Create Dynamic Group for this instance and add Policy: '
                    '"Allow dynamic-group <group-name> to manage public-ips in tenancy"'
                )
            raise e

        primary_priv_ip = next((ip for ip in priv_ips if ip.is_primary), None)
        if not primary_priv_ip:
            raise ValueError('Primary private IP not found on VNIC')

        # Release old public IP
        try:
            pub_ip_details = oci.core.models.GetPublicIpByPrivateIpIdDetails(private_ip_id=primary_priv_ip.id)
            pub_ip = self.client.get_public_ip_by_private_ip_id(pub_ip_details).data
            if pub_ip and pub_ip.id:
                logger.info(f'Releasing old Public IP: {pub_ip.ip_address} (OCID: {pub_ip.id})')
                self.client.delete_public_ip(pub_ip.id)
                time.sleep(2)
        except Exception as e:
            if getattr(e, 'status', None) != 404:
                raise RuntimeError('Cannot safely release the previous OCI address') from e

        # Create new public IP
        logger.info('Allocating new Ephemeral Public IP from Oracle Cloud pool...')
        create_details = oci.core.models.CreatePublicIpDetails(
            compartment_id=self.compartment_id,
            lifetime='EPHEMERAL',
            private_ip_id=primary_priv_ip.id,
            display_name=f'sentinel-ephemeral-{int(time.time())}'
        )
        try:
            new_pub_ip = self.client.create_public_ip(create_details).data
            logger.info(f'Successfully assigned NEW Public IP: {new_pub_ip.ip_address}')
            return new_pub_ip.ip_address
        except Exception as alloc_err:
            logger.error(f'Initial allocation failed ({alloc_err}). Initiating emergency failsafe recovery...')
            time.sleep(3)
            try:
                emergency_details = oci.core.models.CreatePublicIpDetails(
                    compartment_id=self.compartment_id,
                    lifetime='EPHEMERAL',
                    private_ip_id=primary_priv_ip.id,
                    display_name=f'sentinel-recovery-{int(time.time())}'
                )
                recovered = self.client.create_public_ip(emergency_details).data
                logger.warning(f'Emergency failsafe recovery restored public IP: {recovered.ip_address}')
                return recovered.ip_address
            except Exception as rec_err:
                logger.critical(f'Emergency failsafe recovery failed: {rec_err}')
                raise RuntimeError(f'Public IP creation failed ({alloc_err}) and emergency recovery failed ({rec_err}).')

class LightsailCloudProvider(BaseCloudProvider):
    def __init__(self, access_key_id: str = '', secret_access_key: str = '', region: str = 'us-east-1', instance_name: str = ''):
        self.access_key_id = access_key_id.strip() if access_key_id else ''
        self.secret_access_key = secret_access_key.strip() if secret_access_key else ''
        self.region = region.strip() if region else 'us-east-1'
        self.instance_name = instance_name.strip() if instance_name else ''

    def get_name(self) -> str:
        return f"AWS Lightsail ({self.region})"

    def _call_api(self, target_action: str, payload_dict: dict) -> dict:
        if not self.access_key_id or not self.secret_access_key:
            raise ValueError("AWS Access Key ID and Secret Access Key must be configured.")
        
        region = self.region or 'us-east-1'
        host = f"lightsail.{region}.amazonaws.com"
        endpoint = f"https://{host}/"
        
        now = datetime.now(timezone.utc)
        amz_date = now.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = now.strftime('%Y%m%d')
        
        body_str = json.dumps(payload_dict)
        payload_hash = hashlib.sha256(body_str.encode('utf-8')).hexdigest()
        
        canonical_uri = '/'
        canonical_querystring = ''
        canonical_headers = (
            f"content-type:application/x-amz-json-1.1\n"
            f"host:{host}\n"
            f"x-amz-date:{amz_date}\n"
            f"x-amz-target:TrentServiceVersion20161128.{target_action}\n"
        )
        signed_headers = "content-type;host;x-amz-date;x-amz-target"
        canonical_request = f"POST\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{region}/lightsail/aws4_request"
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        
        k_date = hmac.new(('AWS4' + self.secret_access_key).encode('utf-8'), date_stamp.encode('utf-8'), hashlib.sha256).digest()
        k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
        k_service = hmac.new(k_region, b'lightsail', hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b'aws4_request', hashlib.sha256).digest()
        
        signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        auth_header = f"{algorithm} Credential={self.access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        
        headers = {
            'Content-Type': 'application/x-amz-json-1.1',
            'X-Amz-Date': amz_date,
            'X-Amz-Target': f'TrentServiceVersion20161128.{target_action}',
            'Authorization': auth_header
        }
        
        resp = requests.post(endpoint, headers=headers, data=body_str, timeout=20)
        if resp.status_code != 200:
            err_msg = resp.text
            try:
                err_json = resp.json()
                err_msg = err_json.get('message') or err_json.get('__type', resp.text)
            except Exception:
                pass
            raise RuntimeError(f"AWS Lightsail API error ({resp.status_code}): {err_msg}")
        return resp.json()

    def test_connection(self) -> Tuple[bool, str]:
        if not self.access_key_id or not self.secret_access_key:
            return False, "AWS Access Key ID or Secret Access Key is missing."
        try:
            if self.instance_name:
                res = self._call_api('GetInstance', {'instanceName': self.instance_name})
                inst = res.get('instance', {})
                pub_ip = inst.get('publicIpAddress', 'unknown')
                state = inst.get('state', {}).get('name', 'unknown')
                return True, f"AWS Lightsail connection successful. Instance '{self.instance_name}' found (Status: {state}, Current IP: {pub_ip})."
            else:
                res = self._call_api('GetInstances', {})
                instances = res.get('instances', [])
                return True, f"AWS Lightsail connection successful in region {self.region}. Found {len(instances)} instance(s)."
        except Exception as e:
            return False, str(e)

    def change_public_ip(self) -> str:
        if not self.instance_name:
            raise ValueError("AWS Lightsail instance_name is required to change public IP.")
        
        logger.info(f"Initiating AWS Lightsail IP replacement for instance: {self.instance_name}")
        
        # 1. Fetch existing static IPs attached to this instance
        old_static_ip_names = []
        try:
            static_ips_res = self._call_api('GetStaticIps', {})
            for sip in static_ips_res.get('staticIps', []):
                if sip.get('attachedTo') == self.instance_name:
                    old_static_ip_names.append(sip.get('name'))
        except Exception as e:
            logger.warning(f"Could not list existing static IPs: {e}")

        # 2. Allocate new static IP
        new_static_name = f"sentinel-{self.instance_name}-{int(time.time())}"
        logger.info(f"Allocating new Lightsail static IP: {new_static_name}")
        self._call_api('AllocateStaticIp', {'staticIpName': new_static_name})

        # 3. Attach new static IP to instance
        logger.info(f"Attaching {new_static_name} to instance {self.instance_name}...")
        try:
            self._call_api('AttachStaticIp', {'staticIpName': new_static_name, 'instanceName': self.instance_name})
            detail = self._call_api('GetStaticIp', {'staticIpName': new_static_name}).get('staticIp', {})
            if detail.get('attachedTo') != self.instance_name or not detail.get('ipAddress'):
                raise RuntimeError('Lightsail did not confirm the new address attachment')
        except Exception:
            # Release only after confirming it is not attached; uncertain operations need manual reconciliation.
            try:
                detail = self._call_api('GetStaticIp', {'staticIpName': new_static_name}).get('staticIp', {})
                if not detail.get('attachedTo'):
                    self._call_api('ReleaseStaticIp', {'staticIpName': new_static_name})
                for old_name in old_static_ip_names:
                    self._call_api('AttachStaticIp', {'staticIpName': old_name, 'instanceName': self.instance_name})
            except Exception as recovery_error:
                logger.error('Lightsail compensation needs manual reconciliation: %s', recovery_error)
            raise

        # 4. Release old static IP(s) to avoid unattached IP charges
        for old_name in old_static_ip_names:
            try:
                logger.info(f"Releasing old static IP: {old_name}")
                self._call_api('ReleaseStaticIp', {'staticIpName': old_name})
            except Exception as e:
                logger.warning(f"Failed to release old static IP {old_name}: {e}")

        # 5. Query details of newly attached static IP
        sip_detail = self._call_api('GetStaticIp', {'staticIpName': new_static_name})
        new_ip = sip_detail.get('staticIp', {}).get('ipAddress')
        if not new_ip:
            inst_data = self._call_api('GetInstance', {'instanceName': self.instance_name})
            new_ip = inst_data.get('instance', {}).get('publicIpAddress')
            
        logger.info(f"AWS Lightsail successfully attached NEW Public IP: {new_ip}")
        return new_ip

class HetznerCloudProvider(BaseCloudProvider):
    def __init__(self, api_token: str = '', server_id: str = '', ip_type: str = 'primary'):
        self.api_token = api_token.strip() if api_token else ''
        self.server_id = str(server_id).strip() if server_id else ''
        self.ip_type = ip_type.strip().lower() if ip_type else 'primary'
        self.base_url = 'https://api.hetzner.cloud/v1'

    def get_name(self) -> str:
        return f"Hetzner Cloud ({self.ip_type.capitalize()} IP)"

    def _headers(self) -> dict:
        if not self.api_token:
            raise ValueError("Hetzner API token must be configured.")
        return {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }

    def _wait_action(self, action_id: int, timeout: int = 60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            r = requests.get(f"{self.base_url}/actions/{action_id}", headers=self._headers(), timeout=10)
            if r.status_code == 200:
                status = r.json().get('action', {}).get('status')
                if status == 'success':
                    return True
                elif status == 'error':
                    err = r.json().get('action', {}).get('error', {})
                    raise RuntimeError(f"Hetzner action failed: {err.get('message')}")
            time.sleep(2)
        raise TimeoutError(f"Hetzner action {action_id} timed out after {timeout}s")

    def test_connection(self) -> Tuple[bool, str]:
        if not self.api_token:
            return False, "Hetzner Cloud API token is missing."
        try:
            if self.server_id:
                r = requests.get(f"{self.base_url}/servers/{self.server_id}", headers=self._headers(), timeout=10)
                if r.status_code == 200:
                    srv = r.json().get('server', {})
                    s_name = srv.get('name', 'unknown')
                    status = srv.get('status', 'unknown')
                    ipv4 = srv.get('public_net', {}).get('ipv4', {}).get('ip', 'none')
                    return True, f"Hetzner Cloud connection successful. Server '{s_name}' (ID: {self.server_id}, Status: {status}, IPv4: {ipv4}) verified."
                return False, f"Hetzner API error ({r.status_code}): {r.text}"
            else:
                r = requests.get(f"{self.base_url}/servers", headers=self._headers(), timeout=10)
                if r.status_code == 200:
                    count = len(r.json().get('servers', []))
                    return True, f"Hetzner Cloud connection successful. Found {count} server(s)."
                return False, f"Hetzner API error ({r.status_code}): {r.text}"
        except Exception as e:
            return False, str(e)

    def change_public_ip(self) -> str:
        if not self.server_id:
            raise ValueError("Hetzner server_id is required to change public IP.")
        
        if self.ip_type == 'primary' and not ConfigManager.load().get('hetzner', {}).get('external_controller', False):
            raise RuntimeError('Primary IP rotation requires an external controller; self-hosted shutdown is unsafe. Use floating IP mode.')
        logger.info(f"Initiating Hetzner Cloud IP replacement for server: {self.server_id} (mode: {self.ip_type})")
        
        # 1. Fetch server information
        r = requests.get(f"{self.base_url}/servers/{self.server_id}", headers=self._headers(), timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"Failed to fetch Hetzner server {self.server_id}: {r.text}")
        srv = r.json().get('server', {})
        datacenter = srv.get('datacenter', {}).get('name')
        location = srv.get('datacenter', {}).get('location', {}).get('name')
        is_running = srv.get('status') == 'running'
        
        if self.ip_type == 'floating':
            # Floating IP workflow
            logger.info(f"Creating Hetzner Floating IP in location {location}...")
            post_data = {
                'type': 'ipv4',
                'home_location': location,
                'server': int(self.server_id),
                'description': f"sentinel-{int(time.time())}"
            }
            r_flip = requests.post(f"{self.base_url}/floating_ips", headers=self._headers(), json=post_data, timeout=15)
            if r_flip.status_code not in (200, 201):
                raise RuntimeError(f"Failed to create Hetzner Floating IP: {r_flip.text}")
            flip_data = r_flip.json().get('floating_ip', {})
            new_ip = flip_data.get('ip')
            logger.info(f"Successfully assigned Hetzner Floating IP: {new_ip}")
            return new_ip
        else:
            # Primary IP workflow
            old_pip_id = srv.get('public_net', {}).get('primary_ipv4')
            if not old_pip_id:
                for pip in srv.get('primary_ips', []):
                    if pip.get('type') == 'ipv4':
                        old_pip_id = pip.get('id')
                        break

            # Create new Primary IP
            new_pip_name = f"sentinel-pip-{int(time.time())}"
            logger.info(f"Creating new Hetzner Primary IP '{new_pip_name}' in datacenter {datacenter}...")
            create_payload = {
                'type': 'ipv4',
                'name': new_pip_name,
                'datacenter': datacenter,
                'auto_delete': False
            }
            r_pip = requests.post(f"{self.base_url}/primary_ips", headers=self._headers(), json=create_payload, timeout=15)
            if r_pip.status_code not in (200, 201):
                raise RuntimeError(f"Failed to create Hetzner Primary IP: {r_pip.text}")
            new_pip_info = r_pip.json().get('primary_ip', {})
            new_pip_id = new_pip_info.get('id')
            new_ip_addr = new_pip_info.get('ip')

            def action(path, payload=None):
                response = requests.post(self.base_url + path, headers=self._headers(), json=payload, timeout=15)
                if response.status_code not in (200, 201):
                    raise RuntimeError('Hetzner rejected ' + path)
                action_id = response.json().get('action', {}).get('id')
                if not action_id:
                    raise RuntimeError('Hetzner returned no action ID')
                self._wait_action(action_id)
            try:
                if is_running:
                    action(f'/servers/{self.server_id}/actions/poweroff')
                if old_pip_id:
                    action(f'/primary_ips/{old_pip_id}/actions/unassign')
                action(f'/primary_ips/{new_pip_id}/actions/assign', {'server': int(self.server_id)})
                if is_running:
                    action(f'/servers/{self.server_id}/actions/poweron')
            except Exception:
                try:
                    action(f'/primary_ips/{new_pip_id}/actions/unassign')
                    if old_pip_id:
                        action(f'/primary_ips/{old_pip_id}/actions/assign', {'server': int(self.server_id)})
                    if is_running:
                        action(f'/servers/{self.server_id}/actions/poweron')
                    requests.delete(f'{self.base_url}/primary_ips/{new_pip_id}', headers=self._headers(), timeout=10)
                except Exception as recovery_error:
                    logger.critical('Hetzner compensation needs manual reconciliation: %s', recovery_error)
                raise

            # Delete old primary IP
            if old_pip_id:
                try:
                    logger.info(f"Deleting old Primary IP {old_pip_id}...")
                    requests.delete(f"{self.base_url}/primary_ips/{old_pip_id}", headers=self._headers(), timeout=10)
                except Exception as e:
                    logger.warning(f"Notice deleting old Primary IP {old_pip_id}: {e}")

            logger.info(f"Hetzner Cloud successfully assigned NEW Primary IP: {new_ip_addr}")
            return new_ip_addr

class AzureCloudProvider(BaseCloudProvider):
    def __init__(
        self,
        subscription_id: str = '',
        resource_group: str = '',
        vm_name: str = '',
        nic_name: str = '',
        client_id: str = '',
        client_secret: str = '',
        tenant_id: str = ''
    ):
        self.subscription_id = subscription_id.strip() if subscription_id else ''
        self.resource_group = resource_group.strip() if resource_group else ''
        self.vm_name = vm_name.strip() if vm_name else ''
        self.nic_name = nic_name.strip() if nic_name else ''
        self.client_id = client_id.strip() if client_id else ''
        self.client_secret = client_secret.strip() if client_secret else ''
        self.tenant_id = tenant_id.strip() if tenant_id else ''
        self.api_version = '2023-09-01'

    def get_name(self) -> str:
        return "Microsoft Azure"

    def _get_access_token(self) -> str:
        if not self.tenant_id or not self.client_id or not self.client_secret:
            raise ValueError("Azure tenant_id, client_id, and client_secret are required.")
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://management.azure.com/.default'
        }
        r = requests.post(token_url, data=data, timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"Azure token acquisition failed ({r.status_code}): {r.text}")
        return r.json().get('access_token', '')

    def _headers(self, token: str) -> dict:
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def _discover_nic_if_needed(self, token: str):
        if self.nic_name:
            return self.nic_name
        if not self.vm_name:
            raise ValueError("Either Azure nic_name or vm_name must be specified.")
        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Compute/virtualMachines/{self.vm_name}?api-version=2023-09-01"
        r = requests.get(url, headers=self._headers(token), timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"Failed to query Azure VM {self.vm_name}: {r.text}")
        nics = r.json().get('properties', {}).get('networkProfile', {}).get('networkInterfaces', [])
        if not nics:
            raise ValueError(f"No network interfaces found on Azure VM {self.vm_name}")
        nic_id = nics[0].get('id', '')
        self.nic_name = nic_id.split('/')[-1]
        return self.nic_name

    def test_connection(self) -> Tuple[bool, str]:
        if not self.subscription_id or not self.resource_group:
            return False, "Azure subscription_id and resource_group are required."
        try:
            token = self._get_access_token()
            nic = self._discover_nic_if_needed(token)
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version={self.api_version}"
            r = requests.get(url, headers=self._headers(token), timeout=15)
            if r.status_code == 200:
                data = r.json()
                loc = data.get('location', 'unknown')
                ip_configs = data.get('properties', {}).get('ipConfigurations', [])
                current_pip = 'None'
                if ip_configs:
                    current_pip = ip_configs[0].get('properties', {}).get('publicIPAddress', {}).get('id', 'None').split('/')[-1]
                return True, f"Azure connection successful. NIC '{nic}' found in {loc} (RG: {self.resource_group}, PublicIP: {current_pip})."
            return False, f"Azure API error ({r.status_code}): {r.text}"
        except Exception as e:
            return False, str(e)

    def change_public_ip(self) -> str:
        if not self.subscription_id or not self.resource_group:
            raise ValueError("Azure subscription_id and resource_group are required.")

        token = self._get_access_token()
        nic = self._discover_nic_if_needed(token)
        headers = self._headers(token)

        logger.info(f"Initiating Azure Public IP replacement for NIC: {nic} in RG: {self.resource_group}")

        # 1. Fetch current NIC configuration
        nic_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version={self.api_version}"
        r = requests.get(nic_url, headers=headers, timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"Failed to fetch Azure NIC {nic}: {r.text}")
        nic_data = r.json()
        location = nic_data.get('location')
        ip_configs = nic_data.get('properties', {}).get('ipConfigurations', [])
        if not ip_configs:
            raise ValueError(f"NIC {nic} has no IP configurations.")

        primary_ip_config = next((item for item in ip_configs if item.get('properties', {}).get('primary')), None)
        if primary_ip_config is None:
            if len(ip_configs) != 1:
                raise RuntimeError('Cannot identify the primary NIC IP configuration')
            primary_ip_config = ip_configs[0]
        old_pip = primary_ip_config.get('properties', {}).get('publicIPAddress', {})
        old_pip_id = old_pip.get('id') if old_pip else None

        # 2. Create new Public IP resource
        new_pip_name = f"sentinel-pip-{int(time.time())}"
        new_pip_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Network/publicIPAddresses/{new_pip_name}?api-version={self.api_version}"
        pip_body = {
            'location': location,
            'sku': {'name': 'Standard'},
            'properties': {
                'publicIPAllocationMethod': 'Static'
            }
        }
        logger.info(f"Creating new Azure Public IP: {new_pip_name} in {location}...")
        r_pip = requests.put(new_pip_url, headers=headers, json=pip_body, timeout=30)
        if r_pip.status_code not in (200, 201):
            raise RuntimeError(f"Failed to create Azure Public IP: {r_pip.text}")
        new_pip_data = r_pip.json()
        new_pip_id = new_pip_data.get('id')

        # 3. Attach new Public IP to NIC
        primary_ip_config['properties']['publicIPAddress'] = {'id': new_pip_id}
        logger.info(f"Updating Azure NIC {nic} to attach new Public IP {new_pip_name}...")
        r_nic_up = requests.put(nic_url, headers=headers, json=nic_data, timeout=30)
        if r_nic_up.status_code not in (200, 201, 202):
            raise RuntimeError(f"Failed to update Azure NIC: {r_nic_up.text}")

        # Poll until new IP is available
        new_ip = None
        for _ in range(15):
            time.sleep(2)
            chk_pip = requests.get(new_pip_url, headers=headers, timeout=10)
            if chk_pip.status_code == 200:
                new_ip = chk_pip.json().get('properties', {}).get('ipAddress')
                if new_ip:
                    break

        if not new_ip:
            raise RuntimeError('Azure allocation did not return an address; old resource retained')
        confirmed = False
        for _ in range(30):
            response = requests.get(nic_url, headers=headers, timeout=10)
            response.raise_for_status()
            properties = response.json().get('properties', {})
            state = properties.get('provisioningState')
            if state == 'Failed':
                raise RuntimeError('Azure NIC binding failed; old public IP retained')
            bound = any(item.get('properties', {}).get('publicIPAddress', {}).get('id') == new_pip_id for item in properties.get('ipConfigurations', []))
            if state == 'Succeeded' and bound:
                confirmed = True
                break
            time.sleep(2)
        if not confirmed:
            raise RuntimeError('Azure NIC binding not confirmed; old public IP retained')

        # 4. Clean up old Public IP if existed
        if old_pip_id:
            try:
                logger.info(f"Deleting old Azure Public IP: {old_pip_id}")
                del_url = f"https://management.azure.com{old_pip_id}?api-version={self.api_version}"
                requests.delete(del_url, headers=headers, timeout=15)
            except Exception as e:
                logger.warning(f"Notice deleting old Azure Public IP: {e}")

        logger.info(f"Azure successfully assigned NEW Public IP: {new_ip}")
        return new_ip

class CustomHookProvider(BaseCloudProvider):
    def __init__(self, hook_cmd):
        self.hook_cmd = hook_cmd

    def get_name(self) -> str:
        return "Custom Script / Hook"

    def test_connection(self) -> Tuple[bool, str]:
        if not self.hook_cmd:
            return False, "Hook command is not configured"
        return True, f"Custom hook script configured: {self.hook_cmd}"

    def change_public_ip(self) -> str:
        if not self.hook_cmd:
            raise ValueError("No custom hook script or command configured.")
        logger.info(f"Executing custom Re-IP hook: {self.hook_cmd}")
        res = subprocess.run(self.hook_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        new_ip = res.stdout.strip()
        if not (new_ip and len(new_ip.split('.')) == 4):
            new_ip = SystemMonitor().get_public_ip()
        return new_ip

class GenericProvider(BaseCloudProvider):
    def get_name(self) -> str:
        return "Generic VPS (Monitoring & Alert Only)"

    def test_connection(self) -> Tuple[bool, str]:
        return True, "Generic VPS mode (WARP renewal only, automatic cloud re-IP not supported)"

    def change_public_ip(self) -> str:
        logger.info("Generic VPS detected: Automatic IP swap not supported by cloud provider.")
        logger.info("Attempting WARP egress renewal...")
        try:
            subprocess.run("warp-cli disconnect && sleep 1 && warp-cli connect", shell=True, check=False)
        except Exception:
            pass
        return SystemMonitor().get_public_ip()

def get_cloud_provider(cfg):
    """
    Factory method returning the active Cloud Provider instance based on configuration.
    """
    p_type = cfg.get('provider', {}).get('type', 'auto')

    if p_type == 'oracle':
        return OracleCloudProvider(cfg.get('oci', {}).get('config_path'))
    elif p_type == 'lightsail':
        ls_cfg = cfg.get('lightsail', {})
        return LightsailCloudProvider(
            access_key_id=ls_cfg.get('access_key_id', ''),
            secret_access_key=ls_cfg.get('secret_access_key', ''),
            region=ls_cfg.get('region', 'us-east-1'),
            instance_name=ls_cfg.get('instance_name', '')
        )
    elif p_type == 'hetzner':
        hz_cfg = cfg.get('hetzner', {})
        return HetznerCloudProvider(
            api_token=hz_cfg.get('api_token', ''),
            server_id=hz_cfg.get('server_id', ''),
            ip_type=hz_cfg.get('ip_type', 'primary')
        )
    elif p_type == 'azure':
        az_cfg = cfg.get('azure', {})
        return AzureCloudProvider(
            subscription_id=az_cfg.get('subscription_id', ''),
            resource_group=az_cfg.get('resource_group', ''),
            vm_name=az_cfg.get('vm_name', ''),
            nic_name=az_cfg.get('nic_name', ''),
            client_id=az_cfg.get('client_id', ''),
            client_secret=az_cfg.get('client_secret', ''),
            tenant_id=az_cfg.get('tenant_id', '')
        )
    elif p_type == 'hook':
        return CustomHookProvider(cfg.get('provider', {}).get('hook_cmd', ''))
    elif p_type == 'generic':
        return GenericProvider()

    # auto mode: inspect host platform
    if p_type != 'auto':
        logger.warning(f"Unrecognized provider type '{p_type}', falling back to auto-detection.")

    cloud_info = get_cloud_info()
    provider_name = cloud_info.get('provider', '')

    if 'Oracle' in provider_name:
        return OracleCloudProvider(cfg.get('oci', {}).get('config_path'))
    elif 'AWS' in provider_name:
        ls_cfg = cfg.get('lightsail', {})
        return LightsailCloudProvider(
            access_key_id=ls_cfg.get('access_key_id', ''),
            secret_access_key=ls_cfg.get('secret_access_key', ''),
            region=ls_cfg.get('region', 'us-east-1'),
            instance_name=ls_cfg.get('instance_name', '')
        )
    elif 'Hetzner' in provider_name:
        hz_cfg = cfg.get('hetzner', {})
        return HetznerCloudProvider(
            api_token=hz_cfg.get('api_token', ''),
            server_id=hz_cfg.get('server_id', ''),
            ip_type=hz_cfg.get('ip_type', 'primary')
        )
    elif 'Azure' in provider_name:
        az_cfg = cfg.get('azure', {})
        return AzureCloudProvider(
            subscription_id=az_cfg.get('subscription_id', ''),
            resource_group=az_cfg.get('resource_group', ''),
            vm_name=az_cfg.get('vm_name', ''),
            nic_name=az_cfg.get('nic_name', ''),
            client_id=az_cfg.get('client_id', ''),
            client_secret=az_cfg.get('client_secret', ''),
            tenant_id=az_cfg.get('tenant_id', '')
        )
    else:
        return GenericProvider()

# Backwards compatibility alias
OracleManager = OracleCloudProvider

# ==============================================================================
# DNS Provider Abstraction (Multi-Provider Support)
# ==============================================================================

class BaseDnsProvider:
    """
    Abstract interface for managing DNS records and verifying domain zone credentials.
    """
    def verify_token(self) -> Tuple[bool, str]:
        raise NotImplementedError

    def list_zones(self) -> Tuple[bool, list, str]:
        raise NotImplementedError

    def update_dns_record(self, record_name: str = '', new_ip: str = None) -> bool:
        raise NotImplementedError

    def get_name(self) -> str:
        return self.__class__.__name__


class CloudflareDnsProvider(BaseDnsProvider):
    def __init__(self, api_token, zone_name=''):
        self.api_token = api_token.strip() if api_token else ''
        self.zone_name = zone_name.strip()
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }

    def get_name(self) -> str:
        return 'Cloudflare DNS'

    def verify_token(self):
        if not self.api_token:
            return False, 'API Token is empty'
        try:
            r = requests.get('https://api.cloudflare.com/client/v4/user/tokens/verify', headers=self.headers, timeout=5)
            res = r.json()
            if res.get('success'):
                return True, 'Token verified successfully'
            return False, res.get('messages', [{}])[0].get('message', 'Invalid token')
        except Exception as e:
            return False, str(e)

    def list_zones(self):
        if not self.api_token:
            return False, [], 'API Token is empty'
        try:
            r = requests.get('https://api.cloudflare.com/client/v4/zones?status=active', headers=self.headers, timeout=6)
            res = r.json()
            if res.get('success'):
                zones = [{'id': z['id'], 'name': z['name']} for z in res.get('result', [])]
                return True, zones, 'Zones retrieved successfully'
            errors = res.get('errors', [{}])[0].get('message', 'Failed to retrieve zones')
            return False, [], errors
        except Exception as e:
            return False, [], str(e)

    def update_dns_record(self, record_name='', new_ip=None):
        if not self.api_token:
            raise ValueError('Cloudflare API Token not configured')
        if not new_ip:
            raise ValueError('new_ip is required')

        # Get Zone ID
        url = f'https://api.cloudflare.com/client/v4/zones?name={self.zone_name}'
        r = requests.get(url, headers=self.headers, timeout=5)
        res = r.json()
        if not res.get('success') or not res.get('result'):
            raise ValueError(f'Zone {self.zone_name} not found in Cloudflare account.')
        zone_id = res['result'][0]['id']

        # Get DNS Record ID
        dns_url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}'
        r = requests.get(dns_url, headers=self.headers, timeout=5)
        res = r.json()
        if not res.get('success') or not res.get('result'):
            # Create record if not found
            logger.info(f'Record {record_name} not found, creating new A record...')
            create_url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'
            payload = {
                'type': 'A',
                'name': record_name,
                'content': new_ip,
                'ttl': 60,
                'proxied': False
            }
            r = requests.post(create_url, headers=self.headers, json=payload, timeout=5)
            c_res = r.json()
            if not c_res.get('success'):
                raise RuntimeError(f'Failed to create A record: {c_res.get("errors")}')
            return True

        record = res['result'][0]
        record_id = record['id']

        # Update A Record
        update_url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}'
        payload = {
            'type': 'A',
            'name': record_name,
            'content': new_ip,
            'ttl': record.get('ttl', 60),
            'proxied': record.get('proxied', False)
        }
        r = requests.put(update_url, headers=self.headers, json=payload, timeout=5)
        u_res = r.json()
        if not u_res.get('success'):
            raise RuntimeError(f'Failed to update DNS record: {u_res.get("errors")}')

        logger.info(f'Cloudflare DNS updated: {record_name} -> {new_ip}')
        return True


# Backwards compatibility alias
CloudflareManager = CloudflareDnsProvider


class WebhookDnsProvider(BaseDnsProvider):
    """Adapter for an administrator-operated HTTPS DNS update gateway."""
    def __init__(self, cfg):
        self.cfg = cfg
    def update_dns_record(self, record_name='', new_ip=None):
        import ipaddress
        from net_policy import open_secure, read_json
        ipaddress.ip_address(new_ip)
        payload = json.dumps({'record_name': record_name, 'ip': new_ip}).encode()
        import urllib.request
        req = urllib.request.Request(self.cfg['url'], data=payload, headers={
            'Authorization': 'Bearer ' + self.cfg.get('api_token', ''), 'Content-Type': 'application/json'})
        with open_secure(req) as response:
            result = read_json(response)
        if result.get('success') is not True or result.get('ip') != new_ip:
            raise RuntimeError('DNS gateway did not confirm the requested address')
        return True


def dns_settings(cfg):
    dns = dict(cfg.get('cloudflare', {}))
    dns.update({k: v for k, v in cfg.get('dns', {}).items() if v is not None})
    dns.setdefault('type', 'cloudflare')
    return dns


def get_dns_provider(cfg: dict, zone_name: str = '') -> BaseDnsProvider:
    dns = dns_settings(cfg)
    if dns['type'] == 'cloudflare':
        return CloudflareDnsProvider(dns.get('api_token', ''), zone_name or dns.get('zone_name', ''))
    if dns['type'] == 'webhook':
        return WebhookDnsProvider(dns)
    raise ValueError('Unsupported DNS provider: ' + str(dns['type']))

def generate_rsa_keypair(key_dir=None):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key_dir = key_dir or OCI_DIR
    os.makedirs(key_dir, mode=0o700, exist_ok=True)
    key_path = os.path.join(key_dir, 'oci_api_key.pem')
    pub_path = os.path.join(key_dir, 'oci_api_key_public.pem')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    atomic_write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    atomic_write(pub_path, public, mode=0o644)
    return public.decode().strip(), key_path

def save_oci_config(raw_config_text, key_path, oci_dir=None):
    oci_dir = oci_dir or OCI_DIR
    os.makedirs(oci_dir, mode=0o700, exist_ok=True)
    lines = raw_config_text.strip().splitlines()
    new_lines = []
    has_key_file = False
    for l in lines:
        l_s = l.strip()
        if l_s.startswith("key_file="):
            new_lines.append(f"key_file={key_path}")
            has_key_file = True
        elif l_s:
            new_lines.append(l_s)
    if not has_key_file:
        new_lines.append(f"key_file={key_path}")
    
    cfg_file = os.path.join(oci_dir, "config")
    atomic_write(cfg_file, '\n'.join(new_lines) + '\n')
    return cfg_file

if __name__ == '__main__':
    info = get_cloud_info()
    print("Detected Cloud Environment:", info)
