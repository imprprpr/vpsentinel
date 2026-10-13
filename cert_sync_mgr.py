from net_policy import open_secure, read_limited
from secure_files import transactional, atomic_write
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# VPSentinel - Distributed Certificate Synchronization & Hot Reload Manager
# ==============================================================================

import os
import sys
import time
import json
import logging
import hashlib
import threading
import subprocess
import tempfile
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from service_mgr import get_service_manager

logger = logging.getLogger('CertSync')

# Default certificate paths
from paths import CERT_DIR
DEFAULT_CERT_DIRS = [CERT_DIR]

def resolve_cert_dir(custom_dir: Optional[str] = None) -> str:
    """Resolves existing or target certificate directory."""
    if custom_dir and custom_dir.strip():
        return custom_dir.strip()
    for d in DEFAULT_CERT_DIRS:
        if os.path.exists(d):
            return d
    return DEFAULT_CERT_DIRS[0]

class CertManager:
    """Manages local X.509 certificate parsing, fingerprinting, and bundle reading."""

    @staticmethod
    def calculate_fingerprint(data: bytes) -> str:
        """Calculates SHA-256 fingerprint for certificate data."""
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def parse_certificate(cls, cert_path: str) -> Dict[str, Any]:
        """
        Parses PEM certificate file and extracts metadata:
        domains, issuer, valid_from, valid_to, days_left, fingerprint.
        """
        if not os.path.exists(cert_path):
            return {
                'exists': False,
                'domains': [],
                'issuer': 'N/A',
                'valid_from': '',
                'valid_to': '',
                'days_left': 0,
                'fingerprint': '',
                'error': f'Certificate file not found: {cert_path}'
            }

        try:
            with open(cert_path, 'rb') as f:
                raw_bytes = f.read()

            if not raw_bytes:
                return {
                    'exists': False,
                    'domains': [],
                    'issuer': 'N/A',
                    'valid_from': '',
                    'valid_to': '',
                    'days_left': 0,
                    'fingerprint': '',
                    'error': 'Certificate file is empty'
                }

            fingerprint = cls.calculate_fingerprint(raw_bytes)
            domains = []
            issuer_str = 'Unknown'
            valid_from_str = ''
            valid_to_str = ''
            days_left = 0

            # Try parsing with cryptography library
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_pem_x509_certificate(raw_bytes, default_backend())

                # Common Name
                cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if cn_attrs:
                    domains.append(cn_attrs[0].value)

                # Subject Alternative Names (SANs)
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    dns_names = san_ext.value.get_values_for_type(x509.DNSName)
                    for d in dns_names:
                        if d not in domains:
                            domains.append(d)
                except Exception:
                    pass

                # Issuer
                issuer_cns = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                issuer_orgs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
                if issuer_orgs and issuer_cns:
                    issuer_str = f"{issuer_orgs[0].value} ({issuer_cns[0].value})"
                elif issuer_orgs:
                    issuer_str = issuer_orgs[0].value
                elif issuer_cns:
                    issuer_str = issuer_cns[0].value

                # Validity dates
                valid_from = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
                valid_to = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after

                valid_from_str = valid_from.strftime('%Y-%m-%d %H:%M:%S UTC')
                valid_to_str = valid_to.strftime('%Y-%m-%d %H:%M:%S UTC')

                now_utc = datetime.now(timezone.utc)
                if valid_to.tzinfo is None:
                    now_utc = datetime.utcnow()
                diff = valid_to - now_utc
                days_left = max(0, diff.days)

            except Exception as crypto_err:
                logger.debug(f"Cryptography parser fallback: {crypto_err}")
                # Fallback: OpenSSL CLI or simple string extraction
                domains, issuer_str, valid_to_str, days_left = cls._parse_with_openssl(cert_path)

            return {
                'exists': True,
                'domains': domains,
                'issuer': issuer_str,
                'valid_from': valid_from_str,
                'valid_to': valid_to_str,
                'days_left': days_left,
                'fingerprint': fingerprint,
                'cert_path': cert_path,
                'error': None
            }

        except Exception as e:
            logger.error(f"Failed to parse certificate {cert_path}: {e}")
            return {
                'exists': True,
                'domains': [],
                'issuer': 'Error',
                'valid_from': '',
                'valid_to': '',
                'days_left': 0,
                'fingerprint': '',
                'error': str(e)
            }

    @classmethod
    def _parse_with_openssl(cls, cert_path: str) -> Tuple[List[str], str, str, int]:
        """Fallback certificate inspection via openssl CLI."""
        domains = []
        issuer = 'Unknown'
        valid_to = ''
        days_left = 0
        try:
            cmd = ['openssl', 'x509', '-in', cert_path, '-noout', '-subject', '-issuer', '-enddate']
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.startswith('subject='):
                        for part in line.replace('subject=', '').split(','):
                            if 'CN=' in part or 'CN =' in part:
                                domains.append(part.split('=')[1].strip())
                    elif line.startswith('issuer='):
                        for part in line.replace('issuer=', '').split(','):
                            if 'CN=' in part or 'CN =' in part or 'O=' in part:
                                issuer = part.split('=')[1].strip()
                    elif line.startswith('notAfter='):
                        valid_to = line.replace('notAfter=', '').strip()
                        try:
                            dt = datetime.strptime(valid_to, '%b %d %H:%M:%S %Y %Z')
                            days_left = max(0, (dt - datetime.utcnow()).days)
                        except Exception:
                            pass
        except Exception as e:
            logger.debug(f"openssl parser failed: {e}")
        return domains, issuer, valid_to, days_left

    @classmethod
    def get_local_cert_info(cls, cert_dir: Optional[str] = None) -> Dict[str, Any]:
        """Inspects fullchain.pem and privkey.pem in target directory."""
        target_dir = resolve_cert_dir(custom_dir=cert_dir)
        fullchain_path = os.path.join(target_dir, 'fullchain.pem')
        privkey_path = os.path.join(target_dir, 'privkey.pem')

        info = cls.parse_certificate(fullchain_path)
        info['cert_dir'] = target_dir
        info['fullchain_path'] = fullchain_path
        info['privkey_path'] = privkey_path
        info['privkey_exists'] = os.path.exists(privkey_path) and os.path.getsize(privkey_path) > 0

        # Check key permissions
        if info['privkey_exists']:
            try:
                st = os.stat(privkey_path)
                info['privkey_mode'] = oct(st.st_mode)[-3:]
            except Exception:
                info['privkey_mode'] = 'unknown'
        else:
            info['privkey_mode'] = 'none'

        return info

    @classmethod
    def read_cert_bundle(cls, cert_dir: Optional[str] = None) -> Dict[str, Any]:
        """Reads fullchain.pem and privkey.pem to package as a bundle."""
        cert_dir = resolve_cert_dir(cert_dir)
        current = os.path.join(cert_dir, '.current')
        if os.path.islink(current):
            cert_dir = os.path.realpath(current)
        target_dir = resolve_cert_dir(custom_dir=cert_dir)
        fullchain_path = os.path.join(target_dir, 'fullchain.pem')
        privkey_path = os.path.join(target_dir, 'privkey.pem')

        if not os.path.exists(fullchain_path) or not os.path.exists(privkey_path):
            raise FileNotFoundError(f"Certificate bundle missing in {target_dir}")

        with open(fullchain_path, 'r', encoding='utf-8') as f:
            cert_pem = f.read()

        with open(privkey_path, 'r', encoding='utf-8') as f:
            key_pem = f.read()

        info = cls.parse_certificate(fullchain_path)
        return {
            'fingerprint': info.get('fingerprint', cls.calculate_fingerprint(cert_pem.encode('utf-8'))),
            'domains': info.get('domains', []),
            'issuer': info.get('issuer', 'Unknown'),
            'valid_to': info.get('valid_to', ''),
            'days_left': info.get('days_left', 0),
            'cert_pem': cert_pem,
            'key_pem': key_pem,
            'timestamp': int(time.time())
        }


class CertSyncAgent:
    """Handles remote certificate inspection, pulling, atomic saving, and service reload."""

    @staticmethod
    def _create_ssl_context(verify_ssl: bool = True) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    @classmethod
    def check_master_status(
        cls,
        master_url: str,
        sync_token: str,
        verify_ssl: bool = True,
        timeout: int = 8
    ) -> Dict[str, Any]:
        """Queries master GET /api/cert/status to check latest certificate fingerprint."""
        base = master_url.strip().rstrip('/')
        url = f"{base}/api/cert/status"
        headers = {
            'User-Agent': 'VPSentinel-CertSync/2.4',
            'Authorization': f"Bearer {sync_token.strip()}"
        }

        ctx = cls._create_ssl_context(verify_ssl)
        req = urllib.request.Request(url, headers=headers)
        t0 = time.time()
        try:
            with open_secure(req, timeout=timeout, context=ctx) as resp:
                rtt = round((time.time() - t0) * 1000, 1)
                data = json.loads(read_limited(resp).decode('utf-8'))
                data['rtt_ms'] = rtt
                return data
        except urllib.error.HTTPError as he:
            return {'status': 'error', 'http_code': he.code, 'error': f"Master returned HTTP {he.code}"}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    @classmethod
    def pull_cert_bundle(
        cls,
        master_url: str,
        sync_token: str,
        verify_ssl: bool = True,
        timeout: int = 15
    ) -> Dict[str, Any]:
        """Downloads full certificate bundle from master GET /api/cert/bundle."""
        base = master_url.strip().rstrip('/')
        url = f"{base}/api/cert/bundle"
        headers = {
            'User-Agent': 'VPSentinel-CertSync/2.4',
            'Authorization': f"Bearer {sync_token.strip()}"
        }

        ctx = cls._create_ssl_context(verify_ssl)
        req = urllib.request.Request(url, headers=headers)
        try:
            with open_secure(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(read_limited(resp).decode('utf-8'))
                return data
        except urllib.error.HTTPError as he:
            raise RuntimeError(f"Master bundle request failed with HTTP {he.code}")
        except Exception as e:
            raise RuntimeError(f"Failed to connect to master: {e}")

    @classmethod
    @transactional
    def save_cert_bundle_atomic(
        cls,
        cert_pem: str,
        key_pem: str,
        target_dir: str
    ) -> Tuple[str, str]:
        """
        Atomically saves fullchain.pem and privkey.pem to target_dir.
        Ensures strict permissions (dir: 0755, privkey: 0600, fullchain: 0644).
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from datetime import datetime, timezone
        import uuid
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
        public = lambda obj: obj.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if public(cert) != public(key):
            raise ValueError('Certificate and private key do not match')
        now = datetime.now(timezone.utc)
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError('Certificate is expired or not yet valid')
        os.makedirs(target_dir, mode=0o700, exist_ok=True)
        generation = '.bundle-' + uuid.uuid4().hex
        version = os.path.join(target_dir, generation)
        os.mkdir(version, 0o700)
        atomic_write(os.path.join(version, 'privkey.pem'), key_pem)
        atomic_write(os.path.join(version, 'fullchain.pem'), cert_pem, 0o644)
        current = os.path.join(target_dir, '.current')
        # Migrate existing files to a complete generation before exposing stable links.
        if not os.path.islink(current):
            legacy = os.path.join(target_dir, '.bundle-legacy-' + uuid.uuid4().hex)
            os.mkdir(legacy, 0o700)
            for name in ('fullchain.pem', 'privkey.pem'):
                old = os.path.join(target_dir, name)
                if os.path.isfile(old):
                    with open(old, 'rb') as stream:
                        atomic_write(os.path.join(legacy, name), stream.read(), 0o600 if name == 'privkey.pem' else 0o644)
                else:
                    with open(os.path.join(version, name), 'rb') as stream:
                        atomic_write(os.path.join(legacy, name), stream.read(), 0o600 if name == 'privkey.pem' else 0o644)
            os.symlink(os.path.basename(legacy), current)
        for name in ('fullchain.pem', 'privkey.pem'):
            path = os.path.join(target_dir, name)
            desired = '.current/' + name
            if not os.path.islink(path) or os.readlink(path) != desired:
                tmp = path + '.link-' + uuid.uuid4().hex
                os.symlink(desired, tmp)
                os.replace(tmp, path)
        temp_link = current + '.new-' + uuid.uuid4().hex
        os.symlink(generation, temp_link)
        os.replace(temp_link, current)
        directory_fd = os.open(target_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return os.path.join(target_dir, 'fullchain.pem'), os.path.join(target_dir, 'privkey.pem')

    @classmethod
    def reload_downstream_services(
        cls,
        services: Optional[List[str]] = None,
        hook_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Reloads or restarts downstream services (x-ui, nginx, caddy, vpsentinel)
        and executes optional post-sync hook script.
        """
        if services is None:
            services = ['x-ui', 'nginx']

        results = []

        for svc in services:
            svc_name = svc.strip().lower()
            if not svc_name:
                continue

            # 3x-ui / Xray reload
            if svc_name in ('x-ui', '3x-ui', 'xray', 'nginx', 'caddy'):
                mgr = get_service_manager()
                ok, detail = mgr.reload('x-ui' if svc_name == '3x-ui' else svc_name)
                results.append({
                    'service': svc_name,
                    'action': 'reload',
                    'success': ok,
                    'detail': detail or ('x-ui reloaded' if ok else 'Exit non-zero')
                })

            # VPSentinel Dashboard service (Uvicorn)
            elif svc_name in ('vpsentinel', 'oracle-sentinel'):
                # Schedule graceful delayed restart (1s) so HTTP response returns cleanly
                def _delayed_restart():
                    time.sleep(1.0)
                    mgr = get_service_manager()
                    mgr.restart('vpsentinel')
                threading.Thread(target=_delayed_restart, daemon=True).start()
                results.append({
                    'service': 'vpsentinel',
                    'action': 'restart_scheduled',
                    'success': None,
                    'pending': True,
                    'detail': 'Restart queued; completion must be confirmed after reconnect'
                })

        # Post-sync hook script
        if hook_path and hook_path.strip():
            target_hook = hook_path.strip()
            if os.path.exists(target_hook) and os.access(target_hook, os.X_OK):
                try:
                    res = subprocess.run([target_hook], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
                    results.append({
                        'service': 'custom_hook',
                        'action': 'execute',
                        'success': res.returncode == 0,
                        'detail': f'Returncode {res.returncode}: {res.stdout.strip() or res.stderr.strip()}'
                    })
                except Exception as ex:
                    results.append({
                        'service': 'custom_hook',
                        'action': 'execute',
                        'success': False,
                        'detail': str(ex)
                    })

        return results


def serialized_sync(fn):
    import functools
    @functools.wraps(fn)
    def wrapped(cls, *args, **kwargs):
        with cls._operation_lock:
            return fn(cls, *args, **kwargs)
    return wrapped

class CertSyncManager:
    """High-level controller coordinating role checks, polling, and API interactions."""

    _lock = threading.RLock()
    _poller_thread = None
    _operation_lock = threading.RLock()

    @classmethod
    def get_sync_config(cls, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Returns normalized cert_sync config block."""
        if cfg is None:
            from sentinel_core import ConfigManager
            cfg = ConfigManager.load()
        sync_cfg = cfg.get('cert_sync', {})
        default_dir = resolve_cert_dir(sync_cfg.get('cert_dir'))
        return {
            'enabled': bool(sync_cfg.get('enabled', False)),
            'role': sync_cfg.get('role', 'disabled'), # 'disabled', 'master', 'edge'
            'master_url': sync_cfg.get('master_url', '').strip(),
            'sync_token': sync_cfg.get('sync_token', '').strip(),
            'cert_dir': default_dir,
            'poll_interval_hours': int(sync_cfg.get('poll_interval_hours', 12)),
            'auto_reload_services': sync_cfg.get('auto_reload_services', ['x-ui', 'vpsentinel', 'nginx']),
            'post_sync_hook': sync_cfg.get('post_sync_hook', '').strip(),
            'verify_ssl': True,
            'expected_domains': sync_cfg.get('expected_domains', []),
            'last_sync_time': int(sync_cfg.get('last_sync_time', 0)),
            'last_fingerprint': sync_cfg.get('last_fingerprint', ''),
            'last_sync_status': sync_cfg.get('last_sync_status', 'never'),
            'last_sync_message': sync_cfg.get('last_sync_message', '')
        }

    @classmethod
    @transactional
    def update_sync_config(cls, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Updates cert_sync configuration block in config.json."""
        from sentinel_core import ConfigManager
        with cls._lock:
            cfg = ConfigManager.load()
            if 'cert_sync' not in cfg:
                cfg['cert_sync'] = {}

            for k in [
                'enabled', 'role', 'master_url', 'sync_token', 'cert_dir',
                'poll_interval_hours', 'auto_reload_services', 'post_sync_hook', 'expected_domains',
                'verify_ssl', 'last_sync_time', 'last_fingerprint',
                'last_sync_status', 'last_sync_message'
            ]:
                if k in new_settings:
                    cfg['cert_sync'][k] = new_settings[k]

            ConfigManager.save(cfg)
            return cls.get_sync_config(cfg)

    @classmethod
    @serialized_sync
    def perform_edge_sync(cls, force: bool = False) -> Dict[str, Any]:
        """
        Executes an edge sync cycle:
        1. Queries master status
        2. Compares fingerprint with local cert
        3. Pulls and saves if different or missing or force
        4. Reloads services
        5. Updates persistent status
        """
        from sentinel_core import ConfigManager
        cfg = ConfigManager.load()
        sync_cfg = cls.get_sync_config(cfg)

        if sync_cfg['role'] != 'edge':
            return {
                'success': False,
                'status': 'skipped',
                'message': f"Node role is '{sync_cfg['role']}', not 'edge'."
            }

        master_url = sync_cfg['master_url']
        sync_token = sync_cfg['sync_token']
        cert_dir = sync_cfg['cert_dir']
        verify_ssl = sync_cfg['verify_ssl']

        if not master_url or not sync_token:
            msg = "Master URL or Sync Token is empty in cert_sync config."
            cls._update_sync_status(status='failed', message=msg)
            return {'success': False, 'status': 'failed', 'message': msg}

        # Step 1: Probe master status
        probe = CertSyncAgent.check_master_status(master_url, sync_token, verify_ssl=verify_ssl)
        if probe.get('status') == 'error':
            msg = f"Master probe failed: {probe.get('error')}"
            cls._update_sync_status(status='failed', message=msg)
            return {'success': False, 'status': 'failed', 'message': msg}

        master_fp = probe.get('fingerprint', '').strip()
        local_info = CertManager.get_local_cert_info(cert_dir)
        local_fp = local_info.get('fingerprint', '').strip()

        # Step 2: Compare fingerprints
        if not force and local_info.get('exists') and local_info.get('privkey_exists') and local_fp and local_fp == master_fp:
            msg = f"Local certificate is already identical to master (Fingerprint: {master_fp[:16]}...)"
            cls._update_sync_status(status='up_to_date', message=msg, fingerprint=master_fp)
            return {
                'success': True,
                'status': 'up_to_date',
                'fingerprint': master_fp,
                'message': msg,
                'reloaded': []
            }

        # Step 3: Pull bundle
        try:
            bundle = CertSyncAgent.pull_cert_bundle(master_url, sync_token, verify_ssl=verify_ssl)
            cert_pem = bundle.get('cert_pem', '')
            key_pem = bundle.get('key_pem', '')
            downloaded_fp = bundle.get('fingerprint', '')

            if not cert_pem or not key_pem:
                raise ValueError("Master returned empty certificate or private key.")

            actual_fp = CertManager.calculate_fingerprint(cert_pem.encode())
            if not downloaded_fp or downloaded_fp != actual_fp or (master_fp and master_fp != actual_fp):
                raise ValueError('Certificate fingerprint does not match the authenticated master')
            from cryptography import x509
            parsed = x509.load_pem_x509_certificate(cert_pem.encode())
            sans = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            expected = sync_cfg.get('expected_domains', []) or cfg.get('cert_sync', {}).get('expected_domains', [])
            for domain in expected:
                if domain not in sans and not any(name.startswith('*.') and domain.count('.') == name.count('.') and domain.endswith(name[1:]) for name in sans):
                    raise ValueError('Certificate SAN does not cover ' + domain)
            current = os.path.join(cert_dir, '.current')
            previous = os.readlink(current) if os.path.islink(current) else None
            # Step 4: Atomic save
            CertSyncAgent.save_cert_bundle_atomic(cert_pem, key_pem, cert_dir)

            # Step 5: Reload services
            services = sync_cfg.get('auto_reload_services', ['x-ui', 'vpsentinel', 'nginx'])
            hook = sync_cfg.get('post_sync_hook', '')
            reload_results = CertSyncAgent.reload_downstream_services(services=services, hook_path=hook)

            failed = [item for item in reload_results if not item.get('success') and not item.get('pending')]
            if failed:
                if previous:
                    rollback = current + '.rollback'
                    if os.path.lexists(rollback): os.unlink(rollback)
                    os.symlink(previous, rollback)
                    os.replace(rollback, current)
                    CertSyncAgent.reload_downstream_services(services=[x for x in services if x not in ('vpsentinel', 'oracle-sentinel')])
                raise RuntimeError('Downstream reload failed: ' + str(failed))
            pending = any(item.get('pending') for item in reload_results)
            status = 'reload_pending' if pending else 'success'
            msg = f"Successfully synchronized certificate (Fingerprint: {downloaded_fp[:16]}...)"
            cls._update_sync_status(status=status, message=msg, fingerprint=downloaded_fp)

            return {
                'success': not pending,
                'status': status,
                'fingerprint': downloaded_fp,
                'domains': bundle.get('domains', []),
                'valid_to': bundle.get('valid_to', ''),
                'days_left': bundle.get('days_left', 0),
                'reloaded': reload_results,
                'message': msg
            }

        except Exception as e:
            err_msg = f"Failed to pull/save certificate bundle: {e}"
            logger.error(err_msg)
            cls._update_sync_status(status='failed', message=err_msg)
            return {'success': False, 'status': 'failed', 'message': err_msg}

    @classmethod
    @transactional
    def _update_sync_status(
        cls,
        status: str,
        message: str,
        fingerprint: Optional[str] = None
    ):
        """Updates last sync state in config."""
        from sentinel_core import ConfigManager
        with cls._lock:
            cfg = ConfigManager.load()
            if 'cert_sync' not in cfg:
                cfg['cert_sync'] = {}
            cfg['cert_sync']['last_sync_time'] = int(time.time())
            cfg['cert_sync']['last_sync_status'] = status
            cfg['cert_sync']['last_sync_message'] = message
            if fingerprint:
                cfg['cert_sync']['last_fingerprint'] = fingerprint
            ConfigManager.save(cfg)

    @classmethod
    def start_background_poller(cls, get_config_func=None, interval_hours: Optional[int] = None):
        """Starts background daemon to periodically check & sync certificate."""
        existing = getattr(cls, '_poller_thread', None)
        if existing is not None and existing.is_alive():
            return existing
        stop_event = threading.Event()
        cls._stop_event = stop_event
        def _loop():
            logger.info("Starting Distributed Certificate Sync background poller...")
            while not stop_event.is_set():
                try:
                    cfg = get_config_func() if callable(get_config_func) else cls.get_sync_config()
                    sync_cfg = cls.get_sync_config(cfg)
                    role = sync_cfg.get('role', 'disabled')
                    enabled = sync_cfg.get('enabled', False)

                    if enabled and role == 'edge':
                        interval = interval_hours or sync_cfg.get('poll_interval_hours', 12)
                        last_sync = sync_cfg.get('last_sync_time', 0)
                        now = int(time.time())

                        if now - last_sync >= interval * 3600:
                            logger.info("Executing scheduled edge certificate check...")
                            res = cls.perform_edge_sync(force=False)
                            logger.info(f"Edge certificate sync result: {res.get('status')} - {res.get('message')}")
                except Exception as e:
                    logger.error(f"Error in CertSync background loop: {e}")

                stop_event.wait(300) # Check criteria every 5 minutes

        with cls._lock:
            if cls._poller_thread is None or not cls._poller_thread.is_alive():
                cls._poller_thread = threading.Thread(target=_loop, name="CertSyncPollerDaemon", daemon=True)
                cls._poller_thread.start()
        return cls._poller_thread

if __name__ == '__main__':
    info = CertManager.get_local_cert_info()
    print("Local Certificate Info:", json.dumps(info, indent=2))
