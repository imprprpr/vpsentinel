#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPSentinel Authentication, Session & Host Guard Module
Author: Antigravity Agent
"""

import os
import time
import hmac
import hashlib
import secrets
import base64
import logging
import ipaddress
import threading
from collections import OrderedDict
from secure_files import atomic_write, transactional
from typing import Optional, Dict, Any, Tuple
try:
    from fastapi import Request, Response, HTTPException
except ImportError:
    Request = Any
    Response = Any
    HTTPException = Exception

logger = logging.getLogger("AuthMgr")

DEFAULT_ADMIN_USER = "admin"
DEFAULT_SAFE_PATH = "/sentinel"
SESSION_TTL_SEC = 86400 * 30  # 30 days session validity
PBKDF2_ITERATIONS = 600_000
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_WINDOW_SEC = 900  # 15 minutes

class AuthManager:
    def __init__(self, cfg_mgr):
        self.cfg_mgr = cfg_mgr
        self._failed_attempts = OrderedDict()
        self._attempt_lock = threading.RLock()
        self._global_failures = []
        self._ensure_security_config()

    @transactional
    def _ensure_security_config(self):
        """Initializes default security settings in config.json if not present."""
        cfg = self.cfg_mgr.load()
        sec = cfg.setdefault("security", {})
        changed = False

        if "auth_enabled" not in sec:
            sec["auth_enabled"] = True
            changed = True

        if "admin_username" not in sec:
            sec["admin_username"] = DEFAULT_ADMIN_USER
            changed = True

        if "session_secret" not in sec or not sec["session_secret"]:
            sec["session_secret"] = secrets.token_hex(32)
            changed = True

        if "admin_password_hash" not in sec or not sec["admin_password_hash"]:
            initial_pass = secrets.token_urlsafe(16)
            sec["admin_password_hash"] = self.hash_password(initial_pass)
            sec["must_change_password"] = True
            changed = True
            from paths import get_config_path
            atomic_write(get_config_path() + '.initial-password', initial_pass + '\n')
            logger.warning("Initial password saved in the protected .initial-password file next to config; change it after first login.")

        if not sec.get('mesh_token'):
            sec['mesh_token'] = secrets.token_hex(32)
            changed = True

        if "sub_token" not in sec or not sec["sub_token"]:
            sec["sub_token"] = secrets.token_hex(16)
            changed = True

        if "secret_path" not in sec:
            sec["secret_path"] = DEFAULT_SAFE_PATH
            changed = True

        if "enable_host_guard" not in sec:
            sec["enable_host_guard"] = True
            changed = True

        if "allowed_hosts" not in sec:
            # Auto populate domain if known
            cf_record = cfg.get("cloudflare", {}).get("record_name", "").strip()
            sec["allowed_hosts"] = [cf_record] if cf_record else []
            changed = True

        if changed:
            self.cfg_mgr.save(cfg)
            logger.info("Security configuration initialized successfully.")

    def get_security_config(self) -> Dict[str, Any]:
        cfg = self.cfg_mgr.load()
        return cfg.get("security", {})

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None, iterations: int = PBKDF2_ITERATIONS) -> str:
        if not salt:
            salt = secrets.token_hex(16)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
        return f"pbkdf2_sha256${iterations}${salt}${derived.hex()}"

    @classmethod
    def verify_password(cls, password: str, stored_hash: str) -> bool:
        if not stored_hash or len(password) > 1024:
            return False
        try:
            if stored_hash.startswith("pbkdf2_sha256$"):
                parts = stored_hash.split("$")
                if len(parts) != 4:
                    return False
                _, iter_str, salt, expected_hex = parts
                iterations = int(iter_str)
                calculated = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
                return hmac.compare_digest(expected_hex, calculated.hex())
            elif ":" in stored_hash:
                # Backward compatibility with legacy salt:key
                salt, expected_key = stored_hash.split(":", 1)
                calculated_key = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
                return hmac.compare_digest(expected_key, calculated_key)
            return False
        except Exception:
            return False

    @staticmethod
    def _client_key(client_ip):
        try:
            return str(ipaddress.ip_address(client_ip))
        except ValueError:
            return 'unknown'

    def is_client_locked(self, client_ip):
        now = time.time()
        with self._attempt_lock:
            self._global_failures = [t for t in self._global_failures if now - t < 60]
            if len(self._global_failures) >= 100:
                return True, 60
            attempts = [t for t in self._failed_attempts.get(self._client_key(client_ip), []) if now - t < LOCKOUT_WINDOW_SEC]
            if len(attempts) >= MAX_LOGIN_ATTEMPTS:
                return True, max(1, int(LOCKOUT_WINDOW_SEC - now + attempts[0]))
        return False, 0

    def record_login_attempt(self, client_ip, success):
        key, now = self._client_key(client_ip), time.time()
        with self._attempt_lock:
            if success:
                self._failed_attempts.pop(key, None)
                return
            self._global_failures = [t for t in self._global_failures if now - t < 60][-99:] + [now]
            expired = [k for k, v in self._failed_attempts.items() if not v or now - v[-1] >= LOCKOUT_WINDOW_SEC]
            for stale in expired: self._failed_attempts.pop(stale, None)
            attempts = [t for t in self._failed_attempts.pop(key, []) if now - t < LOCKOUT_WINDOW_SEC]
            self._failed_attempts[key] = (attempts + [now])[-MAX_LOGIN_ATTEMPTS:]
            while len(self._failed_attempts) > 1024:
                self._failed_attempts.popitem(last=False)

    def authenticate_admin(self, username: str, password: str, client_ip: str = "unknown") -> Tuple[bool, str]:
        with self._attempt_lock:
            return self._authenticate_admin(username, password, client_ip)

    def _authenticate_admin(self, username: str, password: str, client_ip: str = "unknown") -> Tuple[bool, str]:
        locked, rem_sec = self.is_client_locked(client_ip)
        if locked:
            return False, f"登录失败次数过多，已被系统临时封锁，请在 {rem_sec} 秒后重试"

        sec = self.get_security_config()
        expected_user = sec.get("admin_username", DEFAULT_ADMIN_USER)
        expected_hash = sec.get("admin_password_hash", "")

        if username != expected_user or not self.verify_password(password, expected_hash):
            self.record_login_attempt(client_ip, success=False)
            return False, "用户名或密码错误"

        self.record_login_attempt(client_ip, success=True)

        # Smoothly upgrade legacy salt:sha256 hash to PBKDF2 upon successful login
        if expected_hash and (not expected_hash.startswith("pbkdf2_sha256$") or int(expected_hash.split('$')[1]) < PBKDF2_ITERATIONS):
            try:
                def _upgrade(cfg):
                    cfg.setdefault("security", {})["admin_password_hash"] = self.hash_password(password)
                    return True
                self.cfg_mgr.update(_upgrade)
                logger.info("Upgraded admin password hash to PBKDF2-HMAC-SHA256.")
            except Exception as e:
                logger.warning(f"Failed to auto-upgrade password hash: {e}")

        # Generate HMAC session token
        token = self.create_session_token(username)
        return True, token

    def create_session_token(self, username: str) -> str:
        sec = self.get_security_config()
        secret_str = sec.get("session_secret")
        if not secret_str:
            secret_str = secrets.token_hex(32)
            cfg = self.cfg_mgr.load()
            cfg.setdefault("security", {})["session_secret"] = secret_str
            self.cfg_mgr.save(cfg)
        secret_key = secret_str.encode("utf-8")
        timestamp = str(int(time.time()))
        payload = f"{username}:{timestamp}"
        signature = hmac.new(secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        raw = f"{payload}:{signature}"
        return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")

    def verify_session_token(self, token: Optional[str]) -> bool:
        if not token:
            return False
        sec = self.get_security_config()
        try:
            raw = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
            parts = raw.split(":")
            if len(parts) != 3:
                return False
            username, timestamp_str, signature = parts
            timestamp = int(timestamp_str)
            now = int(time.time())

            if username != sec.get("admin_username", DEFAULT_ADMIN_USER) or timestamp > now + 30 or now - timestamp > SESSION_TTL_SEC:
                return False  # Expired

            secret_str = sec.get("session_secret")
            if not secret_str:
                return False
            secret_key = secret_str.encode("utf-8")
            expected_payload = f"{username}:{timestamp_str}"
            expected_sig = hmac.new(secret_key, expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()
            return hmac.compare_digest(signature, expected_sig)
        except Exception:
            return False

    def is_request_authenticated(self, request: Request) -> bool:
        sec = self.get_security_config()
        if not sec.get("auth_enabled", True):
            return True

        # 1. Check Cookie
        cookie_token = request.cookies.get("sentinel_session")
        if self.verify_session_token(cookie_token):
            return True

        # 2. Check Authorization Header (Bearer <token>)
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            if self.verify_session_token(token):
                return True

        # Query parameter session_token intentionally rejected to prevent log leakage
        return False

    def verify_subscription_access(self, request: Request) -> bool:
        """Verifies if request has permission to download Clash/Singbox sub."""
        sec = self.get_security_config()
        if not sec.get("auth_enabled", True):
            return True

        # If admin is logged in
        if self.is_request_authenticated(request):
            return True

        # Check sub_token query parameter or path
        expected_sub_token = sec.get("sub_token", "")
        if not expected_sub_token:
            return False

        token_param = request.query_params.get("token", "")
        if token_param and hmac.compare_digest(token_param, expected_sub_token):
            return True

        # Also support sub_token passed via Bearer
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            b_token = auth_header[7:].strip()
            if hmac.compare_digest(b_token, expected_sub_token):
                return True

        return False

    def check_host_guard(self, request: Request) -> bool:
        """
        Validates request Host header.
        Rejects raw IP scans (e.g. https://129.146.230.81:20540).
        """
        sec = self.get_security_config()
        if not sec.get("enable_host_guard", True):
            return True

        # During first-run uninitialized state without configured allowed_hosts,
        # allow IP access so user can open setup wizard
        cfg = self.cfg_mgr.load()
        if not cfg.get("initialized", False) and not sec.get("allowed_hosts"):
            return True

        # A telemetry credential bypasses Host Guard only for its own read-only endpoint.
        if getattr(getattr(request, 'url', None), 'path', None) == '/api/mesh/telemetry':
            mesh_token = sec.get('mesh_token', '')
            supplied = request.headers.get('authorization', '').removeprefix('Bearer ').strip()
            if mesh_token and supplied and hmac.compare_digest(supplied, mesh_token):
                return True

        # Authenticated requests (admin session or valid sub/bearer token) bypass Host Guard
        if self.is_request_authenticated(request) or self.verify_subscription_access(request):
            return True

        raw_host = request.headers.get("host", "").strip()
        if not raw_host:
            return False

        # Extract hostname part without port
        hostname = raw_host.split(":")[0].strip().lower()

        # Local loopback client accessing local loopback host
        client_host = request.client.host if request.client else ""
        if hostname in ("127.0.0.1", "localhost", "::1") and client_host in ("127.0.0.1", "::1", "localhost"):
            return True

        # Build allowed list
        cfg = self.cfg_mgr.load()
        cf_record = cfg.get("cloudflare", {}).get("record_name", "").strip().lower()
        allowed = [h.strip().lower() for h in sec.get("allowed_hosts", []) if h.strip()]
        if cf_record and cf_record not in allowed:
            allowed.append(cf_record)

        # Check if hostname matches any allowed host
        if hostname in allowed:
            return True

        # If it's a raw IP address that wasn't explicitly whitelisted, reject!
        try:
            ipaddress.ip_address(hostname)
            # It IS a raw IP address (e.g. 129.146.230.81) -> BLOCK!
            logger.warning(f"Host Guard blocked direct IP probe: Host='{raw_host}' from Client='{request.client.host if request.client else 'unknown'}'")
            return False
        except ValueError:
            # It is a domain name. If allowed_hosts list is empty, allow it; otherwise require match.
            if not allowed:
                return True
            return False

    @transactional
    def update_password(self, new_password: str) -> bool:
        if not new_password or len(new_password) < 12 or len(new_password) > 1024:
            return False
        cfg = self.cfg_mgr.load()
        sec = cfg.setdefault("security", {})
        sec["admin_password_hash"] = self.hash_password(new_password)
        sec["must_change_password"] = False
        # Invalidate existing sessions by rotating session secret
        sec["session_secret"] = secrets.token_hex(32)
        self.cfg_mgr.save(cfg)
        from paths import get_config_path
        initial_file = get_config_path() + '.initial-password'
        if os.path.exists(initial_file):
            os.unlink(initial_file)
        logger.info("Admin password updated successfully.")
        return True

    @transactional
    def update_security_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.cfg_mgr.load()
        sec = cfg.setdefault("security", {})
        for k in ["auth_enabled", "secret_path", "enable_host_guard", "allowed_hosts"]:
            if k in settings:
                sec[k] = settings[k]
        if settings.get("regenerate_sub_token"):
            sec["sub_token"] = secrets.token_hex(16)
        self.cfg_mgr.save(cfg)
        return {k: v for k, v in sec.items() if k not in ("session_secret", "admin_password_hash")}

    def revoke_sessions(self):
        def rotate(cfg):
            cfg.setdefault('security', {})['session_secret'] = secrets.token_hex(32)
        self.cfg_mgr.update(rotate)

    def is_privileged_request(self, request):
        token = request.cookies.get('sentinel_session')
        header = request.headers.get('authorization', '')
        if header.lower().startswith('bearer '):
            token = header[7:].strip()
        return self.verify_session_token(token)
