import os
import sys
import json
import time
import threading
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    import tests.sandbox  # noqa: F401
except ImportError:
    import sandbox  # noqa: F401

from starlette.testclient import TestClient

import app
import sentinel_core
import auth_mgr
import sub_engine
import mesh_mgr

class TestSecurityAudit(unittest.TestCase):
    TEST_ADMIN_PASS = "TestAdminPass2026!"

    @classmethod
    def setUpClass(cls):
        cls.orig_env_cfg = os.environ.get('VPSENTINEL_CONFIG_PATH')
        cls.orig_config = sentinel_core.ConfigManager.load()
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.tmp_cfg_path = os.path.join(cls.tmp_dir.name, 'config.json')
        os.environ['VPSENTINEL_CONFIG_PATH'] = cls.tmp_cfg_path
        sentinel_core.ConfigManager.invalidate_cache()

        test_cfg = json.loads(json.dumps(cls.orig_config))
        test_cfg["initialized"] = True
        test_cfg["security"] = {
            "auth_enabled": True,
            "admin_username": "admin",
            "admin_password_hash": app.auth.hash_password(cls.TEST_ADMIN_PASS),
            "session_secret": "test_security_session_secret_12345",
            "secret_path": "/sentinel",
            "sub_token": "test_security_sub_token_123",
            "enable_host_guard": True,
            "allowed_hosts": ["vps.example.com"]
        }
        test_cfg["cloudflare"] = {
            "api_token": "",
            "zone_name": "",
            "record_name": "vps.example.com"
        }
        sentinel_core.ConfigManager.save(test_cfg)
        cls.sec_cfg = test_cfg["security"]
        cls.sub_token = "test_security_sub_token_123"
        cls.admin_token = app.auth.create_session_token("admin")
        cls.client = TestClient(app.app, base_url='https://vps.example.com')

    @classmethod
    def tearDownClass(cls):
        if cls.orig_env_cfg is not None:
            os.environ['VPSENTINEL_CONFIG_PATH'] = cls.orig_env_cfg
        else:
            os.environ.pop('VPSENTINEL_CONFIG_PATH', None)
        cls.tmp_dir.cleanup()
        sentinel_core.ConfigManager.invalidate_cache()

    def test_unauthenticated_sensitive_endpoints_return_401(self):
        endpoints = [
            '/api/custom-nodes',
            '/api/mesh/nodes',
            '/api/mesh/overview',
            '/api/services',
            '/api/sub/rules',
            '/api/transits',
            '/api/traffic/stats',
            '/api/speedtest/status',
            '/api/status',
            '/api/ip/audit'
        ]
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertEqual(
                res.status_code,
                401,
                f"Endpoint {ep} should return 401 for unauthenticated request, got {res.status_code}"
            )

    def test_authenticated_endpoints_succeed(self):
        if not self.admin_token:
            self.skipTest("No admin token available")

        cookies = {"sentinel_session": self.admin_token}
        res_custom = self.client.get('/api/custom-nodes', cookies=cookies)
        self.assertEqual(res_custom.status_code, 200)

        res_transits = self.client.get('/api/transits', cookies=cookies)
        self.assertEqual(res_transits.status_code, 200)

        res_sub_rules = self.client.get('/api/sub/rules', cookies=cookies)
        self.assertEqual(res_sub_rules.status_code, 200)

        res_mesh_nodes = self.client.get('/api/mesh/nodes', cookies=cookies)
        self.assertEqual(res_mesh_nodes.status_code, 200)

        res_traffic = self.client.get('/api/traffic/stats', cookies=cookies)
        self.assertEqual(res_traffic.status_code, 200)

    def test_setup_endpoints_require_auth_for_external_clients(self):
        # Simulate an unauthenticated external client
        client_external = TestClient(
            app.app,
            base_url='https://vps.example.com'
        )
        res_cf = client_external.post('/api/setup/verify-cf', json={'token': 'test'})
        self.assertEqual(res_cf.status_code, 401)

        res_key = client_external.post('/api/setup/generate-key')
        self.assertEqual(res_key.status_code, 401)

        res_save = client_external.post('/api/setup/save', json={'provider_type': 'auto'})
        self.assertEqual(res_save.status_code, 401)

        # Test check_setup_allowed directly with mock requests
        class DummySetupReq:
            def __init__(self, peer_ip, headers=None):
                self.client = type("Client", (), {"host": peer_ip})()
                self.headers = headers or {}
                self.cookies = {}
                self.state = type("State", (), {"client_ip": peer_ip})()

        orig_cfg = sentinel_core.ConfigManager.load()
        try:
            cfg = json.loads(json.dumps(orig_cfg))
            cfg['initialized'] = False
            sentinel_core.ConfigManager.save(cfg)

            # Direct localhost request without proxy headers -> Allowed
            req_direct_local = DummySetupReq('127.0.0.1')
            app.check_setup_allowed(req_direct_local)

            # Localhost peer but with reverse proxy headers (e.g., from unauthenticated nginx) -> Rejected (401)
            req_proxied = DummySetupReq('127.0.0.1', {'x-forwarded-for': '203.0.113.199'})
            with self.assertRaises(app.HTTPException) as ctx:
                app.check_setup_allowed(req_proxied)
            self.assertEqual(ctx.exception.status_code, 401)

            # External peer -> Rejected (401)
            req_ext = DummySetupReq('203.0.113.199')
            with self.assertRaises(app.HTTPException) as ctx:
                app.check_setup_allowed(req_ext)
            self.assertEqual(ctx.exception.status_code, 401)
        finally:
            sentinel_core.ConfigManager.save(orig_cfg)

    def test_atomic_config_storage_concurrency(self):
        errors = []

        def worker(thread_idx):
            for i in range(10):
                val = f"test_val_{thread_idx}_{i}"
                ok = sentinel_core.ConfigManager.update_key(f"test_concurrency_{thread_idx}", val)
                if not ok:
                    errors.append(f"Write failure in thread {thread_idx} loop {i}")
                cfg = sentinel_core.ConfigManager.load()
                if not isinstance(cfg, dict):
                    errors.append(f"Read corrupted in thread {thread_idx} loop {i}")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(errors), 0, f"Concurrent config write errors: {errors}")

    def test_host_guard_ip_and_auth_bypass(self):
        class DummyRequest:
            def __init__(self, host, cookies=None, headers=None, client_ip="203.0.113.5"):
                self.headers = headers or {"host": host}
                self.cookies = cookies or {}
                self.query_params = {}
                self.client = type("Client", (), {"host": client_ip})()

        # Unauthenticated raw IP probe should be rejected
        req_raw_ip = DummyRequest(host="129.146.230.81")
        self.assertFalse(app.auth.check_host_guard(req_raw_ip))

        # Authenticated raw IP probe with admin cookie should be allowed
        req_auth_ip = DummyRequest(
            host="129.146.230.81",
            cookies={"sentinel_session": self.admin_token}
        )
        self.assertTrue(app.auth.check_host_guard(req_auth_ip))

        # Authenticated raw IP probe with Bearer token should be allowed
        req_bearer_ip = DummyRequest(
            host="129.146.230.81",
            headers={"host": "129.146.230.81", "authorization": f"Bearer {self.sub_token}"}
        )
        self.assertTrue(app.auth.check_host_guard(req_bearer_ip))

    def test_mesh_proxy_aggregation_in_subscriptions(self):
        mock_mesh_nodes = [
            {
                "id": "node_test_mesh",
                "name": "Tokyo-Test",
                "host": "tokyo.test.com:20540",
                "enabled": True,
                "proxy_nodes": [
                    {
                        "type": "vless",
                        "name": "[Tokyo-Test] VLESS-Reality",
                        "server": "140.238.10.10",
                        "port": 8443,
                        "uuid": "00000000-0000-0000-0000-000000000001",
                        "network": "tcp",
                        "tls": True,
                        "flow": "xtls-rprx-vision",
                        "servername": "swdist.apple.com",
                        "reality-opts": {
                            "public-key": "abcdef123456",
                            "short-id": "1234"
                        },
                        "raw_link": "vless://00000000-0000-0000-0000-000000000001@140.238.10.10:8443?security=reality&sni=swdist.apple.com&pbk=abcdef123456&sid=1234&type=tcp&flow=xtls-rprx-vision#[Tokyo-Test] VLESS-Reality"
                    }
                ]
            }
        ]

        original_get_nodes = mesh_mgr.MeshManager.get_nodes
        try:
            mesh_mgr.MeshManager.get_nodes = classmethod(lambda cls: mock_mesh_nodes)

            # Test Clash output contains mesh proxy
            clash_yaml = sub_engine.SubEngine.generate_clash_yaml()
            self.assertIn("[Tokyo-Test] VLESS-Reality", clash_yaml)

            # Test Sing-box output contains mesh proxy
            singbox_json = sub_engine.SubEngine.generate_singbox_json()
            self.assertIn("[Tokyo-Test] VLESS-Reality", singbox_json)

            # Test Base64 output contains mesh proxy link
            b64_output = sub_engine.SubEngine.generate_v2ray_base64()
            import base64
            decoded = base64.b64decode(b64_output).decode('utf-8')
            self.assertIn("[Tokyo-Test] VLESS-Reality", decoded)
        finally:
            mesh_mgr.MeshManager.get_nodes = original_get_nodes

    def test_pbkdf2_hashing_and_legacy_compatibility(self):
        # 1. PBKDF2 hash generation
        pwd = "MySecretPass_2026!"
        h = app.auth.hash_password(pwd)
        self.assertTrue(h.startswith("pbkdf2_sha256$600000$"))
        self.assertTrue(app.auth.verify_password(pwd, h))
        self.assertFalse(app.auth.verify_password("WrongPass", h))

        # 2. Legacy salt:sha256 verification and auto-upgrade
        import hashlib
        salt = "testsalt123456"
        legacy_key = hashlib.sha256((salt + pwd).encode("utf-8")).hexdigest()
        legacy_hash = f"{salt}:{legacy_key}"
        self.assertTrue(app.auth.verify_password(pwd, legacy_hash))

        # Test auto-upgrade via authenticate_admin
        cfg = sentinel_core.ConfigManager.load()
        cfg.setdefault("security", {})["admin_password_hash"] = legacy_hash
        sentinel_core.ConfigManager.save(cfg)

        ok, token = app.auth.authenticate_admin("admin", pwd, client_ip="198.51.100.1")
        self.assertTrue(ok)
        new_cfg = sentinel_core.ConfigManager.load()
        upgraded_hash = new_cfg.get("security", {}).get("admin_password_hash", "")
        self.assertTrue(upgraded_hash.startswith("pbkdf2_sha256$600000$"))
        self.assertTrue(app.auth.verify_password(pwd, upgraded_hash))

    def test_brute_force_lockout(self):
        target_ip = "198.51.100.99"
        # Reset any previous attempts for this IP
        app.auth._failed_attempts.pop(target_ip, None)

        # 5 failed attempts
        for i in range(auth_mgr.MAX_LOGIN_ATTEMPTS):
            ok, msg = app.auth.authenticate_admin("admin", "invalid_password", client_ip=target_ip)
            self.assertFalse(ok)

        # 6th attempt should be blocked by rate limiter
        ok, msg = app.auth.authenticate_admin("admin", "invalid_password", client_ip=target_ip)
        self.assertFalse(ok)
        self.assertIn("登录失败次数过多", msg)

        # Another IP should not be blocked
        other_ip = "198.51.100.100"
        app.auth._failed_attempts.pop(other_ip, None)
        locked, _ = app.auth.is_client_locked(other_ip)
        self.assertFalse(locked)

    def test_query_param_session_token_rejected(self):
        # Even with valid session token in query param, request must return 401
        res = self.client.get(f'/api/custom-nodes?session_token={self.admin_token}')
        self.assertEqual(res.status_code, 401)

    def test_udp_listening_socket_check(self):
        import socket
        sys_monitor = sentinel_core.SystemMonitor()
        
        # Test an unbound high UDP port -> should return False
        self.assertFalse(sys_monitor.check_port_listening(59999, proto='udp'))

        # Bind a real UDP port and verify check_port_listening returns True
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp_sock.bind(('127.0.0.1', 0))
            bound_port = udp_sock.getsockname()[1]
            self.assertTrue(sys_monitor.check_port_listening(bound_port, proto='udp'))
            # Check TCP on same port should return False
            self.assertFalse(sys_monitor.check_port_listening(bound_port, proto='tcp'))
        finally:
            udp_sock.close()

    def test_reip_cooldown_circuit_breaker(self):
        import asyncio
        cfg = sentinel_core.ConfigManager.load()
        cfg.setdefault('monitor', {})['auto_heal_enabled'] = True
        cfg['monitor']['reip_cooldown_hours'] = 24
        # Set last_reip_timestamp to 1 hour ago
        cfg['monitor']['last_reip_timestamp'] = int(time.time()) - 3600
        sentinel_core.ConfigManager.save(cfg)

        app.runtime_state['heal_in_progress'] = False
        app.runtime_state['status'] = 'healthy'

        # Running AUTO heal within 24h window should be suppressed
        with patch('notification.NotificationManager.broadcast'):
            asyncio.run(app.run_healing_routine('AUTO'))
        # Should not transition to 'healing' because cooldown blocked it
        self.assertFalse(app.runtime_state['heal_in_progress'])
        self.assertEqual(app.runtime_state['status'], 'healthy')

    def test_setup_status_unauthenticated_leak_prevention(self):
        orig_cfg = sentinel_core.ConfigManager.load()
        try:
            cfg = json.loads(json.dumps(orig_cfg))
            cfg['initialized'] = True
            cfg['notifications'] = {
                'custom_webhook': {
                    'enabled': True,
                    'url': 'https://hooks.slack.com/services/T123/B456/SECRET'
                }
            }
            sentinel_core.ConfigManager.save(cfg)

            # Unauthenticated request: config must be None, notifications omitted
            res_unauth = self.client.get('/api/setup/status')
            self.assertEqual(res_unauth.status_code, 200)
            data_unauth = res_unauth.json()
            self.assertTrue(data_unauth.get('initialized'))
            self.assertIsNone(data_unauth.get('config'))
            self.assertIsNone(data_unauth.get('notifications'))

            # Authenticated request: config present, webhook secret masked
            res_auth = self.client.get(
                '/api/setup/status',
                cookies={'sentinel_session': self.admin_token}
            )
            self.assertEqual(res_auth.status_code, 200)
            data_auth = res_auth.json()
            self.assertIsNotNone(data_auth.get('config'))
            notif_cfg = data_auth.get('config', {}).get('notifications', {})
            expected_masked = app.mask_token('https://hooks.slack.com/services/T123/B456/SECRET', head=8, tail=4)
            self.assertEqual(
                notif_cfg.get('custom_webhook', {}).get('url'),
                expected_masked
            )
        finally:
            sentinel_core.ConfigManager.save(orig_cfg)

    def test_cert_bundle_private_key_auth_enforcement(self):
        # 1. Unauthenticated request must return 401
        res_unauth = self.client.get('/api/cert/bundle')
        self.assertEqual(res_unauth.status_code, 401)

        # 2. sub_token must be strictly rejected with 401
        res_sub = self.client.get(
            '/api/cert/bundle',
            headers={'Authorization': f'Bearer {self.sub_token}'}
        )
        self.assertEqual(res_sub.status_code, 401)

        # 3. sync_token bearer must be accepted (proceeds past auth check: 200 or 404, never 401)
        sync_token = 'valid_sync_token_for_audit_test_99'
        orig_cfg = sentinel_core.ConfigManager.load()
        try:
            cfg = json.loads(json.dumps(orig_cfg))
            cfg.setdefault('cert_sync', {})['sync_token'] = sync_token
            sentinel_core.ConfigManager.save(cfg)

            res_sync = self.client.get(
                '/api/cert/bundle',
                headers={'Authorization': f'Bearer {sync_token}'}
            )
            self.assertIn(res_sync.status_code, [200, 404])
        finally:
            sentinel_core.ConfigManager.save(orig_cfg)

        # 4. Admin session cookie must be accepted
        res_admin = self.client.get(
            '/api/cert/bundle',
            cookies={'sentinel_session': self.admin_token}
        )
        self.assertIn(res_admin.status_code, [200, 404])

    def test_login_rate_limiter_spoofed_headers(self):
        class DummyClient:
            def __init__(self, host):
                self.host = host

        class DummyReq:
            def __init__(self, host_peer, headers=None):
                self.client = DummyClient(host_peer)
                self.headers = headers or {}

        # 1. Untrusted peer trying to spoof CF-Connecting-IP -> ignored, use peer IP
        req_untrusted = DummyReq('203.0.113.10', {'CF-Connecting-IP': '198.51.100.9'})
        resolved_ip = app.resolve_client_ip(req_untrusted)
        self.assertEqual(resolved_ip, '203.0.113.10')

        # 2. Trusted Cloudflare proxy sending CF-Connecting-IP -> accepted
        req_trusted = DummyReq('173.245.48.10', {'CF-Connecting-IP': '198.51.100.9'})
        resolved_ip = app.resolve_client_ip(req_trusted)
        self.assertEqual(resolved_ip, '198.51.100.9')

        # 3. Loopback peer sending spoofed CF-Connecting-IP without custom_cidrs -> returns 127.0.0.1
        app._loopback_proxy_warned = False
        req_loopback_cf = DummyReq('127.0.0.1', {'CF-Connecting-IP': '198.51.100.9'})
        resolved_ip = app.resolve_client_ip(req_loopback_cf)
        self.assertEqual(resolved_ip, '127.0.0.1')
        self.assertTrue(app._loopback_proxy_warned)

        # 4. Loopback peer sending spoofed single XFF without custom_cidrs -> returns 127.0.0.1
        req_local_default_xff = DummyReq('127.0.0.1', {'X-Forwarded-For': '1.2.3.4'})
        resolved_ip = app.resolve_client_ip(req_local_default_xff)
        self.assertEqual(resolved_ip, '127.0.0.1')

        # 5. Loopback configured in custom_cidrs with XFF -> traverses right-to-left
        req_local_configured = DummyReq('127.0.0.1', {'X-Forwarded-For': '1.2.3.4, 198.51.100.9'})
        resolved_ip = app.resolve_client_ip(req_local_configured, custom_cidrs=['127.0.0.1'])
        self.assertEqual(resolved_ip, '198.51.100.9')

        # 6. Multi-proxy network in XFF -> skips trusted hops from right to left
        req_multi_proxy = DummyReq('127.0.0.1', {'X-Forwarded-For': '198.51.100.9, 10.0.0.1'})
        resolved_ip = app.resolve_client_ip(req_multi_proxy, custom_cidrs=['127.0.0.1', '10.0.0.0/8'])
        self.assertEqual(resolved_ip, '198.51.100.9')

    def test_daily_reip_quota_and_force_override(self):
        import asyncio
        from unittest.mock import patch, MagicMock
        now = int(time.time())
        orig_cfg = sentinel_core.ConfigManager.load()
        try:
            cfg = json.loads(json.dumps(orig_cfg))
            cfg.setdefault('monitor', {})['auto_heal_enabled'] = True
            cfg['monitor']['reip_cooldown_hours'] = 0
            cfg['monitor']['max_reip_per_day'] = 2
            cfg['monitor']['reip_history'] = [now - 3600, now - 1800]
            sentinel_core.ConfigManager.save(cfg)

            app.runtime_state['heal_in_progress'] = False
            with patch('notification.NotificationManager.broadcast'):
                res = asyncio.run(app.run_healing_routine('AUTO', force=False))
            self.assertFalse(res['ok'])
            self.assertIn('Daily Re-IP quota exceeded', res['error'])

            # With force=True, quota is bypassed and routine attempts execution
            mock_prov = MagicMock()
            mock_prov.get_name.return_value = 'MockCloud'
            mock_prov.test_connection.return_value = (False, 'Controlled mock validation stop')
            with patch('notification.NotificationManager.broadcast'), \
                 patch('sentinel_core.get_cloud_provider', return_value=mock_prov), \
                 patch.object(app.monitor, 'get_public_ip', return_value='198.51.100.1'):
                res_forced = asyncio.run(app.run_healing_routine('MANUAL', force=True))
                self.assertNotIn('Daily Re-IP quota exceeded', res_forced.get('error', ''))
        finally:
            sentinel_core.ConfigManager.save(orig_cfg)

    def test_uplink_network_down_detection(self):
        from unittest.mock import patch
        sys_mon = sentinel_core.SystemMonitor()
        orig_check_uplink = sys_mon.check_uplink_alive
        try:
            # Simulate total local uplink failure with unresponsive domestic targets
            sys_mon.check_uplink_alive = lambda: False
            with patch('socket.socket.connect', side_effect=OSError('Network unreachable')):
                probe_res = sys_mon.check_domestic_probes()
                self.assertFalse(probe_res['uplink_alive'])
                self.assertTrue(probe_res['network_down'])
                self.assertFalse(probe_res['blocked_suspected'])

                # Full state should reflect network_down without triggering Re-IP
                full_state = sys_mon.get_full_state(force_refresh=True)
                self.assertEqual(full_state.get('health'), 'network_down')
        finally:
            sys_mon.check_uplink_alive = orig_check_uplink

    def test_config_manager_atomic_update_and_chmod(self):
        def mutator(cfg):
            cfg['test_audit_transaction_key'] = 'persisted_successfully'
            return True

        ok = sentinel_core.ConfigManager.update(mutator)
        self.assertTrue(ok)
        loaded = sentinel_core.ConfigManager.load()
        self.assertEqual(loaded.get('test_audit_transaction_key'), 'persisted_successfully')

        st = os.stat(sentinel_core.get_active_config_path())
        self.assertEqual(st.st_mode & 0o777, 0o600)

    def test_host_guard_localhost_peer_check(self):
        class DummyReq:
            def __init__(self, host, client_ip):
                self.headers = {'host': host}
                self.cookies = {}
                self.query_params = {}
                self.client = type('Client', (), {'host': client_ip})()

        # External client spoofing host 'localhost' must be rejected
        req_ext = DummyReq(host='localhost', client_ip='203.0.113.88')
        self.assertFalse(app.auth.check_host_guard(req_ext))

        # External client spoofing host '127.0.0.1' must be rejected
        req_ext_ip = DummyReq(host='127.0.0.1', client_ip='203.0.113.88')
        self.assertFalse(app.auth.check_host_guard(req_ext_ip))

        # True loopback client accessing localhost must be allowed
        req_loopback = DummyReq(host='localhost', client_ip='127.0.0.1')
        self.assertTrue(app.auth.check_host_guard(req_loopback))

    def test_server_header_decoy(self):
        res = self.client.get('/api/setup/status')
        self.assertEqual(res.headers.get('server'), 'nginx/1.22.1')

    def test_sub_engine_node_and_tag_deduplication(self):
        used = set()
        tag1 = sub_engine._unique('VLESS-Proxy', used)
        tag2 = sub_engine._unique('VLESS-Proxy', used)
        tag3 = sub_engine._unique('VLESS-Proxy', used)
        self.assertEqual(tag1, 'VLESS-Proxy')
        self.assertEqual(tag2, 'VLESS-Proxy-2')
        self.assertEqual(tag3, 'VLESS-Proxy-3')

    def test_login_rate_limiter_memory_pruning(self):
        # Populate _failed_attempts with expired entries past threshold
        now = time.time()
        for i in range(1050):
            app.auth._failed_attempts[f"198.51.100.{i}"] = [now - 2000]

        self.assertGreater(len(app.auth._failed_attempts), 1000)
        # Next failed attempt must trigger pruning of expired entries
        app.auth.record_login_attempt("203.0.113.99", success=False)
        self.assertLessEqual(len(app.auth._failed_attempts), 50)
        self.assertIn("203.0.113.99", app.auth._failed_attempts)
        app.auth._failed_attempts.pop("203.0.113.99", None)

    def test_config_manager_mtime_caching(self):
        # 1. Warm cache
        cfg1 = sentinel_core.ConfigManager.load()
        cfg2 = sentinel_core.ConfigManager.load()
        self.assertEqual(cfg1, cfg2)

        # 2. Update via save and ensure cache is synchronized
        orig_key = cfg1.get('test_cache_key')
        cfg1['test_cache_key'] = 'cache_val_123'
        sentinel_core.ConfigManager.save(cfg1)

        cfg_reloaded = sentinel_core.ConfigManager.load()
        self.assertEqual(cfg_reloaded.get('test_cache_key'), 'cache_val_123')

        # Clean up
        if orig_key is None:
            cfg_reloaded.pop('test_cache_key', None)
        else:
            cfg_reloaded['test_cache_key'] = orig_key
        sentinel_core.ConfigManager.save(cfg_reloaded)

    @patch('sentinel_core.get_cloud_provider')
    def test_reip_cooldown_and_quota_null_handling(self, mock_get_prov):
        mock_prov = MagicMock()
        mock_prov.test_connection.return_value = (True, "Mock Provider OK")
        mock_prov.change_public_ip.return_value = "198.51.100.88"
        mock_get_prov.return_value = mock_prov

        import asyncio
        orig_cfg = sentinel_core.ConfigManager.load()
        try:
            cfg = json.loads(json.dumps(orig_cfg))
            mon = cfg.setdefault('monitor', {})
            mon['reip_cooldown_hours'] = None
            mon['max_reip_per_day'] = None
            mon['last_reip_timestamp'] = None
            sentinel_core.ConfigManager.save(cfg)

            # Triggering routine must gracefully fallback defaults without TypeError
            with patch('notification.NotificationManager.broadcast'):
                res = asyncio.run(app.run_healing_routine(trigger_source='MANUAL', force=False))
            self.assertIsInstance(res, dict)
        finally:
            sentinel_core.ConfigManager.save(orig_cfg)

    @patch('sentinel_core.OracleManager')
    def test_settings_api_redact_notifications(self, mock_oci):
        mock_mgr = MagicMock()
        mock_mgr.client = None
        mock_mgr.instance_id = None
        mock_mgr.vnic_id = None
        mock_mgr.compartment_id = None
        mock_mgr.region = "us-phoenix-1"
        mock_mgr.init_error = None
        mock_oci.return_value = mock_mgr

        orig_cfg = sentinel_core.ConfigManager.load()
        try:
            cfg = json.loads(json.dumps(orig_cfg))
            cfg['notifications'] = {
                'enabled': True,
                'telegram': {'enabled': True, 'bot_token': '123456789:ABCDEFsecret', 'chat_id': '999'},
                'discord': {'enabled': True, 'webhook_url': 'https://discord.com/api/webhooks/123/xyz'},
                'bark': {'enabled': True, 'bark_key': 'barksecretkey123'},
                'custom_webhook': {'enabled': True, 'url': 'https://example.com/hook?key=secret'}
            }
            sentinel_core.ConfigManager.save(cfg)

            res = self.client.get('/api/settings', cookies={'sentinel_session': self.admin_token})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            notifs = data.get('notifications', {})
            self.assertEqual(notifs['telegram']['bot_token'], '****cret')
            self.assertIn('****', notifs['discord']['webhook_url'])
            self.assertEqual(notifs['bark']['bark_key'], '****y123')
            self.assertIn('****', notifs['custom_webhook']['url'])
        finally:
            sentinel_core.ConfigManager.save(orig_cfg)

if __name__ == '__main__':
    unittest.main()
