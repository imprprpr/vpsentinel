#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for EdgeTunnel (edt) Integration.
Tests CleanIPManager, SubEngine segregated strategy groups, and API endpoints.
Strictly Zero Emojis.
"""

import os
import sys
import json
import base64
import yaml
import unittest
from unittest.mock import patch

# Ensure root dir in path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    import tests.sandbox  # noqa: F401
except ImportError:
    import sandbox  # noqa: F401

from clean_ip_mgr import CleanIPManager, DEFAULT_CLEAN_IPS
from sentinel_core import ConfigManager
from sub_engine import SubEngine
from starlette.testclient import TestClient
import app as sentinel_app


class TestEdgeTunnelIntegration(unittest.TestCase):
    def setUp(self):
        self.original_config = ConfigManager.load()
        # Mock test config
        test_cfg = dict(self.original_config)
        test_cfg['security'] = {
            'auth_enabled': True,
            'admin_username': 'admin',
            'admin_password_hash': '6330c17d1e70aceb2d98e6060f7621c4:8c2c9abd4a860bce630b4ad7ed37d8f4c4bb5d7b9aab8a4adf4464c19d4313fb',
            'session_secret': 'test_secret_key_1234567890_test',
            'secret_path': '/sentinel',
            'sub_token': 'test_sub_token_123',
            'enable_host_guard': False,
            'allowed_hosts': []
        }
        test_cfg['edgetunnel'] = {
            'enabled': True,
            'pages_domain': 'test-pages.pages.dev',
            'worker_domain': 'test-worker.workers.dev',
            'uuid': '11111111-2222-3333-4444-555555555555',
            'path': '/?ed=2048',
            'proxy_ip': '1.0.0.1',
            'clean_ips': {
                'telecom': ['162.159.192.1', 'ct.v6.rocks'],
                'unicom': ['162.159.193.1', 'cu.v6.rocks'],
                'mobile': ['162.159.195.1', 'cm.v6.rocks'],
                'anycast': ['104.16.80.1', 'cloudflare.com']
            },
            'auto_refresh_clean_ips': True,
            'enable_fallback_group': True
        }
        ConfigManager.save(test_cfg)
        self.client = TestClient(sentinel_app.app, base_url="https://vps.example.com")

    def tearDown(self):
        ConfigManager.save(self.original_config)

    def test_clean_ip_manager(self):
        self.assertTrue(CleanIPManager.is_edt_enabled())
        ips = CleanIPManager.get_clean_ips()
        self.assertIn('telecom', ips)
        self.assertIn('unicom', ips)
        self.assertIn('mobile', ips)
        self.assertEqual(ips['telecom'][0], '162.159.192.1')

        # Test preferred IP
        pref = CleanIPManager.get_preferred_ip('telecom')
        self.assertEqual(pref, '162.159.192.1')

    def test_extract_edt_nodes(self):
        nodes = SubEngine.extract_edt_nodes()
        self.assertGreater(len(nodes), 0)
        # Verify Pages and Worker nodes are created
        names = [n['name'] for n in nodes]
        self.assertTrue(any('[edt-Pages] 电信优选' in name for name in names))
        self.assertTrue(any('[edt-Pages] 联通优选' in name for name in names))
        self.assertTrue(any('[edt-Pages] 移动优选' in name for name in names))
        self.assertTrue(any('[edt-Worker] 电信优选' in name for name in names))

        for n in nodes:
            self.assertEqual(n['uuid'], '11111111-2222-3333-4444-555555555555')
            self.assertEqual(n['port'], 443)
            self.assertIn(n['host'], ['test-pages.pages.dev', 'test-worker.workers.dev'])

    def test_clash_yaml_segregated_groups(self):
        # Generate Clash YAML with EDT enabled
        clash_text = SubEngine.generate_clash_yaml()
        config = yaml.safe_load(clash_text)

        proxies = config.get('proxies', [])
        proxy_groups = config.get('proxy-groups', [])

        proxy_map = {g['name']: g for g in proxy_groups}

        # 1. Verify segregated groups exist
        self.assertIn('原生节点 (VPS)', proxy_map)
        self.assertIn('边缘节点 (EDT)', proxy_map)
        self.assertIn('容灾自愈 (Fallback)', proxy_map)
        select_group = next((g for g in proxy_groups if '节点选择' in g['name']), None)
        self.assertIsNotNone(select_group)

        # 2. Strict Segregation Check: Native group must NOT contain edt nodes
        native_proxies = proxy_map['原生节点 (VPS)']['proxies']
        for p in native_proxies:
            self.assertFalse(p.startswith('[edt-'), f"EDT node {p} leaked into native VPS group")

        # 3. Strict Segregation Check: EDT group must contain ONLY edt nodes (and its auto-test)
        edt_proxies = proxy_map['边缘节点 (EDT)']['proxies']
        for p in edt_proxies:
            if p == '边缘-自动测速':
                continue
            self.assertTrue(p.startswith('[edt-'), f"Non-EDT node {p} found in EDT group")

        # 4. Fallback group check
        fallback = proxy_map['容灾自愈 (Fallback)']
        self.assertEqual(fallback['type'], 'fallback')
        # Ensure fallback contains both native and edt nodes
        self.assertTrue(any(p.startswith('[edt-') for p in fallback['proxies']))

        # 5. Global selector contains the segregated group options
        self.assertIn('原生节点 (VPS)', select_group['proxies'])
        self.assertIn('边缘节点 (EDT)', select_group['proxies'])
        self.assertIn('容灾自愈 (Fallback)', select_group['proxies'])

    def test_singbox_json_segregated_groups(self):
        singbox_text = SubEngine.generate_singbox_json()
        config = json.loads(singbox_text)

        outbounds = config.get('outbounds', [])
        outbound_map = {o['tag']: o for o in outbounds}

        # 1. Verify segregated groups exist in Sing-box
        self.assertIn('native-select', outbound_map)
        self.assertIn('edt-select', outbound_map)
        self.assertIn('fallback', outbound_map)
        self.assertIn('select', outbound_map)

        # 2. Strict Segregation: native-select must not contain [edt- nodes
        for item in outbound_map['native-select']['outbounds']:
            self.assertFalse(item.startswith('[edt-'), f"EDT node {item} leaked into native-select")

        # 3. Strict Segregation: edt-select must only contain [edt- nodes and edt-urltest
        for item in outbound_map['edt-select']['outbounds']:
            if item == 'edt-urltest':
                continue
            self.assertTrue(item.startswith('[edt-'), f"Non-EDT node {item} in edt-select")

        # 4. Global select contains the dedicated groups
        self.assertIn('native-select', outbound_map['select']['outbounds'])
        self.assertIn('edt-select', outbound_map['select']['outbounds'])
        self.assertIn('fallback', outbound_map['select']['outbounds'])

    def test_v2ray_base64_contains_edt(self):
        b64_text = SubEngine.generate_v2ray_base64()
        decoded = base64.b64decode(b64_text).decode('utf-8')
        lines = [line.strip() for line in decoded.splitlines() if line.strip()]

        # Must have vless links with host=test-pages.pages.dev and test-worker.workers.dev
        edt_links = [l for l in lines if 'test-pages.pages.dev' in l or 'test-worker.workers.dev' in l]
        self.assertGreater(len(edt_links), 0)
        for link in edt_links:
            self.assertTrue(link.startswith('vless://'))
            self.assertIn('type=ws', link)
            self.assertIn('security=tls', link)

    def test_backward_compatibility_when_edt_disabled(self):
        # Disable EDT
        cfg = ConfigManager.load()
        cfg['edgetunnel']['enabled'] = False
        ConfigManager.save(cfg)

        clash_text = SubEngine.generate_clash_yaml()
        config = yaml.safe_load(clash_text)
        proxy_groups = config.get('proxy-groups', [])
        group_names = [g['name'] for g in proxy_groups]

        # EDT groups should not be present
        self.assertNotIn('边缘节点 (EDT)', group_names)
        self.assertNotIn('原生节点 (VPS)', group_names)
        self.assertTrue(any('节点选择' in name for name in group_names))

        singbox_text = SubEngine.generate_singbox_json()
        sb_config = json.loads(singbox_text)
        sb_tags = [o['tag'] for o in sb_config.get('outbounds', [])]
        self.assertNotIn('edt-select', sb_tags)
        self.assertNotIn('native-select', sb_tags)
        self.assertIn('select', sb_tags)

    def test_api_edt_endpoints(self):
        # Unauthenticated calls should be rejected
        res = self.client.get('/api/edt/config')
        self.assertEqual(res.status_code, 401)

        res = self.client.post('/api/edt/config', json={'enabled': True})
        self.assertEqual(res.status_code, 401)

        res = self.client.post('/api/edt/refresh-clean-ips')
        self.assertEqual(res.status_code, 401)

        res = self.client.get('/api/edt/status')
        self.assertEqual(res.status_code, 401)

        # Authenticated calls
        session_token = sentinel_app.auth.create_session_token('admin')
        cookies = {'sentinel_session': session_token}

        # 1. GET /api/edt/config
        res = self.client.get('/api/edt/config', cookies=cookies)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'ok')
        self.assertTrue(data['edgetunnel']['enabled'])
        self.assertEqual(data['edgetunnel']['pages_domain'], 'test-pages.pages.dev')

        # 2. POST /api/edt/config
        update_payload = {
            'enabled': True,
            'pages_domain': 'updated-pages.pages.dev',
            'worker_domain': 'updated-worker.workers.dev',
            'uuid': '99999999-8888-7777-6666-555555555555',
            'path': '/?ed=2048'
        }
        res = self.client.post('/api/edt/config', json=update_payload, cookies=cookies)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['status'], 'ok')

        # Verify persisted
        cfg = ConfigManager.load()
        self.assertEqual(cfg['edgetunnel']['pages_domain'], 'updated-pages.pages.dev')
        self.assertEqual(cfg['edgetunnel']['uuid'], '99999999-8888-7777-6666-555555555555')

        # 3. POST /api/edt/refresh-clean-ips
        # Unit tests validate scheduling; never run a real network benchmark.
        with patch('edt_optimizer.Optimizer.start', return_value=True) as start:
            res = self.client.post('/api/edt/refresh-clean-ips', cookies=cookies)
            start.assert_called_once_with()
        self.assertEqual(res.status_code, 200)
        self.assertIn('clean_ips', res.json())
        self.assertEqual(res.json()['status'], 'started')
        self.assertIn('optimizer', res.json())

        # 5. Domain sanitization test in config save
        dirty_payload = {
            'pages_domain': 'https://my-pages.pages.dev/admin',
            'worker_domain': 'http://my-worker.workers.dev:443/ws?query=1'
        }
        res = self.client.post('/api/edt/config', json=dirty_payload, cookies=cookies)
        self.assertEqual(res.status_code, 200)
        cfg = ConfigManager.load()
        self.assertEqual(cfg['edgetunnel']['pages_domain'], 'my-pages.pages.dev')
        self.assertEqual(cfg['edgetunnel']['worker_domain'], 'my-worker.workers.dev')

    def test_sanitize_domain_helper(self):
        self.assertEqual(CleanIPManager.sanitize_domain('https://imprprpr001.ccwu.cc/admin'), 'imprprpr001.ccwu.cc')
        self.assertEqual(CleanIPManager.sanitize_domain('http://imprprpr.dpdns.org/'), 'imprprpr.dpdns.org')
        self.assertEqual(CleanIPManager.sanitize_domain('imprprpr001.ccwu.cc:443/path#frag'), 'imprprpr001.ccwu.cc')
        self.assertEqual(CleanIPManager.sanitize_domain('  HTTPS://sub.domain.com  '), 'sub.domain.com')
        self.assertEqual(CleanIPManager.sanitize_domain(''), '')


if __name__ == '__main__':
    unittest.main()
