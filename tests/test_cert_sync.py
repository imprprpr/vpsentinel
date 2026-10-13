#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# VPSentinel - Distributed Certificate Synchronization & Hot Reload Tests
# ==============================================================================

import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    import tests.sandbox  # noqa: F401
except ImportError:
    import sandbox  # noqa: F401

import json
import time
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

import app
import sentinel_core
import cert_sync_mgr
from cert_sync_mgr import CertManager, CertSyncAgent, CertSyncManager

def generate_test_cert_and_key():
    """Generates a test X.509 certificate and private key in PEM format using cryptography."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'master.example.com'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'VPSentinel Test CA')
    ])

    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()
    ).serial_number(12345).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=1)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=60)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName('master.example.com'),
            x509.DNSName('*.master.example.com')
        ]),
        critical=False
    ).sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return cert_pem, key_pem


class TestCertManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix='sentinel_cert_test_')

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_calculate_fingerprint(self):
        data = b"sample_certificate_content"
        fp = CertManager.calculate_fingerprint(data)
        self.assertIsInstance(fp, str)
        self.assertEqual(len(fp), 64)

    def test_parse_certificate_missing(self):
        fake_path = os.path.join(self.test_dir, 'non_existent.pem')
        info = CertManager.parse_certificate(fake_path)
        self.assertFalse(info['exists'])
        self.assertEqual(info['domains'], [])
        self.assertIn('not found', info['error'])

    def test_parse_certificate_valid(self):
        cert_pem, key_pem = generate_test_cert_and_key()
        cert_path = os.path.join(self.test_dir, 'fullchain.pem')
        with open(cert_path, 'w', encoding='utf-8') as f:
            f.write(cert_pem)

        info = CertManager.parse_certificate(cert_path)
        self.assertTrue(info['exists'])
        self.assertIn('master.example.com', info['domains'])
        self.assertIn('*.master.example.com', info['domains'])
        self.assertIn('VPSentinel Test CA', info['issuer'])
        self.assertGreaterEqual(info['days_left'], 58)
        self.assertTrue(len(info['fingerprint']) == 64)
        self.assertIsNone(info['error'])

    def test_get_local_cert_info_and_read_bundle(self):
        cert_pem, key_pem = generate_test_cert_and_key()
        cert_path = os.path.join(self.test_dir, 'fullchain.pem')
        key_path = os.path.join(self.test_dir, 'privkey.pem')

        with open(cert_path, 'w', encoding='utf-8') as f:
            f.write(cert_pem)
        with open(key_path, 'w', encoding='utf-8') as f:
            f.write(key_pem)

        info = CertManager.get_local_cert_info(self.test_dir)
        self.assertTrue(info['exists'])
        self.assertTrue(info['privkey_exists'])
        self.assertEqual(info['cert_dir'], self.test_dir)

        bundle = CertManager.read_cert_bundle(self.test_dir)
        self.assertEqual(bundle['cert_pem'], cert_pem)
        self.assertEqual(bundle['key_pem'], key_pem)
        self.assertEqual(bundle['fingerprint'], info['fingerprint'])
        self.assertIn('master.example.com', bundle['domains'])


class TestCertSyncAgent(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix='sentinel_agent_test_')

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_cert_bundle_atomic_and_permissions(self):
        cert_pem, key_pem = generate_test_cert_and_key()
        fullchain, privkey = CertSyncAgent.save_cert_bundle_atomic(cert_pem, key_pem, self.test_dir)

        self.assertTrue(os.path.exists(fullchain))
        self.assertTrue(os.path.exists(privkey))

        # Check file content
        with open(fullchain, 'r', encoding='utf-8') as f:
            self.assertEqual(f.read(), cert_pem)
        with open(privkey, 'r', encoding='utf-8') as f:
            self.assertEqual(f.read(), key_pem)

        # Check permissions: privkey should be 0600
        st = os.stat(privkey)
        self.assertEqual(oct(st.st_mode)[-3:], '600')

    @patch('cert_sync_mgr.open_secure')
    def test_check_master_status(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            'status': 'ok',
            'fingerprint': 'abc1234567890abcdef',
            'domains': ['master.example.com'],
            'issuer': 'Test Issuer',
            'valid_to': '2026-12-31 00:00:00 UTC',
            'days_left': 90
        }).encode('utf-8')
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        status = CertSyncAgent.check_master_status(
            master_url='https://master.example.com:20540',
            sync_token='secret_test_token'
        )
        self.assertEqual(status['status'], 'ok')
        self.assertEqual(status['fingerprint'], 'abc1234567890abcdef')
        self.assertIn('master.example.com', status['domains'])

    @patch('cert_sync_mgr.open_secure')
    def test_pull_cert_bundle(self, mock_urlopen):
        cert_pem, key_pem = generate_test_cert_and_key()
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            'status': 'ok',
            'fingerprint': 'fedcba0987654321',
            'cert_pem': cert_pem,
            'key_pem': key_pem,
            'domains': ['master.example.com'],
            'valid_to': '2026-12-31 00:00:00 UTC'
        }).encode('utf-8')
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        bundle = CertSyncAgent.pull_cert_bundle(
            master_url='https://master.example.com:20540',
            sync_token='secret_test_token'
        )
        self.assertEqual(bundle['status'], 'ok')
        self.assertEqual(bundle['fingerprint'], 'fedcba0987654321')
        self.assertEqual(bundle['cert_pem'], cert_pem)
        self.assertEqual(bundle['key_pem'], key_pem)

    @patch('subprocess.run')
    def test_reload_downstream_services(self, mock_subproc):
        mock_subproc.return_value = MagicMock(returncode=0, stdout='Reloaded', stderr='')

        services = ['x-ui', 'nginx', 'caddy']
        results = CertSyncAgent.reload_downstream_services(services=services)

        self.assertEqual(len(results), 3)
        for r in results:
            self.assertTrue(r['success'])


class TestCertSyncManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix='sentinel_mgr_test_')
        self.orig_config = sentinel_core.ConfigManager.load()

        test_cfg = json.loads(json.dumps(self.orig_config))
        test_cfg['cert_sync'] = {
            'enabled': True,
            'role': 'edge',
            'master_url': 'https://master.example.com:20540',
            'sync_token': 'test_sync_token_123',
            'cert_dir': self.test_dir,
            'poll_interval_hours': 12,
            'auto_reload_services': ['x-ui', 'nginx'],
            'verify_ssl': False,
            'last_sync_time': 0,
            'last_fingerprint': '',
            'last_sync_status': 'never'
        }
        sentinel_core.ConfigManager.save(test_cfg)

    def tearDown(self):
        sentinel_core.ConfigManager.save(self.orig_config)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_get_and_update_sync_config(self):
        cfg = CertSyncManager.get_sync_config()
        self.assertEqual(cfg['role'], 'edge')
        self.assertEqual(cfg['master_url'], 'https://master.example.com:20540')

        updated = CertSyncManager.update_sync_config({'poll_interval_hours': 24, 'verify_ssl': True})
        self.assertEqual(updated['poll_interval_hours'], 24)
        self.assertTrue(updated['verify_ssl'])

    @patch.object(CertSyncAgent, 'check_master_status')
    @patch.object(CertSyncAgent, 'pull_cert_bundle')
    @patch.object(CertSyncAgent, 'reload_downstream_services')
    def test_perform_edge_sync_mismatch_downloads(self, mock_reload, mock_pull, mock_status):
        cert_pem, key_pem = generate_test_cert_and_key()
        master_fp = CertManager.calculate_fingerprint(cert_pem.encode('utf-8'))

        mock_status.return_value = {
            'status': 'ok',
            'fingerprint': master_fp,
            'domains': ['master.example.com']
        }
        mock_pull.return_value = {
            'status': 'ok',
            'fingerprint': master_fp,
            'cert_pem': cert_pem,
            'key_pem': key_pem,
            'domains': ['master.example.com'],
            'valid_to': '2026-12-31 00:00:00 UTC',
            'days_left': 60
        }
        mock_reload.return_value = [{'service': 'x-ui', 'success': True}]

        res = CertSyncManager.perform_edge_sync(force=False)
        self.assertTrue(res['success'])
        self.assertEqual(res['status'], 'success')
        self.assertEqual(res['fingerprint'], master_fp)

        # Verify files were saved
        local_info = CertManager.get_local_cert_info(self.test_dir)
        self.assertTrue(local_info['exists'])
        self.assertEqual(local_info['fingerprint'], master_fp)

    @patch.object(CertSyncAgent, 'check_master_status')
    def test_perform_edge_sync_already_up_to_date(self, mock_status):
        cert_pem, key_pem = generate_test_cert_and_key()
        CertSyncAgent.save_cert_bundle_atomic(cert_pem, key_pem, self.test_dir)
        local_info = CertManager.get_local_cert_info(self.test_dir)
        local_fp = local_info['fingerprint']

        mock_status.return_value = {
            'status': 'ok',
            'fingerprint': local_fp,
            'domains': ['master.example.com']
        }

        res = CertSyncManager.perform_edge_sync(force=False)
        self.assertTrue(res['success'])
        self.assertEqual(res['status'], 'up_to_date')


class TestCertRestEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp(prefix='sentinel_rest_cert_')
        cls.orig_config = sentinel_core.ConfigManager.load()

        test_cfg = json.loads(json.dumps(cls.orig_config))
        test_cfg['initialized'] = True
        test_cfg['security'] = {
            'auth_enabled': True,
            'admin_username': 'admin',
            'admin_password_hash': app.auth.hash_password('mNq7gQGr'),
            'session_secret': 'test_cert_secret_key_123',
            'secret_path': '/sentinel',
            'sub_token': 'test_sub_token_abc',
            'enable_host_guard': True,
            'allowed_hosts': ['vps.example.com']
        }
        test_cfg['cert_sync'] = {
            'enabled': True,
            'role': 'master',
            'master_url': '',
            'sync_token': 'secret_mesh_sync_token_999',
            'cert_dir': cls.test_dir,
            'poll_interval_hours': 12,
            'auto_reload_services': ['x-ui'],
            'verify_ssl': True,
            'last_sync_time': 0,
            'last_fingerprint': '',
            'last_sync_status': 'never'
        }
        sentinel_core.ConfigManager.save(test_cfg)

        cls.cert_pem, cls.key_pem = generate_test_cert_and_key()
        CertSyncAgent.save_cert_bundle_atomic(cls.cert_pem, cls.key_pem, cls.test_dir)

        cls.client = TestClient(app.app, base_url='https://vps.example.com')
        cls.admin_token = app.auth.create_session_token('admin')

    @classmethod
    def tearDownClass(cls):
        sentinel_core.ConfigManager.save(cls.orig_config)
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_unauthenticated_requests_fail(self):
        res1 = self.client.get('/api/cert/info')
        self.assertEqual(res1.status_code, 401)

        res2 = self.client.get('/api/cert/status')
        self.assertEqual(res2.status_code, 401)

        res3 = self.client.get('/api/cert/bundle')
        self.assertEqual(res3.status_code, 401)

        res4 = self.client.post('/api/cert/config', json={'role': 'edge'})
        self.assertEqual(res4.status_code, 401)

        res5 = self.client.post('/api/cert/sync-now', json={})
        self.assertEqual(res5.status_code, 401)

    def test_admin_can_access_cert_info(self):
        res = self.client.get(
            '/api/cert/info',
            headers={'Authorization': f'Bearer {self.admin_token}'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'ok')
        self.assertTrue(data['certificate']['exists'])
        self.assertEqual(data['config']['role'], 'master')

    def test_remote_node_status_probe_with_sync_token(self):
        res = self.client.get(
            '/api/cert/status',
            headers={'Authorization': 'Bearer secret_mesh_sync_token_999'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'ok')
        self.assertTrue(len(data['fingerprint']) == 64)
        self.assertIn('master.example.com', data['domains'])

    def test_remote_node_bundle_pull_with_sync_token(self):
        res = self.client.get(
            '/api/cert/bundle',
            headers={'Authorization': 'Bearer secret_mesh_sync_token_999'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['cert_pem'], self.cert_pem)
        self.assertEqual(data['key_pem'], self.key_pem)

    @patch('cert_sync_mgr.CertSyncAgent.reload_downstream_services')
    def test_save_cert_config_and_sync_now(self, mock_reload):
        mock_reload.return_value = [{'service': 'nginx', 'action': 'reload', 'success': True, 'detail': 'mock'}]
        # Update config via admin
        res = self.client.post(
            '/api/cert/config',
            headers={'Authorization': f'Bearer {self.admin_token}'},
            json={'poll_interval_hours': 6, 'post_sync_hook': '/tmp/test_hook.sh'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['config']['poll_interval_hours'], 6)
        self.assertEqual(data['config']['post_sync_hook'], '/tmp/test_hook.sh')

        # Trigger sync-now in master mode (which reloads local services)
        res_sync = self.client.post(
            '/api/cert/sync-now',
            headers={'Authorization': f'Bearer {self.admin_token}'},
            json={'force': True}
        )
        self.assertEqual(res_sync.status_code, 200)
        sync_data = res_sync.json()
        self.assertTrue(sync_data['success'])
        self.assertEqual(sync_data['status'], 'reloaded')


if __name__ == '__main__':
    unittest.main()
