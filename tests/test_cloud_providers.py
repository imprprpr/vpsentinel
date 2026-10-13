#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Oracle Sentinel - Cloud Providers Test Suite
# Tests AWS Lightsail, Hetzner Cloud, Azure ARM, Custom Hook, and Generic Providers
# ==============================================================================

import os
import sys
import json
import time
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Setup path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    import tests.sandbox  # noqa: F401
except ImportError:
    import sandbox  # noqa: F401

import sentinel_core
import app
from starlette.testclient import TestClient


class TestCloudInfoDetection(unittest.TestCase):
    def setUp(self):
        sentinel_core.invalidate_cloud_info_cache()

    def tearDown(self):
        sentinel_core.invalidate_cloud_info_cache()

    def test_detection_by_dmi_amazon(self):
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', unittest.mock.mock_open(read_data="Amazon EC2 Instance")):
            info = sentinel_core.get_cloud_info()
            self.assertIn("AWS", info['provider'])

    def test_detection_by_dmi_hetzner(self):
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', unittest.mock.mock_open(read_data="Hetzner vServer")):
            info = sentinel_core.get_cloud_info()
            self.assertIn("Hetzner", info['provider'])

    def test_detection_by_dmi_azure(self):
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', unittest.mock.mock_open(read_data="Microsoft Corporation Virtual Machine 7783-7084-3265-9085-8269-3286-77")):
            info = sentinel_core.get_cloud_info()
            self.assertIn("Azure", info['provider'])

    def test_detection_fallback_generic(self):
        with patch('os.path.exists', return_value=False), \
             patch('requests.get', side_effect=Exception("Metadata unreachable")):
            info = sentinel_core.get_cloud_info()
            self.assertIn("Generic", info['provider'])

    def test_generic_fallback_cached_with_ttl_and_recovers(self):
        # 1. First probe fails with exception -> returns Generic VPS and caches with TTL
        with patch('os.path.exists', return_value=False), \
             patch('requests.get', side_effect=Exception("Metadata unreachable")) as mock_get:
            info1 = sentinel_core.get_cloud_info()
            self.assertEqual(info1['provider'], sentinel_core.GENERIC_PROVIDER)
            self.assertEqual(mock_get.call_count, 4)
            self.assertIsNotNone(sentinel_core._cached_cloud_info)
            self.assertEqual(sentinel_core._cached_cloud_info['provider'], sentinel_core.GENERIC_PROVIDER)

            # 2. Second call immediately within TTL: returns from cache, zero additional network calls
            t0 = time.time()
            info_cached = sentinel_core.get_cloud_info()
            dt = time.time() - t0
            self.assertEqual(info_cached['provider'], sentinel_core.GENERIC_PROVIDER)
            self.assertEqual(mock_get.call_count, 4)
            self.assertLess(dt, 0.1)

        # 3. Simulate TTL expiry and network recovery -> next call re-probes and detects Oracle Cloud
        sentinel_core._cached_cloud_info_ts = time.time() - (sentinel_core.CLOUD_INFO_TTL + 10)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'canonicalRegionName': 'us-phoenix-1'}
        with patch('os.path.exists', return_value=False), \
             patch('requests.get', return_value=mock_resp) as mock_get_recovered:
            info2 = sentinel_core.get_cloud_info()
            self.assertEqual(info2['provider'], 'Oracle Cloud')
            self.assertIsNotNone(sentinel_core._cached_cloud_info)
            self.assertEqual(sentinel_core._cached_cloud_info['provider'], 'Oracle Cloud')
            self.assertEqual(mock_get_recovered.call_count, 1)

            # 4. Positive cloud result does NOT expire after TTL
            sentinel_core._cached_cloud_info_ts = time.time() - (sentinel_core.CLOUD_INFO_TTL + 10)
            info_positive = sentinel_core.get_cloud_info()
            self.assertEqual(info_positive['provider'], 'Oracle Cloud')
            self.assertEqual(mock_get_recovered.call_count, 1)

    def test_invalidate_cloud_info_cache(self):
        sentinel_core._cached_cloud_info = {'provider': 'Test Cloud'}
        sentinel_core._cached_cloud_info_ts = time.time()
        sentinel_core.invalidate_cloud_info_cache()
        self.assertIsNone(sentinel_core._cached_cloud_info)
        self.assertEqual(sentinel_core._cached_cloud_info_ts, 0.0)

    def test_config_manager_save_and_reload_invalidates_cloud_cache(self):
        sentinel_core._cached_cloud_info = {'provider': 'Old Cloud'}
        sentinel_core._cached_cloud_info_ts = time.time()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_cfg = os.path.join(tmp_dir, 'config.json')
            with patch.dict(os.environ, {'VPSENTINEL_CONFIG_PATH': tmp_cfg}):
                sentinel_core.ConfigManager.save({'test': 'isolated'})
                self.assertIsNone(sentinel_core._cached_cloud_info)
                self.assertEqual(sentinel_core._cached_cloud_info_ts, 0.0)

                # Invalidate via explicit ConfigManager.invalidate_cache()
                sentinel_core._cached_cloud_info = {'provider': 'Old Cloud'}
                sentinel_core._cached_cloud_info_ts = time.time()
                sentinel_core.ConfigManager.invalidate_cache()
                self.assertIsNone(sentinel_core._cached_cloud_info)
                self.assertEqual(sentinel_core._cached_cloud_info_ts, 0.0)


class TestLightsailCloudProvider(unittest.TestCase):
    def setUp(self):
        self.provider = sentinel_core.LightsailCloudProvider(
            access_key_id='test-ak',
            secret_access_key='test-sk',
            region='us-east-1',
            instance_name='my-instance'
        )

    def test_test_connection_missing_keys(self):
        empty_prov = sentinel_core.LightsailCloudProvider()
        ok, msg = empty_prov.test_connection()
        self.assertFalse(ok)
        self.assertIn("missing", msg.lower())

    @patch('requests.post')
    def test_test_connection_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'instance': {
                'name': 'my-instance',
                'state': {'name': 'running'},
                'publicIpAddress': '198.51.100.10'
            }
        }
        mock_post.return_value = mock_resp

        ok, msg = self.provider.test_connection()
        self.assertTrue(ok)
        self.assertIn("successful", msg)
        self.assertIn("my-instance", msg)

    @patch('requests.post')
    def test_change_public_ip_full_cycle(self, mock_post):
        def side_effect(url, headers=None, data=None, timeout=None):
            target = headers.get('X-Amz-Target', '')
            resp = MagicMock()
            resp.status_code = 200
            if 'GetStaticIps' in target:
                resp.json.return_value = {
                    'staticIps': [
                        {'name': 'old-static-ip-1', 'attachedTo': 'my-instance', 'ipAddress': '198.51.100.1'}
                    ]
                }
            elif 'AllocateStaticIp' in target:
                resp.json.return_value = {'operations': [{'status': 'Succeeded'}]}
            elif 'AttachStaticIp' in target:
                resp.json.return_value = {'operations': [{'status': 'Succeeded'}]}
            elif 'ReleaseStaticIp' in target:
                resp.json.return_value = {'operations': [{'status': 'Succeeded'}]}
            elif 'GetStaticIp' in target:
                resp.json.return_value = {
                    'staticIp': {'ipAddress': '198.51.100.99', 'name': 'new-ip', 'attachedTo': 'my-instance'}
                }
            else:
                resp.json.return_value = {}
            return resp

        mock_post.side_effect = side_effect
        new_ip = self.provider.change_public_ip()
        self.assertEqual(new_ip, '198.51.100.99')


class TestHetznerCloudProvider(unittest.TestCase):
    def setUp(self):
        self.provider_prim = sentinel_core.HetznerCloudProvider(
            api_token='hz-secret-token',
            server_id='100200',
            ip_type='primary'
        )
        self.provider_flip = sentinel_core.HetznerCloudProvider(
            api_token='hz-secret-token',
            server_id='100200',
            ip_type='floating'
        )

    def test_test_connection_missing_token(self):
        empty_prov = sentinel_core.HetznerCloudProvider()
        ok, msg = empty_prov.test_connection()
        self.assertFalse(ok)
        self.assertIn("missing", msg.lower())

    @patch('requests.get')
    def test_test_connection_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'server': {
                'id': 100200,
                'name': 'debian-nbg1',
                'status': 'running',
                'public_net': {'ipv4': {'ip': '116.203.10.20'}}
            }
        }
        mock_get.return_value = mock_resp

        ok, msg = self.provider_prim.test_connection()
        self.assertTrue(ok)
        self.assertIn("debian-nbg1", msg)

    @patch('requests.post')
    @patch('requests.get')
    def test_change_floating_ip(self, mock_get, mock_post):
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            'server': {
                'id': 100200,
                'status': 'running',
                'datacenter': {'name': 'nbg1-dc3', 'location': {'name': 'nbg1'}}
            }
        }
        mock_get.return_value = mock_get_resp

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 201
        mock_post_resp.json.return_value = {
            'floating_ip': {'id': 999, 'ip': '159.69.50.60'}
        }
        mock_post.return_value = mock_post_resp

        new_ip = self.provider_flip.change_public_ip()
        self.assertEqual(new_ip, '159.69.50.60')

    @patch('time.sleep', return_value=None)
    @patch('requests.delete')
    @patch('requests.post')
    @patch('requests.get')
    def test_change_primary_ip_cycle(self, mock_get, mock_post, mock_del, mock_sleep):
        def get_side_effect(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            if 'actions' in url:
                resp.json.return_value = {'action': {'id': 10, 'status': 'success'}}
            else:
                resp.json.return_value = {
                    'server': {
                        'id': 100200,
                        'status': 'off',
                        'datacenter': {'name': 'nbg1-dc3'},
                        'public_net': {'primary_ipv4': 888}
                    }
                }
            return resp

        mock_get.side_effect = get_side_effect

        def post_side_effect(url, headers=None, json=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 201
            if 'primary_ips' in url and not 'actions' in url:
                resp.json.return_value = {
                    'primary_ip': {'id': 999, 'ip': '168.119.88.99'}
                }
            else:
                resp.json.return_value = {'action': {'id': 10, 'status': 'success'}}
            return resp

        mock_post.side_effect = post_side_effect

        with patch.object(sentinel_core.ConfigManager, 'load', return_value={'hetzner': {'external_controller': True}}):
            new_ip = self.provider_prim.change_public_ip()
        self.assertEqual(new_ip, '168.119.88.99')
        mock_del.assert_called()


class TestAzureCloudProvider(unittest.TestCase):
    def setUp(self):
        self.provider = sentinel_core.AzureCloudProvider(
            subscription_id='sub-1234',
            resource_group='rg-sentinel',
            vm_name='vm-sentinel',
            nic_name='nic-sentinel',
            client_id='client-1234',
            client_secret='secret-1234',
            tenant_id='tenant-1234'
        )

    def test_test_connection_missing_required(self):
        empty_prov = sentinel_core.AzureCloudProvider()
        ok, msg = empty_prov.test_connection()
        self.assertFalse(ok)
        self.assertIn("required", msg.lower())

    @patch('requests.get')
    @patch('requests.post')
    def test_test_connection_success(self, mock_post, mock_get):
        tok_resp = MagicMock()
        tok_resp.status_code = 200
        tok_resp.json.return_value = {'access_token': 'azure-mock-bearer-token'}
        mock_post.return_value = tok_resp

        nic_resp = MagicMock()
        nic_resp.status_code = 200
        nic_resp.json.return_value = {
            'location': 'eastus',
            'properties': {
                'provisioningState': 'Succeeded',
                    'ipConfigurations': [
                    {'properties': {'publicIPAddress': {'id': '/subscriptions/.../sentinel-pip-old'}}}
                ]
            }
        }
        mock_get.return_value = nic_resp

        ok, msg = self.provider.test_connection()
        self.assertTrue(ok)
        self.assertIn("successful", msg)
        self.assertIn("nic-sentinel", msg)

    @patch('time.sleep', return_value=None)
    @patch('requests.delete')
    @patch('requests.put')
    @patch('requests.get')
    @patch('requests.post')
    def test_change_public_ip_cycle(self, mock_post, mock_get, mock_put, mock_del, mock_sleep):
        tok_resp = MagicMock()
        tok_resp.status_code = 200
        tok_resp.json.return_value = {'access_token': 'azure-mock-bearer-token'}
        mock_post.return_value = tok_resp

        nic_reads = 0
        def get_side_effect(url, headers=None, timeout=None):
            nonlocal nic_reads
            resp = MagicMock()
            resp.status_code = 200
            if 'networkInterfaces' in url:
                nic_reads += 1
                resp.json.return_value = {
                    'location': 'eastus',
                    'properties': {
                        'provisioningState': 'Succeeded',
                    'ipConfigurations': [
                            {
                                'name': 'ipconfig1',
                                'properties': {'publicIPAddress': {'id': '/sub/.../new-pip-id' if nic_reads > 1 else '/sub/.../old-pip'}}
                            }
                        ]
                    }
                }
            elif 'publicIPAddresses' in url:
                resp.json.return_value = {
                    'properties': {'ipAddress': '20.198.55.66'}
                }
            return resp

        mock_get.side_effect = get_side_effect

        def put_side_effect(url, headers=None, json=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            if 'publicIPAddresses' in url:
                resp.json.return_value = {'id': '/sub/.../new-pip-id'}
            elif 'networkInterfaces' in url:
                resp.json.return_value = {'properties': {}}
            return resp

        mock_put.side_effect = put_side_effect

        new_ip = self.provider.change_public_ip()
        self.assertEqual(new_ip, '20.198.55.66')
        mock_del.assert_called()


class TestCloudProviderFactory(unittest.TestCase):
    def test_factory_dispatch_lightsail(self):
        cfg = {
            'provider': {'type': 'lightsail'},
            'lightsail': {'access_key_id': 'ak', 'secret_access_key': 'sk', 'instance_name': 'test-inst'}
        }
        prov = sentinel_core.get_cloud_provider(cfg)
        self.assertIsInstance(prov, sentinel_core.LightsailCloudProvider)
        self.assertEqual(prov.instance_name, 'test-inst')

    def test_factory_dispatch_hetzner(self):
        cfg = {
            'provider': {'type': 'hetzner'},
            'hetzner': {'api_token': 'tok', 'server_id': '999', 'ip_type': 'floating'}
        }
        prov = sentinel_core.get_cloud_provider(cfg)
        self.assertIsInstance(prov, sentinel_core.HetznerCloudProvider)
        self.assertEqual(prov.server_id, '999')
        self.assertEqual(prov.ip_type, 'floating')

    def test_factory_dispatch_azure(self):
        cfg = {
            'provider': {'type': 'azure'},
            'azure': {'subscription_id': 'sub', 'resource_group': 'rg', 'vm_name': 'vm1'}
        }
        prov = sentinel_core.get_cloud_provider(cfg)
        self.assertIsInstance(prov, sentinel_core.AzureCloudProvider)
        self.assertEqual(prov.vm_name, 'vm1')

    def test_factory_dispatch_hook(self):
        cfg = {
            'provider': {'type': 'hook', 'hook_cmd': '/usr/local/bin/my_reip.sh'}
        }
        prov = sentinel_core.get_cloud_provider(cfg)
        self.assertIsInstance(prov, sentinel_core.CustomHookProvider)
        ok, msg = prov.test_connection()
        self.assertTrue(ok)
        self.assertIn("my_reip.sh", msg)

    def test_factory_dispatch_generic(self):
        cfg = {'provider': {'type': 'generic'}}
        prov = sentinel_core.get_cloud_provider(cfg)
        self.assertIsInstance(prov, sentinel_core.GenericProvider)
        ok, msg = prov.test_connection()
        self.assertTrue(ok)
        self.assertIn("Generic VPS", msg)

    def test_factory_dispatch_unrecognized_falls_back_to_auto(self):
        cfg = {'provider': {'type': 'unknown_provider'}}
        with patch('sentinel_core.get_cloud_info', return_value={'provider': 'Generic VPS / Dedicated Server'}):
            prov = sentinel_core.get_cloud_provider(cfg)
            self.assertIsInstance(prov, sentinel_core.GenericProvider)


class TestProviderRestEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(
            app.app,
            base_url='https://vps.example.com'
        )
        self.admin_token = app.auth.create_session_token("admin")
        self.client.cookies = {'sentinel_session': self.admin_token}

    @patch.object(sentinel_core.LightsailCloudProvider, 'test_connection')
    def test_api_provider_test_lightsail(self, mock_test):
        mock_test.return_value = (True, "Lightsail mock ok")
        res = self.client.post('/api/provider/test', json={
            'provider_type': 'lightsail',
            'lightsail': {
                'access_key_id': 'ak',
                'secret_access_key': 'sk',
                'region': 'us-east-1',
                'instance_name': 'test-vm'
            }
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['message'], "Lightsail mock ok")

    @patch.object(sentinel_core.HetznerCloudProvider, 'test_connection')
    def test_api_provider_test_hetzner(self, mock_test):
        mock_test.return_value = (True, "Hetzner mock ok")
        res = self.client.post('/api/provider/test', json={
            'provider_type': 'hetzner',
            'hetzner': {
                'api_token': 'tok',
                'server_id': '12345'
            }
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['message'], "Hetzner mock ok")

    @patch.object(sentinel_core.AzureCloudProvider, 'test_connection')
    def test_api_provider_test_azure(self, mock_test):
        mock_test.return_value = (True, "Azure mock ok")
        res = self.client.post('/api/provider/test', json={
            'provider_type': 'azure',
            'azure': {
                'subscription_id': 'sub-1',
                'resource_group': 'rg-1',
                'vm_name': 'vm-1'
            }
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['message'], "Azure mock ok")


if __name__ == '__main__':
    unittest.main()
