"""Regression coverage for the October security review; all paths are synthetic."""
from tests import sandbox  # noqa: F401
import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

import app
import auth_mgr
import bot_mgr
import cert_sync_mgr
import mesh_mgr
import net_policy
import paths
import privileged_helper
import sentinel_core
import service_mgr
from secure_files import atomic_write
from tests.test_cert_sync import generate_test_cert_and_key


class IsolatedConfig(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'VPSENTINEL_CONFIG_PATH': self.directory.name + '/config.json'})
        self.env.start()
        sentinel_core.ConfigManager.invalidate_cache()
        self.cfg = sentinel_core.ConfigManager
        self.cfg.save({'initialized': True, 'security': {'admin_username': 'admin', 'auth_enabled': True,
            'admin_password_hash': auth_mgr.AuthManager.hash_password('correct-password'), 'must_change_password': False,
            'session_secret': 'test-secret', 'sub_token': 'test-sub', 'enable_host_guard': False}})
        self.auth = auth_mgr.AuthManager(self.cfg)
    def tearDown(self):
        self.env.stop()
        sentinel_core.ConfigManager.invalidate_cache()
        self.directory.cleanup()
    def signed(self, user, stamp):
        payload = f'{user}:{stamp}'
        signature = hmac.new(b'test-secret', payload.encode(), hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(f'{payload}:{signature}'.encode()).decode()


class TestAuthenticationFixes(IsolatedConfig):
    def test_future_and_other_user_sessions_rejected(self):
        self.assertFalse(self.auth.verify_session_token(self.signed('admin', int(time.time()) + 3600)))
        self.assertFalse(self.auth.verify_session_token(self.signed('stranger', int(time.time()))))
        self.assertTrue(self.auth.verify_session_token(self.auth.create_session_token('admin')))
    def test_revocation_invalidates_copied_token(self):
        token = self.auth.create_session_token('admin')
        self.auth.revoke_sessions()
        self.assertFalse(self.auth.verify_session_token(token))
    def test_missing_subscription_token_fails_closed(self):
        self.cfg.update(lambda c: c['security'].update(sub_token=''))
        request = SimpleNamespace(cookies={}, headers={}, query_params={})
        self.assertFalse(self.auth.verify_subscription_access(request))
    def test_internal_secrets_not_returned(self):
        result = self.auth.update_security_settings({'enable_host_guard': True})
        self.assertNotIn('session_secret', result)
        self.assertNotIn('admin_password_hash', result)
    def test_stronger_password_policy(self):
        self.assertFalse(self.auth.update_password('short'))
        self.assertFalse(self.auth.update_password('x' * 1025))
        self.assertTrue(self.auth.update_password('long-valid-password'))
    def test_active_limiter_has_bound(self):
        for n in range(1500):
            self.auth.record_login_attempt(f'2001:db8::{n:x}', False)
        self.assertLessEqual(len(self.auth._failed_attempts), 1024)
        self.assertTrue(self.auth.is_client_locked('203.0.113.1')[0])
    def test_invalid_ip_uses_one_bucket(self):
        for n in range(20): self.auth.record_login_attempt('untrusted-' + str(n), False)
        self.assertEqual(list(self.auth._failed_attempts), ['unknown'])
    def test_auth_disabled_does_not_validate_arbitrary_admin_token(self):
        self.cfg.update(lambda c: c['security'].update(auth_enabled=False))
        self.assertFalse(self.auth.verify_session_token('nonsense'))
    def test_initial_password_is_private_and_not_logged(self):
        self.cfg.update(lambda c: c['security'].update(admin_password_hash=''))
        with patch('auth_mgr.logger') as logger:
            auth_mgr.AuthManager(self.cfg)
        location = paths.get_config_path() + '.initial-password'
        password = open(location).read().strip()
        self.assertEqual(os.stat(location).st_mode & 0o777, 0o600)
        self.assertNotIn(password, str(logger.mock_calls))


class TestPersistenceFixes(IsolatedConfig):
    def test_temporary_file_private_before_replace(self):
        real_replace = os.replace
        modes = []
        def replace(source, destination):
            modes.append(os.stat(source).st_mode & 0o777)
            return real_replace(source, destination)
        with patch('secure_files.os.replace', side_effect=replace):
            self.cfg.save(self.cfg.load())
        self.assertEqual(modes, [0o600])
    def test_write_failures_propagate(self):
        with patch('sentinel_core.atomic_write', side_effect=OSError('full')):
            with self.assertRaises(OSError): self.cfg.save(self.cfg.load())
    def test_atomic_updates_preserve_every_writer(self):
        def worker():
            for _ in range(20):
                self.cfg.update(lambda c: c.update(counter=c.get('counter', 0) + 1))
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(10)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(self.cfg.load()['counter'], 100)
    def test_symlink_write_rejected(self):
        target = self.directory.name + '/target'
        link = self.directory.name + '/link'
        atomic_write(target, 'original')
        os.symlink(target, link)
        with self.assertRaises(ValueError): atomic_write(link, 'replacement')
        self.assertEqual(open(target).read(), 'original')
    def test_partial_settings_preserve_notifications(self):
        cfg = self.cfg.load()
        cfg['notifications'] = {'enabled': True, 'telegram': {'enabled': True, 'bot_token': 'saved', 'chat_id': '123', 'bot_enabled': True}}
        self.cfg.save(cfg)
        request = SimpleNamespace(url=SimpleNamespace(path='/api/settings'))
        with patch.object(app, 'cfg_mgr', self.cfg), patch.object(app, 'check_admin'):
            app.update_settings(app.SettingsModel(auto_heal=False), request)
        self.assertEqual(self.cfg.load()['notifications']['telegram']['bot_token'], 'saved')
        self.assertTrue(self.cfg.load()['notifications']['enabled'])
    def test_changed_config_path_does_not_reuse_cached_document(self):
        before = self.cfg.load()
        alternate = self.directory.name + '/alternate.json'
        with open(alternate, 'w') as f: json.dump({'marker': 'other'}, f)
        with patch.dict(os.environ, {'VPSENTINEL_CONFIG_PATH': alternate}):
            self.assertEqual(self.cfg.load()['marker'], 'other')
        self.assertEqual(self.cfg.load()['security'], before['security'])


class TestOutboundPolicy(unittest.TestCase):
    def addresses(self, ip): return [(2, 1, 6, '', (ip, 443))]
    def test_http_and_embedded_credentials_rejected(self):
        for url in ('http://example.com', 'https://user:pass@example.com'):
            with self.assertRaises(ValueError): net_policy.validate_url(url)
    def test_metadata_always_rejected(self):
        with patch('socket.getaddrinfo', return_value=self.addresses('169.254.169.254')):
            with self.assertRaises(ValueError): net_policy.validate_url('https://metadata.test', True)
    def test_private_requires_explicit_opt_in(self):
        with patch('socket.getaddrinfo', return_value=self.addresses('10.0.0.1')):
            with self.assertRaises(ValueError): net_policy.validate_url('https://private.test')
            self.assertEqual(net_policy.validate_url('https://private.test', True).hostname, 'private.test')
    def test_redirects_rejected(self):
        with self.assertRaises(ValueError): net_policy.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.test')
    def test_response_size_bounded(self):
        with self.assertRaises(ValueError): net_policy.read_limited(io.BytesIO(b'x'*11), limit=10)
    def test_dns_rebinding_rechecked_at_connect(self):
        connection = net_policy.PinnedHTTPSConnection('public.test')
        connection.allow_private = False
        with patch('socket.getaddrinfo', return_value=self.addresses('127.0.0.1')):
            with self.assertRaises(ValueError): connection.connect()
    def test_cannot_disable_certificate_checks(self):
        self.assertTrue(cert_sync_mgr.CertSyncAgent._create_ssl_context(False).check_hostname)


class TestServiceAndBotFixes(unittest.TestCase):
    def test_noop_reports_unsupported(self):
        self.assertFalse(service_mgr.NoopServiceManager().reload('x-ui')[0])
        self.assertFalse(service_mgr.NoopServiceManager().is_active('x-ui'))
    def test_shell_service_name_rejected(self):
        with self.assertRaises(ValueError): service_mgr.SystemdServiceManager().reload('x-ui; touch /tmp/exploit')
    def test_broker_rejects_unknown_actions(self):
        with self.assertRaises(ValueError): privileged_helper.dispatch({'operation': 'service', 'name': 'ssh', 'action': 'restart'})
        with self.assertRaises(ValueError): privileged_helper.dispatch({'operation': 'shell', 'command': 'id'})
    def test_group_sender_cannot_reip(self):
        bot = bot_mgr.TelegramInteractiveBot(get_config_func=lambda: {'notifications': {'telegram': {'admin_user_ids': [42]}}})
        with patch.object(bot, 'handle_reip_command') as reip:
            bot.process_update({'callback_query': {'from': {'id': 99}, 'data': 'cmd_reip_exec', 'message': {'chat': {'id': -123}}}}, 'token', '-123')
            reip.assert_not_called()
    def test_bot_control_needs_explicit_enable(self):
        bot = bot_mgr.TelegramInteractiveBot(get_config_func=lambda: {'notifications': {'enabled': True, 'telegram': {'bot_token': 'token', 'chat_id': '42'}}})
        self.assertFalse(bot.get_bot_credentials()[2])
    def test_primary_rotation_fails_before_any_cloud_operation(self):
        provider = sentinel_core.HetznerCloudProvider('token', '123', 'primary')
        with patch.object(sentinel_core.ConfigManager, 'load', return_value={}), patch('requests.get') as get:
            with self.assertRaises(RuntimeError): provider.change_public_ip()
            get.assert_not_called()


class TestCertificateValidation(unittest.TestCase):
    def test_mismatched_key_never_replaces_files(self):
        cert, key = generate_test_cert_and_key()
        _, another = generate_test_cert_and_key()
        with tempfile.TemporaryDirectory() as directory:
            cert_sync_mgr.CertSyncAgent.save_cert_bundle_atomic(cert, key, directory)
            previous = os.readlink(directory + '/.current')
            with self.assertRaises(ValueError): cert_sync_mgr.CertSyncAgent.save_cert_bundle_atomic(cert, another, directory)
            self.assertEqual(os.readlink(directory + '/.current'), previous)
    def test_bundle_generation_and_permissions(self):
        cert, key = generate_test_cert_and_key()
        with tempfile.TemporaryDirectory() as directory:
            a, b = cert_sync_mgr.CertSyncAgent.save_cert_bundle_atomic(cert, key, directory)
            self.assertEqual(os.path.dirname(os.path.realpath(a)), os.path.dirname(os.path.realpath(b)))
            self.assertEqual(os.stat(b).st_mode & 0o777, 0o600)
            self.assertEqual(cert_sync_mgr.CertManager.read_cert_bundle(directory)['key_pem'], key)


class TestHealingRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_provider_constructor_failure_releases_runtime_flag(self):
        cfg = {'monitor': {'max_reip_per_day': 2}, 'provider': {'type': 'custom'}}
        manager = MagicMock()
        manager.load.return_value = cfg
        manager.update.side_effect = lambda mutate: mutate(cfg)
        app.runtime_state['heal_in_progress'] = False
        with patch.object(app, 'cfg_mgr', manager), patch.object(app.monitor, 'get_public_ip', return_value='198.51.100.1'), patch('sentinel_core.get_cloud_provider', side_effect=RuntimeError('construction failed')), patch('notification.NotificationManager.broadcast'), patch('app.asyncio.sleep', return_value=None):
            result = await app.run_healing_routine()
        self.assertFalse(result['ok'])
        self.assertFalse(app.runtime_state['heal_in_progress'])
    async def test_outbound_loss_is_not_proof_of_inbound_block(self):
        self.assertFalse(app.confirmed_inbound_failure({'monitor': {}}))
    async def test_uncertain_previous_operation_blocks_repeat(self):
        cfg = {'monitor': {'healing_operation': {'phase': 'uncertain'}}}
        manager = MagicMock(load=lambda:cfg)
        manager.update.side_effect = lambda fn: fn(cfg)
        app.runtime_state['heal_in_progress'] = False
        with patch.object(app, 'cfg_mgr', manager), patch('sentinel_core.get_cloud_provider') as provider:
            result = await app.run_healing_routine(force=True)
            provider.assert_not_called()
        self.assertFalse(result['ok'])
        self.assertFalse(app.runtime_state['heal_in_progress'])

class TestManagementBoundaries(IsolatedConfig):
    def client(self):
        from starlette.testclient import TestClient
        return TestClient(app.app, base_url='https://vps.example.com')
    def test_subscription_cannot_read_management_status(self):
        with patch.object(app, 'auth', self.auth), patch.object(app, 'cfg_mgr', self.cfg):
            response = self.client().get('/api/status?token=test-sub')
        self.assertEqual(response.status_code, 401)
    def test_subscription_cannot_connect_management_websocket(self):
        from starlette.websockets import WebSocketDisconnect
        with patch.object(app, 'auth', self.auth), patch.object(app, 'cfg_mgr', self.cfg):
            with self.assertRaises(WebSocketDisconnect):
                with self.client().websocket_connect('/ws/live?token=test-sub'): pass
    def test_websocket_foreign_origin_rejected(self):
        from starlette.websockets import WebSocketDisconnect
        token = self.auth.create_session_token('admin')
        with patch.object(app, 'auth', self.auth), patch.object(app, 'cfg_mgr', self.cfg):
            with self.assertRaises(WebSocketDisconnect):
                with self.client().websocket_connect('/ws/live', headers={'cookie': 'sentinel_session='+token, 'origin': 'https://evil.test'}): pass
    def test_auth_disabled_does_not_publish_private_key(self):
        self.cfg.update(lambda c: c['security'].update(auth_enabled=False))
        with patch.object(app, 'auth', self.auth), patch.object(app, 'cfg_mgr', self.cfg):
            self.assertEqual(self.client().get('/api/cert/bundle').status_code, 401)
    def test_cookie_cross_origin_mutation_rejected(self):
        token = self.auth.create_session_token('admin')
        with patch.object(app, 'auth', self.auth), patch.object(app, 'cfg_mgr', self.cfg):
            response = self.client().post('/api/heal/trigger', headers={'cookie':'sentinel_session='+token,'origin':'https://evil.test'})
        self.assertEqual(response.status_code, 403)
    def test_logout_revokes_session(self):
        token = self.auth.create_session_token('admin')
        with patch.object(app, 'auth', self.auth), patch.object(app, 'cfg_mgr', self.cfg):
            response = self.client().post('/api/auth/logout', headers={'cookie':'sentinel_session='+token})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.auth.verify_session_token(token))
    def test_initial_password_change_flow(self):
        self.cfg.update(lambda c: c['security'].update(must_change_password=True))
        token=self.auth.create_session_token('admin')
        with patch.object(app,'auth',self.auth), patch.object(app,'cfg_mgr',self.cfg):
            client=self.client()
            client.cookies.set('sentinel_session',token)
            self.assertEqual(client.get('/api/settings').status_code,403)
            response=client.post('/api/auth/update-password',json={'old_password':'correct-password','new_password':'new-strong-password'})
            self.assertEqual(response.status_code,200)
            self.assertFalse(self.auth.verify_session_token(token))
            self.assertFalse(self.auth.get_security_config()['must_change_password'])
            self.assertTrue(self.auth.verify_session_token(response.cookies['sentinel_session']))
    def test_dns_retry_changes_no_ip(self):
        self.cfg.update(lambda c: c.update(monitor={'dns_sync_pending':True,'last_reip_new_ip':'198.51.100.8'},dns={'record_name':'node.example.com'}))
        provider = MagicMock()
        provider.update_dns_record.return_value = True
        with patch.object(app, 'cfg_mgr', self.cfg), patch('sentinel_core.get_dns_provider', return_value=provider), patch('sentinel_core.get_cloud_provider') as cloud:
            self.assertTrue(app.retry_pending_dns())
            cloud.assert_not_called()
        self.assertFalse(self.cfg.load()['monitor']['dns_sync_pending'])
    def test_unsupported_dns_provider_fails_closed(self):
        with self.assertRaises(ValueError): sentinel_core.get_dns_provider({'dns':{'type':'unsupported'}})

class TestNeutralSources(IsolatedConfig):
    def test_config_source_does_not_require_3xui(self):
        from node_sources import collect_native_nodes
        self.cfg.update(lambda c: c.update(proxy_sources=[{'type':'config','nodes':[{'protocol':'trojan','type':'trojan','server':'vps.example.com','port':443,'password':'secret','name':'generic'}]}]))
        with patch('sub_engine.SubEngine._extract_sqlite_nodes') as sqlite:
            records = collect_native_nodes(sqlite, '/not/a/database')
            sqlite.assert_not_called()
        self.assertEqual(records[0][0], 'trojan')
        self.assertEqual(records[0][1]['name'], 'generic')
    def test_node_snapshot_returns_independent_copies(self):
        from node_sources import collect_native_nodes
        self.cfg.update(lambda c: c.update(proxy_sources=[{'type':'config','nodes':[{'protocol':'trojan','server':'vps.example.com','port':443,'name':'original'}]}]))
        collector = MagicMock()
        first=collect_native_nodes(collector,'/none')
        first[0][1]['name']='changed'
        self.assertEqual(collect_native_nodes(collector,'/none')[0][1]['name'],'original')

class TestFailureCompensation(IsolatedConfig):
    def test_certificate_reload_failure_restores_previous_generation(self):
        first, first_key = generate_test_cert_and_key()
        second, second_key = generate_test_cert_and_key()
        cert_dir = self.directory.name + '/cert'
        cert_sync_mgr.CertSyncAgent.save_cert_bundle_atomic(first, first_key, cert_dir)
        previous = os.readlink(cert_dir + '/.current')
        fp = cert_sync_mgr.CertManager.calculate_fingerprint(second.encode())
        self.cfg.update(lambda c: c.update(cert_sync={'role':'edge','master_url':'https://master.example.com','sync_token':'sync','cert_dir':cert_dir,'auto_reload_services':['x-ui'],'expected_domains':['master.example.com']}))
        with patch.object(cert_sync_mgr.CertSyncAgent,'check_master_status',return_value={'status':'ok','fingerprint':fp}), patch.object(cert_sync_mgr.CertSyncAgent,'pull_cert_bundle',return_value={'cert_pem':second,'key_pem':second_key,'fingerprint':fp}), patch.object(cert_sync_mgr.CertSyncAgent,'reload_downstream_services',side_effect=[[{'success':False,'service':'x-ui'}],[{'success':True,'service':'x-ui'}]]):
            result=cert_sync_mgr.CertSyncManager.perform_edge_sync()
        self.assertFalse(result['success'])
        self.assertEqual(os.readlink(cert_dir+'/.current'),previous)
        self.assertEqual(cert_sync_mgr.CertManager.read_cert_bundle(cert_dir)['cert_pem'],first)
    def test_certificate_fingerprint_mismatch_does_not_install(self):
        certificate,key=generate_test_cert_and_key()
        cert_dir=self.directory.name+'/cert'
        self.cfg.update(lambda c: c.update(cert_sync={'role':'edge','master_url':'https://master.example.com','sync_token':'sync','cert_dir':cert_dir,'auto_reload_services':[]}))
        with patch.object(cert_sync_mgr.CertSyncAgent,'check_master_status',return_value={'status':'ok','fingerprint':'wrong'}), patch.object(cert_sync_mgr.CertSyncAgent,'pull_cert_bundle',return_value={'cert_pem':certificate,'key_pem':key,'fingerprint':'wrong'}):
            result=cert_sync_mgr.CertSyncManager.perform_edge_sync()
        self.assertFalse(result['success'])
        self.assertFalse(os.path.exists(cert_dir+'/.current'))
    def test_lightsail_attach_failure_releases_new_unattached_address(self):
        provider=sentinel_core.LightsailCloudProvider('key','secret',instance_name='instance')
        calls=[]
        def call(action,payload):
            calls.append((action,payload))
            if action=='GetStaticIps': return {'staticIps':[{'name':'old','attachedTo':'instance'}]}
            if action=='GetStaticIp': return {'staticIp':{'attachedTo':None}}
            if action=='AttachStaticIp' and payload['staticIpName']!='old': raise RuntimeError('attach failed')
            return {}
        with patch.object(provider,'_call_api',side_effect=call):
            with self.assertRaises(RuntimeError): provider.change_public_ip()
        self.assertTrue(any(action=='ReleaseStaticIp' and payload['staticIpName']!='old' for action,payload in calls))
        self.assertIn(('AttachStaticIp',{'staticIpName':'old','instanceName':'instance'}),calls)
        self.assertFalse(any(action=='ReleaseStaticIp' and payload['staticIpName']=='old' for action,payload in calls))
    def test_hetzner_failed_assignment_compensates_and_powers_on(self):
        self.cfg.update(lambda c: c.update(hetzner={'external_controller':True}))
        provider=sentinel_core.HetznerCloudProvider('token','123','primary')
        get=MagicMock(status_code=200)
        get.json.return_value={'server':{'status':'running','datacenter':{'name':'dc'},'public_net':{'primary_ipv4':10}}}
        def post(url,**kwargs):
            response=MagicMock(status_code=201)
            if url.endswith('/primary_ips'): response.json.return_value={'primary_ip':{'id':20,'ip':'198.51.100.20'}}
            elif url.endswith('/primary_ips/20/actions/assign'): response.status_code=500
            else: response.json.return_value={'action':{'id':1}}
            return response
        with patch('requests.get',return_value=get), patch('requests.post',side_effect=post) as posting, patch('requests.delete') as deleting, patch.object(provider,'_wait_action',return_value=True):
            with self.assertRaises(RuntimeError): provider.change_public_ip()
        self.assertTrue(any('/primary_ips/10/actions/assign' in args.args[0] for args in posting.call_args_list))
        self.assertTrue(any('/servers/123/actions/poweron' in args.args[0] for args in posting.call_args_list))
        deleting.assert_called_once()
    def test_multiprocess_config_transactions_preserve_every_increment(self):
        import subprocess,sys
        code="from sentinel_core import ConfigManager; [ConfigManager.update(lambda c: c.update(counter=c.get('counter',0)+1)) for _ in range(10)]"
        workers=[subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE) for _ in range(4)]
        for worker in workers:
            _,error=worker.communicate(timeout=30)
            self.assertEqual(worker.returncode,0,error.decode())
        self.assertEqual(self.cfg.load()['counter'],40)


if __name__ == '__main__': unittest.main()
