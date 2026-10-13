"""Network-free regression coverage for scheduling, probe scopes and measured subscriptions."""
import asyncio
import copy
import hashlib
import json
import ssl
import time
import unittest
from unittest.mock import AsyncMock, patch

import tests.sandbox  # noqa: F401
from starlette.testclient import TestClient
import app
from edt_optimizer import Optimizer, collect_candidates, endpoints, fingerprint, measure_candidates, measure_endpoint, validate_candidate, choose
from sentinel_core import ConfigManager
from sub_engine import SubEngine

UUID = '11111111-2222-3333-4444-555555555555'
IP = '104.16.80.1'


def row(ip=IP, success=1, latency=20):
    return {'ip': ip, 'success_rate': success, 'latency_ms': latency if success else None,
            'jitter_ms': 2 if success else None, 'download_mbps': 8 if success else None}


class OptimizerTests(unittest.TestCase):
    def setUp(self):
        self.saved = ConfigManager.load()
        self.old_state = copy.deepcopy(Optimizer.state)
        cfg = copy.deepcopy(self.saved)
        cfg['initialized'] = True
        cfg['security'].update(auth_enabled=True, must_change_password=False, enable_host_guard=False,
                               admin_username='admin', session_secret='optimizer-test-secret')
        cfg['edgetunnel'] = {'enabled': True, 'pages_domain': 'probe.example.com', 'uuid': UUID,
                            'path': '/?ed=2048', 'clean_ips': {'anycast': [IP]}, 'optimizer': {}}
        ConfigManager.save(cfg)
        Optimizer.state = {'running': False, 'completed': 0, 'total': 0}
        self.client = TestClient(app.app, base_url='https://vps.example.com')
        self.admin = {'Authorization': 'Bearer '+app.auth.create_session_token('admin')}
        self.fp = fingerprint(endpoints(cfg['edgetunnel']))

    def tearDown(self):
        ConfigManager.save(self.saved)
        Optimizer.state = self.old_state
        self.client.close()

    def register(self, isp='telecom'):
        response = self.client.post('/api/edt/agents', json={'isp': isp, 'region': 'test-region'}, headers=self.admin)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        return data, {'Authorization': 'Bearer '+data['token']}

    def task(self, headers):
        with patch('edt_optimizer.collect_candidates', return_value=[IP]):
            response = self.client.get('/api/edt/probe/task', headers=headers)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_candidate_rejects_private_metadata_and_non_cloudflare(self):
        for ip in ('127.0.0.1', '169.254.169.254', '10.0.0.1', '8.8.8.8', '::1', 'bad'):
            with self.subTest(ip=ip), self.assertRaises(ValueError): validate_candidate(ip)
        self.assertEqual(validate_candidate(IP), IP)

    def test_sampling_is_bounded_and_public(self):
        values = collect_candidates({'optimizer': {'candidates': [IP]*40}, 'clean_ips': {}})
        self.assertLessEqual(len(values), 24)
        self.assertEqual(len(values), len(set(values)))
        self.assertTrue(all(validate_candidate(ip) for ip in values))

    def test_proxy_path_matches_subscription(self):
        edt = ConfigManager.load()['edgetunnel']
        edt['proxy_ip'] = 'proxy.example.com'
        self.assertEqual(endpoints(edt)[0]['path'], '/proxyip=proxy.example.com')
        edt['proxy_ip'] = '127.0.0.1'
        with self.assertRaises(ValueError): endpoints(edt)

    def test_invalid_endpoints_are_rejected(self):
        for change in ({'uuid': 'bad'}, {'path': '//other.example'}, {'pages_domain': '127.0.0.1'}, {'path': '/\r\nX: y'}):
            edt = ConfigManager.load()['edgetunnel']; edt.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): endpoints(edt)

    def test_hysteresis_keeps_close_previous_winner(self):
        rows = [row(IP, latency=21), row('104.16.80.2', latency=20)]
        self.assertEqual(choose(rows, [IP])[0], IP)
        rows[0]['latency_ms'] = 100
        self.assertEqual(choose(rows, [IP])[0], '104.16.80.2')
        self.assertEqual(choose([row(success=0)], [IP]), [])

    def test_refresh_preserves_compatibility_without_blocking(self):
        with patch.object(Optimizer, 'start', return_value=True) as start:
            response = self.client.post('/api/edt/refresh-clean-ips', headers=self.admin)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'started')
        self.assertIn('clean_ips', response.json())
        self.assertIn('optimizer', response.json())
        start.assert_called_once()
        with patch.object(Optimizer, 'start', return_value=False):
            self.assertEqual(self.client.post('/api/edt/refresh-clean-ips', headers=self.admin).json()['status'], 'running')

    def test_config_normalizes_domains_before_validation(self):
        response = self.client.post('/api/edt/config', headers=self.admin, json={'pages_domain':'https://updated.example.com/admin'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ConfigManager.load()['edgetunnel']['pages_domain'], 'updated.example.com')
        self.assertEqual(self.client.post('/api/edt/config', headers=self.admin, json={'candidates':['127.0.0.1']}).status_code, 422)

    def test_config_saves_pools_and_optimizer_settings_together(self):
        response = self.client.post('/api/edt/config', headers=self.admin, json={
            'pages_domain':'new.example.com', 'interval_sec':1800, 'candidates':[IP],
            'clean_ips':{'telecom':[IP]}})
        self.assertEqual(response.status_code, 200)
        edt = ConfigManager.load()['edgetunnel']
        self.assertEqual(edt['pages_domain'],'new.example.com')
        self.assertEqual(edt['optimizer']['interval_sec'],1800)
        self.assertEqual(edt['clean_ips']['telecom'],[IP])

    def test_server_results_are_never_labelled_as_three_operators(self):
        Optimizer.store([row()], 'anycast', self.fp, 'server')
        nodes = SubEngine.extract_edt_nodes()
        self.assertTrue(nodes)
        self.assertTrue(all(n['isp']=='anycast' for n in nodes))
        self.assertTrue(all('服务器侧优选' in n['name'] for n in nodes))

    def test_failure_retains_last_verified_pool(self):
        Optimizer.store([row()], 'anycast', self.fp, 'server')
        before = ConfigManager.load()['edgetunnel']['optimizer']['verified_pools']['anycast']
        Optimizer.store([row(success=0)], 'anycast', self.fp, 'server')
        after = ConfigManager.load()['edgetunnel']['optimizer']['verified_pools']['anycast']
        self.assertEqual(before, after)
        self.assertTrue(SubEngine.extract_edt_nodes())

    def test_expired_and_changed_endpoint_results_are_not_subscribed(self):
        Optimizer.store([row()], 'anycast', self.fp, 'server')
        ConfigManager.update(lambda c:c['edgetunnel']['optimizer']['verified_pools']['anycast'].update(timestamp=time.time()-21601))
        self.assertEqual(SubEngine.extract_edt_nodes(), [])
        Optimizer.store([row()], 'anycast', self.fp, 'server')
        ConfigManager.update(lambda c:c['edgetunnel'].update(uuid='99999999-8888-7777-6666-555555555555'))
        self.assertEqual(SubEngine.extract_edt_nodes(), [])
        with self.assertRaises(ValueError): Optimizer.store([row()], 'anycast', self.fp, 'server')

    def test_probe_scope_and_token_redaction(self):
        data, headers = self.register()
        cfg = ConfigManager.load()['edgetunnel']['optimizer']
        self.assertNotIn(data['token'], json.dumps(cfg))
        self.assertEqual(cfg['agents'][0]['token_hash'], hashlib.sha256(data['token'].encode()).hexdigest())
        self.assertEqual(self.client.get('/api/edt/optimizer', headers=headers).status_code, 401)
        self.assertEqual(self.client.get('/api/status', headers=headers).status_code, 401)
        self.assertEqual(self.client.get('/api/edt/probe/task').status_code, 401)
        task = self.task(headers)
        self.assertNotIn(data['token'], json.dumps(Optimizer.status()))
        self.assertEqual(self.task(headers)['id'], task['id'])

    def test_reports_are_bound_to_task_and_only_accepted_once(self):
        data, headers = self.register(); task = self.task(headers)
        route = '/api/edt/probe/report'; report = {'task_id':task['id'], 'results':[row()]}
        wrong = dict(report, task_id='wrong')
        self.assertEqual(self.client.post(route,json=wrong,headers=headers).status_code,409)
        wrong = dict(report,results=[row('104.16.80.2')])
        self.assertEqual(self.client.post(route,json=wrong,headers=headers).status_code,422)
        self.assertEqual(self.client.post(route,json=report,headers=headers).status_code,200)
        self.assertEqual(self.client.post(route,json=report,headers=headers).status_code,409)
        self.assertEqual(self.client.get('/api/edt/probe/task',headers=headers).status_code,409)
        nodes=SubEngine.extract_edt_nodes()
        self.assertTrue(nodes); self.assertTrue(all(n['isp']=='telecom' for n in nodes))

    def test_probe_result_validation_and_expiration(self):
        data,headers=self.register(); task=self.task(headers)
        bad=row();bad['latency_ms']=None
        self.assertEqual(self.client.post('/api/edt/probe/report',headers=headers,json={'task_id':task['id'],'results':[bad]}).status_code,422)
        ConfigManager.update(lambda c:c['edgetunnel']['optimizer']['tasks'][data['id']].update(expires_at=time.time()-1))
        self.assertEqual(self.client.post('/api/edt/probe/report',headers=headers,json={'task_id':task['id'],'results':[row()]}).status_code,409)

    def test_revocation_blocks_task_and_pending_report(self):
        data,headers=self.register(); task=self.task(headers)
        self.assertEqual(self.client.delete('/api/edt/agents/'+data['id'],headers=self.admin).status_code,200)
        self.assertEqual(self.client.get('/api/edt/probe/task',headers=headers).status_code,401)
        self.assertEqual(self.client.post('/api/edt/probe/report',headers=headers,json={'task_id':task['id'],'results':[row()]}).status_code,401)
        with self.assertRaises(ValueError): Optimizer.store([row()],'telecom',self.fp,data['id'],task['id'])


class ProbeMeasurements(unittest.IsolatedAsyncioTestCase):
    async def test_measurements_require_both_trials_and_all_endpoints(self):
        task={'candidates':[IP], 'endpoints':[{'host':'one.example'},{'host':'two.example'}]}
        with patch('edt_optimizer.measure_endpoint',new=AsyncMock(return_value=(20,8))), patch.object(Optimizer.stop,'is_set',return_value=False):
            result=await measure_candidates(task)
        self.assertEqual(result[0]['success_rate'],1)
        with patch('edt_optimizer.measure_endpoint',new=AsyncMock(side_effect=[(20,8),ValueError(),(20,8),ValueError()])):
            result=await measure_candidates(task)
        self.assertEqual(result[0]['success_rate'],0)
        self.assertIsNone(result[0]['download_mbps'])

    async def test_partial_success_is_not_eligible(self):
        task={'candidates':[IP],'endpoints':[{}]}
        with patch('edt_optimizer.measure_endpoint',new=AsyncMock(side_effect=[(20,8),TimeoutError()])):
            result=await measure_candidates(task)
        self.assertEqual(result[0]['success_rate'],0.5)
        self.assertEqual(choose(result,[]),[])

    async def test_proxy_download_checks_tls_and_vless_framing(self):
        class TLS:
            def __init__(self): self.calls=0;self.data=b'HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n'+b'x'*65536
            def do_handshake(self):
                self.calls+=1
                if self.calls<3:raise ssl.SSLWantReadError()
            def write(self,data):self.request=data;return len(data)
            def read(self,length):b,self.data=self.data[:length],self.data[length:];return b
        class Context:
            def wrap_bio(self,*args,**kwargs):return tls
        class Socket:
            def __init__(self):self.packets=[b'\x00',b'\x00server-hello'];self.sent=[]
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def send(self,data):self.sent.append(data)
            async def recv(self):return self.packets.pop(0)
        tls=TLS();ws=Socket();verified=ssl.create_default_context()
        with patch('websockets.connect',return_value=ws) as connect,patch('edt_optimizer.ssl.create_default_context',side_effect=[verified,Context()]):
            latency,speed=await measure_endpoint(IP,{'host':'probe.example.com','uuid':UUID,'path':'/'})
        self.assertGreaterEqual(latency,0);self.assertGreater(speed,0)
        self.assertEqual(connect.call_args.kwargs['host'],IP)
        self.assertEqual(connect.call_args.kwargs['server_hostname'],'probe.example.com')
        self.assertEqual(connect.call_args.kwargs['ssl'].verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(connect.call_args.kwargs['ssl'].check_hostname)
        self.assertEqual(ws.sent[0][:1],b'\x00');self.assertIn(b'speed.cloudflare.com',ws.sent[0])
        self.assertIn(b'GET /__down?bytes=65536',tls.request)
