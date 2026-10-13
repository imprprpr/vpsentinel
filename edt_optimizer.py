"""Bounded VLESS-over-WebSocket measurements and operator-scoped probe tasks."""
import asyncio
import copy
import hashlib
import hmac
import ipaddress
import json
import secrets
import ssl
import statistics
import threading
import time
import uuid

from sentinel_core import ConfigManager
from net_policy import open_secure, read_limited, validate_url

CF_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
    '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
    '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
    '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'))
ISPS = ('telecom', 'unicom', 'mobile')
LIMIT = 24


def validate_candidate(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not ip.is_global or not any(ip in net for net in CF_NETWORKS):
        raise ValueError('Candidate must be a public Cloudflare IPv4 address')
    return str(ip)


def endpoints(edt):
    from validation import host as validate_host
    found = []
    for kind in ('pages', 'worker'):
        host = edt.get(kind + '_domain', '').strip()
        key = edt.get(kind + '_uuid', '').strip() or edt.get('uuid', '').strip()
        if host and key:
            validate_host(host)
            if ipaddress_like(host): raise ValueError('Endpoint must be a hostname')
            uuid.UUID(key)
            path = edt.get('path', '/?ed=2048') or '/?ed=2048'
            proxy_ip = edt.get('proxy_ip', '').strip()
            if proxy_ip and 'proxyip=' not in path:
                validate_host(proxy_ip)
                if ipaddress_like(proxy_ip) and not ipaddress.ip_address(proxy_ip).is_global:
                    raise ValueError('Proxy override must be public')
                path = '/proxyip=' + proxy_ip
            if not path.startswith('/') or path.startswith('//') or len(path) > 512 or any(c in path for c in '\r\n#'):
                raise ValueError('Invalid WebSocket path')
            found.append({'host': host, 'uuid': key, 'path': path})
    if not found: raise ValueError('Configure a deployed Pages or Worker endpoint and UUID first')
    return found


def ipaddress_like(host):
    try: ipaddress.ip_address(host); return True
    except ValueError: return False


def fingerprint(eps):
    return hashlib.sha256(json.dumps(eps, sort_keys=True).encode()).hexdigest()


async def measure_endpoint(ip, endpoint):
    """Verify outer TLS, VLESS authentication, inner TLS and an actual HTTPS download."""
    import websockets
    started = time.perf_counter()
    async with websockets.connect('wss://' + endpoint['host'] + endpoint['path'],
            host=validate_candidate(ip), port=443, server_hostname=endpoint['host'],
            ssl=ssl.create_default_context(), compression=None, max_size=1048576,
            open_timeout=7, close_timeout=1) as ws:
        target = b'speed.cloudflare.com'
        header = b'\x00' + uuid.UUID(endpoint['uuid']).bytes + b'\x00\x01\x01\xbb\x02' + bytes([len(target)]) + target
        await ws.send(header)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=target.decode())
        response_header = bytearray()
        header_done = False
        async def flush():
            while outgoing.pending: await ws.send(outgoing.read())
        async def receive():
            nonlocal header_done
            packet = await ws.recv()
            if not isinstance(packet, bytes): raise ValueError('Binary VLESS response required')
            if not header_done:
                response_header.extend(packet)
                if len(response_header) < 2: return
                if response_header[0] != 0: raise ValueError('Invalid VLESS version')
                length = 2 + response_header[1]
                if len(response_header) < length: return
                packet = bytes(response_header[length:]); header_done = True
                response_header.clear()
            if packet: incoming.write(packet)
        while True:
            try: tls.do_handshake(); await flush(); break
            except ssl.SSLWantReadError: await flush(); await receive()
        latency = (time.perf_counter() - started) * 1000
        request = b'GET /__down?bytes=65536 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n'
        tls.write(request); await flush(); download_start = time.perf_counter()
        data = bytearray()
        while len(data) <= 131072:
            try:
                block = tls.read(16384)
                if not block: break
                data.extend(block)
            except ssl.SSLWantReadError: await receive(); continue
            if b'\r\n\r\n' in data:
                headers, body = bytes(data).split(b'\r\n\r\n', 1)
                if not headers.startswith(b'HTTP/1.1 200'): raise ValueError('Download did not return HTTP 200')
                lengths = [line.split(b':',1)[1].strip() for line in headers.split(b'\r\n')[1:] if line.lower().startswith(b'content-length:')]
                chunked = any(line.lower().strip()==b'transfer-encoding: chunked' for line in headers.split(b'\r\n'))
                size = 0
                if chunked:
                    remaining = body
                    while b'\r\n' in remaining:
                        line, tail = remaining.split(b'\r\n',1)
                        length = int(line.split(b';',1)[0],16)
                        if length > 65536: raise ValueError('Oversized HTTP chunk')
                        if len(tail)<length+2: break
                        if tail[length:length+2] != b'\r\n': raise ValueError('Invalid HTTP chunk')
                        size += length; remaining = tail[length+2:]
                        if length == 0: break
                elif lengths == [b'65536']: size = len(body)
                else: raise ValueError('Unexpected download length or transfer encoding')
                if size >= 65536:
                    return latency, 65536 * 8 / max(time.perf_counter()-download_start, 0.001) / 1000000
        raise ValueError('Incomplete proxy download')


async def measure_candidates(task, progress=None):
    eps = task['endpoints']; semaphore = asyncio.Semaphore(4)
    async def candidate(ip):
        successes, latencies, speeds = 0, [], []
        failure = None
        async with semaphore:
            for _ in range(2):
                if progress and Optimizer.stop.is_set(): break
                try:
                    values = []
                    for ep in eps:
                        values.append(await asyncio.wait_for(measure_endpoint(ip, ep), 18))
                    successes += 1
                    latencies.append(max(v[0] for v in values)); speeds.append(min(v[1] for v in values))
                except Exception as exc: failure = type(exc).__name__
            row = {'ip': ip, 'success_rate': successes / 2,
                   'latency_ms': round(statistics.median(latencies), 2) if latencies else None,
                   'jitter_ms': round(max(latencies)-min(latencies), 2) if latencies else None,
                   'download_mbps': round(min(speeds), 3) if speeds else None,
                   'failure_reason': failure}
            if progress: progress()
            return row
    return await asyncio.gather(*(candidate(validate_candidate(ip)) for ip in task['candidates']))


def collect_candidates(edt):
    opt = edt.get('optimizer', {}); values = list(opt.get('candidates', []))
    for pool in edt.get('clean_ips', {}).values():
        for item in pool:
            try: values.append(validate_candidate(item))
            except ValueError: pass
    # Only administrator configured HTTPS sources; no credentials, redirects or private hosts.
    for url in opt.get('sources', [])[:3]:
        try:
            validate_url(url)
            with open_secure(url, timeout=6) as response:
                raw = read_limited(response, 16384).decode()
            for item in raw.replace(',', ' ').split()[:256]:
                try: values.append(validate_candidate(item))
                except ValueError: pass
        except Exception: pass
    # Obtain fresh candidates by bounded sampling of the official address ranges.
    for net in CF_NETWORKS:
        values.append(str(net.network_address + secrets.randbelow(net.num_addresses-2)+1))
    valid = []
    for item in values:
        try: item = validate_candidate(item)
        except ValueError: continue
        if item not in valid: valid.append(item)
    return valid[:LIMIT]


def choose(rows, previous):
    good = [r for r in rows if r['success_rate'] == 1 and r.get('download_mbps', 0) > 0]
    good.sort(key=lambda r: (r['latency_ms'] + r['jitter_ms'], -r['download_mbps']))
    if good and previous:
        old = next((r for r in good if r['ip'] == previous[0]), None)
        if old and old['latency_ms']+old['jitter_ms'] <= (good[0]['latency_ms']+good[0]['jitter_ms'])*1.15:
            good.remove(old); good.insert(0, old)
    return [r['ip'] for r in good[:4]]


class Optimizer:
    lock = threading.Lock()
    state = {'running': False, 'completed': 0, 'total': 0}
    stop = threading.Event()
    thread = None

    @classmethod
    def task(cls):
        edt = ConfigManager.load().get('edgetunnel', {})
        eps = endpoints(edt)
        return {'id': secrets.token_hex(16), 'expires_at': time.time()+3600,
                'fingerprint': fingerprint(eps), 'endpoints': eps, 'candidates': collect_candidates(edt)}

    @classmethod
    def start(cls):
        with cls.lock:
            if cls.state['running']: return False
            # Validate before scheduling, so configuration errors are immediately visible.
            endpoints(ConfigManager.load().get('edgetunnel', {}))
            ConfigManager.update(lambda c: c.setdefault('edgetunnel', {}).setdefault('optimizer', {}).update(last_attempt_at=time.time()))
            cls.state = {'running': True, 'completed': 0, 'total': 0, 'started_at': time.time()}
            threading.Thread(target=cls.run, daemon=True).start()
            return True

    @classmethod
    def run(cls):
        try:
            task = cls.task()
            with cls.lock: cls.state['total'] = len(task['candidates'])
            def progress():
                with cls.lock: cls.state['completed'] += 1
            rows = asyncio.run(measure_candidates(task, progress))
            if cls.stop.is_set(): return
            cls.store(rows, 'anycast', task['fingerprint'], 'server')
            cls.state['error'] = None if any(r['success_rate']==1 for r in rows) else 'No fully usable endpoint; previous pool retained'
        except Exception as exc:
            cls.state['error'] = str(exc)[:200]
        finally:
            with cls.lock: cls.state['running'] = False

    @classmethod
    def store(cls, rows, isp, expected, source, task_id=None):
        def save(cfg):
            edt = cfg.setdefault('edgetunnel', {})
            if fingerprint(endpoints(edt)) != expected: raise ValueError('Endpoint configuration changed; discard old measurements')
            opt = edt.setdefault('optimizer', {})
            if source != 'server':
                task = opt.get('tasks', {}).get(source, {})
                if not any(a['id']==source for a in opt.get('agents', [])) or task.get('id') != task_id or task.get('expires_at',0)<time.time() or task.get('reported'):
                    raise ValueError('Probe revoked, task expired or report already submitted')
                task['reported'] = True
            reports = opt.setdefault('reports', {})
            reports[source] = {'isp': isp, 'timestamp': time.time(), 'fingerprint': expected, 'results': rows}
            fresh = [r for r in reports.values() if r['isp']==isp and r['fingerprint']==expected and time.time()-r['timestamp']<21600]
            combined = []
            for ip in {v['ip'] for r in fresh for v in r['results']}:
                samples = [v for r in fresh for v in r['results'] if v['ip']==ip]
                # Never let a failed measurement be hidden by another probe's success.
                if not all(v['success_rate']==1 for v in samples): continue
                combined.append({'ip': ip, 'success_rate': 1,
                    'latency_ms': statistics.median(v['latency_ms'] for v in samples),
                    'jitter_ms': max(v['jitter_ms'] for v in samples),
                    'download_mbps': min(v['download_mbps'] for v in samples)})
            pools = edt.setdefault('clean_ips', {})
            chosen = choose(combined, pools.get(isp, []))
            if chosen: pools[isp] = chosen
            opt['last_completed_at'] = time.time()
        ConfigManager.update(save)

    @classmethod
    def status(cls):
        opt = ConfigManager.load().get('edgetunnel', {}).get('optimizer', {})
        reports = {k: {f: v for f, v in r.items() if f != 'fingerprint'} for k, r in opt.get('reports', {}).items()}
        with cls.lock: state = copy.deepcopy(cls.state)
        return dict(state, reports=reports, last_completed_at=opt.get('last_completed_at'),
                    agents=[{'id': a['id'], 'isp': a['isp'], 'region': a['region']} for a in opt.get('agents', [])])

    @classmethod
    def start_scheduler(cls):
        if cls.thread and cls.thread.is_alive(): return
        cls.stop.clear()
        def loop():
            while not cls.stop.wait(60):
                edt = ConfigManager.load().get('edgetunnel', {}); opt = edt.get('optimizer', {})
                if edt.get('enabled') and edt.get('auto_refresh_clean_ips', True) and time.time()-max(opt.get('last_completed_at', 0),opt.get('last_attempt_at',0))>=opt.get('interval_sec',3600):
                    try: cls.start()
                    except ValueError: pass
        cls.thread = threading.Thread(target=loop, daemon=True); cls.thread.start()


def authenticate_agent(token):
    digest = hashlib.sha256(token.encode()).hexdigest()
    for a in ConfigManager.load().get('edgetunnel', {}).get('optimizer', {}).get('agents', []):
        if hmac.compare_digest(a['token_hash'], digest): return a
    raise ValueError('Invalid probe credential')
