#!/usr/bin/env python3
"""Run on a device connected to the registered operator, not on the coordinator VPS."""
import argparse
import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from edt_optimizer import measure_candidates, validate_candidate, endpoints
from net_policy import open_secure, read_limited, validate_url


def main():
    parser = argparse.ArgumentParser(description='Electric/Unicom/Mobile EdgeTunnel probe')
    parser.add_argument('--server', required=True, help='HTTPS control center URL')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    token = os.environ.get('VPSENTINEL_PROBE_TOKEN', '')
    if not token: parser.error('Set VPSENTINEL_PROBE_TOKEN in the environment')
    base = args.server.rstrip('/'); validate_url(base)
    def call(path, data=None):
        req = urllib.request.Request(base+path, headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},
                                     data=json.dumps(data).encode() if data is not None else None)
        with open_secure(req,timeout=20) as response: return json.loads(read_limited(response,65536))
    while True:
        try:
            task = call('/api/edt/probe/task')
            if len(task['candidates'])>24 or not 1<=len(task['endpoints'])<=2: raise ValueError('Oversized task')
            for ip in task['candidates']: validate_candidate(ip)
            for ep in task['endpoints']:
                endpoints({'pages_domain':ep['host'],'uuid':ep['uuid'],'path':ep['path']})
            results = asyncio.run(measure_candidates(task))
            call('/api/edt/probe/report',{'task_id':task['id'],'results':results})
            print('Report submitted; usable candidates:',sum(r['success_rate']==1 for r in results),flush=True)
        except urllib.error.HTTPError as exc:
            print('Coordinator response:',exc.code,flush=True)
            if args.once: return 1
        except Exception as exc:
            print('Probe failed:',type(exc).__name__,flush=True)
            if args.once: return 1
        if args.once: return 0
        time.sleep(3600)


if __name__=='__main__': sys.exit(main())
