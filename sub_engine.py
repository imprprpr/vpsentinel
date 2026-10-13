#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from secure_files import transactional
import json
import base64
import sqlite3
import logging
import urllib.parse
import yaml
from transit_mgr import TransitManager
from custom_node_mgr import CustomNodeManager
from sentinel_core import ConfigManager
from clean_ip_mgr import CleanIPManager

logger = logging.getLogger('SubEngine')
from paths import XUI_DB_PATH
DB_PATH = XUI_DB_PATH

DEFAULT_RULES_CONFIG = {
    'adblock': True,
    'ai_group': True,
    'media_group': True,
    'auto_test': True,
    'direct_cn': True,
    'hy2_hop': False,
    'oracle_bypass': True
}

def _unique(base: str, used_set: set) -> str:
    if base not in used_set:
        used_set.add(base)
        return base
    idx = 2
    while f"{base}-{idx}" in used_set:
        idx += 1
    res = f"{base}-{idx}"
    used_set.add(res)
    return res

class SubEngine:
    @staticmethod
    def get_rules_config():
        cfg = ConfigManager.load()
        rules = cfg.get('rules_config', DEFAULT_RULES_CONFIG)
        return {**DEFAULT_RULES_CONFIG, **rules}

    @staticmethod
    @transactional
    def save_rules_config(rules):
        cfg = ConfigManager.load()
        cfg['rules_config'] = rules
        return ConfigManager.save(cfg)

    @staticmethod
    def get_server_ip():
        try:
            import sentinel_core
            mon = sentinel_core.SystemMonitor()
            ip = mon.get_public_ip()
            if ip and ip != '127.0.0.1':
                return ip
        except Exception:
            pass
        try:
            import urllib.request
            ip = urllib.request.urlopen('https://api.ipify.org', timeout=3).read().decode('utf-8').strip()
            if ip and ip != '127.0.0.1':
                return ip
        except Exception:
            pass
        return '198.51.100.1'

    @staticmethod
    def get_server_domain():
        try:
            cfg = ConfigManager.load()
            rec = cfg.get('dns', {}).get('record_name') or cfg.get('cloudflare', {}).get('record_name')
            if rec:
                return rec
        except Exception:
            pass
        return 'vps.example.com'

    @staticmethod
    def extract_nodes_from_db():
        from node_sources import collect_native_nodes
        return collect_native_nodes(SubEngine._extract_sqlite_nodes, DB_PATH)

    @staticmethod
    def _extract_sqlite_nodes():
        if not os.path.exists(DB_PATH):
            logger.error(f'Database {DB_PATH} not found.')
            return []

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(inbounds);")
        cols = [c[1] for c in cursor.fetchall()]
        has_remark = 'remark' in cols
        q = f"SELECT id, tag, port, protocol, settings, stream_settings, enable{', remark' if has_remark else ''} FROM inbounds WHERE enable = 1;"
        cursor.execute(q)
        rows = cursor.fetchall()
        conn.close()

        nodes = []
        domain = SubEngine.get_server_domain()
        server_ip = SubEngine.get_server_ip()

        used_clash_names = set()
        used_singbox_tags = set()

        for row in rows:
            inbound_id = row[0]
            tag = row[1] or ''
            port = row[2]
            proto = row[3]
            st_raw = row[4]
            ss_raw = row[5]
            enabled = row[6]
            remark = row[7] if has_remark and len(row) > 7 and row[7] else ''

            try:
                st = json.loads(st_raw) if st_raw else {}
                ss = json.loads(ss_raw) if ss_raw else {}
            except Exception:
                continue

            clients = st.get('clients', [])
            for client in (clients or [{}]):
                if client.get('enable') is False:
                    continue


                label = str(remark).strip() or str(tag).strip()

                if proto == 'vless' and ss.get('security') == 'reality':
                    rs = ss.get('realitySettings', {})
                    rs_st = rs.get('settings', {})
                    proto_label = label or 'VPS-Reality'
                    node_name = _unique(f"[VPS] {proto_label}", used_clash_names)
                    node_tag = _unique(proto_label, used_singbox_tags)
                    node = {
                        'name': node_name,
                        'tag': node_tag,
                        'type': 'vless',
                        'server': server_ip,
                        'port': port,
                        'uuid': client.get('id', ''),
                        'network': ss.get('network', 'tcp'),
                        'tls': True,
                        'udp': True,
                        'flow': client.get('flow', 'xtls-rprx-vision'),
                        'servername': rs.get('serverNames', ['swdist.apple.com'])[0] if rs.get('serverNames') else 'swdist.apple.com',
                        'reality-opts': {
                            'public-key': rs_st.get('publicKey', ''),
                            'short-id': rs.get('shortIds', ['cb2ebc41'])[0] if rs.get('shortIds') else ''
                        },
                        'client-fingerprint': rs_st.get('fingerprint', 'chrome')
                    }
                    nodes.append(('reality', node))

                elif proto == 'hysteria':
                    proto_label = label or 'VPS-Hy2'
                    node_name = _unique(f"[VPS] {proto_label}", used_clash_names)
                    node_tag = _unique(proto_label, used_singbox_tags)
                    node = {
                        'name': node_name,
                        'tag': node_tag,
                        'type': 'hysteria2',
                        'server': server_ip,
                        'port': port,
                        'password': client.get('auth', ''),
                        'sni': ss.get('tlsSettings', {}).get('serverName', domain),
                        'skip-cert-verify': False
                    }
                    nodes.append(('hy2', node))

                elif proto == 'trojan':
                    proto_label = label or 'VPS-Trojan'
                    node_name = _unique(f"[VPS] {proto_label}", used_clash_names)
                    node_tag = _unique(proto_label, used_singbox_tags)
                    node = {
                        'name': node_name,
                        'tag': node_tag,
                        'type': 'trojan',
                        'server': server_ip,
                        'port': port,
                        'password': client.get('password', ''),
                        'sni': ss.get('tlsSettings', {}).get('serverName', domain),
                        'skip-cert-verify': False,
                        'client-fingerprint': 'chrome',
                        'udp': True
                    }
                    nodes.append(('trojan', node))

        return nodes

    @staticmethod
    def extract_edt_nodes():
        """
        Extracts EdgeTunnel VLESS-WS clean IP nodes.
        Strictly zero emojis.
        """
        try:
            if not CleanIPManager.is_edt_enabled():
                return []
            edt = CleanIPManager.get_edt_config()
            uuid = edt.get('uuid', '').strip()
            pages_uuid = edt.get('pages_uuid', '').strip() or uuid
            worker_uuid = edt.get('worker_uuid', '').strip() or uuid
            pages = CleanIPManager.sanitize_domain(edt.get('pages_domain', ''))
            worker = CleanIPManager.sanitize_domain(edt.get('worker_domain', ''))
            path = edt.get('path', '/?ed=2048').strip() or '/?ed=2048'
            proxy_ip = edt.get('proxy_ip', '').strip()
            if proxy_ip and 'proxyip=' not in path:
                path = f"/proxyip={proxy_ip}"
            clean_ips = CleanIPManager.get_clean_ips()

            nodes = []
            isp_map = [
                ('telecom', '电信优选'),
                ('unicom', '联通优选'),
                ('mobile', '移动优选'),
                ('anycast', 'Anycast优选')
            ]

            endpoints = []
            if pages and pages_uuid:
                endpoints.append(('Pages', pages, pages_uuid))
            if worker and worker_uuid:
                endpoints.append(('Worker', worker, worker_uuid))

            for ep_type, ep_domain, ep_uuid in endpoints:
                for isp_key, isp_title in isp_map:
                    pool = clean_ips.get(isp_key, [])
                    filtered = [
                        str(ip).strip() for ip in pool
                        if str(ip).strip() and 'v6.rocks' not in str(ip).lower() and str(ip).lower() != 'cloudflare.com'
                    ]
                    if not filtered:
                        from clean_ip_mgr import DEFAULT_CLEAN_IPS
                        filtered = list(DEFAULT_CLEAN_IPS.get(isp_key, ['162.159.192.1']))

                    chosen = filtered[:2] if len(filtered) >= 2 else filtered[:1]
                    for idx, server in enumerate(chosen):
                        suffix = f" #{idx+1}" if len(chosen) > 1 else ""
                        node_name = f'[edt-{ep_type}] {isp_title}{suffix}'
                        nodes.append({
                            'name': node_name,
                            'server': server,
                            'port': 443,
                            'uuid': ep_uuid,
                            'host': ep_domain,
                            'path': path,
                            'isp': isp_key,
                            'source': ep_type.lower()
                        })
            return nodes
        except Exception as e:
            logger.debug(f"Error extracting edt nodes: {e}")
            return []

    @staticmethod
    def edt_node_to_clash(n):
        return {
            'name': n['name'],
            'type': 'vless',
            'server': n['server'],
            'port': n['port'],
            'uuid': n['uuid'],
            'network': 'ws',
            'tls': True,
            'udp': True,
            'servername': n['host'],
            'ws-opts': {
                'path': n['path'],
                'headers': {
                    'Host': n['host']
                }
            },
            'client-fingerprint': 'chrome'
        }

    @staticmethod
    def edt_node_to_singbox(n):
        return {
            'type': 'vless',
            'tag': n['name'],
            'server': n['server'],
            'server_port': n['port'],
            'uuid': n['uuid'],
            'network': 'tcp',
            'tls': {
                'enabled': True,
                'server_name': n['host'],
                'utls': {
                    'enabled': True,
                    'fingerprint': 'chrome'
                }
            },
            'transport': {
                'type': 'ws',
                'path': n['path'],
                'headers': {
                    'Host': n['host']
                }
            },
            'packet_encoding': 'xudp'
        }

    @staticmethod
    def edt_node_to_v2ray_link(n):
        encoded_path = urllib.parse.quote(n['path'])
        encoded_host = urllib.parse.quote(n['host'])
        encoded_name = urllib.parse.quote(n['name'])
        return f"vless://{n['uuid']}@{n['server']}:{n['port']}?type=ws&security=tls&fp=chrome&path={encoded_path}&host={encoded_host}&sni={encoded_host}#{encoded_name}"

    # --- 1. Clash / Mihomo YAML Generator ---
    @staticmethod
    def generate_clash_yaml(rules_override=None):
        rules_cfg = rules_override or SubEngine.get_rules_config()
        raw_nodes = SubEngine.extract_nodes_from_db()
        transits = TransitManager.get_transits()

        native_proxies = []
        native_names = []

        # 1. Direct Nodes
        for ntype, node_data in raw_nodes:
            n = node_data.copy()
            if ntype == 'hy2' and rules_cfg.get('hy2_hop', False):
                n['ports'] = '20000-40000'
                n['name'] = 'VPS-Hy2 (Hop)'
            native_proxies.append(n)
            native_names.append(n['name'])

        # 2. Transit / Relay Nodes
        for t in transits:
            if not t.get('enabled', True):
                continue
            t_name = t.get('name', 'Transit')
            t_host = t.get('host', '')
            if not t_host:
                continue

            for ntype, base_node in raw_nodes:
                relay_node = base_node.copy()
                if ntype == 'hy2':
                    relay_node['name'] = f'[{t_name}] Hy2 Relay'
                    relay_node['server'] = t_host
                    relay_node['port'] = t.get('hy2_port', 20443)
                    if 'ports' in relay_node:
                        del relay_node['ports']
                    native_proxies.append(relay_node)
                    native_names.append(relay_node['name'])
                elif ntype == 'reality':
                    relay_node['name'] = f'[{t_name}] Reality Relay'
                    relay_node['server'] = t_host
                    relay_node['port'] = t.get('reality_port', 28443)
                    native_proxies.append(relay_node)
                    native_names.append(relay_node['name'])
                elif ntype == 'trojan':
                    relay_node['name'] = f'[{t_name}] Trojan Relay'
                    relay_node['server'] = t_host
                    relay_node['port'] = t.get('trojan_port', 22083)
                    native_proxies.append(relay_node)
                    native_names.append(relay_node['name'])

        # 3. Custom / External Standalone Nodes
        custom_nodes = CustomNodeManager.get_custom_nodes()
        for cn in custom_nodes:
            if not cn.get('enabled', True):
                continue
            cp = CustomNodeManager.to_clash_proxy(cn)
            if cp:
                native_proxies.append(cp)
                native_names.append(cp['name'])

        # 4. Multi-Node Sentinel Mesh Aggregated Proxies
        try:
            from mesh_mgr import MeshManager
            for mn in MeshManager.get_nodes():
                if not mn.get('enabled', True):
                    continue
                for mp in mn.get('proxy_nodes', []):
                    cp = CustomNodeManager.to_clash_proxy(mp)
                    if cp and cp['name'] not in native_names:
                        native_proxies.append(cp)
                        native_names.append(cp['name'])
        except Exception as e:
            logger.debug(f"Error aggregating mesh nodes for Clash: {e}")

        # 5. EdgeTunnel (EDT) Serverless Clean IP Nodes
        edt_proxies = []
        edt_names = []
        for en in SubEngine.extract_edt_nodes():
            cp = SubEngine.edt_node_to_clash(en)
            if cp and cp['name'] not in edt_names:
                edt_proxies.append(cp)
                edt_names.append(cp['name'])

        all_proxies = native_proxies + edt_proxies

        if not native_names and not edt_names:
            native_names = ['DIRECT']

        proxy_groups = []

        if edt_names:
            # Segregated Strategy Groups when EdgeTunnel is active
            # 1. Native VPS Select Group (strictly native nodes only)
            native_group_proxies = []
            if rules_cfg.get('auto_test', True) and native_names:
                native_group_proxies.append('原生-自动测速')
            native_group_proxies.extend(native_names)
            native_group_proxies.append('DIRECT')

            proxy_groups.append({
                'name': '原生节点 (VPS)',
                'type': 'select',
                'proxies': native_group_proxies
            })

            # 2. Native URL-Test Group (tests native nodes only)
            if rules_cfg.get('auto_test', True) and native_names:
                proxy_groups.append({
                    'name': '原生-自动测速',
                    'type': 'url-test',
                    'url': 'https://www.gstatic.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': list(native_names)
                })

            # 3. EDT Edge Select Group (strictly edt clean IP nodes only)
            edt_group_proxies = []
            if rules_cfg.get('auto_test', True):
                edt_group_proxies.append('边缘-自动测速')
            edt_group_proxies.extend(edt_names)

            proxy_groups.append({
                'name': '边缘节点 (EDT)',
                'type': 'select',
                'proxies': edt_group_proxies
            })

            # 4. EDT URL-Test Group (tests edt clean IP nodes only)
            if rules_cfg.get('auto_test', True):
                proxy_groups.append({
                    'name': '边缘-自动测速',
                    'type': 'url-test',
                    'url': 'https://www.gstatic.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': list(edt_names)
                })

            # 5. Fallback Group: Native VPS first, fallback to EDT edge nodes
            fallback_proxies = list(native_names) + list(edt_names)
            proxy_groups.append({
                'name': '容灾自愈 (Fallback)',
                'type': 'fallback',
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 180,
                'proxies': fallback_proxies
            })

            # 6. Global Selector Group (switches between segregated groups or DIRECT)
            proxy_groups.append({
                'name': '节点选择',
                'type': 'select',
                'proxies': ['原生节点 (VPS)', '边缘节点 (EDT)', '容灾自愈 (Fallback)', 'DIRECT']
            })

            # 7. AI Service Group
            if rules_cfg.get('ai_group', True):
                proxy_groups.append({
                    'name': 'AI 智能服务',
                    'type': 'select',
                    'proxies': ['节点选择', '原生节点 (VPS)', '边缘节点 (EDT)', 'DIRECT']
                })

            # 8. Media Streaming Group
            if rules_cfg.get('media_group', True):
                proxy_groups.append({
                    'name': '国际流媒体',
                    'type': 'select',
                    'proxies': ['节点选择', '边缘节点 (EDT)', '原生节点 (VPS)', 'DIRECT']
                })

            # 9. Ad Block Group
            if rules_cfg.get('adblock', True):
                proxy_groups.append({
                    'name': '广告拦截',
                    'type': 'select',
                    'proxies': ['REJECT', 'DIRECT']
                })

            # 10. Direct
            proxy_groups.append({
                'name': '全球直连',
                'type': 'select',
                'proxies': ['DIRECT']
            })
        else:
            # Standard legacy groups when EDT is not active
            group_select_proxies = []
            if rules_cfg.get('auto_test', True):
                group_select_proxies.append('自动优选')
            group_select_proxies.extend(native_names)
            group_select_proxies.append('DIRECT')

            proxy_groups.append({
                'name': '节点选择',
                'type': 'select',
                'proxies': group_select_proxies
            })

            # Group: 自动优选
            if rules_cfg.get('auto_test', True):
                proxy_groups.append({
                    'name': '自动优选',
                    'type': 'url-test',
                    'url': 'https://www.gstatic.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': list(native_names)
                })

            # Group: AI 智能服务
            if rules_cfg.get('ai_group', True):
                proxy_groups.append({
                    'name': 'AI 智能服务',
                    'type': 'select',
                    'proxies': ['节点选择'] + list(native_names)
                })

            # Group: 国际流媒体
            if rules_cfg.get('media_group', True):
                proxy_groups.append({
                    'name': '国际流媒体',
                    'type': 'select',
                    'proxies': ['节点选择'] + list(native_names)
                })

            # Group: 广告拦截
            if rules_cfg.get('adblock', True):
                proxy_groups.append({
                    'name': '广告拦截',
                    'type': 'select',
                    'proxies': ['REJECT', 'DIRECT']
                })

            # Group: 全球直连
            proxy_groups.append({
                'name': '全球直连',
                'type': 'select',
                'proxies': ['DIRECT']
            })

        rules = [
            'IP-CIDR,127.0.0.0/8,全球直连,no-resolve',
            'IP-CIDR,172.16.0.0/12,全球直连,no-resolve',
            'IP-CIDR,192.168.0.0/16,全球直连,no-resolve',
            'IP-CIDR,10.0.0.0/8,全球直连,no-resolve',
            'IP-CIDR,100.64.0.0/10,全球直连,no-resolve',
            'IP-CIDR6,fc00::/7,全球直连,no-resolve',
            'IP-CIDR6,fe80::/10,全球直连,no-resolve',
            'IP-CIDR6,::1/128,全球直连,no-resolve'
        ]

        if rules_cfg.get('oracle_bypass', True):
            rules.extend([
                'DOMAIN-SUFFIX,oracle.com,全球直连',
                'DOMAIN-SUFFIX,oraclecloud.com,全球直连',
                'DOMAIN-SUFFIX,oracleiaas.com,全球直连'
            ])
        else:
            rules.extend([
                'DOMAIN-SUFFIX,oracle.com,节点选择',
                'DOMAIN-SUFFIX,oraclecloud.com,节点选择',
                'DOMAIN-SUFFIX,oracleiaas.com,节点选择'
            ])

        if rules_cfg.get('adblock', True):
            rules.extend([
                'GEOSITE,category-ads-all,广告拦截',
                'DOMAIN-KEYWORD,adservice,广告拦截'
            ])

        if rules_cfg.get('ai_group', True):
            rules.extend([
                'GEOSITE,openai,AI 智能服务',
                'GEOSITE,anthropic,AI 智能服务',
                'DOMAIN-SUFFIX,openai.com,AI 智能服务',
                'DOMAIN-SUFFIX,chatgpt.com,AI 智能服务',
                'DOMAIN-SUFFIX,oaistatic.com,AI 智能服务',
                'DOMAIN-SUFFIX,oaiusercontent.com,AI 智能服务',
                'DOMAIN-SUFFIX,anthropic.com,AI 智能服务',
                'DOMAIN-SUFFIX,claude.ai,AI 智能服务',
                'DOMAIN-SUFFIX,claudecontent.com,AI 智能服务',
                'DOMAIN-KEYWORD,openai,AI 智能服务',
                'DOMAIN-KEYWORD,anthropic,AI 智能服务',
                'DOMAIN-KEYWORD,claude,AI 智能服务'
            ])

        if rules_cfg.get('media_group', True):
            rules.extend([
                'GEOSITE,netflix,国际流媒体',
                'GEOSITE,youtube,国际流媒体',
                'GEOSITE,disney,国际流媒体',
                'GEOSITE,spotify,国际流媒体',
                'DOMAIN-SUFFIX,netflix.com,国际流媒体',
                'DOMAIN-SUFFIX,nflxext.com,国际流媒体',
                'DOMAIN-SUFFIX,nflximg.net,国际流媒体',
                'DOMAIN-SUFFIX,nflxvideo.net,国际流媒体',
                'DOMAIN-SUFFIX,youtube.com,国际流媒体',
                'DOMAIN-SUFFIX,googlevideo.com,国际流媒体',
                'DOMAIN-SUFFIX,disneyplus.com,国际流媒体',
                'DOMAIN-SUFFIX,spotify.com,国际流媒体'
            ])

        rules.extend([
            'GEOSITE,github,节点选择',
            'GEOSITE,telegram,节点选择',
            'GEOSITE,twitter,节点选择',
            'DOMAIN-SUFFIX,github.com,节点选择',
            'DOMAIN-SUFFIX,telegram.org,节点选择',
            'DOMAIN-SUFFIX,twitter.com,节点选择',
            'DOMAIN-SUFFIX,x.com,节点选择'
        ])

        if rules_cfg.get('direct_cn', True):
            rules.extend([
                'GEOSITE,cn,全球直连',
                'GEOIP,CN,全球直连'
            ])

        rules.append('MATCH,节点选择')

        server_ip = SubEngine.get_server_ip()
        domain = SubEngine.get_server_domain()
        clash_config = {
            'port': 7890,
            'socks-port': 7891,
            'mixed-port': 7892,
            'allow-lan': True,
            'mode': 'rule',
            'log-level': 'info',
            'unified-delay': True,
            'hosts': {
                domain: server_ip
            },
            'dns': {
                'enable': True,
                'listen': '0.0.0.0:1053',
                'enhanced-mode': 'fake-ip',
                'fake-ip-range': '198.18.0.1/16',
                'fake-ip-filter': [
                    '*.lan',
                    '*.local',
                    '+.oracle.com',
                    '+.oraclecloud.com',
                    '+.oracleiaas.com'
                ],
                'default-nameserver': [
                    '223.5.5.5',
                    '119.29.29.29',
                    '114.114.114.114'
                ],
                'nameserver': [
                    '223.5.5.5',
                    '119.29.29.29'
                ],
                'nameserver-policy': {
                    '+.oracle.com': ['223.5.5.5', '119.29.29.29'],
                    '+.oraclecloud.com': ['223.5.5.5', '119.29.29.29'],
                    '+.oracleiaas.com': ['223.5.5.5', '119.29.29.29']
                },
                'fallback': [
                    'https://1.1.1.1/dns-query',
                    'https://8.8.8.8/dns-query'
                ],
                'fallback-filter': {
                    'geoip': True,
                    'geoip-code': 'CN',
                    'ipcidr': [
                        '240.0.0.0/4'
                    ]
                }
            },
            'geox-url': {
                'geoip': f'https://{domain}:20540/static/geo/geoip.dat',
                'geosite': f'https://{domain}:20540/static/geo/geosite.dat',
                'mmdb': f'https://{domain}:20540/static/geo/country.mmdb'
            },
            'proxies': all_proxies,
            'proxy-groups': proxy_groups,
            'rules': rules
        }

        return yaml.dump(clash_config, allow_unicode=True, sort_keys=False)

    # --- 2. v2rayN / Shadowrocket / 通用 Base64 订阅 ---
    @staticmethod
    def generate_v2ray_base64():
        raw_nodes = SubEngine.extract_nodes_from_db()
        transits = TransitManager.get_transits()
        rules_cfg = SubEngine.get_rules_config()

        links = []

        # 1. Direct Nodes
        for ntype, n in raw_nodes:
            if ntype == 'reality':
                name = urllib.parse.quote('VPS (Reality)')
                pbk = n['reality-opts']['public-key']
                sid = n['reality-opts']['short-id']
                sni = n['servername']
                fp = n['client-fingerprint']
                flow = n['flow']
                link = f"vless://{n['uuid']}@{n['server']}:{n['port']}?type=tcp&security=reality&pbk={pbk}&fp={fp}&sni={sni}&sid={sid}&flow={flow}#{name}"
                links.append(link)

            elif ntype == 'hy2':
                hop = rules_cfg.get('hy2_hop', False)
                name = urllib.parse.quote('VPS-Hy2 (端口跳跃)' if hop else 'VPS-Hy2')
                mport_param = "&mport=20000-40000" if hop else ""
                link = f"hysteria2://{n['password']}@{n['server']}:{n['port']}?sni={n['sni']}&insecure=0{mport_param}#{name}"
                links.append(link)

            elif ntype == 'trojan':
                name = urllib.parse.quote('VPS-Trojan (TLS)')
                link = f"trojan://{n['password']}@{n['server']}:{n['port']}?security=tls&sni={n['sni']}&type=tcp#{name}"
                links.append(link)

        # 2. Transit Nodes
        for t in transits:
            if not t.get('enabled', True):
                continue
            t_name = t.get('name', '中转')
            t_host = t.get('host', '')
            if not t_host:
                continue

            for ntype, n in raw_nodes:
                if ntype == 'reality':
                    name = urllib.parse.quote(f"[{t_name}] Reality专线")
                    pbk = n['reality-opts']['public-key']
                    sid = n['reality-opts']['short-id']
                    sni = n['servername']
                    fp = n['client-fingerprint']
                    flow = n['flow']
                    port = t.get('reality_port', 28443)
                    link = f"vless://{n['uuid']}@{t_host}:{port}?type=tcp&security=reality&pbk={pbk}&fp={fp}&sni={sni}&sid={sid}&flow={flow}#{name}"
                    links.append(link)

                elif ntype == 'hy2':
                    name = urllib.parse.quote(f"[{t_name}] Hy2专线")
                    port = t.get('hy2_port', 20443)
                    link = f"hysteria2://{n['password']}@{t_host}:{port}?sni={n['sni']}&insecure=0#{name}"
                    links.append(link)

                elif ntype == 'trojan':
                    name = urllib.parse.quote(f"[{t_name}] Trojan专线")
                    port = t.get('trojan_port', 22083)
                    link = f"trojan://{n['password']}@{t_host}:{port}?security=tls&sni={n['sni']}&type=tcp#{name}"
                    links.append(link)

        # 3. Custom / External Standalone Nodes
        custom_nodes = CustomNodeManager.get_custom_nodes()
        for cn in custom_nodes:
            if not cn.get('enabled', True):
                continue
            link = CustomNodeManager.to_share_link(cn)
            if link:
                links.append(link)

        # 4. Multi-Node Sentinel Mesh Aggregated Proxies
        try:
            from mesh_mgr import MeshManager
            for mn in MeshManager.get_nodes():
                if not mn.get('enabled', True):
                    continue
                for mp in mn.get('proxy_nodes', []):
                    link = CustomNodeManager.to_share_link(mp)
                    if link and link not in links:
                        links.append(link)
        except Exception as e:
            logger.debug(f"Error aggregating mesh nodes for Base64: {e}")

        # 5. EdgeTunnel (EDT) Serverless Clean IP Nodes
        try:
            for en in SubEngine.extract_edt_nodes():
                link = SubEngine.edt_node_to_v2ray_link(en)
                if link and link not in links:
                    links.append(link)
        except Exception as e:
            logger.debug(f"Error aggregating edt nodes for Base64: {e}")

        joined_text = "\n".join(links) + "\n"
        return base64.b64encode(joined_text.encode('utf-8')).decode('utf-8')

    # --- 3. Sing-box JSON Generator ---
    @staticmethod
    def generate_singbox_json(rules_override=None):
        rules_cfg = rules_override or SubEngine.get_rules_config()
        raw_nodes = SubEngine.extract_nodes_from_db()
        transits = TransitManager.get_transits()

        native_outbounds = []
        native_tags = []

        # 1. Direct Nodes
        for ntype, n in raw_nodes:
            tag = n.get('tag') or _unique(f"Oracle-{ntype.title()}", native_tags)
            if ntype == 'reality':
                native_outbounds.append({
                    'type': 'vless',
                    'tag': tag,
                    'server': n['server'],
                    'server_port': n['port'],
                    'uuid': n['uuid'],
                    'flow': n['flow'],
                    'network': 'tcp',
                    'tls': {
                        'enabled': True,
                        'server_name': n['servername'],
                        'reality': {
                            'enabled': True,
                            'public_key': n['reality-opts']['public-key'],
                            'short_id': n['reality-opts']['short-id']
                        },
                        'utls': {
                            'enabled': True,
                            'fingerprint': 'chrome'
                        }
                    },
                    'packet_encoding': 'xudp'
                })
                native_tags.append(tag)

            elif ntype == 'hy2':
                native_outbounds.append({
                    'type': 'hysteria2',
                    'tag': tag,
                    'server': n['server'],
                    'server_port': n['port'],
                    'up_mbps': 100,
                    'down_mbps': 100,
                    'password': n['password'],
                    'tls': {
                        'enabled': True,
                        'server_name': n['sni']
                    }
                })
                native_tags.append(tag)

            elif ntype == 'trojan':
                native_outbounds.append({
                    'type': 'trojan',
                    'tag': tag,
                    'server': n['server'],
                    'server_port': n['port'],
                    'password': n['password'],
                    'tls': {
                        'enabled': True,
                        'server_name': n['sni']
                    }
                })
                native_tags.append(tag)

        # 2. Transit Nodes
        used_transit_tags = set(native_tags)
        for t in transits:
            if not t.get('enabled', True):
                continue
            t_name = t.get('name', 'Transit')
            t_host = t.get('host', '')
            if not t_host:
                continue

            for ntype, n in raw_nodes:
                base_t_tag = f"[{t_name}] {n.get('tag', ntype.title())} Relay"
                tag = _unique(base_t_tag, used_transit_tags)
                if ntype == 'reality':
                    native_outbounds.append({
                        'type': 'vless',
                        'tag': tag,
                        'server': t_host,
                        'server_port': t.get('reality_port', 28443),
                        'uuid': n['uuid'],
                        'flow': n['flow'],
                        'network': 'tcp',
                        'tls': {
                            'enabled': True,
                            'server_name': n['servername'],
                            'reality': {
                                'enabled': True,
                                'public_key': n['reality-opts']['public-key'],
                                'short_id': n['reality-opts']['short-id']
                            },
                            'utls': {'enabled': True, 'fingerprint': 'chrome'}
                        },
                        'packet_encoding': 'xudp'
                    })
                    native_tags.append(tag)
                elif ntype == 'hy2':
                    native_outbounds.append({
                        'type': 'hysteria2',
                        'tag': tag,
                        'server': t_host,
                        'server_port': t.get('hy2_port', 20443),
                        'up_mbps': 100,
                        'down_mbps': 100,
                        'password': n['password'],
                        'tls': {'enabled': True, 'server_name': n['sni']}
                    })
                    native_tags.append(tag)
                elif ntype == 'trojan':
                    native_outbounds.append({
                        'type': 'trojan',
                        'tag': tag,
                        'server': t_host,
                        'server_port': t.get('trojan_port', 22083),
                        'password': n['password'],
                        'tls': {'enabled': True, 'server_name': n['sni']}
                    })
                    native_tags.append(tag)

        # 3. Custom / External Standalone Nodes
        custom_nodes = CustomNodeManager.get_custom_nodes()
        for cn in custom_nodes:
            if not cn.get('enabled', True):
                continue
            sb_out = CustomNodeManager.to_singbox_outbound(cn)
            if sb_out:
                native_outbounds.append(sb_out)
                native_tags.append(sb_out['tag'])

        # 4. Multi-Node Sentinel Mesh Aggregated Proxies
        try:
            from mesh_mgr import MeshManager
            for mn in MeshManager.get_nodes():
                if not mn.get('enabled', True):
                    continue
                for mp in mn.get('proxy_nodes', []):
                    sb_out = CustomNodeManager.to_singbox_outbound(mp)
                    if sb_out and sb_out['tag'] not in native_tags:
                        native_outbounds.append(sb_out)
                        native_tags.append(sb_out['tag'])
        except Exception as e:
            logger.debug(f"Error aggregating mesh nodes for Sing-box: {e}")

        # 5. EdgeTunnel (EDT) Serverless Clean IP Nodes
        edt_outbounds = []
        edt_tags = []
        try:
            for en in SubEngine.extract_edt_nodes():
                sb_out = SubEngine.edt_node_to_singbox(en)
                if sb_out and sb_out['tag'] not in edt_tags:
                    edt_outbounds.append(sb_out)
                    edt_tags.append(sb_out['tag'])
        except Exception as e:
            logger.debug(f"Error aggregating edt nodes for Sing-box: {e}")

        if edt_tags:
            # Segregated Groups for Native VPS and EDT Edge Nodes
            head_groups = [
                {
                    'type': 'selector',
                    'tag': 'select',
                    'outbounds': ['native-select', 'edt-select', 'fallback', 'direct']
                },
                {
                    'type': 'selector',
                    'tag': 'native-select',
                    'outbounds': (['native-urltest'] if native_tags else []) + list(native_tags) + ['direct']
                },
                {
                    'type': 'urltest',
                    'tag': 'native-urltest',
                    'outbounds': list(native_tags) if native_tags else ['direct'],
                    'url': 'https://www.gstatic.com/generate_204',
                    'interval': '5m'
                },
                {
                    'type': 'selector',
                    'tag': 'edt-select',
                    'outbounds': ['edt-urltest'] + list(edt_tags)
                },
                {
                    'type': 'urltest',
                    'tag': 'edt-urltest',
                    'outbounds': list(edt_tags),
                    'url': 'https://www.gstatic.com/generate_204',
                    'interval': '5m'
                },
                {
                    'type': 'urltest',
                    'tag': 'fallback',
                    'outbounds': (list(native_tags) if native_tags else []) + list(edt_tags),
                    'url': 'https://www.gstatic.com/generate_204',
                    'interval': '3m'
                },
                {'type': 'direct', 'tag': 'direct'},
                {'type': 'block', 'tag': 'block'},
                {'type': 'dns', 'tag': 'dns-out'}
            ]
            all_outbounds = head_groups + native_outbounds + edt_outbounds
        else:
            if not native_tags:
                native_tags = ['direct']
            selector_outbounds = ['urltest'] + list(native_tags) + ['direct']
            head_groups = [
                {'type': 'selector', 'tag': 'select', 'outbounds': selector_outbounds},
                {'type': 'urltest', 'tag': 'urltest', 'outbounds': list(native_tags), 'url': 'https://www.gstatic.com/generate_204', 'interval': '5m'},
                {'type': 'direct', 'tag': 'direct'},
                {'type': 'block', 'tag': 'block'},
                {'type': 'dns', 'tag': 'dns-out'}
            ]
            all_outbounds = head_groups + native_outbounds

        route_rules = [
            {'ip_is_private': True, 'outbound': 'direct'}
        ]
        if rules_cfg.get('oracle_bypass', True):
            route_rules.append({
                'domain_suffix': ['oracle.com', 'oraclecloud.com', 'oracleiaas.com'],
                'outbound': 'direct'
            })
        else:
            route_rules.append({
                'domain_suffix': ['oracle.com', 'oraclecloud.com', 'oracleiaas.com'],
                'outbound': 'select'
            })
        if rules_cfg.get('adblock', True):
            route_rules.append({'geosite': 'category-ads-all', 'outbound': 'block'})
        if rules_cfg.get('ai_group', True):
            route_rules.append({'geosite': 'openai', 'outbound': 'select'})
        if rules_cfg.get('media_group', True):
            route_rules.append({'geosite': 'netflix', 'outbound': 'select'})
        if rules_cfg.get('direct_cn', True):
            route_rules.append({'geoip': 'cn', 'outbound': 'direct'})
            route_rules.append({'geosite': 'cn', 'outbound': 'direct'})

        singbox_config = {
            'dns': {
                'servers': [
                    {'tag': 'remote', 'address': 'https://1.1.1.1/dns-query', 'detour': 'select'},
                    {'tag': 'local', 'address': '223.5.5.5', 'detour': 'direct'}
                ],
                'rules': [
                    {'geosite': 'cn', 'server': 'local'},
                    {'geoip': 'cn', 'server': 'local'}
                ]
            },
            'inbounds': [
                {'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 2080}
            ],
            'outbounds': all_outbounds,
            'route': {
                'rules': route_rules,
                'auto_detect_interface': True
            }
        }

        return json.dumps(singbox_config, indent=2, ensure_ascii=False)

if __name__ == '__main__':
    print("V2Ray Base64 length:", len(SubEngine.generate_v2ray_base64()))
    print("Sing-box Outbounds:", len(json.loads(SubEngine.generate_singbox_json())['outbounds']))
