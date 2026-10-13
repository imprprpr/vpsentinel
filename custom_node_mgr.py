from secure_files import transactional
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import time
import logging
import urllib.parse
import base64
from sentinel_core import ConfigManager

logger = logging.getLogger('CustomNodeManager')

class CustomNodeManager:
    @staticmethod
    def get_custom_nodes():
        cfg = ConfigManager.load()
        return cfg.get('custom_nodes', [])

    @staticmethod
    @transactional
    def save_custom_nodes(nodes_list):
        cfg = ConfigManager.load()
        cfg['custom_nodes'] = nodes_list
        return ConfigManager.save(cfg)

    @staticmethod
    def parse_link(link: str) -> dict:
        """Parses vless://, hysteria2://, hy2://, trojan://, ss:// links into a structured dict."""
        link = link.strip()
        if not link:
            raise ValueError("Empty link")

        parsed = urllib.parse.urlparse(link)
        scheme = parsed.scheme.lower()
        tag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ''

        if scheme == 'vless':
            uuid = parsed.username or ''
            host = parsed.hostname or ''
            port = parsed.port or 443
            qs = urllib.parse.parse_qs(parsed.query)

            security = qs.get('security', ['none'])[0]
            flow = qs.get('flow', [''])[0]
            sni = qs.get('sni', qs.get('serverName', ['']))[0]
            pbk = qs.get('pbk', [''])[0]
            sid = qs.get('sid', [''])[0]
            fp = qs.get('fp', ['chrome'])[0]
            network = qs.get('type', ['tcp'])[0]

            node_data = {
                'type': 'vless',
                'name': tag or f'VLESS-{host}:{port}',
                'server': host,
                'port': int(port),
                'uuid': uuid,
                'network': network,
                'tls': security in ('tls', 'reality'),
                'udp': True,
                'flow': flow,
                'servername': sni,
                'client-fingerprint': fp,
                'raw_link': link
            }
            if security == 'reality':
                node_data['reality-opts'] = {
                    'public-key': pbk,
                    'short-id': sid
                }
            return node_data

        elif scheme in ('hysteria2', 'hy2'):
            password = parsed.username or (parsed.netloc.split('@')[0] if '@' in parsed.netloc else '')
            host = parsed.hostname or ''
            port = parsed.port or 443
            qs = urllib.parse.parse_qs(parsed.query)
            sni = qs.get('sni', [host])[0]
            insecure = qs.get('insecure', ['0'])[0] in ('1', 'true', 'True')
            ports = qs.get('mport', qs.get('ports', ['']))[0]

            node_data = {
                'type': 'hysteria2',
                'name': tag or f'Hy2-{host}:{port}',
                'server': host,
                'port': int(port),
                'password': password,
                'sni': sni,
                'skip-cert-verify': insecure,
                'raw_link': link
            }
            if ports:
                node_data['ports'] = ports
            return node_data

        elif scheme == 'trojan':
            password = parsed.username or ''
            host = parsed.hostname or ''
            port = parsed.port or 443
            qs = urllib.parse.parse_qs(parsed.query)
            sni = qs.get('sni', [host])[0]
            insecure = qs.get('allowInsecure', ['0'])[0] in ('1', 'true', 'True')

            return {
                'type': 'trojan',
                'name': tag or f'Trojan-{host}:{port}',
                'server': host,
                'port': int(port),
                'password': password,
                'sni': sni,
                'skip-cert-verify': insecure,
                'client-fingerprint': 'chrome',
                'udp': True,
                'raw_link': link
            }

        elif scheme == 'ss':
            if '@' in parsed.netloc:
                user_info = parsed.username or ''
                try:
                    padded = user_info + '=' * (-len(user_info) % 4)
                    decoded = base64.b64decode(padded).decode('utf-8')
                    if ':' in decoded:
                        method, password = decoded.split(':', 1)
                    else:
                        method, password = 'aes-128-gcm', decoded
                except Exception:
                    method, password = 'aes-128-gcm', user_info
                host = parsed.hostname or ''
                port = parsed.port or 8388
            else:
                raw_b64 = parsed.netloc
                padded = raw_b64 + '=' * (-len(raw_b64) % 4)
                decoded = base64.b64decode(padded).decode('utf-8')
                user_part, server_part = decoded.rsplit('@', 1)
                method, password = user_part.split(':', 1)
                host, port = server_part.rsplit(':', 1)

            return {
                'type': 'ss',
                'name': tag or f'SS-{host}:{port}',
                'server': host,
                'port': int(port),
                'cipher': method,
                'password': password,
                'udp': True,
                'raw_link': link
            }

        else:
            raise ValueError(f"Unsupported protocol scheme: {scheme}")

    @staticmethod
    @transactional
    def add_custom_node(node_input):
        """Accepts either a share link string or a dict."""
        if isinstance(node_input, str):
            node_data = CustomNodeManager.parse_link(node_input)
        elif isinstance(node_input, dict):
            if 'link' in node_input and node_input['link']:
                node_data = CustomNodeManager.parse_link(node_input['link'])
                if node_input.get('name'):
                    node_data['name'] = node_input['name']
            else:
                node_data = node_input.copy()
        else:
            raise ValueError("Invalid node input type")

        from validation import host, port
        node_data['server'] = host(node_data.get('server', ''))
        node_data['port'] = port(node_data.get('port', 443))
        if node_data.get('type') not in ('vless', 'hysteria2', 'trojan', 'ss', 'vmess'):
            raise ValueError('Unsupported node protocol')
        if node_data.get('type') in ('vless', 'vmess'):
            import uuid
            try: uuid.UUID(node_data.get('uuid', ''))
            except (ValueError, AttributeError): raise ValueError('Invalid node UUID')
        if len(str(node_data.get('name', ''))) > 256:
            raise ValueError('Node name exceeds 256 characters')
        if 'port' in node_data:
            try:
                p_val = int(node_data['port'])
                if not (1 <= p_val <= 65535):
                    raise ValueError(f"Invalid port: {node_data['port']}. Must be 1-65535.")
                node_data['port'] = p_val
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid node port: {e}")

        if 'id' not in node_data:
            node_data['id'] = f'cnode_{int(time.time() * 1000)}'
        if 'enabled' not in node_data:
            node_data['enabled'] = True
        node_data['created_at'] = time.strftime('%Y-%m-%d %H:%M:%S')

        nodes = CustomNodeManager.get_custom_nodes()
        nodes.append(node_data)
        CustomNodeManager.save_custom_nodes(nodes)
        return node_data

    @staticmethod
    @transactional
    def delete_custom_node(node_id):
        nodes = CustomNodeManager.get_custom_nodes()
        filtered = [n for n in nodes if n.get('id') != node_id]
        CustomNodeManager.save_custom_nodes(filtered)
        return True

    @staticmethod
    @transactional
    def toggle_custom_node(node_id, enabled):
        nodes = CustomNodeManager.get_custom_nodes()
        for n in nodes:
            if n.get('id') == node_id:
                n['enabled'] = enabled
                break
        CustomNodeManager.save_custom_nodes(nodes)
        return True

    @staticmethod
    def to_clash_proxy(node: dict) -> dict:
        """Converts a stored custom node dict into a Clash/Mihomo proxy object."""
        ntype = node.get('type')
        proxy = {
            'name': node.get('name', 'Custom-Node'),
            'type': ntype,
            'server': node.get('server', ''),
            'port': int(node.get('port', 443))
        }

        if ntype == 'vless':
            proxy['uuid'] = node.get('uuid', '')
            proxy['network'] = node.get('network', 'tcp')
            proxy['tls'] = node.get('tls', True)
            proxy['udp'] = node.get('udp', True)
            if node.get('flow'):
                proxy['flow'] = node.get('flow')
            if node.get('servername'):
                proxy['servername'] = node.get('servername')
            if node.get('client-fingerprint'):
                proxy['client-fingerprint'] = node.get('client-fingerprint')
            if 'reality-opts' in node:
                proxy['reality-opts'] = node['reality-opts']

        elif ntype == 'hysteria2':
            proxy['password'] = node.get('password', '')
            proxy['sni'] = node.get('sni', node.get('server', ''))
            proxy['skip-cert-verify'] = node.get('skip-cert-verify', True)
            if node.get('ports'):
                proxy['ports'] = node.get('ports')

        elif ntype == 'trojan':
            proxy['password'] = node.get('password', '')
            proxy['sni'] = node.get('sni', node.get('server', ''))
            proxy['skip-cert-verify'] = node.get('skip-cert-verify', True)
            proxy['udp'] = node.get('udp', True)
            if node.get('client-fingerprint'):
                proxy['client-fingerprint'] = node.get('client-fingerprint')

        elif ntype == 'ss':
            proxy['cipher'] = node.get('cipher', 'aes-128-gcm')
            proxy['password'] = node.get('password', '')
            proxy['udp'] = node.get('udp', True)

        return proxy

    @staticmethod
    def to_singbox_outbound(node: dict) -> dict:
        """Converts a stored custom node dict into a Sing-box outbound object."""
        ntype = node.get('type')
        tag = node.get('name', 'Custom-Node')
        server = node.get('server', '')
        port = int(node.get('port', 443))

        if ntype == 'vless':
            outbound = {
                'type': 'vless',
                'tag': tag,
                'server': server,
                'server_port': port,
                'uuid': node.get('uuid', ''),
                'network': node.get('network', 'tcp'),
                'packet_encoding': 'xudp'
            }
            if node.get('flow'):
                outbound['flow'] = node.get('flow')

            tls_cfg = {'enabled': node.get('tls', True)}
            if node.get('servername'):
                tls_cfg['server_name'] = node.get('servername')

            if 'reality-opts' in node:
                tls_cfg['reality'] = {
                    'enabled': True,
                    'public_key': node['reality-opts'].get('public-key', ''),
                    'short_id': node['reality-opts'].get('short-id', '')
                }
            if node.get('client-fingerprint'):
                tls_cfg['utls'] = {
                    'enabled': True,
                    'fingerprint': node.get('client-fingerprint', 'chrome')
                }
            outbound['tls'] = tls_cfg
            return outbound

        elif ntype == 'hysteria2':
            return {
                'type': 'hysteria2',
                'tag': tag,
                'server': server,
                'server_port': port,
                'up_mbps': 100,
                'down_mbps': 100,
                'password': node.get('password', ''),
                'tls': {
                    'enabled': True,
                    'server_name': node.get('sni', server),
                    'insecure': node.get('skip-cert-verify', True)
                }
            }

        elif ntype == 'trojan':
            return {
                'type': 'trojan',
                'tag': tag,
                'server': server,
                'server_port': port,
                'password': node.get('password', ''),
                'tls': {
                    'enabled': True,
                    'server_name': node.get('sni', server),
                    'insecure': node.get('skip-cert-verify', True)
                }
            }

        elif ntype == 'ss':
            return {
                'type': 'shadowsocks',
                'tag': tag,
                'server': server,
                'server_port': port,
                'method': node.get('cipher', 'aes-128-gcm'),
                'password': node.get('password', '')
            }

        return None

    @staticmethod
    def to_share_link(node: dict) -> str:
        """Returns standard share link (vless://, hysteria2://, trojan://, ss://)."""
        if node.get('raw_link'):
            return node['raw_link']

        ntype = node.get('type')
        name_quoted = urllib.parse.quote(node.get('name', 'Custom-Node'))
        server = node.get('server', '')
        port = node.get('port', 443)

        if ntype == 'vless':
            uuid = node.get('uuid', '')
            params = [('type', node.get('network', 'tcp'))]
            if 'reality-opts' in node:
                params.append(('security', 'reality'))
                params.append(('pbk', node['reality-opts'].get('public-key', '')))
                params.append(('sid', node['reality-opts'].get('short-id', '')))
            elif node.get('tls'):
                params.append(('security', 'tls'))

            if node.get('servername'):
                params.append(('sni', node.get('servername')))
            if node.get('client-fingerprint'):
                params.append(('fp', node.get('client-fingerprint')))
            if node.get('flow'):
                params.append(('flow', node.get('flow')))

            query_str = urllib.parse.urlencode(params)
            return f"vless://{uuid}@{server}:{port}?{query_str}#{name_quoted}"

        elif ntype == 'hysteria2':
            password = node.get('password', '')
            sni = node.get('sni', server)
            insecure = 1 if node.get('skip-cert-verify') else 0
            mport = f"&mport={node['ports']}" if node.get('ports') else ""
            return f"hysteria2://{password}@{server}:{port}?sni={sni}&insecure={insecure}{mport}#{name_quoted}"

        elif ntype == 'trojan':
            password = node.get('password', '')
            sni = node.get('sni', server)
            return f"trojan://{password}@{server}:{port}?security=tls&sni={sni}&type=tcp#{name_quoted}"

        elif ntype == 'ss':
            cipher = node.get('cipher', 'aes-128-gcm')
            pwd = node.get('password', '')
            raw_user = f"{cipher}:{pwd}"
            b64_user = base64.b64encode(raw_user.encode('utf-8')).decode('utf-8')
            return f"ss://{b64_user}@{server}:{port}#{name_quoted}"

        return ""
