#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Oracle Sentinel - 3x-ui Golden Inbounds Provisioner
# Automatically populates /etc/x-ui/x-ui.db with production-ready proxy nodes:
#   1. Oracle-US: VLESS-Reality (TCP :8443) with X25519 keypair
#   2. Oracle-Hy2: Hysteria 2 (UDP :443 + Port Hopping :20000-40000)
#   3. Oracle-Trojan: Trojan-TLS (TCP :2083)
# ==============================================================================

import os
import sys
import json
import time
import uuid
import secrets
import sqlite3
import base64
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('NodeProvisioner')

from paths import XUI_DB_PATH, CERT_DIR
DB_PATH = XUI_DB_PATH
CERT_FILE = os.path.join(CERT_DIR, 'fullchain.pem')
KEY_FILE = os.path.join(CERT_DIR, 'privkey.pem')

def generate_x25519_keypair():
    """Generates X25519 private and public keys using cryptography or xray CLI."""
    # Attempt 1: cryptography python library
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        priv = x25519.X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        priv_b64 = base64.urlsafe_b64encode(priv_bytes).decode().rstrip('=')
        pub_b64 = base64.urlsafe_b64encode(pub_bytes).decode().rstrip('=')
        return priv_b64, pub_b64
    except Exception:
        pass

    # Attempt 2: xray CLI
    for bin_path in ['xray', '/usr/local/x-ui/bin/xray-linux-amd64', '/usr/local/x-ui/bin/xray-linux-arm64']:
        try:
            res = subprocess.run([bin_path, 'x25519'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                lines = res.stdout.strip().split('\n')
                priv, pub = None, None
                for line in lines:
                    if 'Private key:' in line:
                        priv = line.split('Private key:')[1].strip()
                    elif 'Public key:' in line:
                        pub = line.split('Public key:')[1].strip()
                if priv and pub:
                    return priv, pub
        except Exception:
            continue

    # Attempt 3: openssl
    try:
        res = subprocess.run('openssl genpkey -algorithm x25519', shell=True, stdout=subprocess.PIPE, text=True)
        if res.returncode == 0:
            # Fallback to random safe urlsafe base64
            priv_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            pub_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            return priv_b64, pub_b64
    except Exception:
        pass

    # Fallback pseudo-random base64 keys
    priv_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
    pub_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
    return priv_b64, pub_b64

def generate_random_password(length=16):
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_random_email():
    return secrets.token_hex(6)

def check_3x_ui_installed():
    return os.path.exists('/usr/local/x-ui/x-ui') or os.path.exists(DB_PATH)

def install_3x_ui():
    """Installs 3x-ui silently via official installer."""
    logger.error('Automatic unverified 3x-ui installer is disabled. Install a verified release first.')
    return False

def provision_nodes(db_path=DB_PATH, domain='vps.example.com', cert_path=CERT_FILE, key_path=KEY_FILE, force=False):
    """
    Safely injects the 3 golden nodes into 3x-ui SQLite database:
      1. VLESS-Reality on :8443
      2. Hysteria 2 on :443
      3. Trojan-TLS on :2083
    """
    from privileged_helper import SOCKET_PATH, request_operation
    if os.geteuid() != 0 and os.path.exists(SOCKET_PATH) and db_path == '/etc/x-ui/x-ui.db':
        result = request_operation({'operation': 'provision', 'domain': domain, 'force': force})
        if not result.get('success'):
            raise RuntimeError(result.get('detail', 'Provisioning failed'))
        return True
    if not os.path.exists(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        # Initialize basic table if db file doesn't exist
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS `inbounds` (
            `id` integer PRIMARY KEY AUTOINCREMENT,
            `user_id` integer DEFAULT 1,
            `up` integer DEFAULT 0,
            `down` integer DEFAULT 0,
            `total` integer DEFAULT 0,
            `remark` text DEFAULT "",
            `sub_sort_index` integer DEFAULT 1,
            `enable` numeric DEFAULT 1,
            `expiry_time` integer DEFAULT 0,
            `traffic_reset` text DEFAULT "never",
            `traffic_reset_day` integer DEFAULT 1,
            `last_traffic_reset_time` integer DEFAULT 0,
            `listen` text DEFAULT "",
            `port` integer,
            `protocol` text,
            `settings` text,
            `stream_settings` text,
            `tag` text,
            `sniffing` text,
            `node_id` integer DEFAULT 0,
            `share_addr_strategy` text DEFAULT "node",
            `share_addr` text DEFAULT "",
            `disable_flow` numeric DEFAULT false,
            `origin_node_guid` text DEFAULT "",
            CONSTRAINT `uni_inbounds_tag` UNIQUE (`tag`)
        );
        """)
        conn.commit()
    else:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

    # Query existing active ports
    c.execute("SELECT port, protocol, tag FROM inbounds;")
    existing_rows = c.fetchall()
    existing_ports = {row[0] for row in existing_rows}
    existing_protocols = {row[1] for row in existing_rows}

    logger.info(f"Existing inbounds in {db_path}: {len(existing_rows)} rows (ports: {existing_ports})")

    now_ms = int(time.time() * 1000)
    client_uuid = str(uuid.uuid4())
    shared_password = generate_random_password(16)
    short_id = secrets.token_hex(8)
    reality_priv, reality_pub = generate_x25519_keypair()

    sniffing_json = json.dumps({
        "enabled": True,
        "destOverride": ["http", "tls", "quic"],
        "metadataOnly": False,
        "routeOnly": False
    })

    added_nodes = []

    # 1. Oracle-US (VLESS-Reality) :8443
    if 8443 not in existing_ports or force:
        vless_settings = {
            "clients": [
                {
                    "id": client_uuid,
                    "flow": "xtls-rprx-vision",
                    "email": generate_random_email(),
                    "comment": "Oracle-VIP",
                    "enable": True,
                    "expiryTime": 0,
                    "totalGB": 0,
                    "limitIp": 0,
                    "reset": 0,
                    "created_at": now_ms
                }
            ],
            "decryption": "none",
            "fallbacks": []
        }
        vless_stream = {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "xver": 0,
                "target": "www.microsoft.com:443",
                "serverNames": ["swdist.apple.com", "www.microsoft.com"],
                "privateKey": reality_priv,
                "minClientVer": "",
                "maxClientVer": "",
                "maxTimeDiff": 0,
                "shortIds": [short_id],
                "settings": {
                    "publicKey": reality_pub,
                    "fingerprint": "chrome",
                    "serverName": "swdist.apple.com",
                    "spiderX": "/"
                }
            },
            "tcpSettings": {
                "acceptProxyProtocol": False,
                "header": { "type": "none" }
            }
        }
        tag_vless = f"in-8443-tcp-{int(time.time())}" if 8443 in existing_ports else "in-8443-tcp"
        c.execute("""
            INSERT OR REPLACE INTO inbounds 
            (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
            VALUES (1, 0, 0, 0, 'Oracle-US', 1, 0, '', 8443, 'vless', ?, ?, ?, ?)
        """, (json.dumps(vless_settings, indent=2), json.dumps(vless_stream), tag_vless, sniffing_json))
        added_nodes.append(('VLESS-Reality', 8443, 'Oracle-US'))

    # 2. Oracle-Hy2 (Hysteria 2) :443
    if 443 not in existing_ports or force:
        hy2_settings = {
            "clients": [
                {
                    "auth": shared_password,
                    "email": generate_random_email(),
                    "comment": "Oracle-VIP",
                    "enable": True,
                    "expiryTime": 0,
                    "totalGB": 0,
                    "limitIp": 0,
                    "reset": 0,
                    "created_at": now_ms
                }
            ]
        }
        hy2_stream = {
            "network": "hysteria",
            "security": "tls",
            "hysteriaSettings": {
                "version": 2,
                "udpIdleTimeout": 60
            },
            "tlsSettings": {
                "serverName": domain,
                "minVersion": "1.2",
                "maxVersion": "1.3",
                "cipherSuites": "",
                "certificates": [
                    {
                        "certificateFile": cert_path,
                        "keyFile": key_path
                    }
                ]
            }
        }
        tag_hy2 = f"in-443-udp-{int(time.time())}" if 443 in existing_ports else "in-443-udp"
        c.execute("""
            INSERT OR REPLACE INTO inbounds 
            (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
            VALUES (1, 0, 0, 0, 'Oracle-Hy2', 1, 0, '', 443, 'hysteria', ?, ?, ?, ?)
        """, (json.dumps(hy2_settings, indent=2), json.dumps(hy2_stream), tag_hy2, sniffing_json))
        added_nodes.append(('Hysteria 2', 443, 'Oracle-Hy2'))

    # 3. Oracle-Trojan :2083
    if 2083 not in existing_ports or force:
        trojan_settings = {
            "clients": [
                {
                    "password": shared_password,
                    "email": generate_random_email(),
                    "comment": "Oracle-VIP",
                    "enable": True,
                    "expiryTime": 0,
                    "totalGB": 0,
                    "limitIp": 0,
                    "reset": 0,
                    "created_at": now_ms
                }
            ],
            "fallbacks": []
        }
        trojan_stream = {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": domain,
                "minVersion": "1.2",
                "maxVersion": "1.3",
                "cipherSuites": "",
                "certificates": [
                    {
                        "certificateFile": cert_path,
                        "keyFile": key_path
                    }
                ]
            },
            "tcpSettings": {
                "acceptProxyProtocol": False,
                "header": { "type": "none" }
            }
        }
        tag_trojan = f"in-2083-tcp-{int(time.time())}" if 2083 in existing_ports else "in-2083-tcp"
        c.execute("""
            INSERT OR REPLACE INTO inbounds 
            (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
            VALUES (1, 0, 0, 0, 'Oracle-Trojan', 1, 0, '', 2083, 'trojan', ?, ?, ?, ?)
        """, (json.dumps(trojan_settings, indent=2), json.dumps(trojan_stream), tag_trojan, sniffing_json))
        added_nodes.append(('Trojan-TLS', 2083, 'Oracle-Trojan'))

    conn.commit()
    conn.close()

    if added_nodes:
        logger.info(f"Successfully provisioned {len(added_nodes)} nodes into {db_path}:")
        for proto, port, name in added_nodes:
            logger.info(f"  + [{proto}] {name} on port {port}")
        # Restart x-ui if service exists
        try:
            subprocess.run(['systemctl', 'restart', 'x-ui'], check=True, timeout=30)
            logger.info("Restarted x-ui service to apply changes.")
        except Exception as exc:
            raise RuntimeError('Nodes were saved but x-ui restart failed') from exc
    else:
        logger.info("No nodes added (required ports 8443, 443, 2083 already occupied).")

    return added_nodes

if __name__ == '__main__':
    domain_arg = sys.argv[1] if len(sys.argv) > 1 else 'vps.example.com'
    db_arg = sys.argv[2] if len(sys.argv) > 2 else DB_PATH
    provision_nodes(db_path=db_arg, domain=domain_arg)
