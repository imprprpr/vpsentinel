from secure_files import transactional
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import time
import logging
from sentinel_core import ConfigManager

logger = logging.getLogger('TransitManager')

class TransitManager:
    @staticmethod
    def get_transits():
        cfg = ConfigManager.load()
        return cfg.get('transits', [])

    @staticmethod
    @transactional
    def save_transits(transits_list):
        cfg = ConfigManager.load()
        cfg['transits'] = transits_list
        return ConfigManager.save(cfg)

    @staticmethod
    @transactional
    def add_transit(name, host, hy2_port=20443, reality_port=28443, trojan_port=22083):
        for p, label in [(hy2_port, 'hy2_port'), (reality_port, 'reality_port'), (trojan_port, 'trojan_port')]:
            p_int = int(p)
            if not (1 <= p_int <= 65535):
                raise ValueError(f"Invalid port for {label}: {p}. Port must be between 1 and 65535.")

        from validation import host as validate_host, port as validate_port
        host = validate_host(host)
        hy2_port, reality_port, trojan_port = map(validate_port, (hy2_port, reality_port, trojan_port))
        transits = TransitManager.get_transits()
        item = {
            'id': f'transit_{int(time.time())}',
            'name': name.strip(),
            'host': host.strip(),
            'hy2_port': int(hy2_port),
            'reality_port': int(reality_port),
            'trojan_port': int(trojan_port),
            'enabled': True,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        transits.append(item)
        TransitManager.save_transits(transits)
        return item

    @staticmethod
    @transactional
    def delete_transit(transit_id):
        transits = TransitManager.get_transits()
        filtered = [t for t in transits if t.get('id') != transit_id]
        TransitManager.save_transits(filtered)
        return True

    @staticmethod
    @transactional
    def toggle_transit(transit_id, enabled):
        transits = TransitManager.get_transits()
        for t in transits:
            if t.get('id') == transit_id:
                t['enabled'] = enabled
                break
        TransitManager.save_transits(transits)
        return True

    @staticmethod
    def generate_realm_script(target_host='vps.example.com'):
        """Generates a 1-line realm installation & forwarding script for the transit server."""
        import re
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', target_host):
            raise ValueError('Invalid target host')
        return f"""#!/bin/bash
# One-click Transit Port Forwarder via Realm
set -e
TARGET="{target_host}"
echo ">>> Installing Realm port forwarder on transit server..."
mkdir -p /opt/realm
RURL="${{REALM_URL:?Set the pinned Realm release URL}}"
CHECKSUM="${{REALM_SHA256:?Set the independently verified SHA-256}}"
[[ "$RURL" == https://* && "$CHECKSUM" =~ ^[a-fA-F0-9]{{64}}$ ]] || exit 1
TMP_REALM=$(mktemp -d)
trap 'rm -rf "$TMP_REALM"' EXIT
curl --proto '=https' --proto-redir '=https' -fsSL "$RURL" -o "$TMP_REALM/realm.tar.gz"
printf '%s  %s\n' "$CHECKSUM" "$TMP_REALM/realm.tar.gz" | sha256sum --check --status
tar -xOf "$TMP_REALM/realm.tar.gz" realm > "$TMP_REALM/realm"
install -m 0755 "$TMP_REALM/realm" /opt/realm/realm

cat << RCFG > /opt/realm/config.toml
[log]
level = "warn"

[[endpoints]]
listen = "0.0.0.0:20443"
remote = "$TARGET:443"

[[endpoints]]
listen = "0.0.0.0:28443"
remote = "$TARGET:8443"

[[endpoints]]
listen = "0.0.0.0:22083"
remote = "$TARGET:2083"
RCFG

sed -i "s/\\$TARGET/$TARGET/g" /opt/realm/config.toml

cat << 'RSERVICE' > /etc/systemd/system/realm.service
[Unit]
Description=Realm Port Forwarder
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/realm/realm -c /opt/realm/config.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
RSERVICE

systemctl daemon-reload
systemctl enable realm
systemctl restart realm
echo ">>> Realm transit service started successfully!"
systemctl status realm --no-pager
"""

if __name__ == '__main__':
    print("TransitManager loaded.")
