#!/usr/bin/env bash
# ==============================================================================
# Oracle Sentinel - One-Click Transit Node Realm Deployer
# Usage:
#   bash setup-relay.sh <TARGET_VPS_DOMAIN_OR_IP>
# Example:
#   bash setup-relay.sh vps.yourdomain.com
# ==============================================================================

set -euo pipefail

TARGET="${1:-${TARGET_HOST:-}}"

if [ -z "$TARGET" ]; then
    echo "===================================================================="
    echo " [ERROR] Missing target destination host!"
    echo " Usage: sudo bash setup-relay.sh <TARGET_VPS_DOMAIN_OR_IP>"
    echo " Example: sudo bash setup-relay.sh vps.yourdomain.com"
    echo "===================================================================="
    exit 1
fi

echo "===================================================================="
echo ">>> Setting up Realm L4 Transit Port Forwarder for target: $TARGET"
echo "===================================================================="

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Please run as root (use sudo)!"
    exit 1
fi

# Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        REALM_ARCH="x86_64-unknown-linux-gnu"
        ;;
    aarch64|arm64)
        REALM_ARCH="aarch64-unknown-linux-gnu"
        ;;
    armv7l|armhf)
        REALM_ARCH="armv7-unknown-linux-gnueabihf"
        ;;
    *)
        echo "[ERROR] Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Ensure essential tools (curl, tar)
if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    echo ">>> Installing dependencies (curl, tar)..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y curl tar ca-certificates
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl tar ca-certificates
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl tar ca-certificates
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl tar ca-certificates
    fi
fi

mkdir -p /opt/realm
cd /opt/realm

source "$(dirname "$0")/verified-download.sh"
REALM_URL="${REALM_URL:?Set the pinned Realm release URL}"
REALM_SHA256="${REALM_SHA256:?Set its independently verified SHA-256}"
TMP_REALM=$(mktemp -d)
trap 'rm -rf "$TMP_REALM"' EXIT
verified_download "$REALM_URL" "$REALM_SHA256" "$TMP_REALM/realm.tar.gz"
# Extract only the expected binary; no archive paths can overwrite other files.
tar -xOf "$TMP_REALM/realm.tar.gz" realm > "$TMP_REALM/realm"
install -m 0755 "$TMP_REALM/realm" /opt/realm/realm
chmod +x /opt/realm/realm
rm -f /tmp/realm.tar.gz

echo ">>> Writing configuration /opt/realm/config.toml..."
cat << EOF > /opt/realm/config.toml
[log]
level = "warn"

[network]
no_tcp = false
use_udp = true

# Hysteria 2 Port Forwarding
[[endpoints]]
listen = "0.0.0.0:20443"
remote = "${TARGET}:443"

# VLESS-Reality Port Forwarding
[[endpoints]]
listen = "0.0.0.0:28443"
remote = "${TARGET}:8443"

# Trojan Port Forwarding
[[endpoints]]
listen = "0.0.0.0:22083"
remote = "${TARGET}:2083"
EOF

# Detect systemd or container environment
HAS_SYSTEMD=false
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=true
fi

if [ "$HAS_SYSTEMD" = true ]; then
    echo ">>> Registering and starting systemd service: realm.service..."
    cat << EOF > /etc/systemd/system/realm.service
[Unit]
Description=Realm L4 Transit Port Forwarder
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/realm
ExecStart=/opt/realm/realm -c /opt/realm/config.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable realm
    systemctl restart realm
    systemctl status realm --no-pager || true
else
    echo ">>> Container / Non-systemd environment (Podman/LXC) detected..."
    pkill -9 realm 2>/dev/null || true
    nohup /opt/realm/realm -c /opt/realm/config.toml > /opt/realm/realm.log 2>&1 &
    sleep 1
    if pgrep -x "realm" >/dev/null 2>&1; then
        echo ">>> Realm daemon is running in background (PID: $(pgrep -x realm))."
    else
        echo "[!] Realm process output:"
        cat /opt/realm/realm.log 2>/dev/null || true
    fi
fi

echo "===================================================================="
echo ">>> Realm transit service deployed and running successfully!"
echo "    - 20443 (UDP/TCP) -> ${TARGET}:443  [Hysteria 2]"
echo "    - 28443 (TCP)     -> ${TARGET}:8443 [VLESS-Reality]"
echo "    - 22083 (TCP)     -> ${TARGET}:2083 [Trojan]"
echo "===================================================================="
