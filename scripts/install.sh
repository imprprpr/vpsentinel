#!/usr/bin/env bash
# ==============================================================================
# VPSentinel - Universal Cloud VPS Installer & Deployment Wizard
# Supports: Ubuntu 20.04+, Debian 11+, RHEL/CentOS/AlmaLinux/Rocky 8+, Arch Linux
# ==============================================================================

set -euo pipefail
umask 077

if [ -d "/opt/oracle-sentinel" ] && [ ! -d "/opt/vpsentinel" ]; then
    echo ">>> 检测到旧版目录 /opt/oracle-sentinel，平滑迁移至 /opt/vpsentinel ..."
    mv /opt/oracle-sentinel /opt/vpsentinel
    ln -s /opt/vpsentinel /opt/oracle-sentinel
fi

INSTALL_DIR="/opt/vpsentinel"
REPO_URL="https://github.com/imprprpr/vpsentinel.git"
VPSENTINEL_REF="${VPSENTINEL_REF:-}"

echo "===================================================================="
echo "          Installing VPSentinel Control Center & Daemon             "
echo "===================================================================="

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script must be run as root (or with sudo)."
    exit 1
fi

# Detect Package Manager & Install System Dependencies
echo ">>> Detecting Linux distribution and package manager..."
if command -v apt-get >/dev/null 2>&1; then
    echo ">>> Detected Debian/Ubuntu ecosystem (apt-get)."
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv git curl openssl iptables
elif command -v dnf >/dev/null 2>&1; then
    echo ">>> Detected RHEL/Fedora/AlmaLinux/Rocky ecosystem (dnf)."
    dnf install -y python3 python3-pip git curl openssl iptables
elif command -v yum >/dev/null 2>&1; then
    echo ">>> Detected CentOS/RHEL legacy ecosystem (yum)."
    yum install -y python3 python3-pip git curl openssl iptables
elif command -v pacman >/dev/null 2>&1; then
    echo ">>> Detected Arch Linux ecosystem (pacman)."
    pacman -Sy --noconfirm python python-pip git curl openssl iptables
else
    echo "[!] Warning: Unknown package manager. Please ensure python3, pip, git, curl, and openssl are installed."
fi

# Ensure installation directory exists
mkdir -p "$INSTALL_DIR"

# If current directory is the source directory, copy files; otherwise clone
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$SCRIPT_DIR/app.py" ]; then
    echo ">>> Copying files from local source tree: $SCRIPT_DIR ..."
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        cp -ru "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    fi
else
    if [ ! -f "$INSTALL_DIR/app.py" ]; then
        echo ">>> Cloning repository from GitHub: $REPO_URL (ref: $VPSENTINEL_REF) ..."
        [[ "$VPSENTINEL_REF" =~ ^[a-f0-9]{40}$ ]] || { echo 'Remote installation requires VPSENTINEL_REF as a verified full commit SHA.' >&2; exit 1; }
        git clone --no-checkout "$REPO_URL" "$INSTALL_DIR"
        git -C "$INSTALL_DIR" checkout --detach "$VPSENTINEL_REF"
    fi
fi

cd "$INSTALL_DIR"
chmod +x "$INSTALL_DIR"/scripts/*.sh "$INSTALL_DIR"/scripts/*.py 2>/dev/null || true

# Setup Python Virtual Environment
echo ">>> Setting up Python virtual environment..."
if [ ! -d "$INSTALL_DIR/venv" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi

"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --require-hashes -r "$INSTALL_DIR/requirements.txt"

# Code remains root-owned; writable data has a separate service account.
getent passwd vpsentinel >/dev/null || useradd --system --home-dir /var/lib/vpsentinel --shell /usr/sbin/nologin vpsentinel
install -d -m 0700 -o vpsentinel -g vpsentinel /var/lib/vpsentinel
install -d -m 0700 -o vpsentinel -g vpsentinel /etc/vpsentinel/cert
if [ -f "$INSTALL_DIR/config.json" ] && [ ! -f /var/lib/vpsentinel/config.json ]; then
    install -m 0600 -o vpsentinel -g vpsentinel "$INSTALL_DIR/config.json" /var/lib/vpsentinel/config.json
fi
export VPSENTINEL_HOME=/var/lib/vpsentinel
export VPSENTINEL_CONFIG_PATH=/var/lib/vpsentinel/config.json
export VPSENTINEL_CERT_DIR=/etc/vpsentinel/cert
export VPSENTINEL_OCI_DIR=/var/lib/vpsentinel/oci
if [ -d /root/.oci ] && [ ! -d "$VPSENTINEL_OCI_DIR" ]; then
    cp -r /root/.oci "$VPSENTINEL_OCI_DIR"
    [ ! -f "$VPSENTINEL_OCI_DIR/config" ] || sed -i 's|/root/.oci/|/var/lib/vpsentinel/oci/|g' "$VPSENTINEL_OCI_DIR/config"
    chown -R vpsentinel:vpsentinel "$VPSENTINEL_OCI_DIR"
    chmod -R go-rwx "$VPSENTINEL_OCI_DIR"
fi
# Initialize config.json if not present
if [ ! -f "$VPSENTINEL_CONFIG_PATH" ]; then
    echo ">>> Creating initial config.json from template..."
    install -m 0600 -o vpsentinel -g vpsentinel "$INSTALL_DIR/config.example.json" "$VPSENTINEL_CONFIG_PATH"
fi

# Install systemd service
echo ">>> Installing systemd unit file..."
if [ -f "$INSTALL_DIR/systemd/vpsentinel.service" ]; then
    cp "$INSTALL_DIR/systemd/vpsentinel.service" /etc/systemd/system/vpsentinel.service
    ln -sf /etc/systemd/system/vpsentinel.service /etc/systemd/system/oracle-sentinel.service
    cp "$INSTALL_DIR/systemd/vpsentinel-control.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable vpsentinel-control vpsentinel
else
    cp "$INSTALL_DIR/systemd/oracle-sentinel.service" /etc/systemd/system/oracle-sentinel.service
    systemctl daemon-reload
    systemctl enable oracle-sentinel
fi

# Open default port on UFW or firewalld if active
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        echo ">>> Allowing port 20540 on UFW..."
        ufw allow 20540/tcp comment "VPSentinel Dashboard"
    fi
elif command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
        echo ">>> Allowing port 20540 on firewalld..."
        firewall-cmd --add-port=20540/tcp --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
fi

# Ensure firewall allows port 20540 and node ports (especially on Oracle Cloud)
if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport 20540 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 20540 -j ACCEPT
    iptables -C INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 8443 -j ACCEPT
    iptables -C INPUT -p udp --dport 20000:40000 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport 20000:40000 -j ACCEPT
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    fi
fi

# Ensure initial TLS certificate exists to prevent uvicorn crash loops (P1-5)
echo ">>> Checking TLS certificates..."
mkdir -p /etc/vpsentinel/cert /etc/oracle-sentinel
ln -sfn /etc/vpsentinel/cert /etc/oracle-sentinel/cert

if [ ! -f /etc/vpsentinel/cert/privkey.pem ] || [ ! -f /etc/vpsentinel/cert/fullchain.pem ]; then
    echo ">>> Generating initial self-signed TLS certificates..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/vpsentinel/cert/privkey.pem \
        -out /etc/vpsentinel/cert/fullchain.pem \
        -days 3650 \
        -subj '/CN=vpsentinel' >/dev/null 2>&1 || true
    chmod 600 /etc/vpsentinel/cert/privkey.pem 2>/dev/null || true
    chmod 644 /etc/vpsentinel/cert/fullchain.pem 2>/dev/null || true
    cp -n /etc/vpsentinel/cert/fullchain.pem /etc/vpsentinel/cert/cert.pem 2>/dev/null || true
fi

SERVER_IP=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || curl -s4 --max-time 3 https://icanhazip.com 2>/dev/null || echo "127.0.0.1")

echo "===================================================================="
echo "[OK] VPSentinel 安装文件准备完成，正在初始化访问凭据。"
echo "===================================================================="

# Retrieve or generate random initial admin password (P0-4: No plaintext initial_password on disk)
PYTHON_BIN="$INSTALL_DIR/venv/bin/python3"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi

INITIAL_PASS=$("$PYTHON_BIN" -c "
import sys, secrets
sys.path.insert(0, '$INSTALL_DIR')
try:
    from sentinel_core import ConfigManager
    from auth_mgr import AuthManager
    import os
    cfg = ConfigManager.load()
    if cfg.get('oci', {}).get('config_path', '').startswith('/root/.oci/'):
        cfg['oci']['config_path'] = '/var/lib/vpsentinel/oci/config'
    sec = cfg.setdefault('security', {})
    sec.pop('initial_password', None)
    if sec.get('admin_password_hash'):
        ConfigManager.save(cfg)
        print('[EXISTING]')
    else:
        raw_pass = secrets.token_urlsafe(16)
        sec['admin_password_hash'] = AuthManager.hash_password(raw_pass)
        sec['must_change_password'] = True
        sec.setdefault('session_secret', secrets.token_hex(32))
        sec.setdefault('sub_token', secrets.token_hex(16))
        sec.setdefault('mesh_token', secrets.token_hex(32))
        ConfigManager.save(cfg)
        print(raw_pass)
except Exception:
    print('[ERROR]')
" 2>/dev/null || echo "[ERROR]")

# Permissions and authentication are ready before the first web process starts.
chown vpsentinel:vpsentinel "$VPSENTINEL_CONFIG_PATH"
chown -R vpsentinel:vpsentinel /etc/vpsentinel/cert
chmod 0700 /etc/vpsentinel/cert
chown -R root:root "$INSTALL_DIR"
chmod -R go-w "$INSTALL_DIR"
# Allow subscription reads without granting the Web process write access to 3x-ui.
if [ -d /etc/x-ui ]; then
    if ! command -v setfacl >/dev/null; then
        if command -v apt-get >/dev/null; then apt-get install -y acl; fi
    fi
    command -v setfacl >/dev/null || { echo 'Install ACL utilities before enabling 3x-ui integration.' >&2; exit 1; }
    setfacl -m u:vpsentinel:rx /etc/x-ui
    setfacl -m d:u:vpsentinel:rX /etc/x-ui
    [ ! -f /etc/x-ui/x-ui.db ] || setfacl -m u:vpsentinel:r /etc/x-ui/x-ui.db
fi
systemctl restart vpsentinel-control
systemctl restart vpsentinel
systemctl is-active --quiet vpsentinel || { echo 'VPSentinel failed to start; inspect the service logs.' >&2; exit 1; }
echo "控制台访问信息："
echo "  访问地址: https://${SERVER_IP}:20540/sentinel"
echo "  初始账号: admin"
if [ "$INITIAL_PASS" = "[EXISTING]" ]; then
    echo "  管理员密码: [已设置，沿用现有密码]"
elif [ "$INITIAL_PASS" = "[ERROR]" ] || [ -z "$INITIAL_PASS" ]; then
    echo "  管理员密码: [生成异常，请进入向导设置或检查 config.json]"
else
    echo "  初始随机密码: ${INITIAL_PASS}"
    echo "  (请妥善保存此密码，首次登入后请立即在控制台中修改；为确保安全，明文密码不会写入配置文件)"
fi
echo "新手极简上手指南："
echo "  1. 复制上方链接在浏览器打开；"
echo "  2. 若 Chrome/Edge 提示'您的连接不是私密连接'，直接键盘盲打这几个字母即可跳过：thisisunsafe"
echo "  3. 网页将自动唤起向导，推荐选择【新手极速模式】，仅需 2 步即可直接生成可用订阅！"
echo "===================================================================="

# Check if running interactively in terminal and user wants CLI wizard
if [ -t 0 ]; then
    read -rp ">>> 是否在终端中启动 CLI 高级向导 (输入 n 可直接在网页端使用)？[y/N]: " RUN_WIZARD
    RUN_WIZARD=${RUN_WIZARD:-n}
    if [[ "$RUN_WIZARD" =~ ^[Yy]$ ]]; then
        python3 "$INSTALL_DIR/scripts/wizard.py"
        exit 0
    fi
fi

echo "提示：您可以随时通过浏览器控制台进行管理，或运行 sudo python3 $INSTALL_DIR/scripts/wizard.py"
echo "===================================================================="
