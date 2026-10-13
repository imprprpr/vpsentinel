#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Oracle Sentinel - Interactive CLI Deployment & Configuration Wizard
# Zero-dependency wizard using pure Python standard library.
# ==============================================================================

import os
os.umask(0o077)
import sys
import json
import time
import shutil
import urllib.request
import urllib.error
import subprocess
import re

# --- ANSI Colors & Formatting ---
C_RESET = '\033[0m'
C_BOLD = '\033[1m'
C_GREEN = '\033[32m'
C_BLUE = '\033[34m'
C_CYAN = '\033[36m'
C_YELLOW = '\033[33m'
C_RED = '\033[31m'
C_MAGENTA = '\033[35m'
C_BG_DARK = '\033[40m'

SENTINEL_DIR = "/opt/vpsentinel" if os.path.exists("/opt/vpsentinel") else (
    "/opt/oracle-sentinel" if os.path.exists("/opt/oracle-sentinel") else "/opt/vpsentinel"
)
from paths import get_config_path, CERT_DIR, OCI_DIR
CONFIG_FILE = get_config_path()
SERVICE_NAME = "vpsentinel"

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    clear_screen()
    banner = f"""
{C_CYAN}{C_BOLD}
  ██████╗ ██████╗  █████╗  ██████╗██╗     ███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ██║   ██║██████╔╝███████║██║     ██║     █████╗      ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ██║   ██║██╔══██╗██╔══██║██║     ██║     ██╔══╝      ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ╚██████╔╝██║  ██║██║  ██║╚██████╗███████╗███████╗    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{C_RESET}
{C_BOLD}   Universal Cloud Sentinel (全能云端自愈守卫) • 极简全自动化交互式部署向导 • v2.0.0{C_RESET}
{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}
"""
    print(banner)

def detect_cloud_info():
    dmi_str = ""
    for df in ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor', '/sys/class/dmi/id/chassis_asset_tag']:
        if os.path.exists(df):
            try:
                with open(df, 'r', encoding='utf-8', errors='ignore') as f:
                    dmi_str += f.read() + " "
            except Exception:
                pass
    if 'OracleCloud' in dmi_str:
        return "Oracle Cloud Infrastructure (OCI)"
    elif 'Amazon' in dmi_str or 'EC2' in dmi_str:
        return "AWS (Amazon EC2)"
    elif 'Alibaba' in dmi_str or 'Aliyun' in dmi_str:
        return "Alibaba Cloud (阿里云)"
    elif 'Tencent' in dmi_str:
        return "Tencent Cloud (腾讯云)"
    elif 'Hetzner' in dmi_str:
        return "Hetzner Cloud"
    elif 'DigitalOcean' in dmi_str:
        return "DigitalOcean"
    return "Generic Linux VPS / Dedicated Server"

def log_info(msg):
    print(f" {C_CYAN}[*]{C_RESET}  {msg}")

def log_success(msg):
    print(f" {C_GREEN}[+]{C_RESET}  {C_BOLD}{msg}{C_RESET}")

def log_warn(msg):
    print(f" {C_YELLOW}[!]{C_RESET}  {C_YELLOW}{msg}{C_RESET}")

def log_err(msg):
    print(f" {C_RED}[-]{C_RESET}  {C_RED}{msg}{C_RESET}")

def prompt(text, default=None, is_secret=False):
    suffix = f" [{C_YELLOW}{default}{C_RESET}]" if default is not None else ""
    prompt_str = f" {C_BOLD}{text}{suffix}:{C_RESET} "
    try:
        val = input(prompt_str).strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n [!] 用户取消操作，向导已退出。")
        sys.exit(0)
    if not val and default is not None:
        return default
    return val

def run_cmd(cmd, check=True):
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)
        return True, res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip()

def get_public_ip():
    providers = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com"
    ]
    for url in providers:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.68.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                ip = resp.read().decode('utf-8').strip()
                if ip and len(ip.split('.')) == 4:
                    return ip
        except Exception:
            continue
    return "127.0.0.1"

# --- STEP 1: Cloud Provider Mode ---
def step_cloud_provider_mode(detected_cloud):
    print(f"\n{C_MAGENTA}{C_BOLD}[步骤 1/7] 云平台适配与运行模式选择{C_RESET}")
    print(f"{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    log_info(f"系统智能探测到当前宿主机环境: {C_BOLD}{C_GREEN}{detected_cloud}{C_RESET}")
    
    default_choice = "1" if "Oracle" in detected_cloud else "2"
    print(f" {C_YELLOW}模式 1{C_RESET}: Oracle Cloud (甲骨文云) - 启用 OCI API 自动换 IP 与 Cloudflare 联动")
    print(f" {C_YELLOW}模式 2{C_RESET}: 通用 VPS (搬瓦工/RackNerd/Hetzner/腾讯云/阿里云等) - 连通性探针 + 阻断告警 + 订阅聚合")
    print(f" {C_YELLOW}模式 3{C_RESET}: 自定义 Hook 脚本模式 - 遭遇阻断时执行自定义 Shell 脚本调用云商 API 换 IP")
    
    choice = prompt("请选择运行模式 (1/2/3)", default_choice)
    if choice == "1":
        return "oracle", ""
    elif choice == "3":
        cmd = prompt("请输入触发换 IP 的自定义脚本或命令", "/usr/local/bin/change_ip.sh")
        return "hook", cmd
    else:
        log_info("已启用通用 VPS 模式：无需 OCI 凭据，将专注于国内连通性巡检、多渠道告警推送与多协议订阅聚合。")
        return "generic", ""

# --- STEP 2: Firewall & BBR ---
def step_firewall_and_bbr():
    print(f"\n{C_MAGENTA}{C_BOLD}[步骤 2/7] 底层防火墙放通、端口跳跃与 BBR 拥塞控制调优{C_RESET}")
    print(f"{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    print(" 许多云服务商（特别是甲骨文云）默认启用了严苛的 iptables DROP 规则，会导致外部端口无法连通。")
    ans = prompt("是否自动清理原生 iptables 阻断并开启 BBR？(y/n)", "y").lower()
    if ans == 'y':
        log_info("正在解除 iptables 阻断规则并放通入站流量...")
        run_cmd("iptables -P INPUT ACCEPT")
        run_cmd("iptables -P FORWARD ACCEPT")
        run_cmd("iptables -P OUTPUT ACCEPT")
        run_cmd("iptables -F")
        
        # 针对 Hysteria 2 自动配置端口跳跃 (20000-40000 -> 443)
        log_info("正在配置 Hysteria 2 端口跳跃转发规则 (UDP 20000:40000 -> 443)...")
        run_cmd("iptables -t nat -A PREROUTING -p udp --dport 20000:40000 -j REDIRECT --to-ports 443")
        
        # 保存 iptables
        if shutil.which("netfilter-persistent"):
            run_cmd("netfilter-persistent save")
        elif os.path.exists("/etc/iptables"):
            run_cmd("iptables-save > /etc/iptables/rules.v4")

        # 开启 BBR
        log_info("正在开启 Linux 原生 BBR 拥塞控制算法...")
        bbr_conf = "\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"
        with open("/etc/sysctl.conf", "a") as f:
            f.write(bbr_conf)
        run_cmd("sysctl -p")
        log_success("底层防火墙阻断已破除，端口跳跃已配置，BBR 加速已生效！")
    else:
        log_warn("已跳过防火墙与网络调优。")

# --- STEP 3: Provider Re-IP Configuration ---
def step_provider_config(provider_mode, hook_cmd):
    print(f"\n{C_MAGENTA}{C_BOLD}[步骤 3/7] 节点公网 IP 自愈变动凭据配置{C_RESET}")
    print(f"{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    if provider_mode == "oracle":
        return step_oci_config()
    elif provider_mode == "hook":
        log_success(f"已绑定自定义换 IP 触发命令: {hook_cmd}")
        return ""
    else:
        log_info("通用 VPS 模式：自动换 IP 功能由云服务商限制，阻断时将自动触发多渠道告警与 WARP 节点调度。")
        return ""

def step_oci_config():
    print(" OCI API 是实现“GFW 封锁后自动申请新公网 IP 并解绑旧 IP”的核心凭证。")
    print(f" {C_YELLOW}选项 1{C_RESET}: 自动生成全新的 RSA API 密钥对，并打印公钥供您在甲骨文后台粘贴 (推荐)")
    print(f" {C_YELLOW}选项 2{C_RESET}: 我已在 /root/.oci/config 配置好，直接检测并使用")
    print(f" {C_YELLOW}选项 3{C_RESET}: 暂不配置 (跳过 OCI 自愈功能，仅使用可视化订阅与监控)")
    
    choice = prompt("请选择配置方式 (1/2/3)", "1")

    if choice == "1":
        os.makedirs(OCI_DIR, exist_ok=True)
        key_path = os.path.join(OCI_DIR, "oci_api_key.pem")
        pub_path = os.path.join(OCI_DIR, "oci_api_key_public.pem")

        log_info("正在生成 2048 位标准 RSA API 私钥...")
        run_cmd(f"openssl genrsa -out {key_path} 2048")
        run_cmd(f"chmod 600 {key_path}")
        run_cmd(f"openssl rsa -pubout -in {key_path} -out {pub_path}")

        with open(pub_path, "r") as f:
            pub_content = f.read().strip()

        print(f"\n{C_GREEN}{C_BOLD}┌────────────────────── 请复制以下公钥内容 (包含 BEGIN/END) ──────────────────────┐{C_RESET}")
        print(f"{C_CYAN}{pub_content}{C_RESET}")
        print(f"{C_GREEN}{C_BOLD}└──────────────────────────────────────────────────────────────────────────────────┘{C_RESET}\n")

        print(" [*] 【甲骨文网页后台操作步骤】:")
        print(" 1. 登录 Oracle Cloud 控制台: https://cloud.oracle.com/")
        print(" 2. 点击右上角个人头像 -> 【用户设置 (User Settings)】 -> 左下方点击【API 密钥 (API Keys)】")
        print(" 3. 点击【添加 API 密钥 (Add API Key)】 -> 选择【粘贴公钥】 -> 粘贴上方公钥内容 -> 点击【添加】")
        print(" 4. 添加完成后，页面会弹出一个文本框，展示形如以下的配置内容：")
        print(f"{C_YELLOW}    [DEFAULT]\n    user=ocid1.user.oc1...\n    fingerprint=xx:xx:xx...\n    tenancy=ocid1.tenancy.oc1...\n    region=us-phoenix-1\n    key_file=<待填>{C_RESET}\n")

        print(f"请将甲骨文网页上弹出的完整配置文本直接粘贴在下方（可多行粘贴，输入空行后回车结束）：")
        lines = []
        while True:
            try:
                line = input()
                if not line.strip() and lines:
                    break
                if line.strip():
                    lines.append(line.strip())
            except EOFError:
                break
        
        raw_text = "\n".join(lines)
        if "user=" in raw_text and "tenancy=" in raw_text:
            # 替换 key_file 为生成的私钥路径
            new_lines = []
            for l in lines:
                if l.startswith("key_file="):
                    new_lines.append(f"key_file={key_path}")
                else:
                    new_lines.append(l)
            if not any(l.startswith("key_file=") for l in new_lines):
                new_lines.append(f"key_file={key_path}")
            
            oci_cfg_file = os.path.join(OCI_DIR, "config")
            with open(oci_cfg_file, "w") as f:
                f.write("\n".join(new_lines) + "\n")
            run_cmd(f"chmod 600 {oci_cfg_file}")
            log_success(f"OCI API 配置文件已成功保存至 {oci_cfg_file}！")
            return oci_cfg_file
        else:
            log_warn("未检测到标准 OCI 配置内容，已保存密钥，请稍后手动编辑 /root/.oci/config。")
            return os.path.join(OCI_DIR, "config")

    elif choice == "2":
        oci_cfg_file = os.path.join(OCI_DIR, "config")
        if os.path.exists(oci_cfg_file):
            log_success(f"检测到现有 OCI 配置文件: {oci_cfg_file}")
            return oci_cfg_file
        else:
            log_err(f"未找到 {oci_cfg_file}！将创建空白占位符。")
            return oci_cfg_file
    else:
        log_info("已跳过 OCI 自动化配置。")
        return ""

# --- STEP 4: Cloudflare API & Domain Verification ---
def step_cloudflare_config(current_ip):
    print(f"\n{C_MAGENTA}{C_BOLD}[步骤 4/7] Cloudflare 自动化 DNS 解析联动{C_RESET}")
    print(f"{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    print(" 当节点换 IP 后，Sentinel 将调用此 Token 自动将您的域名 A 记录秒级刷新至新 IP。")
    print(" Token 申请路径: Cloudflare Dash -> 个人资料 -> API 令牌 -> 创建令牌 -> 编辑区域 DNS 模板\n")

    while True:
        token = prompt("请输入 Cloudflare API Token (输入 s 跳过)", "").strip()
        if not token or token.lower() == 's':
            log_warn("已跳过 Cloudflare 联动设置。")
            return "", "", ""

        log_info("正在验证 Token 并检索名下域名 Zone...")
        req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/zones?status=active",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("success"):
                    zones = data.get("result", [])
                    if not zones:
                        log_warn("Token 验证有效，但在该账号下未找到任何处于 Active 状态的域名。")
                        zone_name = prompt("请手动输入 Zone 顶级域名 (如 example.com)")
                    else:
                        print(f"\n {C_GREEN}[+] Token 验证成功！检测到以下托管域名：{C_RESET}")
                        for idx, z in enumerate(zones, 1):
                            print(f"   [{C_CYAN}{idx}{C_RESET}] {z.get('name')}")
                        z_idx = prompt("请选择要绑定的域名序号", "1")
                        try:
                            zone_name = zones[int(z_idx) - 1].get('name')
                        except Exception:
                            zone_name = zones[0].get('name')
                        log_success(f"已选择主域名: {zone_name}")

                    record_name = prompt(f"请输入解析到本 VPS 的完整域名", f"vps.{zone_name}")
                    
                    # 尝试自动检测或创建 A 记录
                    log_info(f"正在同步创建/更新 Cloudflare A 记录: {record_name} -> {current_ip} ...")
                    return token, zone_name, record_name
                else:
                    log_err("Cloudflare 验证失败: " + str(data.get("errors")))
        except Exception as e:
            log_err(f"请求 Cloudflare API 出错: {e}")
        
        retry = prompt("Token 似乎无效或网络不通，是否重新输入？(y/n)", "y").lower()
        if retry != 'y':
            return "", "", ""

# --- STEP 5: SSL/TLS Certificate Provisioning ---
def step_ssl_cert(cf_token, domain):
    import re
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', domain):
        raise ValueError('Invalid domain')
    print(f"\n{C_MAGENTA}{C_BOLD}[步骤 5/7] SSL / TLS 证书自动签发 (DNS-01 零端口依赖){C_RESET}")
    print(f"{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    os.makedirs(CERT_DIR, exist_ok=True)
    priv_file = os.path.join(CERT_DIR, "privkey.pem")
    cert_file = os.path.join(CERT_DIR, "fullchain.pem")

    if os.path.exists(priv_file) and os.path.exists(cert_file):
        log_success(f"检测到已有证书存在于 {CERT_DIR}，无需重复申请。")
        return priv_file, cert_file

    if not cf_token or not domain:
        log_warn("未提供 Cloudflare 凭证，正在生成临时自签名证书以确保 HTTPS 仪表盘正常启动...")
        run_cmd(f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {priv_file} -out {cert_file} -subj '/CN=oracle-sentinel'")
        run_cmd(f"chmod 600 {priv_file}")
        log_success("自签名证书生成完毕！")
        return priv_file, cert_file

    ans = prompt(f"是否利用 acme.sh 通过 Cloudflare DNS-01 自动为 {domain} 申请正式 ECC 证书？(y/n)", "y").lower()
    if ans == 'y':
        log_info("正在安装/配置 acme.sh 零依赖证书自动化客户端...")
        if not shutil.which("acme.sh") and not os.path.exists("/root/.acme.sh/acme.sh"):
            raise RuntimeError('Install a verified acme.sh release before requesting certificates')
        
        acme_bin = "/root/.acme.sh/acme.sh" if os.path.exists("/root/.acme.sh/acme.sh") else "acme.sh"
        log_info(f"正在静默申请 {domain} ECC 证书 (全程无需占用 80/443 端口)...")
        os.environ["CF_Token"] = cf_token
        ok, out = run_cmd(f"{acme_bin} --issue --dns dns_cf -d {domain} --keylength ec-256 --force")
        if ok or os.path.exists(f"/root/.acme.sh/{domain}_ecc/{domain}.key"):
            run_cmd(f"{acme_bin} --install-cert -d {domain} --ecc --key-file {priv_file} --fullchain-file {cert_file}")
            log_success(f"证书已成功签发并自动挂载至 {CERT_DIR}！")
        else:
            log_warn("acme.sh 申请遇到延迟或失败，正在降级为自签名证书保证服务正常启动...")
            run_cmd(f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {priv_file} -out {cert_file} -subj '/CN={domain}'")
    else:
        run_cmd(f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {priv_file} -out {cert_file} -subj '/CN={domain}'")

    run_cmd(f"chmod 600 {priv_file}")
    return priv_file, cert_file

# --- STEP 6: 3x-ui Golden Inbounds Auto-Provisioning ---
def step_3x_ui_nodes(domain):
    import re
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', domain):
        raise ValueError('Invalid domain')
    print(f"\n{C_MAGENTA}{C_BOLD}[步骤 6/7] 3x-ui 节点全家桶自动入库与初始化{C_RESET}")
    print(f"{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    print(" 自动向 3x-ui 写入经过生产调优的『黄金三剑客』出海节点，装完免去任何面板手动配置：")
    print(f"  1. {C_GREEN}Oracle-US{C_RESET}     : VLESS-Reality (TCP :8443) 自动生成 X25519 密钥对")
    print(f"  2. {C_GREEN}Oracle-Hy2{C_RESET}    : Hysteria 2 (UDP :443 + 内核端口跳跃 20000:40000)")
    print(f"  3. {C_GREEN}Oracle-Trojan{C_RESET} : Trojan-TLS (TCP :2083)")

    script_path = os.path.join(SENTINEL_DIR, "scripts", "node_provisioner.py")
    if not os.path.exists(script_path):
        script_path = os.path.join(os.path.dirname(__file__), "node_provisioner.py")

    ans = prompt("是否自动注入上述三大黄金出海节点？(y/n)", "y").lower()
    if ans == 'y':
        try:
            # Try importing node_provisioner directly
            sys.path.insert(0, os.path.dirname(script_path))
            import node_provisioner
            added = node_provisioner.provision_nodes(domain=domain)
            if added:
                log_success(f"成功注入 {len(added)} 个黄金节点！服务已热重载生效。")
            else:
                log_info("节点对应端口已存在，已保持现有配置不覆盖。")
        except Exception as e:
            # Fallback to subprocess
            ok, out = run_cmd(f"python3 {script_path} {domain}")
            if ok:
                log_success("3x-ui 节点注入命令已成功执行！")
            else:
                log_warn(f"注入节点时遇到提示: {out}")
    else:
        log_info("已跳过节点自动预置，您可稍后在 3x-ui 面板手动创建入站。")

# --- STEP 7: Multi-Channel Alert Notifications ---
def step_notifications():
    print(f"\n{C_MAGENTA}{C_BOLD}[步骤 7/7] 多渠道阻断告警通知中枢配置{C_RESET}")
    print(f"{C_BLUE}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    print(" 当节点遭受 GFW 阻断、触发自愈或换 IP 成功时，Sentinel 将向管理员即时发送推送卡片。")
    print(" 支持渠道：Telegram Bot、Discord Webhook、Bark (iOS)、自定义 Webhook。")
    ans = prompt("是否配置告警通知渠道？(y/n)", "n").lower()
    
    notify_cfg = {
        "enabled": False,
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "discord": {"enabled": False, "webhook_url": ""},
        "bark": {"enabled": False, "bark_key": ""},
        "custom_webhook": {"enabled": False, "url": ""}
    }
    if ans != 'y':
        log_info("已跳过告警通知配置 (可稍后在 Web 控制台设置面板中随时配置)。")
        return notify_cfg

    notify_cfg["enabled"] = True
    # Telegram
    tg_ans = prompt("是否配置 Telegram Bot 通知？(y/n)", "n").lower()
    if tg_ans == 'y':
        tg_token = prompt("请输入 Telegram Bot Token (例如: 123456:ABC-DEF...)")
        tg_chat = prompt("请输入 Telegram Chat ID (个人或群组 ID)")
        if tg_token and tg_chat:
            notify_cfg["telegram"] = {"enabled": True, "bot_token": tg_token, "chat_id": tg_chat}
            log_success("Telegram 通知已配置！")

    # Discord
    dc_ans = prompt("是否配置 Discord Webhook 通知？(y/n)", "n").lower()
    if dc_ans == 'y':
        dc_url = prompt("请输入 Discord Webhook 完整 URL")
        if dc_url:
            notify_cfg["discord"] = {"enabled": True, "webhook_url": dc_url}
            log_success("Discord Webhook 通知已配置！")

    # Bark
    bark_ans = prompt("是否配置 Bark (iOS 手机推送)？(y/n)", "n").lower()
    if bark_ans == 'y':
        b_key = prompt("请输入 Bark 设备 Key")
        if b_key:
            notify_cfg["bark"] = {"enabled": True, "bark_key": b_key}
            log_success("Bark 通知已配置！")

    return notify_cfg

# --- Finalize Configuration & Systemd ---
def finalize_setup(provider_type, hook_cmd, cf_token, zone_name, record_name, oci_path, notify_cfg):
    log_info(f"正在写入生产环境 {CONFIG_FILE} ...")
    cfg = {
        "provider": {
            "type": provider_type,
            "hook_cmd": hook_cmd
        },
        "cloudflare": {
            "api_token": cf_token,
            "zone_name": zone_name,
            "record_name": record_name
        },
        "oci": {
            "auth_method": "config_file" if oci_path else "none",
            "config_path": oci_path if oci_path else "/root/.oci/config"
        },
        "monitor": {
            "interval_sec": 15,
            "loss_threshold": 75.0,
            "consecutive_failures": 3,
            "auto_heal_enabled": False,
            "auto_heal_mode": "notify_only",
            "reip_cooldown_hours": 24,
            "max_reip_per_day": 2,
            "last_reip_timestamp": 0
        },
        "notifications": notify_cfg,
        "rules_config": {
            "adblock": True,
            "ai_group": True,
            "media_group": True,
            "auto_test": True,
            "direct_cn": True,
            "hy2_hop": False
        },
        "transits": []
    }
    os.makedirs(SENTINEL_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    run_cmd(f"chmod 600 {CONFIG_FILE}")

    log_info(f"正在重载并重启 {SERVICE_NAME} 系统守护进程...")
    run_cmd("systemctl daemon-reload")
    run_cmd(f"systemctl enable {SERVICE_NAME}")
    run_cmd(f"systemctl restart {SERVICE_NAME}")

def main():
    if os.geteuid() != 0:
        print(f"\n {C_RED}[!] 请使用 root 权限运行此向导 (例如: sudo python3 {sys.argv[0]}){C_RESET}\n")
        sys.exit(1)

    print_banner()
    detected_cloud = detect_cloud_info()
    pub_ip = get_public_ip()
    log_info(f"当前 VPS 公网 IPv4: {C_BOLD}{pub_ip}{C_RESET}")

    # Step 1: Provider Mode
    provider_type, hook_cmd = step_cloud_provider_mode(detected_cloud)

    # Step 2: Firewall & BBR
    step_firewall_and_bbr()

    # Step 3: Provider / OCI
    oci_path = step_provider_config(provider_type, hook_cmd)

    # Step 4: Cloudflare
    cf_token, zone_name, record_name = step_cloudflare_config(pub_ip)

    # Step 5: SSL Cert
    step_ssl_cert(cf_token, record_name or "vps.example.com")

    # Step 6: 3x-ui Golden Inbounds Auto-Provisioning
    step_3x_ui_nodes(record_name or "vps.example.com")

    # Step 7: Notifications
    notify_cfg = step_notifications()

    # Finalize
    finalize_setup(provider_type, hook_cmd, cf_token, zone_name, record_name, oci_path, notify_cfg)

    # Success Card
    access_host = record_name if record_name else pub_ip
    print(f"""
{C_GREEN}{C_BOLD}
════════════════════════════════════════════════════════════════════════════════════════
 [SUCCESS] Universal Cloud Sentinel 全能云端自愈守卫已部署并成功运行！
════════════════════════════════════════════════════════════════════════════════════════
{C_RESET}
  {C_BOLD}控制中心 Web 访问地址{C_RESET}:
    [+] {C_CYAN}{C_BOLD}https://{access_host}:20540/{C_RESET}

  {C_BOLD}多协议订阅直连端点{C_RESET}:
    • Clash / OpenClash: {C_YELLOW}https://{access_host}:20540/sub/clash{C_RESET}
    • v2rayN / v2rayNG:  {C_YELLOW}https://{access_host}:20540/sub/v2ray{C_RESET}
    • Sing-box (1.8+):   {C_YELLOW}https://{access_host}:20540/sub/singbox{C_RESET}
    • Shadowrocket:      {C_YELLOW}https://{access_host}:20540/sub/shadowrocket{C_RESET}

  {C_BOLD}核心自愈与监控状态{C_RESET}:
    • 当前宿主环境: {C_CYAN}{detected_cloud}{C_RESET}
    • 连续阻断阈值: {C_BOLD}丢包率 > 75% 且 连续 3 次探测失败{C_RESET}
    • 自动自愈联动: {C_GREEN}{'已启用' if (cf_token and (oci_path or hook_cmd)) else '已开启巡检与告警'}{C_RESET}

  {C_BOLD}常用运维指令{C_RESET}:
    • 守护进程实时日志: {C_CYAN}journalctl -u {SERVICE_NAME} -f{C_RESET}
    • 重启守护进程:     {C_CYAN}systemctl restart {SERVICE_NAME}{C_RESET}
    • 重新运行此向导:   {C_CYAN}python3 {SENTINEL_DIR}/scripts/wizard.py{C_RESET}
────────────────────────────────────────────────────────────────────────────────────────
""")

if __name__ == "__main__":
    main()
