from net_policy import open_secure, read_limited
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# VPSentinel - Interactive Telegram & Discord Bot Manager
# ==============================================================================

import os
import time
import json
import logging
import threading
import urllib.request
import urllib.parse
import urllib.error

logger = logging.getLogger('BotManager')

from paths import CONFIG_PATH

class TelegramInteractiveBot:
    def __init__(self, get_state_func=None, get_config_func=None, run_healing_func=None):
        self.get_state_func = get_state_func
        self.get_config_func = get_config_func
        self.run_healing_func = run_healing_func
        self._loop = None
        self._running = False
        self._thread = None
        self._last_update_id = 0
        self._last_active_time = 0
        self._command_count = 0

    def get_bot_credentials(self):
        try:
            cfg = self.get_config_func() if callable(self.get_config_func) else {}
            tg_cfg = cfg.get('notifications', {}).get('telegram', {})
            bot_token = tg_cfg.get('bot_token', '').strip()
            chat_id = str(tg_cfg.get('chat_id', '')).strip()
            bot_enabled = bool(tg_cfg.get('bot_enabled', False) and bot_token and chat_id)
            return bot_token, chat_id, bot_enabled
        except Exception as e:
            logger.error(f'Error reading telegram credentials: {e}')
            return '', '', False

    def send_message(self, bot_token, chat_id, text, reply_markup=None):
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup

        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with open_secure(req, timeout=10) as resp:
                return json.loads(read_limited(resp).decode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending TG message: {e}")
            return None

    def answer_callback(self, bot_token, callback_id, text=""):
        url = f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery"
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with open_secure(req, timeout=8) as resp:
                return True
        except Exception:
            return False

    def get_main_keyboard(self):
        return {
            "inline_keyboard": [
                [
                    {"text": "运行状态", "callback_data": "cmd_status"},
                    {"text": "集群概览", "callback_data": "cmd_mesh"}
                ],
                [
                    {"text": "三网测速", "callback_data": "cmd_speedtest"},
                    {"text": "订阅导出", "callback_data": "cmd_sub"}
                ],
                [
                    {"text": "触发换 IP", "callback_data": "cmd_reip_confirm"}
                ]
            ]
        }

    def handle_status_command(self, bot_token, chat_id):
        try:
            import traffic_mgr
            t_stats = traffic_mgr.TrafficManager.get_traffic_stats()
            t_month = t_stats.get('month', {})
            t_today = t_stats.get('today', {})
        except Exception:
            t_month = {}
            t_today = {}

        state = self.get_state_func() if callable(self.get_state_func) else {}
        metrics = state.get('metrics', {})
        cloud = state.get('cloud', {})
        probes = state.get('probes', {})
        warp = state.get('warp', {})
        pub_ip = state.get('public_ip', '127.0.0.1')

        msg = (
            f"<b>VPSentinel 实例监控概览</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"<b>公网 IP:</b> <code>{pub_ip}</code>\n"
            f"<b>所属区域:</b> {cloud.get('region', 'Oracle Phoenix')} ({cloud.get('ad', 'AD-1')})\n"
            f"<b>系统负载:</b> CPU: {metrics.get('cpu_pct', 0)}% | 内存: {metrics.get('mem_pct', 0)}%\n"
            f"<b>网络速率:</b> ↓ {metrics.get('rx_speed_kb', 0)} KB/s | ↑ {metrics.get('tx_speed_kb', 0)} KB/s\n"
            f"<b>国内探针:</b> 丢包率: {probes.get('loss_pct', 0)}% | RTT: {probes.get('avg_rtt_ms', 0)} ms\n"
            f"<b>WARP 双栈:</b> {'已启用 (' + warp.get('ip', 'N/A') + ')' if warp.get('active') else '未启用'}\n"
            f"<b>运行时间:</b> {metrics.get('uptime', 'N/A')}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"<b>今日出站:</b> {t_today.get('sent_gb', 0)} GB (入站: {t_today.get('recv_gb', 0)} GB)\n"
            f"<b>当月出站:</b> {t_month.get('sent_gb', 0)} GB / {t_month.get('limit_gb', 10240):.0f} GB ({t_month.get('usage_pct', 0)}%)\n"
            f"<b>剩余配额:</b> {t_month.get('remaining_gb', 10240)} GB (距重置 {t_month.get('days_remaining', 0)} 天)"
        )
        self.send_message(bot_token, chat_id, msg, self.get_main_keyboard())

    def handle_sub_command(self, bot_token, chat_id):
        try:
            import sub_engine
            cfg = self.get_config_func() if callable(self.get_config_func) else {}
            domain = cfg.get('cloudflare', {}).get('record_name', 'vps.example.com')
            token = cfg.get('security', {}).get('sub_token', '')
            t_query = f"?token={token}" if token else ""

            msg = (
                f"<b>VPSentinel 客户端订阅链接</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"<b>Clash / Mihomo:</b>\n"
                f"<code>https://{domain}:20540/sub/clash{t_query}</code>\n\n"
                f"<b>Sing-box (JSON):</b>\n"
                f"<code>https://{domain}:20540/sub/singbox{t_query}</code>\n\n"
                f"<b>V2Ray / Shadowrocket (Base64):</b>\n"
                f"<code>https://{domain}:20540/sub/v2ray{t_query}</code>\n\n"
                f"<i>提示：订阅链接已内嵌安全 Token，支持自动更新与甲骨文控制台分流直连。</i>"
            )
            self.send_message(bot_token, chat_id, msg, self.get_main_keyboard())
        except Exception as e:
            self.send_message(bot_token, chat_id, f"生成订阅链接失败: {e}", self.get_main_keyboard())

    def handle_mesh_command(self, bot_token, chat_id):
        try:
            import mesh_mgr
            overview = mesh_mgr.MeshManager.get_mesh_overview(self.get_state_func)
            nodes = overview.get('nodes', [])
            online = overview.get('online_nodes', 0)
            total = overview.get('total_nodes', 0)

            lines = [
                f"<b>Sentinel Mesh 集群状态 ({online}/{total} 在线)</b>",
                "━━━━━━━━━━━━━━━━━━"
            ]
            for n in nodes:
                st = n.get('last_status', {})
                status_icon = "[在线]" if st.get('online') else "[离线]"
                rtt = f"{st.get('rtt_ms', 0)}ms" if st.get('online') else "TIMEOUT"
                cpu = f"CPU:{st.get('cpu_pct', 0)}%" if st.get('online') else "N/A"
                ip = st.get('pub_ip', n.get('host', 'N/A'))
                lines.append(f"• <b>{n.get('name', 'Node')}</b> [{n.get('location', 'Global')}]\n  状态: {status_icon} | 延迟: {rtt} | {cpu}\n  IP: <code>{ip}</code>")

            serverless = overview.get('serverless_endpoints', [])
            if serverless:
                lines.append("\n<b>EdgeTunnel Serverless 边缘端点:</b>")
                for s in serverless:
                    st = s.get('last_status', {})
                    st_icon = "[在线]" if st.get('online') else "[离线]"
                    rtt_txt = f"{st.get('rtt_ms', 0)}ms" if st.get('online') else "TIMEOUT"
                    lines.append(f"• <b>{s.get('name')}</b>\n  状态: {st_icon} | 延迟: {rtt_txt}\n  域名: <code>{s.get('domain')}</code>")

            msg = "\n".join(lines)
            self.send_message(bot_token, chat_id, msg, self.get_main_keyboard())
        except Exception as e:
            self.send_message(bot_token, chat_id, f"获取集群信息失败: {e}", self.get_main_keyboard())

    def handle_reip_command(self, bot_token, chat_id):
        self.send_message(bot_token, chat_id, "正在调用公网 IP 轮换指令，预计耗时 15-30 秒，请稍候...")
        def _task():
            try:
                import asyncio
                res = None
                if not self.run_healing_func or not self._loop or not self._loop.is_running():
                    raise RuntimeError('Healing control loop is unavailable')
                future = asyncio.run_coroutine_threadsafe(self.run_healing_func('MANUAL', force=False), self._loop)
                res = future.result(timeout=180)

                if isinstance(res, dict) and res.get('ok'):
                    new_ip = res.get('new_ip', '未知')
                    dns_note = "Cloudflare DNS 解析已自动更新生效。" if res.get('dns_ok') else "DNS 同步未完成或未配置。"
                    res_msg = (
                        f"<b>公网 IP 轮换成功！</b>\n"
                        f"新公网 IP: <code>{new_ip}</code>\n"
                        f"{dns_note}"
                    )
                else:
                    err = res.get('error') if isinstance(res, dict) else str(res)
                    res_msg = f"<b>换 IP 失败：</b>\n错误原因: {err}"
                self.send_message(bot_token, chat_id, res_msg, self.get_main_keyboard())
            except Exception as e:
                self.send_message(bot_token, chat_id, f"换 IP 执行异常: {e}", self.get_main_keyboard())

        t = threading.Thread(target=_task, daemon=True)
        t.start()

    def handle_speedtest_command(self, bot_token, chat_id):
        self.send_message(bot_token, chat_id, "已触发国内三网骨干节点回程压测，预计耗时 20-35 秒，完成后将自动回传结果...")
        def _task():
            try:
                import speedtest_mgr
                manager = speedtest_mgr.speedtest_mgr
                manager.start_benchmark()
                deadline = time.monotonic() + 180
                while manager.get_status().get('is_running') and time.monotonic() < deadline:
                    time.sleep(1)
                status = manager.get_status()
                if status.get('is_running'): raise TimeoutError('Speedtest is still running')
                res = status.get('last_result') or {}
                results = res.get('results', [])
                lines = [
                    "<b>三网回程网络基准测速报告</b>",
                    "━━━━━━━━━━━━━━━━━━"
                ]
                for r in results:
                    tag = r.get('isp', '电信')
                    rtt = r.get('ping_ms', 0)
                    down = r.get('down_mbps', 0)
                    up = r.get('up_mbps', 0)
                    lines.append(f"• <b>{r.get('name', '节点')}</b> ({tag})\n  延迟: {rtt} ms | ↓ {down} Mbps | ↑ {up} Mbps")

                lines.append("━━━━━━━━━━━━━━━━━━")
                lines.append(f"<i>测试时间: {res.get('timestamp', '刚刚')}</i>")
                self.send_message(bot_token, chat_id, "\n".join(lines), self.get_main_keyboard())
            except Exception as e:
                self.send_message(bot_token, chat_id, f"测速执行异常: {e}", self.get_main_keyboard())

        t = threading.Thread(target=_task, daemon=True)
        t.start()

    def handle_help_command(self, bot_token, chat_id):
        msg = (
            f"<b>VPSentinel 智能交互助手</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"支持的指令列表：\n"
            f"• <code>/status</code> - 查询服务器状态、网络负载与当月流量账单\n"
            f"• <code>/mesh</code> - 集中查看全球受纳管的 VPS 节点矩阵\n"
            f"• <code>/speedtest</code> - 启动国内三网回程带宽与延迟压测\n"
            f"• <code>/sub</code> - 输出 Clash / Sing-box / V2Ray 订阅链接\n"
            f"• <code>/reip</code> - 立即轮换 OCI 公网 IP 并更新 Cloudflare DNS\n"
            f"• <code>/help</code> - 查看指令与帮助说明\n\n"
            f"<i>提示：您也可以直接点击下方快捷按钮快速操作。</i>"
        )
        self.send_message(bot_token, chat_id, msg, self.get_main_keyboard())

    def process_update(self, update, bot_token, admin_chat_id):
        cfg = self.get_config_func() if callable(self.get_config_func) else {}
        allowed = {str(v) for v in cfg.get('notifications', {}).get('telegram', {}).get('admin_user_ids', [])}
        item = update.get('callback_query', update.get('message', {}))
        sender = str(item.get('from', {}).get('id', ''))
        # Private chats remain convenient; groups require an explicit sender allowlist.
        if sender not in allowed and not (str(admin_chat_id).isdigit() and sender == str(admin_chat_id)):
            return
        # 1. Handle Inline Button Clicks (callback_query)
        if "callback_query" in update:
            cb = update["callback_query"]
            cb_id = cb.get("id")
            data = cb.get("data", "")
            user_chat_id = str(cb.get("message", {}).get("chat", {}).get("id", ""))

            if user_chat_id != admin_chat_id:
                self.answer_callback(bot_token, cb_id, "未授权的指令调用！")
                return

            self._last_active_time = int(time.time())
            self._command_count += 1

            if data == "cmd_status":
                self.answer_callback(bot_token, cb_id, "正在获取状态...")
                self.handle_status_command(bot_token, user_chat_id)
            elif data == "cmd_sub":
                self.answer_callback(bot_token, cb_id, "正在生成订阅...")
                self.handle_sub_command(bot_token, user_chat_id)
            elif data == "cmd_mesh":
                self.answer_callback(bot_token, cb_id, "正在查询集群...")
                self.handle_mesh_command(bot_token, user_chat_id)
            elif data == "cmd_speedtest":
                self.answer_callback(bot_token, cb_id, "测速任务已在后台启动！")
                self.handle_speedtest_command(bot_token, user_chat_id)
            elif data == "cmd_reip_confirm":
                confirm_keyboard = {
                    "inline_keyboard": [
                        [
                            {"text": "确认立即更换 IP", "callback_data": "cmd_reip_exec"},
                            {"text": "取消", "callback_data": "cmd_status"}
                        ]
                    ]
                }
                self.answer_callback(bot_token, cb_id)
                self.send_message(bot_token, user_chat_id, "安全二次确认：确定要更换甲骨文 VPS 的公网 IP 吗？现存连接将会中断约 15 秒并自动重新连接。", confirm_keyboard)
            elif data == "cmd_reip_exec":
                self.answer_callback(bot_token, cb_id, "换 IP 任务已提交！")
                self.handle_reip_command(bot_token, user_chat_id)
            return

        # 2. Handle Text Commands
        if "message" in update:
            msg = update["message"]
            user_chat_id = str(msg.get("chat", {}).get("id", ""))
            text = msg.get("text", "").strip()

            if user_chat_id != admin_chat_id:
                self.send_message(bot_token, user_chat_id, "未授权的访问请求，您的 Chat ID 未被添加到允许列表。")
                logger.warning(f"Unauthorized bot message from Chat ID: {user_chat_id}")
                return

            self._last_active_time = int(time.time())
            self._command_count += 1
            cmd = text.split()[0].lower() if text else ""

            if cmd in ["/start", "/help"]:
                self.handle_help_command(bot_token, user_chat_id)
            elif cmd == "/status":
                self.handle_status_command(bot_token, user_chat_id)
            elif cmd == "/sub":
                self.handle_sub_command(bot_token, user_chat_id)
            elif cmd == "/mesh":
                self.handle_mesh_command(bot_token, user_chat_id)
            elif cmd == "/reip":
                self.handle_reip_command(bot_token, user_chat_id)
            elif cmd == "/speedtest":
                self.handle_speedtest_command(bot_token, user_chat_id)
            else:
                self.send_message(bot_token, user_chat_id, f"未知指令: <code>{text}</code>\n发送 <code>/help</code> 查看可用指令列表。", self.get_main_keyboard())

    def _polling_loop(self):
        logger.info("Interactive Telegram Bot Long Polling thread started.")
        while self._running:
            bot_token, admin_chat_id, enabled = self.get_bot_credentials()
            if not enabled or not bot_token or not admin_chat_id:
                time.sleep(10)
                continue

            try:
                url = f"https://api.telegram.org/bot{bot_token}/getUpdates?offset={self._last_update_id}&timeout=20"
                req = urllib.request.Request(url)
                with open_secure(req, timeout=25) as resp:
                    data = json.loads(read_limited(resp).decode('utf-8'))
                    if data.get("ok"):
                        for item in data.get("result", []):
                            update_id = item.get("update_id", 0)
                            self._last_update_id = update_id + 1
                            try:
                                self.process_update(item, bot_token, admin_chat_id)
                            except Exception as ex:
                                logger.error(f"Error processing update {update_id}: {ex}")
            except Exception as e:
                # Normal network timeout or connection reset; sleep briefly before retry
                time.sleep(3)

    def start(self):
        import asyncio
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._polling_loop, name="TGBotPollingDaemon", daemon=True)
            self._thread.start()

    def stop(self):
        self._running = False

    def get_status(self):
        bot_token, admin_chat_id, enabled = self.get_bot_credentials()
        return {
            'running': self._running and bool(bot_token and admin_chat_id),
            'bot_configured': bool(bot_token and admin_chat_id),
            'last_active_time': self._last_active_time,
            'command_count': self._command_count
        }

bot_instance = None

def get_bot_instance(get_state_func=None, get_config_func=None, run_healing_func=None):
    global bot_instance
    if bot_instance is None:
        bot_instance = TelegramInteractiveBot(get_state_func, get_config_func, run_healing_func)
    elif run_healing_func is not None and bot_instance.run_healing_func is None:
        bot_instance.run_healing_func = run_healing_func
    return bot_instance

if __name__ == '__main__':
    bot = get_bot_instance()
    print("Bot status:", bot.get_status())
