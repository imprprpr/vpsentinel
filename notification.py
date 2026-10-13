from net_policy import open_secure, read_limited
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Oracle Sentinel - Multi-Channel Notification Dispatcher
# Supports: Telegram Bot, Discord Webhook, Bark (iOS), ServerChan, Custom Webhooks
# ==============================================================================

import os
import json
import logging
import urllib.request
import urllib.parse
import urllib.error

logger = logging.getLogger('Notification')

class NotificationManager:
    @staticmethod
    def send_telegram(bot_token, chat_id, text):
        if not bot_token or not chat_id:
            return False, "Missing bot_token or chat_id"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with open_secure(req, timeout=8) as resp:
                res = json.loads(read_limited(resp).decode('utf-8'))
                if res.get("ok"):
                    return True, "Telegram notification sent successfully"
                return False, res.get("description", "Failed to send")
        except Exception as e:
            return False, str(e)

    @staticmethod
    def send_discord(webhook_url, title, text, color=0x10b981):
        if not webhook_url:
            return False, "Missing webhook_url"
        payload = {
            "username": "Sentinel Bot",
            "embeds": [
                {
                    "title": title,
                    "description": text,
                    "color": color
                }
            ]
        }
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
            with open_secure(req, timeout=8) as resp:
                return True, "Discord notification sent successfully"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def send_bark(bark_key, title, body):
        if not bark_key:
            return False, "Missing bark_key"
        encoded_title = urllib.parse.quote(title)
        encoded_body = urllib.parse.quote(body)
        url = f"https://api.day.app/{bark_key}/{encoded_title}/{encoded_body}"
        try:
            req = urllib.request.Request(url)
            with open_secure(req, timeout=8) as resp:
                res = json.loads(read_limited(resp).decode('utf-8'))
                if res.get("code") == 200:
                    return True, "Bark notification sent successfully"
                return False, res.get("message", "Failed to send")
        except Exception as e:
            return False, str(e)

    @staticmethod
    def send_custom_webhook(webhook_url, payload_dict):
        if not webhook_url:
            return False, "Missing webhook_url"
        try:
            data = json.dumps(payload_dict).encode('utf-8')
            req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
            with open_secure(req, timeout=8) as resp:
                return True, "Custom webhook triggered successfully"
        except Exception as e:
            return False, str(e)

    @classmethod
    def broadcast(cls, config, title, message, level="INFO"):
        """
        Dispatches message across all enabled notification channels specified in config.json.
        """
        notify_cfg = config.get("notifications", {})
        if not notify_cfg.get("enabled", False):
            return

        results = []

        # Color mapping for Discord
        color_map = {
            "INFO": 0x3b82f6,    # Blue
            "WARN": 0xf59e0b,    # Yellow
            "ERROR": 0xef4444,   # Red
            "SUCCESS": 0x10b981  # Green
        }
        color = color_map.get(level.upper(), 0x3b82f6)

        # 1. Telegram
        tg = notify_cfg.get("telegram", {})
        if tg.get("enabled") and tg.get("bot_token") and tg.get("chat_id"):
            formatted_tg = f"<b>[Sentinel {level}] {title}</b>\n\n{message}"
            ok, msg = cls.send_telegram(tg.get("bot_token"), tg.get("chat_id"), formatted_tg)
            results.append(("Telegram", ok, msg))

        # 2. Discord
        discord = notify_cfg.get("discord", {})
        if discord.get("enabled") and discord.get("webhook_url"):
            ok, msg = cls.send_discord(discord.get("webhook_url"), f"[{level}] {title}", message, color=color)
            results.append(("Discord", ok, msg))

        # 3. Bark
        bark = notify_cfg.get("bark", {})
        if bark.get("enabled") and bark.get("bark_key"):
            ok, msg = cls.send_bark(bark.get("bark_key"), title, message)
            results.append(("Bark", ok, msg))

        # 4. Custom Webhook
        custom = notify_cfg.get("custom_webhook", {})
        if custom.get("enabled") and custom.get("url"):
            payload = {
                "event": "sentinel_alert",
                "level": level,
                "title": title,
                "message": message
            }
            ok, msg = cls.send_custom_webhook(custom.get("url"), payload)
            results.append(("Webhook", ok, msg))

        for name, ok, err in results:
            if not ok:
                logger.warning(f"Notification via {name} failed: {err}")
            else:
                logger.info(f"Notification via {name} sent successfully.")

        return results
