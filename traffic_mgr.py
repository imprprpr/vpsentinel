from secure_files import transactional
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# VPSentinel - Intelligent Traffic Auditing & Billing Quota Alerts
# ==============================================================================

import os
import time
import sqlite3
import logging
import threading
import datetime
import psutil
from notification import NotificationManager

logger = logging.getLogger('TrafficManager')

from paths import TRAFFIC_DB_PATH as DB_PATH

class TrafficManager:
    _lock = threading.Lock()
    _last_sent = 0
    _last_recv = 0
    _initialized = False

    @staticmethod
    def _get_connection():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    @classmethod
    def init_db(cls):
        with cls._lock:
            conn = cls._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS daily_traffic (
                        date TEXT PRIMARY KEY,
                        bytes_sent INTEGER DEFAULT 0,
                        bytes_recv INTEGER DEFAULT 0,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quota_config (
                        id INTEGER PRIMARY KEY,
                        monthly_limit_gb REAL DEFAULT 10240.0,
                        alert_threshold_pct INTEGER DEFAULT 80,
                        reset_day INTEGER DEFAULT 1,
                        last_alerted_month TEXT DEFAULT '',
                        last_alert_level INTEGER DEFAULT 0
                    )
                ''')
                cursor.execute('SELECT COUNT(*) FROM quota_config WHERE id = 1')
                if cursor.fetchone()[0] == 0:
                    cursor.execute('''
                        INSERT INTO quota_config (id, monthly_limit_gb, alert_threshold_pct, reset_day, last_alerted_month, last_alert_level)
                        VALUES (1, 10240.0, 80, 1, '', 0)
                    ''')
                conn.commit()
            except Exception as e:
                logger.error(f'Error initializing traffic db: {e}')
            finally:
                conn.close()

    @staticmethod
    def get_raw_external_counters():
        """Calculates total bytes sent/received across all non-loopback network interfaces."""
        total_sent = 0
        total_recv = 0
        try:
            counters = psutil.net_io_counters(pernic=True)
            for iface, stat in counters.items():
                if iface != 'lo' and not iface.startswith('docker') and not iface.startswith('br-'):
                    total_sent += stat.bytes_sent
                    total_recv += stat.bytes_recv
        except Exception as e:
            logger.error(f'Error reading network counters: {e}')
        return total_sent, total_recv

    @classmethod
    def poll_and_record(cls, notification_config=None):
        if not cls._initialized:
            cls.init_db()
            curr_sent, curr_recv = cls.get_raw_external_counters()
            cls._last_sent = curr_sent
            cls._last_recv = curr_recv
            cls._initialized = True
            return

        curr_sent, curr_recv = cls.get_raw_external_counters()
        with cls._lock:
            # Handle counter reset (reboot)
            if curr_sent < cls._last_sent or curr_recv < cls._last_recv:
                delta_sent = curr_sent
                delta_recv = curr_recv
            else:
                delta_sent = curr_sent - cls._last_sent
                delta_recv = curr_recv - cls._last_recv

            cls._last_sent = curr_sent
            cls._last_recv = curr_recv

            if delta_sent > 0 or delta_recv > 0:
                today_str = datetime.date.today().strftime('%Y-%m-%d')
                conn = cls._get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO daily_traffic (date, bytes_sent, bytes_recv, updated_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(date) DO UPDATE SET
                            bytes_sent = bytes_sent + excluded.bytes_sent,
                            bytes_recv = bytes_recv + excluded.bytes_recv,
                            updated_at = CURRENT_TIMESTAMP
                    ''', (today_str, delta_sent, delta_recv))
                    conn.commit()
                except Exception as e:
                    logger.error(f'Error recording traffic delta: {e}')
                finally:
                    conn.close()

        # Check quota alerting
        if notification_config:
            cls.check_quota_alert(notification_config)

    @classmethod
    def get_quota_config(cls):
        cls.init_db()
        conn = cls._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM quota_config WHERE id = 1')
            row = cursor.fetchone()
            if row:
                return {
                    'monthly_limit_gb': float(row['monthly_limit_gb']),
                    'alert_threshold_pct': int(row['alert_threshold_pct']),
                    'reset_day': int(row['reset_day']),
                    'last_alerted_month': str(row['last_alerted_month']),
                    'last_alert_level': int(row['last_alert_level'])
                }
        except Exception as e:
            logger.error(f'Error getting quota config: {e}')
        finally:
            conn.close()
        return {'monthly_limit_gb': 10240.0, 'alert_threshold_pct': 80, 'reset_day': 1, 'last_alerted_month': '', 'last_alert_level': 0}

    @classmethod
    def set_quota_config(cls, monthly_limit_gb=None, alert_threshold_pct=None, reset_day=None):
        cls.init_db()
        conn = cls._get_connection()
        try:
            cursor = conn.cursor()
            curr = cls.get_quota_config()
            limit = monthly_limit_gb if monthly_limit_gb is not None else curr['monthly_limit_gb']
            thresh = alert_threshold_pct if alert_threshold_pct is not None else curr['alert_threshold_pct']
            rday = reset_day if reset_day is not None else curr['reset_day']

            cursor.execute('''
                UPDATE quota_config SET
                    monthly_limit_gb = ?,
                    alert_threshold_pct = ?,
                    reset_day = ?
                WHERE id = 1
            ''', (float(limit), int(thresh), int(rday)))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f'Error setting quota config: {e}')
            return False
        finally:
            conn.close()

    @classmethod
    def get_billing_cycle_dates(cls, reset_day=1):
        today = datetime.date.today()
        if today.day >= reset_day:
            start_date = datetime.date(today.year, today.month, reset_day)
            # Next month reset
            if today.month == 12:
                next_reset = datetime.date(today.year + 1, 1, reset_day)
            else:
                next_reset = datetime.date(today.year, today.month + 1, reset_day)
        else:
            # Previous month reset
            if today.month == 1:
                start_date = datetime.date(today.year - 1, 12, reset_day)
            else:
                start_date = datetime.date(today.year, today.month - 1, reset_day)
            next_reset = datetime.date(today.year, today.month, reset_day)

        days_remaining = (next_reset - today).days
        return start_date.strftime('%Y-%m-%d'), next_reset.strftime('%Y-%m-%d'), days_remaining

    @classmethod
    def get_traffic_stats(cls):
        cls.init_db()
        cfg = cls.get_quota_config()
        reset_day = cfg['reset_day']
        start_date, next_reset, days_remaining = cls.get_billing_cycle_dates(reset_day)

        conn = cls._get_connection()
        today_str = datetime.date.today().strftime('%Y-%m-%d')
        today_sent = 0
        today_recv = 0
        month_sent = 0
        month_recv = 0

        try:
            cursor = conn.cursor()
            # Today's usage
            cursor.execute('SELECT bytes_sent, bytes_recv FROM daily_traffic WHERE date = ?', (today_str,))
            row = cursor.fetchone()
            if row:
                today_sent = row['bytes_sent']
                today_recv = row['bytes_recv']

            # Current billing cycle usage
            cursor.execute('''
                SELECT SUM(bytes_sent) as sent_sum, SUM(bytes_recv) as recv_sum
                FROM daily_traffic WHERE date >= ?
            ''', (start_date,))
            row = cursor.fetchone()
            if row and row['sent_sum'] is not None:
                month_sent = row['sent_sum']
                month_recv = row['recv_sum']

            # Recent 30 days history
            thirty_days_ago = (datetime.date.today() - datetime.timedelta(days=29)).strftime('%Y-%m-%d')
            cursor.execute('''
                SELECT date, bytes_sent, bytes_recv FROM daily_traffic
                WHERE date >= ? ORDER BY date ASC
            ''', (thirty_days_ago,))
            daily_rows = cursor.fetchall()
            daily_dict = {r['date']: (r['bytes_sent'], r['bytes_recv']) for r in daily_rows}

            # Fill missing days
            history_30d = []
            for i in range(30):
                d = (datetime.date.today() - datetime.timedelta(days=29 - i)).strftime('%Y-%m-%d')
                s, r = daily_dict.get(d, (0, 0))
                history_30d.append({
                    'date': d,
                    'sent_gb': round(s / (1024 ** 3), 3),
                    'recv_gb': round(r / (1024 ** 3), 3),
                    'total_gb': round((s + r) / (1024 ** 3), 3)
                })

        except Exception as e:
            logger.error(f'Error querying traffic stats: {e}')
            history_30d = []
        finally:
            conn.close()

        limit_gb = cfg['monthly_limit_gb']
        month_sent_gb = round(month_sent / (1024 ** 3), 2)
        month_recv_gb = round(month_recv / (1024 ** 3), 2)
        month_total_gb = round((month_sent + month_recv) / (1024 ** 3), 2)
        usage_pct = round((month_sent_gb / limit_gb) * 100, 1) if limit_gb > 0 else 0.0

        return {
            'today': {
                'sent_gb': round(today_sent / (1024 ** 3), 2),
                'recv_gb': round(today_recv / (1024 ** 3), 2),
                'total_gb': round((today_sent + today_recv) / (1024 ** 3), 2)
            },
            'month': {
                'cycle_start': start_date,
                'next_reset': next_reset,
                'days_remaining': days_remaining,
                'sent_gb': month_sent_gb,
                'recv_gb': month_recv_gb,
                'total_gb': month_total_gb,
                'limit_gb': limit_gb,
                'usage_pct': min(usage_pct, 100.0),
                'remaining_gb': max(round(limit_gb - month_sent_gb, 2), 0.0)
            },
            'quota_config': cfg,
            'history_30d': history_30d
        }

    @classmethod
    def check_quota_alert(cls, notification_config):
        cfg = cls.get_quota_config()
        limit_gb = cfg['monthly_limit_gb']
        threshold_pct = cfg['alert_threshold_pct']
        reset_day = cfg['reset_day']

        start_date, _, _ = cls.get_billing_cycle_dates(reset_day)
        current_cycle_id = start_date[:7]  # YYYY-MM

        conn = cls._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT SUM(bytes_sent) FROM daily_traffic WHERE date >= ?', (start_date,))
            row = cursor.fetchone()
            sent_bytes = row[0] or 0
        finally:
            conn.close()

        sent_gb = sent_bytes / (1024 ** 3)
        pct = (sent_gb / limit_gb * 100) if limit_gb > 0 else 0

        # Alert levels: 1 = warning threshold (e.g. 80%), 2 = 90%, 3 = 100%
        alert_level = 0
        if pct >= 100:
            alert_level = 3
        elif pct >= 90:
            alert_level = 2
        elif pct >= threshold_pct:
            alert_level = 1

        last_cycle = cfg.get('last_alerted_month', '')
        last_level = cfg.get('last_alert_level', 0)

        # Trigger notification only when entering a new alert level or new billing cycle
        if alert_level > 0 and (current_cycle_id != last_cycle or alert_level > last_level):
            title = f"VPSentinel 出站流量配额预警 ({pct:.1f}%)"
            message = (
                f"流量账单预警通知：\n"
                f"账单周期：{start_date} 起\n"
                f"当前出站：{sent_gb:.2f} GB / 配额 {limit_gb:.0f} GB\n"
                f"用量比例：{pct:.1f}%\n"
                f"等级：{'超额预警' if alert_level >= 3 else '高用量警告'}\n"
                f"请关注云服务厂商账单配额，避免产生额外扣费。"
            )
            NotificationManager.broadcast(notification_config, title, message, level="WARNING")

            # Update DB with alerted status
            conn = cls._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE quota_config SET last_alerted_month = ?, last_alert_level = ? WHERE id = 1
                ''', (current_cycle_id, alert_level))
                conn.commit()
            finally:
                conn.close()

    @classmethod
    def start_background_collector(cls, get_config_func, interval_sec=60):
        existing = getattr(cls, '_poller_thread', None)
        if existing is not None and existing.is_alive():
            return existing
        stop_event = threading.Event()
        cls._stop_event = stop_event
        def _loop():
            logger.info("Starting background traffic auditing worker...")
            while not stop_event.is_set():
                try:
                    cfg = get_config_func() if callable(get_config_func) else {}
                    cls.poll_and_record(notification_config=cfg)
                except Exception as e:
                    logger.error(f"Traffic worker error: {e}")
                stop_event.wait(interval_sec)

        t = threading.Thread(target=_loop, name="TrafficCollectorDaemon", daemon=True)
        cls._poller_thread = t
        t.start()
        return t

if __name__ == '__main__':
    TrafficManager.init_db()
    TrafficManager.poll_and_record()
    print("Traffic stats:", TrafficManager.get_traffic_stats())
