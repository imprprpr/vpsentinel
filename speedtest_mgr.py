#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPSentinel Speedtest & Network Benchmark Module
Author: Antigravity Agent
"""

import time
import os
import json
import logging
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List

logger = logging.getLogger("SpeedtestMgr")

BENCHMARK_TARGETS = [
    {"name": "中国电信 (上海)", "isp": "电信", "region": "华东", "host": "202.96.209.133"},
    {"name": "中国联通 (北京)", "isp": "联通", "region": "华北", "host": "123.125.81.6"},
    {"name": "中国移动 (上海)", "isp": "移动", "region": "华东", "host": "211.136.112.50"},
    {"name": "中国移动 (广州)", "isp": "移动", "region": "华南", "host": "120.196.165.24"},
    {"name": "腾讯云 BGP (全国优选)", "isp": "BGP", "region": "亚太", "host": "119.29.29.29"},
    {"name": "阿里云 BGP (全国优选)", "isp": "BGP", "region": "亚太", "host": "223.5.5.5"},
    {"name": "Cloudflare Anycast", "isp": "国际", "region": "Anycast", "host": "1.1.1.1"},
    {"name": "Google DNS", "isp": "国际", "region": "全球", "host": "8.8.8.8"},
]

def ping_target(target: Dict[str, str], count: int = 3) -> Dict[str, Any]:
    host = target["host"]
    res = {
        "name": target["name"], "isp": target["isp"], "region": target["region"],
        "host": host, "loss": None, "avg_ms": None, "min_ms": None, "max_ms": None,
        "jitter_ms": None, "status": "探测不可用", "badge": "secondary",
        "method": "icmp", "error_code": None
    }
    try:
        count = max(1, min(int(count), 5))
        dedicated_ping = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "ping")
        ping_tool = dedicated_ping if os.path.isfile(dedicated_ping) else "ping"
        cmd = [ping_tool, "-n", "-c", str(count), "-W", "2", "-w", str(count * 2 + 1), host]
        env = dict(os.environ, LC_ALL="C", LANGUAGE="C")
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 2 + 3, env=env)
        failure = (p.stderr or '').lower()
        if any(message in failure for message in ('operation not permitted', 'permission denied', 'cap_net_raw')):
            res.update(status="本机无 ICMP 权限", error_code="permission_denied")
            return res
        loss = re.search(r"([\d.]+)%\s*(?:packet\s*)?loss", p.stdout, re.I)
        if loss:
            res['loss'] = round(float(loss.group(1)), 1)
        rtt = re.search(r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?", p.stdout)
        if rtt:
            res.update(min_ms=round(float(rtt[1]), 1), avg_ms=round(float(rtt[2]), 1),
                       max_ms=round(float(rtt[3]), 1),
                       jitter_ms=round(float(rtt[4]), 1) if rtt[4] else None)
            avg = res['avg_ms']
            if res['loss'] is not None and res['loss'] >= 50:
                res.update(status="丢包严重", badge="danger")
            elif avg < 60:
                res.update(status="极速", badge="success")
            elif avg < 160:
                res.update(status="优良", badge="success")
            elif avg < 230:
                res.update(status="正常", badge="info")
            else:
                res.update(status="偏高", badge="warning")
        elif res['loss'] is not None:
            res.update(status="未收到 ICMP 回应", badge="warning", error_code="no_reply")
        else:
            res.update(status="探测执行失败", error_code="ping_failed")
    except FileNotFoundError:
        res.update(status="本机缺少 ping 工具", error_code="ping_missing")
    except PermissionError:
        res.update(status="本机无 ICMP 权限", error_code="permission_denied")
    except subprocess.TimeoutExpired:
        res.update(status="探测进程超时", error_code="process_timeout")
    except Exception as exc:
        logger.debug("Ping %s error: %s", host, type(exc).__name__)
        res.update(status="探测异常", error_code="probe_error")
    return res

def run_latency_benchmarks() -> List[Dict[str, Any]]:
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(ping_target, BENCHMARK_TARGETS))
    return results

def run_speedtest_cli() -> Dict[str, Any]:
    cmd = ["speedtest-cli", "--json", "--secure"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=50)
    if p.returncode != 0:
        raise RuntimeError(f"speedtest-cli 异常: {p.stderr.strip() or p.stdout.strip()}")
    data = json.loads(p.stdout)
    
    download_mbps = round(data.get("download", 0) / 1e6, 2)
    upload_mbps = round(data.get("upload", 0) / 1e6, 2)
    ping_ms = round(data.get("ping", 0), 1)
    server = data.get("server", {})
    client = data.get("client", {})

    return {
        "download_mbps": download_mbps,
        "upload_mbps": upload_mbps,
        "ping_ms": ping_ms,
        "server_name": server.get("name", "Unknown"),
        "server_sponsor": server.get("sponsor", "Unknown"),
        "server_country": server.get("country", "Unknown"),
        "server_distance_km": round(server.get("d", 0), 1),
        "client_ip": client.get("ip", ""),
        "client_isp": client.get("isp", ""),
        "bytes_sent_mb": round(data.get("bytes_sent", 0) / (1024 * 1024), 2),
        "bytes_received_mb": round(data.get("bytes_received", 0) / (1024 * 1024), 2),
    }

class SpeedtestManager:
    def __init__(self):
        self.is_running = False
        self.stage = "idle"  # idle, bandwidth, latency, done, error
        self.progress_msg = "空闲待命"
        self.started_at: float = 0.0
        self.last_result: Optional[Dict[str, Any]] = None
        self.history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "stage": self.stage,
            "progress_msg": self.progress_msg,
            "elapsed_sec": round(time.time() - self.started_at, 1) if self.is_running else 0,
            "last_result": self.last_result,
            "history_count": len(self.history)
        }

    def start_benchmark(self, mode: str = "full") -> bool:
        with self._lock:
            if self.is_running:
                return False
            self.is_running = True
            self.started_at = time.time()
            self.stage = "starting"
            self.progress_msg = "正在初始化网络测试引擎..."

        t = threading.Thread(target=self._execute_benchmark_worker, args=(mode,), daemon=True)
        t.start()
        return True

    def _execute_benchmark_worker(self, mode: str):
        t0 = time.time()
        result: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": mode,
            "success": False,
            "duration_sec": 0,
            "bandwidth": None,
            "three_network": [],
            "rating": "N/A",
            "rating_desc": "测试中",
            "error": None
        }

        try:
            # Step 1: Bandwidth speedtest if full mode
            if mode == "full":
                self.stage = "bandwidth"
                self.progress_msg = "正在测试就近骨干节点的上下行带宽与往返延迟..."
                try:
                    result["bandwidth"] = run_speedtest_cli()
                except Exception as e:
                    logger.warning(f"Bandwidth test failed: {e}")
                    result["bandwidth_error"] = str(e)

            # Step 2: Latency benchmarks
            self.stage = "latency"
            self.progress_msg = "正在测试国内三网骨干与国际链路延迟..."
            result["three_network"] = run_latency_benchmarks()

            # Step 3: Synthesis Rating
            dl = result.get("bandwidth", {}).get("download_mbps", 0) if result.get("bandwidth") else 0
            ul = result.get("bandwidth", {}).get("upload_mbps", 0) if result.get("bandwidth") else 0

            # Calculate china avg latency
            cn_pings = [x["avg_ms"] for x in result["three_network"] if x.get("isp") in ("电信", "联通", "移动") and x.get("avg_ms")]
            cn_avg = sum(cn_pings) / len(cn_pings) if cn_pings else None

            if cn_avg is None:
                result["rating"] = "N/A"
                result["rating_desc"] = "未获得国内运营商的有效 ICMP 样本"
            elif mode == "full":
                if dl >= 100 and cn_avg < 180:
                    result["rating"] = "A+"
                    result["rating_desc"] = "超高带宽 / 极佳跨境链路"
                elif dl >= 30 and cn_avg < 220:
                    result["rating"] = "A"
                    result["rating_desc"] = "优良跨境互联 / 流畅 4K 播放"
                elif dl >= 10:
                    result["rating"] = "B"
                    result["rating_desc"] = "常规跨境性能 / 满足日常使用"
                else:
                    result["rating"] = "C"
                    result["rating_desc"] = "受限或丢包较高"
            else:
                # ping only mode
                if cn_avg < 180:
                    result["rating"] = "A+"
                    result["rating_desc"] = "三网直连延迟极佳"
                elif cn_avg < 220:
                    result["rating"] = "A"
                    result["rating_desc"] = "跨境路由优良稳定"
                elif cn_avg < 260:
                    result["rating"] = "B"
                    result["rating_desc"] = "常规跨洋延迟"
                else:
                    result["rating"] = "C"
                    result["rating_desc"] = "网络延迟偏高"

            result["success"] = bool(cn_pings or result.get("bandwidth"))
            result["duration_sec"] = round(time.time() - t0, 1)
            self.stage = "done"
            self.progress_msg = f"测速完成，耗时 {result['duration_sec']} 秒"

            with self._lock:
                self.last_result = result
                self.history.insert(0, {
                    "timestamp": result["timestamp"],
                    "rating": result["rating"],
                    "download_mbps": dl,
                    "upload_mbps": ul,
                    "ping_ms": result.get("bandwidth", {}).get("ping_ms", 0) if result.get("bandwidth") else 0,
                    "cn_avg_latency": round(cn_avg, 1) if cn_avg is not None else None
                })
                if len(self.history) > 10:
                    self.history.pop()

        except Exception as e:
            logger.error(f"Speedtest worker error: {e}", exc_info=True)
            result["error"] = str(e)
            result["success"] = False
            self.stage = "error"
            self.progress_msg = f"测速失败: {str(e)}"
            with self._lock:
                self.last_result = result
        finally:
            with self._lock:
                self.is_running = False

speedtest_mgr = SpeedtestManager()

if __name__ == "__main__":
    print("Testing SpeedtestManager (mode=ping_only)...")
    speedtest_mgr._execute_benchmark_worker(mode="ping_only")
    print(json.dumps(speedtest_mgr.last_result, indent=2, ensure_ascii=False))
