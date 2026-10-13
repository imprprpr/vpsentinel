from secure_files import transactional
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clean IP Manager for EdgeTunnel Integration.
Maintains, tests, and provides Cloudflare Anycast Clean IPs for Telecom, Unicom, and Mobile.
Strictly Zero Emojis.
"""

import socket
import time
import logging
from sentinel_core import ConfigManager

logger = logging.getLogger("CleanIPManager")

DEFAULT_CLEAN_IPS = {
    "telecom": [
        "162.159.192.1",
        "162.159.192.10",
        "cf.090227.xyz",
        "198.41.214.162"
    ],
    "unicom": [
        "162.159.193.1",
        "162.159.193.10",
        "time.is",
        "104.17.80.1"
    ],
    "mobile": [
        "162.159.195.1",
        "162.159.195.10",
        "icook.hk",
        "104.18.80.1"
    ],
    "anycast": [
        "162.159.192.1",
        "cf.090227.xyz",
        "time.is",
        "icook.hk"
    ]
}


def sanitize_domain(domain_str: str) -> str:
    """
    Sanitize user input into a clean FQDN domain string.
    Strips protocol (http://, https://), port, trailing slashes, and paths.
    """
    if not domain_str or not isinstance(domain_str, str):
        return ""
    d = domain_str.strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in d:
        d = d.split(":", 1)[0]
    return d.strip().lower()


def validate_uuid(val: str) -> str:
    """
    Validates and normalizes UUID string.
    Returns normalized lowercase UUID string with hyphens, or empty string if invalid.
    """
    if not val or not isinstance(val, str):
        return ""
    import uuid
    v = val.strip().lower()
    try:
        u = uuid.UUID(v)
        return str(u)
    except Exception:
        return ""


class CleanIPManager:
    @staticmethod
    def sanitize_domain(domain_str: str) -> str:
        return sanitize_domain(domain_str)

    @staticmethod
    def validate_uuid(val: str) -> str:
        return validate_uuid(val)

    @classmethod
    def get_edt_config(cls):
        cfg = ConfigManager.load()
        return cfg.get("edgetunnel", {})

    @classmethod
    def is_edt_enabled(cls):
        edt = cls.get_edt_config()
        if not edt.get("enabled", False):
            return False
        uuid = edt.get("uuid", "").strip()
        pages = cls.sanitize_domain(edt.get("pages_domain", ""))
        worker = cls.sanitize_domain(edt.get("worker_domain", ""))
        pages_uuid = edt.get("pages_uuid", "").strip() or uuid
        worker_uuid = edt.get("worker_uuid", "").strip() or uuid
        return bool((pages and pages_uuid) or (worker and worker_uuid))

    @classmethod
    def get_clean_ips(cls):
        edt = cls.get_edt_config()
        clean_ips = edt.get("clean_ips", {})
        result = {}
        for isp, default_list in DEFAULT_CLEAN_IPS.items():
            current_list = clean_ips.get(isp)
            if isinstance(current_list, list) and current_list:
                filtered = [
                    str(x).strip() for x in current_list
                    if str(x).strip() and "v6.rocks" not in str(x).lower() and str(x).lower() != "cloudflare.com"
                ]
                result[isp] = filtered if filtered else list(default_list)
            else:
                result[isp] = list(default_list)
        return result

    @classmethod
    @transactional
    def save_clean_ips(cls, clean_ips_dict):
        cfg = ConfigManager.load()
        if "edgetunnel" not in cfg:
            cfg["edgetunnel"] = {}
        validated = {}
        for isp in ("telecom", "unicom", "mobile", "anycast"):
            vals = clean_ips_dict.get(isp, [])
            if isinstance(vals, list):
                validated[isp] = [str(x).strip() for x in vals if str(x).strip()]
            else:
                validated[isp] = list(DEFAULT_CLEAN_IPS.get(isp, []))
        cfg["edgetunnel"]["clean_ips"] = validated
        return ConfigManager.save(cfg)

    @classmethod
    def test_ip_latency(cls, target, port=443, timeout=1.5):
        target_str = str(target).strip()
        if not target_str:
            return None
        start_time = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_str, int(port)))
            sock.close()
            latency = (time.perf_counter() - start_time) * 1000.0
            return round(latency, 2)
        except Exception as e:
            logger.debug(f"Latency test failed for {target_str}:{port} - {e}")
            return None

    @classmethod
    def refresh_clean_ips(cls, active_test=False):
        current_pools = cls.get_clean_ips()
        updated_pools = {}

        for isp, ips in current_pools.items():
            if not active_test:
                updated_pools[isp] = list(ips)
                continue

            tested_results = []
            for ip in ips:
                lat = cls.test_ip_latency(ip, port=443, timeout=1.2)
                tested_results.append((ip, lat if lat is not None else 9999.0))

            tested_results.sort(key=lambda item: item[1])
            updated_pools[isp] = [item[0] for item in tested_results]

        cls.save_clean_ips(updated_pools)
        return updated_pools

    @classmethod
    def get_preferred_ip(cls, isp="telecom"):
        pools = cls.get_clean_ips()
        isp_list = pools.get(isp, [])
        if isp_list:
            return isp_list[0]
        anycast_list = pools.get("anycast", [])
        if anycast_list:
            return anycast_list[0]
        return DEFAULT_CLEAN_IPS.get(isp, ["162.159.192.1"])[0]
