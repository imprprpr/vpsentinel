"""Shared validation for externally supplied settings and nodes."""
import ipaddress
import re
import urllib.parse


def host(value):
    value = str(value).strip()
    if len(value) > 253 or not value:
        raise ValueError('Host must contain 1–253 characters')
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        encoded = value.encode('idna').decode()
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', encoded):
            raise ValueError('Invalid host')
        return encoded


def https_url(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('A credential-free HTTPS URL is required')
    host(parsed.hostname)
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Invalid URL port')
    return value.rstrip('/')


def port(value):
    value = int(value)
    if not 1 <= value <= 65535:
        raise ValueError('Port must be between 1 and 65535')
    return value
