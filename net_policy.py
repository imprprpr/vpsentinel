"""Outbound requests never forward credentials to redirects or metadata endpoints."""
import ipaddress
import json
import socket
import ssl
import urllib.parse
import urllib.request

MAX_RESPONSE = 2 * 1024 * 1024


def validate_url(url, allow_private=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('An HTTPS URL without embedded credentials is required')
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split('%')[0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError('Metadata/link-local destinations are forbidden')
        if not allow_private and not ip.is_global:
            raise ValueError('Private destinations require explicit allow_private authorization')
    return parsed


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirects are forbidden for credential-bearing requests')


class PinnedHTTPSConnection(__import__('http.client', fromlist=['HTTPSConnection']).HTTPSConnection):
    """Connect only to the IPs authorized before the request; retain hostname TLS/SNI."""
    def connect(self):
        from http.client import HTTPConnection
        host = self.host
        candidates = socket.getaddrinfo(host, self.port, type=socket.SOCK_STREAM)
        for candidate in candidates:
            ip = ipaddress.ip_address(candidate[4][0].split('%')[0])
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                raise ValueError('Forbidden destination')
            if not self.allow_private and not ip.is_global:
                raise ValueError('Forbidden private destination')
        # The socket uses the validated numeric address, so DNS cannot change at connect time.
        original = self.host
        self.host = candidates[0][4][0]
        try:
            HTTPConnection.connect(self)
        finally:
            self.host = original
        self.sock = self._context.wrap_socket(self.sock, server_hostname=host)


class SafeHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context, allow_private):
        super().__init__(context=context)
        self.allow_private = allow_private

    def https_open(self, req):
        def connection(*args, **kwargs):
            conn = PinnedHTTPSConnection(*args, **kwargs)
            conn.allow_private = self.allow_private
            return conn
        return self.do_open(connection, req, context=self._context)


def open_secure(request, timeout=10, context=None, allow_private=False):
    from sentinel_core import ConfigManager
    network = ConfigManager.load().get('network', {})
    url = request.full_url if hasattr(request, 'full_url') else request
    host = urllib.parse.urlsplit(url).hostname
    allow_private = allow_private or host in network.get('allowed_private_hosts', [])
    validate_url(url, allow_private)
    if network.get('ca_bundle'):
        context = ssl.create_default_context(cafile=network['ca_bundle'])
    if context and (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
        raise ValueError('Certificate and hostname verification are mandatory')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                       SafeHTTPSHandler(context or ssl.create_default_context(), allow_private))
    return opener.open(request, timeout=timeout)


def read_limited(response, limit=MAX_RESPONSE):
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Remote response exceeds size limit')
    return data


def read_json(response):
    return json.loads(read_limited(response).decode('utf-8'))
