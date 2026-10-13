"""Small root broker. Peer credentials and fixed operations bound privilege exposure."""
import json
import os
import pwd
import re
import socket
import struct
import subprocess
import stat

SOCKET_PATH = '/run/vpsentinel-control/control.sock'
SERVICES = frozenset({'vpsentinel', 'x-ui', 'xray', 'nginx', 'caddy'})


def request_operation(payload):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(45)
        connection.connect(SOCKET_PATH)
        connection.sendall(json.dumps(payload).encode() + b'\n')
        data = b''
        while b'\n' not in data and len(data) <= 8192:
            part = connection.recv(8192)
            if not part:
                break
            data += part
    return json.loads(data)


def dispatch(payload):
    if payload.get('operation') == 'xui_read_access':
        # WAL sidecars can be recreated with mode 0600 by the root-owned panel.
        # Grant read access only to fixed regular files in its protected directory.
        for path in ('/etc/x-ui/x-ui.db', '/etc/x-ui/x-ui.db-wal', '/etc/x-ui/x-ui.db-shm'):
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('Invalid database file')
            subprocess.run(['/usr/bin/setfacl', '-m', 'u:vpsentinel:r', path], check=True, capture_output=True, timeout=5)
        return {'success': True, 'detail': 'Database read access refreshed'}
    if payload.get('operation') == 'service':
        name, action = payload.get('name'), payload.get('action')
        if name not in SERVICES or action not in ('reload', 'restart', 'is-active'):
            raise ValueError('Unsupported service operation')
        result = subprocess.run(['/usr/bin/systemctl', action, name], capture_output=True, text=True, timeout=25)
        return {'success': result.returncode == 0, 'detail': (result.stdout + result.stderr)[:2048]}
    if payload.get('operation') == 'provision':
        domain = payload.get('domain', '')
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', domain):
            raise ValueError('Invalid domain')
        from scripts.node_provisioner import provision_nodes
        result = provision_nodes(domain=domain, force=bool(payload.get('force', False)))
        return {'success': bool(result), 'detail': 'Provisioning completed' if result else 'Provisioning failed'}
    raise ValueError('Unsupported operation')


def serve():
    account = pwd.getpwnam('vpsentinel')
    os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o750, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(SOCKET_PATH)
        os.chown(SOCKET_PATH, 0, account.pw_gid)
        os.chmod(SOCKET_PATH, 0o660)
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                try:
                    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid not in (0, account.pw_uid):
                        raise PermissionError('Unauthorized peer')
                    data = b''
                    while b'\n' not in data and len(data) <= 4096:
                        part = connection.recv(4096)
                        if not part:
                            break
                        data += part
                    if len(data) > 4096 or b'\n' not in data:
                        raise ValueError('Invalid request size')
                    result = dispatch(json.loads(data))
                except Exception as exc:
                    result = {'success': False, 'detail': str(exc)[:1024]}
                try:
                    connection.sendall(json.dumps(result).encode() + b'\n')
                except OSError:
                    pass


if __name__ == '__main__':
    serve()
