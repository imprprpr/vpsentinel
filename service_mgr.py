"""Explicit service management; unsupported actions never report success."""
import logging
import os
import re
import shutil
import subprocess
from typing import Tuple
logger = logging.getLogger('ServiceManager')


class BaseServiceManager:
    def reload(self, service_name: str) -> Tuple[bool, str]:
        raise NotImplementedError

    def restart(self, service_name: str) -> Tuple[bool, str]:
        raise NotImplementedError

    def is_active(self, service_name: str) -> bool:
        raise NotImplementedError


def validate_service(name):
    if not re.fullmatch(r'[a-zA-Z0-9_.@-]{1,128}', name):
        raise ValueError('Invalid service name')
    return name


class SystemdServiceManager(BaseServiceManager):
    def _run(self, action, name):
        validate_service(name)
        try:
            result = subprocess.run(['systemctl', action, name], capture_output=True, text=True, timeout=20)
            return result.returncode == 0, (result.stdout + result.stderr).strip()[:4096]
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)

    def reload(self, service_name):
        ok, detail = self._run('reload', service_name)
        return (ok, detail) if ok else self._run('restart', service_name)

    def restart(self, service_name):
        return self._run('restart', service_name)

    def is_active(self, service_name):
        return self._run('is-active', service_name)[0]


class NoopServiceManager(BaseServiceManager):
    def reload(self, service_name):
        return False, 'unsupported: configure a real reload backend or hook'

    def restart(self, service_name):
        return False, 'unsupported: configure a real restart backend or hook'

    def is_active(self, service_name):
        return False


_global_service_manager = None


def is_systemd_available():
    return os.path.exists('/run/systemd/system') and shutil.which('systemctl') is not None


def get_service_manager():
    if _global_service_manager is not None:
        return _global_service_manager
    from privileged_helper import SOCKET_PATH
    if os.path.exists(SOCKET_PATH) and os.geteuid() != 0:
        return BrokerServiceManager()
    return SystemdServiceManager() if is_systemd_available() else NoopServiceManager()


def set_service_manager(mgr):
    global _global_service_manager
    _global_service_manager = mgr

class BrokerServiceManager(SystemdServiceManager):
    def _run(self, action, name):
        from privileged_helper import request_operation
        try:
            result = request_operation({'operation': 'service', 'name': name, 'action': action})
            return bool(result['success']), result.get('detail', '')
        except (OSError, ValueError) as exc:
            return False, str(exc)
