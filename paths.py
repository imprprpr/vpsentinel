"""Startup path contract. Environment changes require a process restart (except test config overrides)."""
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUNTIME_HOME = os.path.abspath(os.environ.get('VPSENTINEL_HOME') or (
    '/var/lib/vpsentinel' if os.path.isdir('/var/lib/vpsentinel') else
    '/opt/vpsentinel' if os.path.isdir('/opt/vpsentinel') else
    '/opt/oracle-sentinel' if os.path.isdir('/opt/oracle-sentinel') else BASE_DIR))


def get_config_path():
    return os.path.abspath(os.environ.get('VPSENTINEL_CONFIG_PATH') or os.path.join(os.environ.get('VPSENTINEL_HOME') or RUNTIME_HOME, 'config.json'))


CONFIG_PATH = get_config_path()
STATIC_PATH = os.path.abspath(os.environ.get('VPSENTINEL_STATIC_PATH') or os.path.join(BASE_DIR, 'static'))
CERT_DIR = os.path.abspath(os.environ.get('VPSENTINEL_CERT_DIR') or (
    '/etc/vpsentinel/cert' if RUNTIME_HOME.startswith('/opt/') or RUNTIME_HOME == '/var/lib/vpsentinel' else os.path.join(RUNTIME_HOME, 'cert')))
TRAFFIC_DB_PATH = os.path.abspath(os.environ.get('VPSENTINEL_TRAFFIC_DB_PATH') or os.path.join(RUNTIME_HOME, 'traffic.db'))
XUI_DB_PATH = os.path.abspath(os.environ.get('VPSENTINEL_XUI_DB_PATH') or '/etc/x-ui/x-ui.db')
OCI_DIR = os.path.abspath(os.environ.get('VPSENTINEL_OCI_DIR') or os.path.join(RUNTIME_HOME, 'oci'))
