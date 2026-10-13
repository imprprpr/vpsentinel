"""Always isolate tests, including when production path overrides are inherited."""
import atexit
import json
import os
import shutil
import tempfile

_sandbox_dir = tempfile.mkdtemp(prefix='sentinel_test_sandbox_')
_saved = {}
for key, value in {
    'VPSENTINEL_CONFIG_PATH': os.path.join(_sandbox_dir, 'config.json'),
    'VPSENTINEL_HOME': _sandbox_dir,
    'VPSENTINEL_TRAFFIC_DB_PATH': os.path.join(_sandbox_dir, 'traffic.db'),
    'VPSENTINEL_CERT_DIR': os.path.join(_sandbox_dir, 'cert'),
    'VPSENTINEL_OCI_DIR': os.path.join(_sandbox_dir, 'oci'),
    'VPSENTINEL_XUI_DB_PATH': os.path.join(_sandbox_dir, 'xui.db'),
    'VPSENTINEL_STATIC_PATH': os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static'),
}.items():
    _saved[key] = os.environ.get(key)
    os.environ[key] = value
with open(os.environ['VPSENTINEL_CONFIG_PATH'], 'w') as stream:
    json.dump({'security': {'admin_password_hash': 'test-only-placeholder',
                           'session_secret': 'test-only-secret', 'sub_token': 'test-only-sub'}}, stream)


def _cleanup():
    for key, value in _saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    shutil.rmtree(_sandbox_dir, ignore_errors=True)


atexit.register(_cleanup)
