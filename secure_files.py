"""Private, durable file writes and configuration transaction locks."""
import contextlib
import functools
import os
import tempfile
import threading
import fcntl


def atomic_write(path, data, mode=0o600):
    path = os.path.abspath(os.fspath(path))
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.islink(path):
        raise ValueError('Refusing to replace a symbolic link')
    fd, temporary = tempfile.mkstemp(prefix='.sentinel-', dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data.encode('utf-8') if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


_local = threading.local()


@contextlib.contextmanager
def config_transaction():
    from sentinel_core import ConfigManager, get_active_config_path
    with ConfigManager._lock:
        depth = getattr(_local, 'depth', 0)
        if depth:
            _local.depth += 1
            try:
                yield
            finally:
                _local.depth -= 1
            return
        path = get_active_config_path() + '.lock'
        os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            _local.depth = 1
            yield
        finally:
            _local.depth = 0
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def transactional(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        with config_transaction():
            return fn(*args, **kwargs)
    return wrapped
