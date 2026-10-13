"""Source adapters return neutral node records, independent from subscription format."""
from dataclasses import dataclass
from typing import Protocol
import copy
import hashlib
import json
import os
import threading
import time


@dataclass(frozen=True)
class NodeSpec:
    protocol: str
    server: str
    port: int
    attributes: dict

    @classmethod
    def from_legacy(cls, protocol, attributes):
        if not attributes.get('server') or not 1 <= int(attributes.get('port', 0)) <= 65535:
            raise ValueError('Node requires a server and valid port')
        return cls(protocol, attributes['server'], int(attributes['port']), copy.deepcopy(attributes))

    def to_legacy(self):
        return self.protocol, copy.deepcopy(self.attributes)


class ProxyDataSource(Protocol):
    def collect(self) -> list[NodeSpec]: ...


class SQLiteSource:
    def __init__(self, collector):
        self.collector = collector
    def collect(self):
        return [NodeSpec.from_legacy(kind, record) for kind, record in self.collector()]


class ConfigSource:
    def __init__(self, records):
        self.records = records
    def collect(self):
        return [NodeSpec.from_legacy(record.get('protocol', record.get('type')), record) for record in self.records if record.get('enabled', True)]


_lock = threading.RLock()
_cached = None
_cache_key = None
_cache_time = 0


def collect_native_nodes(legacy_collector, db_path):
    global _cached, _cache_key, _cache_time
    from sentinel_core import ConfigManager
    cfg = ConfigManager.load()
    sources = cfg.get('proxy_sources', [{'type': 'sqlite'}])
    try:
        stat = os.stat(db_path)
        fingerprint = (os.path.abspath(db_path), stat.st_mtime_ns, stat.st_size, stat.st_ino)
    except OSError:
        fingerprint = (os.path.abspath(db_path), None)
    key = (fingerprint, hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).digest())
    with _lock:
        if key == _cache_key and _cached is not None and time.monotonic() - _cache_time < 5:
            return copy.deepcopy(_cached)
        records = []
        for source in sources:
            if not source.get('enabled', True):
                continue
            if source.get('type') == 'sqlite':
                adapter = SQLiteSource(legacy_collector)
            elif source.get('type') == 'config':
                adapter = ConfigSource(source.get('nodes', []))
            else:
                raise ValueError('Unsupported proxy data source')
            records.extend(adapter.collect())
        _cached = [node.to_legacy() for node in records]
        _cache_key, _cache_time = key, time.monotonic()
        return copy.deepcopy(_cached)
