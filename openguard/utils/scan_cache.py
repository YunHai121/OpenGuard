"""Ruff / ESLint-inspired Content-Hash Incremental File Scan Cache.

Composite invalidation key:
    SHA-256(file_bytes + config_fingerprint + tool_version)
Guarantees zero stale results across `git checkout`, config updates, and OpenGuard upgrades.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from openguard import __version__
from openguard.config import AuditConfig


def compute_config_fingerprint(config: AuditConfig) -> str:
    """Compute a stable SHA-256 fingerprint of scan-affecting configuration fields."""
    payload = {
        "tool_version": __version__,
        "min_confidence": config.min_confidence,
        "entropy_threshold": config.entropy_threshold,
        "custom_rules": config.custom_rules,
        "custom_sast_rules": config.custom_sast_rules,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def compute_file_cache_key(raw_bytes: bytes, config_fp: str, scanner_ns: str) -> str:
    h = hashlib.sha256()
    h.update(scanner_ns.encode("utf-8", errors="replace"))
    h.update(b"|")
    h.update(config_fp.encode("utf-8", errors="replace"))
    h.update(b"|")
    h.update(raw_bytes)
    return h.hexdigest()[:32]


class IncrementalScanCache:
    """Thread-safe JSON-backed content-hash cache stored under `<repo>/.openguard_cache/scan_cache.json`."""

    def __init__(self, repo_root: Path, config: AuditConfig) -> None:
        self.cache_dir = Path(repo_root).resolve() / ".openguard_cache"
        self.cache_file = self.cache_dir / "scan_cache.json"
        self.config_fp = compute_config_fingerprint(config)
        self._lock = threading.Lock()
        self._entries: Dict[str, Any] = {}
        self.hits = 0
        self.misses = 0
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not self.cache_file.is_file():
            return
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8", errors="replace"))
            if (
                isinstance(data, dict)
                and data.get("tool_version") == __version__
                and data.get("config_fp") == self.config_fp
                and isinstance(data.get("entries"), dict)
            ):
                self._entries = data["entries"]
        except Exception:
            self._entries = {}

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._entries:
                self.hits += 1
                return self._entries[key]
            self.misses += 1
            return None

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._entries[key] = value
            self._dirty = True

    def flush(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                # Cap entries at 20,000 to prevent unbounded cache growth
                if len(self._entries) > 20000:
                    keys = list(self._entries.keys())[-15000:]
                    self._entries = {k: self._entries[k] for k in keys}
                payload = {
                    "schema_version": "1.0",
                    "tool_version": __version__,
                    "config_fp": self.config_fp,
                    "entries": self._entries,
                }
                self.cache_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                self._dirty = False
            except OSError:
                pass
