"""Thread-safe in-memory tool result cache (FEATURE-008).

Cache key:  sha256(tool_name + json.dumps(params, sort_keys=True))
TTL:        configurable, default 3600 seconds
Storage:    in-process dict — no Redis, no external services
Safety:     threading.Lock protects all reads and writes
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import timezone, datetime
from typing import Any


class ToolCache:
    """In-memory, thread-safe forensic tool result cache."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl = ttl_seconds
        self._store: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(tool_name: str, params: dict[str, Any]) -> str:
        raw = tool_name + json.dumps(params, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _now() -> float:
        return datetime.now(timezone.utc).timestamp()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, tool_name: str, params: dict[str, Any]) -> Any | None:
        """Return cached result if present and not expired; else None."""
        key = self._make_key(tool_name, params)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if self._now() - entry["timestamp"] > self.ttl:
                del self._store[key]
                return None
            return entry["result"]

    def set(self, tool_name: str, params: dict[str, Any], result: Any) -> None:
        """Store result in cache with current timestamp."""
        key = self._make_key(tool_name, params)
        with self._lock:
            self._store[key] = {"timestamp": self._now(), "result": result}

    def clear(self) -> None:
        """Evict all entries (useful in tests)."""
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        """Number of live (potentially unexpired) entries."""
        with self._lock:
            return len(self._store)


# Module-level singleton — one cache per process lifetime
_global_cache = ToolCache()


def get_cache() -> ToolCache:
    """Return the module-level ToolCache singleton."""
    return _global_cache
