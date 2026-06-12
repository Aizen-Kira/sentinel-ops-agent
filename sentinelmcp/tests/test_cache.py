"""Tests for shared/cache.py — FEATURE-008."""
from __future__ import annotations

import threading
import time
from typing import Any

from shared.cache import ToolCache


class TestToolCacheHitMiss:
    def test_cache_miss_returns_none(self) -> None:
        c = ToolCache()
        assert c.get("vol3_pslist", {}) is None

    def test_cache_hit_returns_result(self) -> None:
        c = ToolCache()
        c.set("vol3_pslist", {}, [{"pid": 4}])
        result = c.get("vol3_pslist", {})
        assert result == [{"pid": 4}]

    def test_different_params_different_keys(self) -> None:
        c = ToolCache()
        c.set("evtxdump", {"channel": "Security"}, ["entry1"])
        c.set("evtxdump", {"channel": "System"}, ["entry2"])
        assert c.get("evtxdump", {"channel": "Security"}) == ["entry1"]
        assert c.get("evtxdump", {"channel": "System"}) == ["entry2"]

    def test_different_tools_different_keys(self) -> None:
        c = ToolCache()
        c.set("tool_a", {}, "result_a")
        c.set("tool_b", {}, "result_b")
        assert c.get("tool_a", {}) == "result_a"
        assert c.get("tool_b", {}) == "result_b"

    def test_params_order_insensitive(self) -> None:
        """sha256 key is built with sort_keys=True — param order must not matter."""
        c = ToolCache()
        c.set("reglookup", {"key": "Run", "image_path": "/d"}, "r")
        assert c.get("reglookup", {"image_path": "/d", "key": "Run"}) == "r"

    def test_size_increments_on_set(self) -> None:
        c = ToolCache()
        assert c.size() == 0
        c.set("a", {}, 1)
        assert c.size() == 1
        c.set("b", {}, 2)
        assert c.size() == 2

    def test_clear_empties_cache(self) -> None:
        c = ToolCache()
        c.set("tool", {}, "data")
        c.clear()
        assert c.size() == 0
        assert c.get("tool", {}) is None


class TestToolCacheTTL:
    def test_entry_valid_before_ttl(self) -> None:
        c = ToolCache(ttl_seconds=60)
        c.set("pslist", {}, "ok")
        assert c.get("pslist", {}) == "ok"

    def test_entry_expired_after_ttl(self) -> None:
        c = ToolCache(ttl_seconds=1)
        c.set("pslist", {}, "ok")
        time.sleep(1.05)
        assert c.get("pslist", {}) is None

    def test_expired_entry_removed_from_store(self) -> None:
        c = ToolCache(ttl_seconds=1)
        c.set("pslist", {}, "ok")
        time.sleep(1.05)
        c.get("pslist", {})  # triggers eviction
        assert c.size() == 0

    def test_ttl_zero_always_expires(self) -> None:
        c = ToolCache(ttl_seconds=0)
        c.set("tool", {}, "data")
        # even 0s TTL: entry should be expired immediately
        time.sleep(0.01)
        assert c.get("tool", {}) is None


class TestToolCacheConcurrent:
    def test_concurrent_writes_no_data_loss(self) -> None:
        c = ToolCache()
        errors: list[Exception] = []

        def writer(i: int) -> None:
            try:
                c.set(f"tool_{i}", {}, f"result_{i}")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert c.size() == 50

    def test_concurrent_reads_consistent(self) -> None:
        c = ToolCache()
        c.set("shared_tool", {}, "stable_result")
        results: list[Any] = []
        errors: list[Exception] = []

        def reader() -> None:
            try:
                results.append(c.get("shared_tool", {}))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert all(r == "stable_result" for r in results)
