"""Concurrency stress testing (FEATURE-015).

Targets: ToolCache, parallel dispatch, realtime pipeline.
100 concurrent executions — no deadlocks, no race conditions.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from unittest.mock import patch

from realtime.pipeline import RealtimeEvent, RealtimePipeline
from shared.cache import ToolCache

CONCURRENT = 100


class TestToolCacheConcurrency:

    def test_concurrent_set(self) -> None:
        cache = ToolCache(ttl_seconds=3600)
        def _w(i: int) -> None:
            cache.set(f"t_{i}", {"i": i}, {"r": i})
        with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
            list(ex.map(_w, range(CONCURRENT)))
        assert cache.size() == CONCURRENT

    def test_concurrent_get(self) -> None:
        cache = ToolCache(ttl_seconds=3600)
        cache.set("s", {"k": "v"}, {"d": 1})
        results: list[Any] = []
        lock = threading.Lock()
        def _r(_: int) -> None:
            r = cache.get("s", {"k": "v"})
            with lock:
                results.append(r)
        with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
            list(ex.map(_r, range(CONCURRENT)))
        assert len(results) == CONCURRENT
        assert all(r == {"d": 1} for r in results)

    def test_mixed_ops(self) -> None:
        cache = ToolCache(ttl_seconds=3600)
        errs: list[str] = []
        def _m(i: int) -> None:
            try:
                if i % 3 == 0:
                    cache.set(f"t_{i}", {"i": i}, {"r": i})
                elif i % 3 == 1:
                    cache.get(f"t_{i-1}", {"i": i-1})
                else:
                    cache.clear()
            except Exception as exc:
                errs.append(str(exc))
        with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
            list(ex.map(_m, range(CONCURRENT)))
        assert not errs

    def test_no_deadlock(self) -> None:
        cache = ToolCache(ttl_seconds=1)
        def _h(i: int) -> None:
            for j in range(50):
                cache.set(f"t_{i}", {"j": j}, {"r": j})
                cache.get(f"t_{i}", {"j": j})
                cache.size()
        with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
            list(ex.map(_h, range(CONCURRENT)))

    def test_concurrent_expiry(self) -> None:
        cache = ToolCache(ttl_seconds=0)
        def _e(i: int) -> None:
            cache.set("x", {"i": i}, {"d": i})
            cache.get("x", {"i": i})
        with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
            list(ex.map(_e, range(CONCURRENT)))


class TestParallelDispatchConcurrency:

    def test_concurrent_dispatch(self) -> None:
        from agent.loop import _dispatch_tool_return
        from shared.models import Case
        case = Case(disk_path="/t/d.E01", memory_path="/t/m.dmp")
        results: list[Any] = []
        lock = threading.Lock()
        def fake(tc: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [{"tool": c["tool"], "result": {"ok": True}, "error": None} for c in tc]
        with patch("agent.loop.call_mcp_tools", side_effect=fake):
            with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
                futs = [ex.submit(_dispatch_tool_return, {"tool": f"t_{i}", "params": {}}, case, 1) for i in range(CONCURRENT)]
                for f in as_completed(futs):
                    with lock:
                        results.append(f.result())
        assert len(results) == CONCURRENT

    def test_concurrent_dispatch_with_failures(self) -> None:
        from agent.loop import _dispatch_tool_return
        from shared.models import Case
        case = Case()
        def flaky(tc: list[dict[str, Any]]) -> list[dict[str, Any]]:
            n = tc[0]["tool"]
            if int(n.split("_")[1]) % 5 == 0:
                raise RuntimeError("boom")
            return [{"tool": n, "result": {"ok": True}, "error": None}]
        errs: list[bool] = []
        lock = threading.Lock()
        with patch("agent.loop.call_mcp_tools", side_effect=flaky):
            with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
                futs = [ex.submit(_dispatch_tool_return, {"tool": f"t_{i}", "params": {}}, case, 1) for i in range(CONCURRENT)]
                for f in as_completed(futs):
                    r = f.result()
                    with lock:
                        errs.append(r[0].get("error") is not None)
        assert any(errs)
        assert sum(1 for e in errs if not e) > CONCURRENT // 2


class TestRealtimePipelineConcurrency:

    def test_concurrent_ingestion(self) -> None:
        bursts: list[Any] = []
        lock = threading.Lock()
        def on_burst(b: Any) -> None:
            with lock:
                bursts.append(b)
        pipe = RealtimePipeline(burst_threshold=CONCURRENT, dispatch_callback=on_burst)
        pipe.start()
        def _i(i: int) -> None:
            pipe.ingest(RealtimeEvent(source="test", event_type=f"e_{i}", data={"i": i}))
        with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
            list(ex.map(_i, range(CONCURRENT)))
        time.sleep(2)
        pipe.stop()
        total = sum(len(b.events) for b in bursts)
        assert total == CONCURRENT

    def test_start_stop_cycle(self) -> None:
        for _ in range(20):
            p = RealtimePipeline(burst_threshold=5)
            p.start()
            p.ingest(RealtimeEvent(source="t", event_type="ping"))
            p.stop()

    def test_no_data_loss(self) -> None:
        evts: list[RealtimeEvent] = []
        lock = threading.Lock()
        def cap(b: Any) -> None:
            with lock:
                evts.extend(b.events)
        pipe = RealtimePipeline(burst_threshold=10, burst_window_seconds=0.5, dispatch_callback=cap)
        pipe.start()
        def _i(i: int) -> None:
            pipe.ingest(RealtimeEvent(source="s", event_type=f"e_{i}", data={"n": i}))
        with ThreadPoolExecutor(max_workers=50) as ex:
            list(ex.map(_i, range(100)))
        time.sleep(3)
        pipe.stop()
        assert len(evts) == 100
