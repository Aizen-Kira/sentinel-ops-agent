"""Tests for realtime/pipeline.py."""
from __future__ import annotations

import time

from realtime.pipeline import BurstWindow, RealtimeEvent, RealtimePipeline


class TestRealtimeEvent:
    def test_default_timestamp_set(self) -> None:
        ev = RealtimeEvent(source="sysmon", event_type="ProcessCreate")
        assert ev.timestamp != ""

    def test_data_defaults_empty(self) -> None:
        ev = RealtimeEvent(source="sysmon", event_type="NetworkConnect")
        assert ev.data == {}


class TestRealtimePipeline:
    def test_burst_threshold_triggers_callback(self) -> None:
        received: list[BurstWindow] = []

        pipeline = RealtimePipeline(
            burst_threshold=3,
            burst_window_seconds=60.0,
            dispatch_callback=received.append,
        )
        pipeline.start()

        for i in range(3):
            pipeline.ingest(RealtimeEvent(source="sysmon", event_type=f"event_{i}"))

        time.sleep(0.5)
        pipeline.stop()
        assert len(received) >= 1
        assert sum(len(b.events) for b in received) >= 3

    def test_stop_does_not_raise(self) -> None:
        pipeline = RealtimePipeline()
        pipeline.start()
        pipeline.stop()  # must not raise

    def test_ingest_without_start_enqueues(self) -> None:
        pipeline = RealtimePipeline()
        ev = RealtimeEvent(source="defender_xdr", event_type="Alert")
        pipeline.ingest(ev)
        assert pipeline._queue.qsize() == 1
