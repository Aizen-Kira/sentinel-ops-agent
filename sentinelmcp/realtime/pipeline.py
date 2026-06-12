"""Realtime streaming event pipeline.

Ingests Sysmon / Defender XDR events, applies correlation,
detects bursts, and dispatches triage runs.
"""
from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timezone, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RealtimeEvent:
    source: str          # "sysmon" | "defender_xdr"
    event_type: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class BurstWindow:
    events: list[RealtimeEvent] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class RealtimePipeline:
    """Single-threaded event ingestion pipeline with burst detection."""

    def __init__(
        self,
        burst_threshold: int = 10,
        burst_window_seconds: float = 30.0,
        dispatch_callback: Callable[[BurstWindow], None] | None = None,
    ) -> None:
        self._burst_threshold = burst_threshold
        self._burst_window_seconds = burst_window_seconds
        self._dispatch_callback = dispatch_callback
        self._queue: queue.Queue[RealtimeEvent] = queue.Queue()
        self._current_burst: BurstWindow = BurstWindow()
        self._running = False
        self._thread: threading.Thread | None = None

    def ingest(self, event: RealtimeEvent) -> None:
        """Enqueue an event for processing."""
        self._queue.put(event)

    def start(self) -> None:
        """Start the background processing thread."""
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="realtime-pipeline")
        self._thread.start()
        logger.info("Realtime pipeline started.")

    def stop(self) -> None:
        """Stop the pipeline gracefully."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Realtime pipeline stopped.")

    def _run(self) -> None:
        while self._running:
            try:
                event = self._queue.get(timeout=1.0)
                self._process(event)
            except queue.Empty:
                self._maybe_flush()

    def _process(self, event: RealtimeEvent) -> None:
        self._current_burst.events.append(event)
        logger.debug("Ingested event: %s from %s", event.event_type, event.source)
        if len(self._current_burst.events) >= self._burst_threshold:
            self._flush()

    def _maybe_flush(self) -> None:
        if not self._current_burst.events:
            return
        start = datetime.fromisoformat(self._current_burst.started_at)
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        if elapsed >= self._burst_window_seconds:
            self._flush()

    def _flush(self) -> None:
        burst = self._current_burst
        self._current_burst = BurstWindow()
        logger.info("Flushing burst of %d event(s)", len(burst.events))
        if self._dispatch_callback:
            try:
                self._dispatch_callback(burst)
            except Exception as exc:  # noqa: BLE001
                logger.error("Burst dispatch callback failed: %s", exc)
