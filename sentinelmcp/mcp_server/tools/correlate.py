"""Correlation tools.

BUG-001: all paths validated via validate_path().
BUG-002: datetime naive/aware mixing fixed — utcnow() replaced with
         datetime.now(timezone.utc).replace(tzinfo=None) consistently.
"""
from __future__ import annotations

import logging
import os
from datetime import timezone, datetime, timedelta
from pathlib import Path
from typing import Any

from mcp_server.parsers.disk_parsers import parse_mft
from mcp_server.parsers.memory_parsers import parse_pslist
from shared.models import CorrelationResult, TimelineGap
from shared.security import validate_path

logger = logging.getLogger(__name__)

_DISK_ROOTS: list[Path] = [Path(os.environ.get("SENTINELMCP_DISK_ROOT", "/evidence"))]
_MEMORY_ROOTS: list[Path] = [Path(os.environ.get("SENTINELMCP_MEMORY_ROOT", "/evidence"))]
_PCAP_ROOTS: list[Path] = [Path(os.environ.get("SENTINELMCP_PCAP_ROOT", "/evidence"))]

_GAP_THRESHOLD_SECONDS = 300  # 5 minutes


def set_roots(
    disk_roots: list[Path] | None = None,
    memory_roots: list[Path] | None = None,
    pcap_roots: list[Path] | None = None,
) -> None:
    global _DISK_ROOTS, _MEMORY_ROOTS, _PCAP_ROOTS
    if disk_roots is not None:
        _DISK_ROOTS = disk_roots
    if memory_roots is not None:
        _MEMORY_ROOTS = memory_roots
    if pcap_roots is not None:
        _PCAP_ROOTS = pcap_roots


# ---------------------------------------------------------------------------
# BUG-002 helper: always produce tz-naïve timezone.utc datetimes for comparison
# ---------------------------------------------------------------------------


def _utcnow_naive() -> datetime:
    """Return a tz-naïve timezone.utc datetime (BUG-002 fix: replaces datetime.utcnow())."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_ts(ts_str: str) -> datetime | None:
    """Parse an ISO-8601 timestamp string into a tz-naïve timezone.utc datetime.

    BUG-002 fix: strips tzinfo after parsing so that all comparisons are
    between naïve datetimes, avoiding TypeError from mixed-aware comparisons.
    """
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is not None:
            # Convert to timezone.utc then strip tzinfo → naïve timezone.utc
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except (ValueError, OverflowError):
        logger.debug("Could not parse timestamp: %r", ts_str)
        return None


# ---------------------------------------------------------------------------
# Tool: correlate_disk_memory
# ---------------------------------------------------------------------------


def correlate_disk_memory(image_path: str, memory_path: str) -> list[dict[str, Any]]:
    """Cross-reference disk file entries with memory process list.

    Identifies processes whose on-disk executable cannot be found in the MFT
    (possible process hollowing / masquerading) and vice-versa.
    """
    validated_disk = validate_path(image_path, _DISK_ROOTS)
    validated_mem = validate_path(memory_path, _MEMORY_ROOTS)

    import subprocess
    mft_raw = subprocess.run(
        ["mftdump", "-f", str(validated_disk)],
        capture_output=True, text=True, timeout=120, shell=False,
    ).stdout
    vol3_raw = subprocess.run(
        ["vol3", "-f", str(validated_mem), "windows.pslist.PsList"],
        capture_output=True, text=True, timeout=300, shell=False,
    ).stdout

    mft_entries = parse_mft(mft_raw)
    proc_entries = parse_pslist(vol3_raw)

    disk_paths = {e.path.lower() for e in mft_entries}
    results: list[CorrelationResult] = []

    for proc in proc_entries:
        anomalies: list[str] = []
        proc_path = (proc.cmd or "").split()[0].lower() if proc.cmd else ""
        on_disk = any(proc_path in dp for dp in disk_paths) if proc_path else True

        if not on_disk:
            anomalies.append(f"Executable '{proc_path}' not found in MFT")

        results.append(CorrelationResult(
            disk_pid=None,
            memory_pid=proc.pid,
            process_name=proc.name,
            matched=on_disk,
            disk_path=proc_path or None,
            memory_cmd=proc.cmd,
            anomalies=anomalies,
        ))

    return [
        {
            "memory_pid": r.memory_pid,
            "process_name": r.process_name,
            "matched": r.matched,
            "disk_path": r.disk_path,
            "memory_cmd": r.memory_cmd,
            "anomalies": r.anomalies,
        }
        for r in results
    ]


# ---------------------------------------------------------------------------
# Tool: timeline_gaps
# ---------------------------------------------------------------------------


def timeline_gaps(
    image_path: str,
    memory_path: str = "",
    pcap_path: str = "",
) -> list[dict[str, Any]]:
    """Identify temporal gaps in the unified artifact timeline.

    BUG-002 fix: uses _parse_ts() which strips tzinfo uniformly, then
    compares only naïve datetimes. _utcnow_naive() replaces datetime.utcnow().
    """
    validate_path(image_path, _DISK_ROOTS)
    if memory_path:
        validate_path(memory_path, _MEMORY_ROOTS)
    if pcap_path:
        validate_path(pcap_path, _PCAP_ROOTS)

    # Collect all timestamps from available sources.
    raw_timestamps: list[tuple[str, str]] = []  # (source, iso_str)

    import subprocess

    mft_raw = subprocess.run(
        ["mftdump", "-f", image_path],
        capture_output=True, text=True, timeout=120, shell=False,
    ).stdout
    for entry in parse_mft(mft_raw):
        if entry.modified:
            raw_timestamps.append(("mft", entry.modified))
        if entry.created:
            raw_timestamps.append(("mft", entry.created))

    # Parse and sort — all naïve timezone.utc datetimes after _parse_ts().
    parsed: list[tuple[datetime, str]] = []
    for source, ts_str in raw_timestamps:
        dt = _parse_ts(ts_str)  # BUG-002 fix: strips tzinfo
        if dt is not None:
            parsed.append((dt, source))

    parsed.sort(key=lambda x: x[0])

    # BUG-002 fix: use _utcnow_naive() instead of datetime.utcnow().
    now = _utcnow_naive()
    gaps: list[TimelineGap] = []

    for i in range(1, len(parsed)):
        prev_dt, prev_src = parsed[i - 1]
        curr_dt, _curr_src = parsed[i]
        delta: timedelta = curr_dt - prev_dt  # both naïve → safe subtraction
        secs = delta.total_seconds()

        if secs > _GAP_THRESHOLD_SECONDS:
            significance = (
                "high" if secs > 3600
                else "medium" if secs > _GAP_THRESHOLD_SECONDS
                else "low"
            )
            # Safe comparison: now is also naïve.
            if curr_dt <= now:
                gaps.append(TimelineGap(
                    start=prev_dt.isoformat(),
                    end=curr_dt.isoformat(),
                    duration_seconds=secs,
                    preceding_event=prev_src,
                    significance=significance,
                ))

    return [
        {
            "start": g.start,
            "end": g.end,
            "duration_seconds": g.duration_seconds,
            "preceding_event": g.preceding_event,
            "significance": g.significance,
        }
        for g in gaps
    ]
