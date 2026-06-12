"""Super-Timeline Correlation Engine (FEATURE-012)."""

from dataclasses import asdict, dataclass
from datetime import timezone, datetime
from typing import Any

import dateutil.parser


@dataclass
class TimelineEvent:
    timestamp: datetime
    source: str
    category: str
    description: str
    evidence: str


def _parse_timestamp(ts: Any) -> datetime | None:
    if not ts:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    try:
        dt: datetime = dateutil.parser.parse(str(ts))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def build_super_timeline(
    disk_events: list[dict[str, Any]] | None = None,
    memory_events: list[dict[str, Any]] | None = None,
    network_events: list[dict[str, Any]] | None = None,
    evtx_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Correlate disk, memory, network, and event artifacts into one unified timeline."""

    disk_events = disk_events or []
    memory_events = memory_events or []
    network_events = network_events or []
    evtx_events = evtx_events or []

    events: list[TimelineEvent] = []

    def ingest(raw_events: list[dict[str, Any]], source: str) -> None:
        for e in raw_events:
            ts = _parse_timestamp(e.get("timestamp") or e.get("time") or e.get("date"))
            if not ts:
                # Tolerate missing timestamps by putting them at Unix epoch 0
                # (or we could drop them, but requirement says "tolerate missing timestamps").
                # Let's use epoch 0 to preserve the artifact, sorted at the beginning.
                ts = datetime.fromtimestamp(0, tz=timezone.utc)

            events.append(TimelineEvent(
                timestamp=ts,
                source=source,
                category=str(e.get("category", "unknown")),
                description=str(e.get("description", "")),
                evidence=str(e.get("evidence", repr(e))),
            ))

    ingest(disk_events, "disk")
    ingest(memory_events, "memory")
    ingest(network_events, "network")
    ingest(evtx_events, "evtx")

    # Suppress exact duplicates
    unique_events = []
    seen = set()
    for ev in events:
        key = (ev.timestamp, ev.source, ev.category, ev.description, ev.evidence)
        if key not in seen:
            seen.add(key)
            unique_events.append(ev)

    # Sort chronologically
    unique_events.sort(key=lambda x: x.timestamp)

    # Return format
    output_events = []
    for ev in unique_events:
        d = asdict(ev)
        d["timestamp"] = ev.timestamp.isoformat()
        output_events.append(d)

    return {
        "events": output_events,
        "summary": {
            "total_events": len(output_events),
            "sources": {
                "disk": sum(1 for e in output_events if e["source"] == "disk"),
                "memory": sum(1 for e in output_events if e["source"] == "memory"),
                "network": sum(1 for e in output_events if e["source"] == "network"),
                "evtx": sum(1 for e in output_events if e["source"] == "evtx"),
            }
        }
    }
