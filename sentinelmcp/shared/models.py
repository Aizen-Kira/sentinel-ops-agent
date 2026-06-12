"""Canonical data models for SentinelMCP.

All dataclasses defined here are the single source of truth for data transport
between agent, mcp_server, and benchmark layers.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FindingStatus(str, Enum):  # noqa: UP042
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNSUPPORTED = "UNSUPPORTED"


class CaseStatus(str, Enum):  # noqa: UP042
    """Lifecycle state of a triage case (V1.1.0 — PHASE 6)."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"


# ---------------------------------------------------------------------------
# Core transport types
# ---------------------------------------------------------------------------


@dataclass
class IOC:
    type: str
    value: str
    source_tool: str
    confidence: float



@dataclass
class Finding:
    """A single triage finding produced by the agent loop."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    status: FindingStatus = FindingStatus.INFERRED
    severity: str = "info"  # critical / high / medium / low / info
    source_tools: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    ttp_ids: list[str] = field(default_factory=list)
    ioc_type: str | None = None
    ioc_value: str | None = None
    extracted_iocs: list[IOC] = field(default_factory=list)


@dataclass
class Gap:
    """A gap identified by the evaluator that requires additional tool runs."""

    suggested_tool: str
    suggested_params: dict[str, object]
    description: str
    finding_id: str


@dataclass
class Case:
    """Input case descriptor for a DFIR triage session."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    disk_path: str = ""
    memory_path: str = ""
    pcap_path: str = ""
    description: str = ""
    # V1.1.0 — Case Management (PHASE 6)
    status: CaseStatus = CaseStatus.OPEN
    retention_days: int = 90  # Default: 90-day retention


@dataclass
class IterationLog:
    """Log entry for one iteration of the self-correction loop."""

    iteration: int
    tools_called: list[str]
    findings_count: int
    gaps_count: int


@dataclass
class TriageResult:
    """Final output of a triage session."""

    findings: list[Finding]
    gaps: list[Gap]
    iterations: list[IterationLog]
    case_id: str
    timeline: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Parser output dataclasses (used only within mcp_server/parsers/)
# ---------------------------------------------------------------------------


@dataclass
class ProcessEntry:
    pid: int
    ppid: int
    name: str
    create_time: str | None = None
    cmd: str | None = None
    exit_time: str | None = None


@dataclass
class NetworkConnection:
    proto: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int | None = None


@dataclass
class MalfindRegion:
    pid: int
    process_name: str
    start: str
    end: str
    tag: str
    hex_dump: str
    disassembly: str


@dataclass
class DnsQuery:
    src_ip: str
    query_name: str
    query_type: str
    response_ips: list[str] = field(default_factory=list)
    timestamp: str | None = None


@dataclass
class HttpRequest:
    src_ip: str
    dst_ip: str
    method: str
    host: str
    uri: str
    user_agent: str
    status_code: int | None = None
    timestamp: str | None = None


@dataclass
class FileEntry:
    path: str
    size: int
    modified: str | None = None
    created: str | None = None
    deleted: bool = False
    inode: int | None = None


@dataclass
class RegistryEntry:
    key: str
    value_name: str
    value_type: str
    value_data: str
    last_written: str | None = None


@dataclass
class EventLogEntry:
    event_id: int
    channel: str
    timestamp: str
    provider: str
    level: str
    message: str
    data: dict[str, str] = field(default_factory=dict)


@dataclass
class PrefetchEntry:
    executable: str
    run_count: int
    last_run: str | None = None
    volumes: list[str] = field(default_factory=list)


@dataclass
class AmcacheEntry:
    name: str
    path: str
    sha1: str | None = None
    file_id: str | None = None
    last_modified: str | None = None


@dataclass
class ShimcacheEntry:
    path: str
    last_modified: str | None = None
    exec_flag: bool | None = None


@dataclass
class NetworkConversation:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    start_time: str | None = None
    end_time: str | None = None


@dataclass
class TimelineEvent:
    timestamp: str
    source: str
    event_type: str
    description: str
    artifact: str
    pid: int | None = None
    ioc: str | None = None


@dataclass
class CorrelationResult:
    disk_pid: int | None
    memory_pid: int | None
    process_name: str
    matched: bool
    disk_path: str | None = None
    memory_cmd: str | None = None
    anomalies: list[str] = field(default_factory=list)


@dataclass
class TimelineGap:
    start: str
    end: str
    duration_seconds: float
    preceding_event: str | None = None
    following_event: str | None = None
    significance: str = "low"
