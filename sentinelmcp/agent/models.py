"""Compatibility shim — BUG-007 fix.

Previously used 'from shared.models import *' (star import).
Now uses explicit named imports. Importers that previously used agent.models
can continue to work; new code should import directly from shared.models.
"""
from __future__ import annotations

from shared.models import (  # noqa: F401  (re-exported for backwards compat)
    AmcacheEntry,
    Case,
    CorrelationResult,
    DnsQuery,
    EventLogEntry,
    FileEntry,
    Finding,
    FindingStatus,
    Gap,
    HttpRequest,
    IterationLog,
    MalfindRegion,
    NetworkConnection,
    NetworkConversation,
    PrefetchEntry,
    ProcessEntry,
    RegistryEntry,
    TimelineEvent,
    TimelineGap,
    TriageResult,
)

__all__ = [
    "AmcacheEntry",
    "Case",
    "CorrelationResult",
    "DnsQuery",
    "EventLogEntry",
    "FileEntry",
    "Finding",
    "FindingStatus",
    "Gap",
    "HttpRequest",
    "IterationLog",
    "MalfindRegion",
    "NetworkConnection",
    "NetworkConversation",
    "PrefetchEntry",
    "ProcessEntry",
    "RegistryEntry",
    "TimelineEvent",
    "TimelineGap",
    "TriageResult",
]
