"""Deterministic gap analysis evaluator — no LLM calls.

Rules are pure Python logic operating on the Finding list and Case.
Every public function in this module must remain LLM-free.
"""
from __future__ import annotations

import logging

from shared.models import Case, Finding, FindingStatus, Gap

logger = logging.getLogger(__name__)

# Tool names referenced in gap suggestions
_TOOL_PSLIST = "vol3_pslist"
_TOOL_NETSCAN = "vol3_netscan"
_TOOL_MALFIND = "vol3_malfind"
_TOOL_CMDLINE = "vol3_cmdline"
_TOOL_EVTXDUMP = "evtxdump"
_TOOL_MFTDUMP = "mftdump"
_TOOL_REGLOOKUP = "reglookup"
_TOOL_TSHARK_DNS = "tshark_dns"
_TOOL_TSHARK_HTTP = "tshark_http"
_TOOL_TSHARK_CONV = "tshark_conversations"
_TOOL_AMCACHE = "amcacheparser"
_TOOL_PECMD = "pecmd"
_TOOL_CORRELATE = "correlate_disk_memory"
_TOOL_TIMELINE = "timeline_gaps"

_SENTINEL_FINDING_ID = "gap-evaluator"


def _has_tool(findings: list[Finding], tool: str) -> bool:
    """Return True if *tool* appears in any finding's source_tools."""
    return any(tool in f.source_tools for f in findings)


def _confirmed_or_inferred(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.status != FindingStatus.UNSUPPORTED]


def find_gaps(findings: list[Finding], case: Case) -> list[Gap]:
    """Apply all gap rules and return a deduplicated list of Gaps.

    This function is the sole public API of the evaluator.
    """
    gaps: list[Gap] = []

    active = _confirmed_or_inferred(findings)
    tools_used = {t for f in findings for t in f.source_tools}

    # Rule 1: Memory image provided but no memory tools run
    if case.memory_path and not any(
        t in tools_used for t in [_TOOL_PSLIST, _TOOL_NETSCAN, _TOOL_MALFIND]
    ):
        gaps.append(Gap(
            suggested_tool=_TOOL_PSLIST,
            suggested_params={"memory_path": case.memory_path},
            description="Memory image present but no memory tools were executed.",
            finding_id=_SENTINEL_FINDING_ID,
        ))

    # Rule 2: Disk image provided but no disk tools run
    if case.disk_path and not any(
        t in tools_used for t in [_TOOL_MFTDUMP, _TOOL_EVTXDUMP, _TOOL_AMCACHE]
    ):
        gaps.append(Gap(
            suggested_tool=_TOOL_MFTDUMP,
            suggested_params={"image_path": case.disk_path},
            description="Disk image present but no disk tools were executed.",
            finding_id=_SENTINEL_FINDING_ID,
        ))

    # Rule 3: PCAP provided but no network tools run
    if case.pcap_path and not any(
        t in tools_used for t in [_TOOL_TSHARK_DNS, _TOOL_TSHARK_HTTP, _TOOL_TSHARK_CONV]
    ):
        gaps.append(Gap(
            suggested_tool=_TOOL_TSHARK_CONV,
            suggested_params={"pcap_path": case.pcap_path},
            description="PCAP present but no network tools were executed.",
            finding_id=_SENTINEL_FINDING_ID,
        ))

    # Rule 4: Suspicious process finding without cmdline evidence
    for f in active:
        if "process" in f.title.lower() and _TOOL_CMDLINE not in f.source_tools:
            gaps.append(Gap(
                suggested_tool=_TOOL_CMDLINE,
                suggested_params={"memory_path": case.memory_path},
                description=f"Finding '{f.title}' lacks command-line evidence.",
                finding_id=f.id,
            ))
            break  # one cmdline gap is enough

    # Rule 5: Network IOC without DNS resolution context
    network_ioc_findings = [
        f for f in active
        if f.ioc_type in ("ip", "domain") and _TOOL_TSHARK_DNS not in f.source_tools
    ]
    for f in network_ioc_findings[:2]:  # cap at 2 gaps
        gaps.append(Gap(
            suggested_tool=_TOOL_TSHARK_DNS,
            suggested_params={"pcap_path": case.pcap_path},
            description=f"Network IOC '{f.ioc_value}' found but DNS context is missing.",
            finding_id=f.id,
        ))

    # Rule 6: Findings present but no cross-correlation run
    if active and case.disk_path and case.memory_path and _TOOL_CORRELATE not in tools_used:
        gaps.append(Gap(
            suggested_tool=_TOOL_CORRELATE,
            suggested_params={
                "image_path": case.disk_path,
                "memory_path": case.memory_path,
            },
            description="Both disk and memory are present but cross-correlation was not run.",
            finding_id=_SENTINEL_FINDING_ID,
        ))

    # Rule 7: Event log clearing (event IDs 1102/104)
    if case.disk_path:
        if not any("1102" in " ".join(f.evidence) for f in active):
            gaps.append(Gap(
                suggested_tool=_TOOL_EVTXDUMP,
                suggested_params={"image_path": case.disk_path, "channel": "Security"},
                description="Event ID 1102 (Security log clearing) not verified.",
                finding_id=_SENTINEL_FINDING_ID,
            ))
        if not any("104" in " ".join(f.evidence) for f in active):
            gaps.append(Gap(
                suggested_tool=_TOOL_EVTXDUMP,
                suggested_params={"image_path": case.disk_path, "channel": "System"},
                description="Event ID 104 (System log clearing) not verified.",
                finding_id=_SENTINEL_FINDING_ID,
            ))

    # Rule 8: Registry persistence
    pers_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SYSTEM\CurrentControlSet\Services",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        r"SOFTWARE\Microsoft\Wbem\CIMOM"
    ]
    if case.disk_path:
        for key in pers_keys:
            if not any(_TOOL_REGLOOKUP in f.source_tools and key.lower() in " ".join(f.evidence).lower() for f in findings):
                gaps.append(Gap(
                    suggested_tool=_TOOL_REGLOOKUP,
                    suggested_params={"image_path": case.disk_path, "key": key},
                    description=f"Registry persistence key '{key}' not investigated.",
                    finding_id=_SENTINEL_FINDING_ID,
                ))

    # Sysmon rule
    has_process = any("process" in f.title.lower() or "execution" in f.title.lower() for f in active)
    has_sysmon = any(_TOOL_EVTXDUMP in f.source_tools and "sysmon" in " ".join(f.evidence).lower() for f in findings)
    if has_process and case.disk_path and not has_sysmon:
        gaps.append(Gap(
            suggested_tool=_TOOL_EVTXDUMP,
            suggested_params={"image_path": case.disk_path, "channel": "Microsoft-Windows-Sysmon/Operational"},
            description="Process execution found but Sysmon data not reviewed.",
            finding_id=_SENTINEL_FINDING_ID,
        ))

    logger.debug("find_gaps produced %d gap(s) from %d finding(s)", len(gaps), len(findings))
    return _deduplicate(gaps)


def _deduplicate(gaps: list[Gap]) -> list[Gap]:
    """Remove duplicate gaps by (suggested_tool, finding_id, params) tuples."""
    import json
    seen: set[tuple[str, str, str]] = set()
    result: list[Gap] = []
    for g in gaps:
        key = (g.suggested_tool, g.finding_id, json.dumps(g.suggested_params, sort_keys=True))
        if key not in seen:
            seen.add(key)
            result.append(g)
    return result
