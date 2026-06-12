"""Self-correction agent loop.

Architecture (6 phases per iteration):
  Phase 1 — Dispatch MCP tools via call_mcp_tools()
  Phase 2 — Claude triage: tool results → Finding list
  Phase 3 — Claude self-evaluation: assign CONFIRMED/INFERRED/UNSUPPORTED
  Phase 4 — Deterministic gap analysis via evaluator.find_gaps()
  Phase 5 — Targeted re-run of gap tools
  Phase 6 — Convergence check (no gaps or max_iter reached)

call_mcp_tools() and call_claude() are module-level so tests can patch them:
    unittest.mock.patch("agent.loop.call_mcp_tools", ...)
    unittest.mock.patch("agent.loop.call_claude", ...)
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agent.evaluator import find_gaps
from shared.ioc import extract_iocs
from shared.models import Case, Finding, FindingStatus, Gap, IterationLog, TriageResult

logger = logging.getLogger(__name__)

# Maximum tool results kept per tool name across iterations (BUG-005 mitigation).
_MAX_RESULTS_PER_TOOL = 2

_TRIAGE_SYSTEM = """You are a DFIR (Digital Forensics and Incident Response) triage analyst.
Given raw tool output, extract structured findings as a JSON array.
Each finding must have: title, description, severity (critical/high/medium/low/info),
source_tools (list), evidence (list of strings), ioc_type (null or ip/domain/hash/path),
ioc_value (null or string), ttp_ids (list of ATT&CK TTP strings like T1003).
Return ONLY the JSON array, no prose."""

_EVAL_SYSTEM = """You are a DFIR evidence quality assessor.
For each finding, assign a status:
  CONFIRMED — directly supported by tool output in evidence
  INFERRED  — logically implied but not directly observed
  UNSUPPORTED — speculation with no supporting evidence
Return a JSON array of {id, status} objects matching the input findings exactly."""

_INITIAL_TOOLS: list[dict[str, Any]] = [
    {"tool": "vol3_pslist", "params": {}},
    {"tool": "vol3_netscan", "params": {}},
    {"tool": "vol3_malfind", "params": {}},
    {"tool": "mftdump", "params": {}},
    {"tool": "evtxdump", "params": {"channel": "Security"}},
    {"tool": "tshark_conversations", "params": {}},
]


# ---------------------------------------------------------------------------
# Module-level patchable functions
# ---------------------------------------------------------------------------


def call_mcp_tools(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dispatch tools directly to the MCP server.  Patchable by tests."""
    from mcp_server.server import dispatch_tool
    from shared.cache import get_cache

    results: list[dict[str, Any]] = []
    cache = get_cache()

    for tc in tool_calls:
        tool_name: str = tc.get("tool", "")
        params: dict[str, Any] = tc.get("params", {})
        try:
            cached_result = cache.get(tool_name, params)
            if cached_result is not None:
                results.append({"tool": tool_name, "result": cached_result, "error": None})
            else:
                result = dispatch_tool(tool_name, params)
                cache.set(tool_name, params, result)
                results.append({"tool": tool_name, "result": result, "error": None})
        except Exception as exc:  # noqa: BLE001
            logger.warning("MCP tool %s failed: %s", tool_name, exc)
            # BUG-004 fix: failures are represented in the result list
            results.append({"tool": tool_name, "result": None, "error": str(exc)})
    return results


def call_claude(messages: list[dict[str, Any]], system: str = "") -> str:
    """Send messages to Claude and return the text response.  Patchable by tests."""
    import anthropic  # lazy import so unit tests need not install SDK

    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=4096,
        system=system,
        messages=messages,  # type: ignore[arg-type]
    )
    block = response.content[0]
    return block.text  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dispatch_tool_return(
    tc: dict[str, Any],
    case: Case,
    iteration: int,
) -> list[dict[str, Any]]:
    """Dispatch a single tool call and return results with iteration tag."""
    tool_name: str = tc.get("tool", "")
    params: dict[str, Any] = {**tc.get("params", {})}

    # Inject case paths into params if not explicitly provided.
    if case.disk_path and "image_path" not in params:
        params["image_path"] = case.disk_path
    if case.memory_path and "memory_path" not in params:
        params["memory_path"] = case.memory_path
    if case.pcap_path and "pcap_path" not in params:
        params["pcap_path"] = case.pcap_path

    try:
        results = call_mcp_tools([{"tool": tool_name, "params": params}])
        for r in results:
            r["_iteration"] = iteration
        return results
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected error dispatching %s: %s", tool_name, exc)
        # BUG-004 fix: always record the failure
        return [{"tool": tool_name, "result": None, "error": str(exc), "_iteration": iteration}]


def _dispatch_tool(
    tc: dict[str, Any],
    case: Case,
    accumulated_context: list[dict[str, Any]],
    iteration: int,
) -> None:
    """Dispatch one tool; append result (or error) to accumulated_context."""
    accumulated_context.extend(_dispatch_tool_return(tc, case, iteration))


def summarize_context(
    accumulated_context: list[dict[str, Any]],
    current_iteration: int,
    active_gaps: list[Gap] | None = None,
    all_findings: list[Finding] | None = None,
) -> list[dict[str, Any]]:
    """FEATURE-006: Advanced context summarization.

    Strategy:
      - Keep ALL entries from current iteration
      - Keep ALL tool failure entries (error is not None)
      - Keep latest 2 successful results per tool from older iterations
      - Compress excess older results into a summary stub
      - Never discard entries whose source_tool is referenced by an active gap
        if the finding that triggered the gap is in all_findings

    Deterministic — no LLM calls.
    """
    # Build protected tool set: tools referenced by findings linked to active gaps
    protected_tools: set[str] = set()
    if active_gaps and all_findings:
        active_finding_ids = {g.finding_id for g in active_gaps}
        for f in all_findings:
            if f.id in active_finding_ids:
                protected_tools.update(f.source_tools)

    current_iter: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    successful_by_tool: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for entry in accumulated_context:
        tool = entry.get("tool", "")
        if entry.get("_iteration") == current_iteration:
            current_iter.append(entry)
        elif entry.get("error") is not None:
            # Preserve all failures regardless of age
            failures.append(entry)
        else:
            successful_by_tool[tool].append(entry)

    summarized: list[dict[str, Any]] = list(current_iter)
    summarized.extend(failures)

    for tool, entries in sorted(successful_by_tool.items()):  # sorted → deterministic
        if tool in protected_tools:
            # Never compress protected tool results
            summarized.extend(entries)
        elif len(entries) > _MAX_RESULTS_PER_TOOL:
            kept = entries[-_MAX_RESULTS_PER_TOOL:]
            dropped = len(entries) - _MAX_RESULTS_PER_TOOL
            summarized.append({
                "tool": tool,
                "summary": (
                    f"{dropped} older result(s) for '{tool}' compressed "
                    "to save context window."
                ),
            })
            summarized.extend(kept)
        else:
            summarized.extend(entries)

    return summarized


# Legacy alias kept for backward-compat with existing tests
def _summarize_context(
    accumulated_context: list[dict[str, Any]],
    current_iter_tools: set[str],
) -> list[dict[str, Any]]:
    """BUG-005 mitigation (legacy signature).  Delegates to summarize_context."""
    # Map to new API: treat anything in current_iter_tools as current iteration
    # We synthesise a sentinel iteration number to match the set.
    _CURRENT = 0  # sentinel
    tagged = []
    for entry in accumulated_context:
        e = dict(entry)
        if e.get("tool", "") in current_iter_tools:
            e["_iteration"] = _CURRENT
        tagged.append(e)
    return summarize_context(tagged, current_iteration=_CURRENT)


def _parse_findings(raw_json: str) -> list[Finding]:
    """Parse Claude's JSON response into Finding dataclasses."""
    try:
        data = json.loads(raw_json)
        if not isinstance(data, list):
            data = data.get("findings", []) if isinstance(data, dict) else []
    except json.JSONDecodeError:
        logger.warning("Could not parse Claude triage response as JSON.")
        return []

    findings: list[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # FEATURE-011: IOC Extraction Framework
        evidence_text = " ".join(list(item.get("evidence", [])))
        ioc_val = str(item.get("ioc_value", "") or "")
        text_to_scan = f"{item.get('title', '')} {item.get('description', '')} {evidence_text} {ioc_val}"
        extracted = extract_iocs(text_to_scan)

        findings.append(Finding(
            title=str(item.get("title", "")),
            description=str(item.get("description", "")),
            severity=str(item.get("severity", "info")),
            source_tools=list(item.get("source_tools", [])),
            evidence=list(item.get("evidence", [])),
            ttp_ids=list(item.get("ttp_ids", [])),
            ioc_type=item.get("ioc_type") or None,
            ioc_value=item.get("ioc_value") or None,
            extracted_iocs=extracted,
        ))
    return findings


def _apply_statuses(findings: list[Finding], raw_json: str) -> list[Finding]:
    """Apply CONFIRMED/INFERRED/UNSUPPORTED statuses from Claude's eval response."""
    try:
        statuses: list[dict[str, str]] = json.loads(raw_json)
        if not isinstance(statuses, list):
            return findings
    except json.JSONDecodeError:
        logger.warning("Could not parse Claude eval response as JSON.")
        return findings

    id_to_status = {s["id"]: s["status"] for s in statuses if isinstance(s, dict)}
    for f in findings:
        raw = id_to_status.get(f.id, "INFERRED").upper()
        try:
            f.status = FindingStatus(raw)
        except ValueError:
            f.status = FindingStatus.INFERRED
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_correction_loop(case: Case, max_iter: int = 8) -> TriageResult:
    """Run the 6-phase self-correction loop and return a TriageResult."""
    accumulated_context: list[dict[str, Any]] = []
    all_findings: list[Finding] = []
    iteration_logs: list[IterationLog] = []
    gaps: list[Gap] = []

    for iteration in range(1, max_iter + 1):
        logger.info("=== Iteration %d / %d ===", iteration, max_iter)
        current_iter_tools: set[str] = set()

        # --- Phase 1: Dispatch tools -----------------------------------------
        if iteration == 1:
            tool_calls = list(_INITIAL_TOOLS)
        else:
            tool_calls = []

        if iteration > 1 and all_findings:
            gaps = find_gaps(all_findings, case)
            tool_calls = [
                {"tool": g.suggested_tool, "params": g.suggested_params}
                for g in gaps
            ]

        # FEATURE-007: Parallel dispatch on iteration 1 only
        if iteration == 1 and tool_calls:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = []
                for tc in tool_calls:
                    current_iter_tools.add(tc.get("tool", ""))
                    futures.append(executor.submit(_dispatch_tool_return, tc, case, iteration))
                # Collect in submission order → deterministic
                for future in futures:
                    accumulated_context.extend(future.result())
        else:
            # Gap-driven dispatch remains sequential
            for tc in tool_calls:
                current_iter_tools.add(tc.get("tool", ""))
                _dispatch_tool(tc, case, accumulated_context, iteration)

        if not tool_calls:
            logger.info("No tools to dispatch — converged.")
            break

        # --- Phase 2: Claude triage -----------------------------------------
        # FEATURE-006: Advanced context summarization
        summarized = summarize_context(
            accumulated_context,
            current_iteration=iteration,
            active_gaps=gaps,
            all_findings=all_findings,
        )
        context_text = json.dumps(summarized, indent=2)

        triage_response = call_claude(
            messages=[{"role": "user", "content": f"Tool results:\n{context_text}"}],
            system=_TRIAGE_SYSTEM,
        )
        new_findings = _parse_findings(triage_response)

        # --- Phase 3: Claude self-evaluation ---------------------------------
        if new_findings:
            findings_for_eval = json.dumps(
                [{"id": f.id, "title": f.title, "evidence": f.evidence} for f in new_findings],
                indent=2,
            )
            eval_response = call_claude(
                messages=[{"role": "user", "content": f"Findings:\n{findings_for_eval}"}],
                system=_EVAL_SYSTEM,
            )
            new_findings = _apply_statuses(new_findings, eval_response)

        all_findings.extend(new_findings)

        # --- Phase 4: Gap analysis -------------------------------------------
        gaps = find_gaps(all_findings, case)

        # Log iteration
        iteration_logs.append(IterationLog(
            iteration=iteration,
            tools_called=list(current_iter_tools),
            findings_count=len(all_findings),
            gaps_count=len(gaps),
        ))

        # --- Phase 6: Convergence check --------------------------------------
        if not gaps:
            logger.info("No gaps remain — converged at iteration %d.", iteration)
            break

    final_gaps = find_gaps(all_findings, case)
    return TriageResult(
        findings=all_findings,
        gaps=final_gaps,
        iterations=iteration_logs,
        case_id=case.id,
    )
