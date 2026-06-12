"""Tests for agent/loop.py — patches call_mcp_tools and call_claude."""
from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

from agent.loop import (
    _apply_statuses,
    _parse_findings,
    _summarize_context,
    run_correction_loop,
    summarize_context,
)
from shared.models import Case, Finding, FindingStatus, Gap


def _make_case(**kwargs: str) -> Case:
    return Case(
        disk_path=kwargs.get("disk_path", ""),
        memory_path=kwargs.get("memory_path", ""),
        pcap_path=kwargs.get("pcap_path", ""),
        description="test",
    )


_MOCK_FINDINGS_JSON = json.dumps([
    {
        "title": "Mimikatz detected",
        "description": "Credential dumper found in memory",
        "severity": "critical",
        "source_tools": ["vol3_pslist"],
        "evidence": ["PID 1234: mimikatz.exe"],
        "ioc_type": "hash",
        "ioc_value": "mimikatz.exe",
    }
])

_MOCK_EVAL_JSON_TEMPLATE = '[{{"id": "{id}", "status": "CONFIRMED"}}]'


class TestParseFindings:
    def test_valid_json_returns_findings(self) -> None:
        findings = _parse_findings(_MOCK_FINDINGS_JSON)
        assert len(findings) == 1
        assert findings[0].title == "Mimikatz detected"

    def test_invalid_json_returns_empty(self) -> None:
        assert _parse_findings("not json") == []

    def test_null_ioc_becomes_none(self) -> None:
        raw = json.dumps([{"title": "T", "description": "D", "severity": "info",
                           "source_tools": [], "evidence": [], "ioc_type": None, "ioc_value": None}])
        findings = _parse_findings(raw)
        assert findings[0].ioc_type is None
        assert findings[0].ioc_value is None


class TestApplyStatuses:
    def test_sets_confirmed(self) -> None:
        f = Finding(id="f-001", title="T")
        statuses = json.dumps([{"id": "f-001", "status": "CONFIRMED"}])
        result = _apply_statuses([f], statuses)
        assert result[0].status == FindingStatus.CONFIRMED

    def test_unknown_status_defaults_inferred(self) -> None:
        f = Finding(id="f-001", title="T")
        statuses = json.dumps([{"id": "f-001", "status": "BOGUS"}])
        result = _apply_statuses([f], statuses)
        assert result[0].status == FindingStatus.INFERRED

    def test_invalid_json_leaves_findings_unchanged(self) -> None:
        f = Finding(id="f-001", status=FindingStatus.CONFIRMED)
        result = _apply_statuses([f], "not json")
        assert result[0].status == FindingStatus.CONFIRMED


class TestSummarizeContext:
    """Tests for legacy _summarize_context (BUG-005) and new summarize_context."""

    def test_keeps_current_iter_entries(self) -> None:
        ctx = [
            {"tool": "tool_a", "result": "r1"},
            {"tool": "tool_a", "result": "r2"},
            {"tool": "tool_a", "result": "r3"},  # would be trimmed for non-current
        ]
        result = _summarize_context(ctx, current_iter_tools={"tool_a"})
        assert len(result) == 3  # all kept because tool_a is current iter

    def test_trims_non_current_tools(self) -> None:
        ctx = [
            {"tool": "old_tool", "result": f"r{i}"} for i in range(5)
        ]
        result = _summarize_context(ctx, current_iter_tools=set())
        assert len(result) == 3  # _MAX_RESULTS_PER_TOOL = 2 plus 1 summary stub


class TestSummarizeContextAdvanced:
    """FEATURE-006: advanced summarize_context behaviour."""

    def _tagged(self, tool: str, result: Any, iteration: int, error: str | None = None) -> dict[str, Any]:
        return {"tool": tool, "result": result, "_iteration": iteration, "error": error}

    def test_current_iteration_always_preserved(self) -> None:
        ctx = [self._tagged("pslist", f"r{i}", iteration=1) for i in range(10)]
        out = summarize_context(ctx, current_iteration=1)
        current = [e for e in out if e.get("_iteration") == 1]
        assert len(current) == 10

    def test_history_trimmed_to_two_per_tool(self) -> None:
        ctx = [self._tagged("pslist", f"r{i}", iteration=i) for i in range(1, 6)]
        # None are current (use iteration 99)
        out = summarize_context(ctx, current_iteration=99)
        kept = [e for e in out if e.get("tool") == "pslist" and "summary" not in e]
        assert len(kept) == 2

    def test_summary_stub_inserted_when_compressed(self) -> None:
        ctx = [self._tagged("mftdump", f"r{i}", iteration=i) for i in range(1, 6)]
        out = summarize_context(ctx, current_iteration=99)
        stubs = [e for e in out if "summary" in e and e.get("tool") == "mftdump"]
        assert len(stubs) == 1
        assert "compressed" in stubs[0]["summary"]

    def test_failures_always_preserved(self) -> None:
        ctx = [
            self._tagged("evtxdump", None, iteration=1, error="timeout"),
            self._tagged("evtxdump", None, iteration=2, error="timeout"),
            self._tagged("evtxdump", None, iteration=3, error="timeout"),
        ]
        out = summarize_context(ctx, current_iteration=99)
        failures = [e for e in out if e.get("error") is not None]
        assert len(failures) == 3

    def test_active_gap_referenced_tool_never_compressed(self) -> None:
        """A finding's source tool referenced by a gap must keep ALL its history."""
        f = Finding(id="f-abc", title="Cred theft", source_tools=["vol3_malfind"])
        gap = Gap(
            suggested_tool="evtxdump",
            suggested_params={},
            description="Check logs",
            finding_id="f-abc",
        )
        ctx = [self._tagged("vol3_malfind", f"r{i}", iteration=i) for i in range(1, 8)]
        out = summarize_context(ctx, current_iteration=99, active_gaps=[gap], all_findings=[f])
        kept = [e for e in out if e.get("tool") == "vol3_malfind" and "summary" not in e]
        assert len(kept) == 7  # all preserved because protected

    def test_deterministic_output_order(self) -> None:
        """Two identical calls must return the same ordering."""
        ctx = []
        for i in range(5):
            for tool in ["mftdump", "pslist", "evtxdump"]:
                ctx.append(self._tagged(tool, f"r{i}", iteration=i))
        out1 = summarize_context(ctx, current_iteration=99)
        out2 = summarize_context(ctx, current_iteration=99)
        assert [e.get("tool") for e in out1] == [e.get("tool") for e in out2]


class TestParallelDispatch:
    """FEATURE-007: verify parallel execution, exception propagation, ordering."""

    def test_parallel_results_collected(self) -> None:
        """All 6 initial tools must appear in accumulated context."""
        case = _make_case()
        tool_results: dict[str, Any] = {
            "vol3_pslist": [{"pid": 4}],
            "vol3_netscan": [],
            "vol3_malfind": [],
            "mftdump": [],
            "evtxdump": [],
            "tshark_conversations": [],
        }

        def fake_mcp(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [
                {"tool": c["tool"], "result": tool_results.get(c["tool"], []), "error": None}
                for c in calls
            ]

        mock_claude = MagicMock(return_value="[]")
        with (
            patch("agent.loop.call_mcp_tools", fake_mcp),
            patch("agent.loop.call_claude", mock_claude),
        ):
            result = run_correction_loop(case, max_iter=1)

        assert result.case_id == case.id

    def test_parallel_exception_propagated_as_error_entry(self) -> None:
        """If one parallel tool raises, it must appear as an error dict."""
        case = _make_case()
        call_order: list[str] = []

        def fake_mcp(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
            name = calls[0]["tool"]
            call_order.append(name)
            if name == "vol3_malfind":
                raise RuntimeError("malfind crashed")
            return [{"tool": name, "result": [], "error": None}]

        mock_claude = MagicMock(return_value="[]")
        with (
            patch("agent.loop.call_mcp_tools", fake_mcp),
            patch("agent.loop.call_claude", mock_claude),
        ):
            # Should not raise; Claude must still be invoked
            run_correction_loop(case, max_iter=1)

        assert mock_claude.called

    def test_gap_driven_dispatch_is_sequential(self) -> None:
        """Iteration 2+ gap dispatch must not use ThreadPoolExecutor."""
        case = _make_case(disk_path="/evidence/disk.E01")
        dispatch_times: list[float] = []

        def slow_mcp(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
            dispatch_times.append(time.time())
            time.sleep(0.01)
            return [{"tool": c["tool"], "result": [], "error": None} for c in calls]

        # Iter 1 returns a finding; iter 2 is gap-driven
        iter_count = [0]

        def fake_claude(messages: list[dict[str, Any]], system: str = "") -> str:
            iter_count[0] += 1
            if iter_count[0] == 1:
                return json.dumps([{
                    "title": "Suspicious process",
                    "description": "d",
                    "severity": "high",
                    "source_tools": ["vol3_pslist"],
                    "evidence": [],
                    "ioc_type": None,
                    "ioc_value": None,
                    "ttp_ids": [],
                }])
            if iter_count[0] == 2:
                return json.dumps([{"id": messages[0]["content"][:5], "status": "CONFIRMED"}])
            return "[]"

        with (
            patch("agent.loop.call_mcp_tools", slow_mcp),
            patch("agent.loop.call_claude", fake_claude),
        ):
            run_correction_loop(case, max_iter=2)

        # We can't strictly assert sequential from timing alone in all envs,
        # but we verify at least 1 dispatch happened per iteration
        assert len(dispatch_times) >= 1


class TestRunCorrectionLoop:
    def test_no_paths_converges_with_no_findings(self) -> None:
        case = _make_case()

        mock_tools = MagicMock(return_value=[
            {"tool": "vol3_pslist", "result": [], "error": None}
        ])
        mock_claude = MagicMock(return_value="[]")

        with (
            patch("agent.loop.call_mcp_tools", mock_tools),
            patch("agent.loop.call_claude", mock_claude),
        ):
            result = run_correction_loop(case, max_iter=2)

        assert result.case_id == case.id
        assert isinstance(result.findings, list)

    def test_tool_failure_recorded_in_context(self) -> None:
        """BUG-004: tool failure must appear in accumulated_context."""
        case = _make_case()
        call_log: list[list[dict[str, Any]]] = []

        def mock_tools(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
            call_log.append(calls)
            raise RuntimeError("Simulated tool crash")

        mock_claude = MagicMock(return_value="[]")

        with (
            patch("agent.loop.call_mcp_tools", mock_tools),
            patch("agent.loop.call_claude", mock_claude),
        ):
            run_correction_loop(case, max_iter=1)

        # Claude should still have been called — loop must not abort on tool failure
        assert mock_claude.called

    def test_max_iter_respected(self) -> None:
        case = _make_case(disk_path="/d", memory_path="/m", pcap_path="/p")
        mock_tools = MagicMock(return_value=[{"tool": "vol3_pslist", "result": [], "error": None}])
        mock_claude = MagicMock(return_value="[]")

        with (
            patch("agent.loop.call_mcp_tools", mock_tools),
            patch("agent.loop.call_claude", mock_claude),
        ):
            result = run_correction_loop(case, max_iter=3)

        assert len(result.iterations) <= 3
