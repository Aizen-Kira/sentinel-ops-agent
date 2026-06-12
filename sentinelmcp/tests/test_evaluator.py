"""Tests for agent/evaluator.py — gap rules, deduplication."""
from __future__ import annotations

from agent.evaluator import _deduplicate, find_gaps
from shared.models import Case, Finding, FindingStatus, Gap


def _case(**kwargs: str) -> Case:
    defaults = dict(
        disk_path="/evidence/disk.E01",
        memory_path="/evidence/mem.dmp",
        pcap_path="/evidence/cap.pcap",
    )
    defaults.update(kwargs)
    return Case(**defaults)


def _finding(**kwargs: object) -> Finding:
    defaults: dict[str, object] = {
        "title": "Test Finding",
        "status": FindingStatus.CONFIRMED,
        "source_tools": [],
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestFindGapsMemory:
    def test_no_memory_tools_suggests_pslist(self) -> None:
        case = _case()
        gaps = find_gaps([], case)
        tools = [g.suggested_tool for g in gaps]
        assert "vol3_pslist" in tools

    def test_memory_tool_present_no_pslist_gap(self) -> None:
        case = _case()
        f = _finding(source_tools=["vol3_pslist"])
        gaps = find_gaps([f], case)
        tools = [g.suggested_tool for g in gaps]
        assert "vol3_pslist" not in tools

    def test_no_memory_path_no_pslist_gap(self) -> None:
        case = _case(memory_path="")
        gaps = find_gaps([], case)
        tools = [g.suggested_tool for g in gaps]
        assert "vol3_pslist" not in tools


class TestFindGapsDisk:
    def test_no_disk_tools_suggests_mftdump(self) -> None:
        case = _case(memory_path="", pcap_path="")
        gaps = find_gaps([], case)
        tools = [g.suggested_tool for g in gaps]
        assert "mftdump" in tools

    def test_no_disk_path_no_disk_gap(self) -> None:
        case = _case(disk_path="", memory_path="", pcap_path="")
        gaps = find_gaps([], case)
        assert gaps == []


class TestFindGapsNetwork:
    def test_no_network_tools_suggests_tshark(self) -> None:
        case = _case(disk_path="", memory_path="")
        gaps = find_gaps([], case)
        tools = [g.suggested_tool for g in gaps]
        assert "tshark_conversations" in tools


class TestFindGapsCorrelation:
    def test_both_images_suggests_correlation(self) -> None:
        case = _case(pcap_path="")
        f = _finding(source_tools=["vol3_pslist", "mftdump"])
        gaps = find_gaps([f], case)
        tools = [g.suggested_tool for g in gaps]
        assert "correlate_disk_memory" in tools


class TestFindGapsEventLog:
    def test_missing_1102_suggests_security(self) -> None:
        case = _case(memory_path="", pcap_path="")
        gaps = find_gaps([], case)
        assert any(g.suggested_tool == "evtxdump" and g.suggested_params.get("channel") == "Security" for g in gaps)

    def test_missing_104_suggests_system(self) -> None:
        case = _case(memory_path="", pcap_path="")
        gaps = find_gaps([], case)
        assert any(g.suggested_tool == "evtxdump" and g.suggested_params.get("channel") == "System" for g in gaps)

    def test_presence_of_1102_prevents_gap(self) -> None:
        case = _case(memory_path="", pcap_path="")
        f = _finding(evidence=["Log cleared 1102"])
        gaps = find_gaps([f], case)
        assert not any(g.suggested_tool == "evtxdump" and g.suggested_params.get("channel") == "Security" for g in gaps)


class TestFindGapsRegistry:
    def test_missing_run_key_suggests_reglookup(self) -> None:
        case = _case(memory_path="", pcap_path="")
        gaps = find_gaps([], case)
        # Should suggest 5 keys
        reg_gaps = [g for g in gaps if g.suggested_tool == "reglookup"]
        assert len(reg_gaps) == 5

    def test_presence_of_key_prevents_gap(self) -> None:
        case = _case(memory_path="", pcap_path="")
        f = _finding(source_tools=["reglookup"], evidence=[r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"])
        gaps = find_gaps([f], case)
        reg_gaps = [g for g in gaps if g.suggested_tool == "reglookup"]
        assert len(reg_gaps) == 4


class TestFindGapsSysmon:
    def test_process_execution_without_sysmon_suggests_sysmon(self) -> None:
        case = _case(memory_path="", pcap_path="")
        f = _finding(title="Suspicious process execution")
        gaps = find_gaps([f], case)
        assert any(g.suggested_tool == "evtxdump" and g.suggested_params.get("channel") == "Microsoft-Windows-Sysmon/Operational" for g in gaps)

    def test_sysmon_presence_prevents_gap(self) -> None:
        case = _case(memory_path="", pcap_path="")
        f1 = _finding(title="Suspicious process execution")
        f2 = _finding(source_tools=["evtxdump"], evidence=["sysmon event 1"])
        gaps = find_gaps([f1, f2], case)
        assert not any(g.suggested_tool == "evtxdump" and g.suggested_params.get("channel") == "Microsoft-Windows-Sysmon/Operational" for g in gaps)


class TestDeduplicate:
    def test_removes_duplicate_tool_finding_pairs(self) -> None:
        g1 = Gap("tool_a", {}, "desc1", "f-001")
        g2 = Gap("tool_a", {}, "desc2", "f-001")
        g3 = Gap("tool_b", {}, "desc3", "f-001")
        result = _deduplicate([g1, g2, g3])
        assert len(result) == 2
        assert result[0].suggested_tool == "tool_a"
        assert result[1].suggested_tool == "tool_b"

    def test_empty_list(self) -> None:
        assert _deduplicate([]) == []
