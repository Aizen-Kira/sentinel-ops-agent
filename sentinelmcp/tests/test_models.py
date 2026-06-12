"""Tests for shared/models.py — dataclass construction and defaults."""
from __future__ import annotations

from shared.models import (
    Case,
    Finding,
    FindingStatus,
    Gap,
    TriageResult,
)


class TestFinding:
    def test_default_status_is_inferred(self) -> None:
        f = Finding()
        assert f.status == FindingStatus.INFERRED

    def test_default_severity_is_info(self) -> None:
        f = Finding()
        assert f.severity == "info"

    def test_unique_ids(self) -> None:
        f1, f2 = Finding(), Finding()
        assert f1.id != f2.id

    def test_ttp_ids_default_empty(self) -> None:
        f = Finding()
        assert f.ttp_ids == []

    def test_source_tools_mutable_default(self) -> None:
        f1, f2 = Finding(), Finding()
        f1.source_tools.append("tool_a")
        assert "tool_a" not in f2.source_tools


class TestCase:
    def test_empty_paths_by_default(self) -> None:
        c = Case()
        assert c.disk_path == ""
        assert c.memory_path == ""
        assert c.pcap_path == ""

    def test_unique_ids(self) -> None:
        c1, c2 = Case(), Case()
        assert c1.id != c2.id


class TestGap:
    def test_construction(self) -> None:
        g = Gap(
            suggested_tool="vol3_pslist",
            suggested_params={"memory_path": "/mem.dmp"},
            description="Missing memory analysis",
            finding_id="f-001",
        )
        assert g.suggested_tool == "vol3_pslist"
        assert g.finding_id == "f-001"


class TestTriageResult:
    def test_construction(self) -> None:
        tr = TriageResult(findings=[], gaps=[], iterations=[], case_id="c-001")
        assert tr.case_id == "c-001"
        assert tr.findings == []


class TestFindingStatus:
    def test_enum_values(self) -> None:
        assert FindingStatus.CONFIRMED.value == "CONFIRMED"
        assert FindingStatus.INFERRED.value == "INFERRED"
        assert FindingStatus.UNSUPPORTED.value == "UNSUPPORTED"
