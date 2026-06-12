"""Tests for agent/reporter.py — HTML generation and XSS prevention (BUG-003)."""
from __future__ import annotations

import html

from agent.reporter import generate_report
from shared.models import Case, Finding, FindingStatus, IterationLog, TriageResult


def _make_result(findings: list[Finding]) -> TriageResult:
    return TriageResult(
        findings=findings,
        gaps=[],
        iterations=[IterationLog(iteration=1, tools_called=["vol3_pslist"], findings_count=len(findings), gaps_count=0)],
        case_id="test-case-001",
    )


def _make_case() -> Case:
    return Case(id="test-case-001", description="Unit test case")


class TestGenerateReport:
    def test_returns_html_string(self) -> None:
        result = _make_result([])
        report = generate_report(result, _make_case())
        assert report.startswith("<!DOCTYPE html>")

    def test_case_id_appears_in_report(self) -> None:
        result = _make_result([])
        report = generate_report(result, _make_case())
        assert "test-case-001" in report

    def test_finding_title_escaped(self) -> None:
        """BUG-003: XSS payload in title must be escaped."""
        xss_title = '<script>alert("xss")</script>'
        f = Finding(
            title=xss_title,
            status=FindingStatus.CONFIRMED,
            severity="critical",
        )
        report = generate_report(_make_result([f]), _make_case())
        assert xss_title not in report
        assert html.escape(xss_title) in report

    def test_evidence_escaped(self) -> None:
        """BUG-003: XSS payload in evidence must be escaped."""
        xss_evidence = '"><img src=x onerror=alert(1)>'
        f = Finding(
            title="Normal Finding",
            evidence=[xss_evidence],
            status=FindingStatus.INFERRED,
        )
        report = generate_report(_make_result([f]), _make_case())
        assert xss_evidence not in report
        assert "&gt;" in report or "&quot;" in report

    def test_ioc_value_escaped(self) -> None:
        """BUG-003: XSS payload in IOC value must be escaped."""
        xss_ioc = '<script>document.cookie</script>'
        f = Finding(
            title="IOC Finding",
            ioc_type="domain",
            ioc_value=xss_ioc,
            status=FindingStatus.CONFIRMED,
        )
        report = generate_report(_make_result([f]), _make_case())
        assert xss_ioc not in report

    def test_description_escaped(self) -> None:
        xss_desc = '&<>"\'injection'
        f = Finding(title="T", description=xss_desc, status=FindingStatus.CONFIRMED)
        report = generate_report(_make_result([f]), _make_case())
        assert xss_desc not in report

    def test_all_statuses_rendered(self) -> None:
        findings = [
            Finding(title="C", status=FindingStatus.CONFIRMED, severity="high"),
            Finding(title="I", status=FindingStatus.INFERRED, severity="medium"),
            Finding(title="U", status=FindingStatus.UNSUPPORTED, severity="low"),
        ]
        report = generate_report(_make_result(findings), _make_case())
        assert "Confirmed Findings" in report
        assert "Inferred Findings" in report
        assert "Unsupported Findings" in report

    def test_owasp_xss_vectors(self) -> None:
        """OWASP XSS test vectors must all be escaped."""
        vectors = [
            '"><script>alert(1)</script>',
            "';alert(String.fromCharCode(88,83,83))//",
            "<img src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
        ]
        for vector in vectors:
            f = Finding(title=vector, description=vector, evidence=[vector],
                        ioc_value=vector, status=FindingStatus.CONFIRMED)
            report = generate_report(_make_result([f]), _make_case())
            assert vector not in report, f"XSS vector not escaped: {vector}"


    def test_ttp_ids_rendered_and_escaped(self) -> None:
        from agent.reporter import generate_report
        from shared.models import Finding, FindingStatus
        f = Finding(
            title="TTP Finding",
            ttp_ids=["T1003", "<script>alert(1)</script>"],
            status=FindingStatus.CONFIRMED,
        )
        # Using a dummy result
        from shared.models import TriageResult
        res = TriageResult(findings=[f], gaps=[], iterations=[], case_id="case1")
        from shared.models import Case
        report = generate_report(res, Case(id="case1"))
        assert "T1003" in report
        assert "<script>" not in report
        assert "&lt;script&gt;" in report
