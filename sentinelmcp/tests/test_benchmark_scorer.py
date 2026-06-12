"""Tests for benchmark/scorer.py — BUG-006."""
from __future__ import annotations

from benchmark.scorer import score_result
from shared.models import Finding, FindingStatus, TriageResult


def _result(findings: list[Finding]) -> TriageResult:
    return TriageResult(findings=findings, gaps=[], iterations=[], case_id="bench-001")


_GT = {
    "known_evil": ["mimikatz.exe", "192.168.10.50"],
    "known_clean": ["svchost.exe", "explorer.exe"],
    "attack_timeline": ["credential dumping via lsass", "psexec lateral movement"],
}


class TestScorerPrimary:
    def test_perfect_confirmed_score(self) -> None:
        findings = [
            Finding(title="Mimikatz", status=FindingStatus.CONFIRMED, ioc_type="hash", ioc_value="mimikatz.exe"),
            Finding(title="Lateral movement to 192.168.10.50", status=FindingStatus.CONFIRMED,
                    ioc_type="ip", ioc_value="192.168.10.50"),
        ]
        scores = score_result(_result(findings), _GT)
        assert scores["confirmed_tp"] == 2
        assert scores["f1"] > 0.0

    def test_clean_process_is_false_positive(self) -> None:
        findings = [
            Finding(title="Suspicious", status=FindingStatus.CONFIRMED,
                    ioc_type="process", ioc_value="svchost.exe"),
        ]
        scores = score_result(_result(findings), _GT)
        assert scores["hallucination_rate"] > 0.0

    def test_no_findings_zero_f1(self) -> None:
        scores = score_result(_result([]), _GT)
        assert scores["f1"] == 0.0

    def test_precision_recall_f1_in_range(self) -> None:
        findings = [
            Finding(title="T", status=FindingStatus.CONFIRMED, ioc_value="mimikatz.exe"),
        ]
        scores = score_result(_result(findings), _GT)
        assert 0.0 <= scores["precision"] <= 1.0
        assert 0.0 <= scores["recall"] <= 1.0
        assert 0.0 <= scores["f1"] <= 1.0


class TestScorerBug006:
    """BUG-006: INFERRED findings must contribute to secondary metrics."""

    def test_all_inferred_shows_nonzero_inferred_recall(self) -> None:
        """Gameable: agent marks everything INFERRED. Should show inferred_recall but zero primary F1."""
        findings = [
            Finding(title="Mimikatz", status=FindingStatus.INFERRED, ioc_value="mimikatz.exe"),
            Finding(title="LM to 192.168.10.50", status=FindingStatus.INFERRED, ioc_value="192.168.10.50"),
        ]
        scores = score_result(_result(findings), _GT)
        # Primary metric: zero — the agent gamed it
        assert scores["confirmed_tp"] == 0
        assert scores["f1"] == 0.0
        # Secondary metric: non-zero — the strategy is now visible
        assert scores["inferred_tp"] > 0
        assert scores["inferred_recall"] > 0.0

    def test_inferred_secondary_keys_present(self) -> None:
        scores = score_result(_result([]), _GT)
        assert "inferred_tp" in scores
        assert "inferred_fn" in scores
        assert "inferred_recall" in scores

    def test_confirmed_findings_dont_double_count_inferred(self) -> None:
        """A CONFIRMED finding should not also count as INFERRED."""
        findings = [
            Finding(title="Mimikatz", status=FindingStatus.CONFIRMED, ioc_value="mimikatz.exe"),
        ]
        scores = score_result(_result(findings), _GT)
        assert scores["confirmed_tp"] == 1
        assert scores["inferred_tp"] == 0
