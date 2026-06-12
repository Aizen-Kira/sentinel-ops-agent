"""Benchmark harness — runs triage cases and collects raw results."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agent.loop import run_correction_loop
from benchmark.scorer import score_result
from shared.models import Case, TriageResult

logger = logging.getLogger(__name__)

_CASES_DIR = Path(__file__).parent / "cases"


def load_case(case_dir: Path) -> tuple[Case, dict[str, Any]]:
    """Load case.json and ground_truth.json from a case directory."""
    with open(case_dir / "case.json", encoding="utf-8") as f:
        case_data: dict[str, Any] = json.load(f)
    with open(case_dir / "ground_truth.json", encoding="utf-8") as f:
        ground_truth: dict[str, Any] = json.load(f)
    case = Case(
        id=case_data.get("id", case_dir.name),
        disk_path=case_data.get("disk_path", ""),
        memory_path=case_data.get("memory_path", ""),
        pcap_path=case_data.get("pcap_path", ""),
        description=case_data.get("description", ""),
    )
    return case, ground_truth


def run_benchmark(
    cases_dir: Path | None = None,
    max_iter: int = 8,
) -> list[dict[str, Any]]:
    """Run all benchmark cases and return scored results."""
    base = cases_dir or _CASES_DIR
    results: list[dict[str, Any]] = []

    case_dirs = sorted(p for p in base.iterdir() if p.is_dir())
    if not case_dirs:
        logger.warning("No benchmark cases found in %s", base)
        return results

    for case_dir in case_dirs:
        if not (case_dir / "case.json").exists():
            continue
        logger.info("Running benchmark case: %s", case_dir.name)
        case, ground_truth = load_case(case_dir)
        try:
            result: TriageResult = run_correction_loop(case, max_iter=max_iter)
            scores = score_result(result, ground_truth)
            results.append({
                "case": case_dir.name,
                "scores": scores,
                "iterations": len(result.iterations),
                "findings": len(result.findings),
            })
            logger.info("Case %s → F1=%.3f hallucination=%.3f",
                        case_dir.name, scores["f1"], scores["hallucination_rate"])
        except Exception as exc:
            logger.error("Case %s failed: %s", case_dir.name, exc)
            results.append({"case": case_dir.name, "error": str(exc)})

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    scores = run_benchmark()
    print(json.dumps(scores, indent=2))
