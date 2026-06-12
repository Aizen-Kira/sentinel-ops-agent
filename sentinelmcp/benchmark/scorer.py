"""Benchmark scorer — BUG-006 fix.

Previous behavior: INFERRED findings were exempt from all scoring,
allowing an agent that marks everything INFERRED to get perfect scores.

Fix: CONFIRMED findings are scored as the primary metric (confirmed_f1).
     INFERRED findings contribute a secondary metric (inferred_recall).
     Both are tracked and reported separately.
"""
from __future__ import annotations

from typing import Any

from shared.models import FindingStatus, TriageResult


def score_result(result: TriageResult, ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Score a TriageResult against ground truth.

    Ground truth schema:
        {
            "known_evil": ["ioc_value_1", "ioc_value_2", ...],
            "known_clean": ["process_name_1", ...],
            "attack_timeline": ["event_description_1", ...]
        }

    Returns:
        {
            "precision": float,
            "recall": float,
            "f1": float,
            "hallucination_rate": float,
            # BUG-006 secondary metrics:
            "confirmed_tp": int,
            "confirmed_fp": int,
            "confirmed_fn": int,
            "inferred_tp": int,
            "inferred_fn": int,
            "inferred_recall": float,
        }
    """
    known_evil: set[str] = {str(x).lower() for x in ground_truth.get("known_evil", [])}
    known_clean: set[str] = {str(x).lower() for x in ground_truth.get("known_clean", [])}
    attack_events: list[str] = [str(x).lower() for x in ground_truth.get("attack_timeline", [])]

    # Sprint 4 additions
    known_iocs = {str(x).lower() for x in ground_truth.get("known_iocs", [])}
    timeline_events = [str(x).lower() for x in ground_truth.get("timeline_events", [])]
    attack_chain = [str(x).lower() for x in ground_truth.get("attack_chain", [])]

    confirmed_findings = [f for f in result.findings if f.status == FindingStatus.CONFIRMED]
    inferred_findings = [f for f in result.findings if f.status == FindingStatus.INFERRED]

    # -----------------------------------------------------------------------
    # Primary metric — CONFIRMED findings only
    # -----------------------------------------------------------------------
    confirmed_tp = 0
    confirmed_fp = 0

    for f in confirmed_findings:
        ioc = (f.ioc_value or "").lower()
        title_lower = f.title.lower()
        # True positive: IOC matches known_evil or title matches an attack event
        is_tp = (
            (ioc and ioc in known_evil)
            or any(ev in title_lower for ev in attack_events)
        )
        # False positive: IOC matches known_clean
        is_fp = (
            (ioc and ioc in known_clean)
            or (f.ioc_value and ioc not in known_evil and not any(ev in title_lower for ev in attack_events))
        )
        if is_tp:
            confirmed_tp += 1
        elif is_fp:
            confirmed_fp += 1

    confirmed_fn = max(0, len(known_evil) - confirmed_tp)

    precision = confirmed_tp / (confirmed_tp + confirmed_fp) if (confirmed_tp + confirmed_fp) > 0 else 0.0
    recall = confirmed_tp / (confirmed_tp + confirmed_fn) if (confirmed_tp + confirmed_fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    # Hallucination: CONFIRMED finding whose IOC is in known_clean
    hallucination_count = sum(
        1 for f in confirmed_findings
        if f.ioc_value and f.ioc_value.lower() in known_clean
    )
    total_confirmed = len(confirmed_findings) or 1
    hallucination_rate = hallucination_count / total_confirmed

    # -----------------------------------------------------------------------
    # BUG-006 secondary metric — INFERRED findings
    # INFERRED recall shows whether the agent at least implied the right IOCs.
    # An agent marking everything INFERRED will show high inferred_recall but
    # zero confirmed_tp, making the gaming strategy obvious.
    # -----------------------------------------------------------------------
    inferred_tp = 0
    inferred_fn = 0

    for f in inferred_findings:
        ioc = (f.ioc_value or "").lower()
        title_lower = f.title.lower()
        if (ioc and ioc in known_evil) or any(ev in title_lower for ev in attack_events):
            inferred_tp += 1

    inferred_fn = max(0, len(known_evil) - inferred_tp - confirmed_tp)
    inferred_recall = (
        inferred_tp / (inferred_tp + inferred_fn)
        if (inferred_tp + inferred_fn) > 0
        else 0.0
    )

    # -----------------------------------------------------------------------
    # Sprint 4 - IOC Extraction Metrics
    # -----------------------------------------------------------------------
    extracted_iocs = set()
    for f in result.findings:
        if hasattr(f, "extracted_iocs"):
            for ioc in getattr(f, "extracted_iocs", []):
                extracted_iocs.add(ioc.value.lower())

    ioc_tp = len(extracted_iocs.intersection(known_iocs))
    ioc_fp = len(extracted_iocs - known_iocs)
    ioc_fn = max(0, len(known_iocs) - ioc_tp)

    ioc_precision = ioc_tp / (ioc_tp + ioc_fp) if (ioc_tp + ioc_fp) > 0 else 0.0
    ioc_recall = ioc_tp / (ioc_tp + ioc_fn) if (ioc_tp + ioc_fn) > 0 else 0.0

    # -----------------------------------------------------------------------
    # Sprint 4 - Timeline Ordering Accuracy
    # -----------------------------------------------------------------------
    # Assuming result may have an optional 'timeline' property
    timeline_ordering_accuracy = 0.0
    if hasattr(result, "timeline") and result.timeline and timeline_events:
        matches = 0
        # simple check for matching sequence
        agent_events = [str(e.get("description", "")).lower() for e in result.timeline.get("events", [])]
        for expected in timeline_events:
            if any(expected in ae for ae in agent_events):
                matches += 1
        timeline_ordering_accuracy = matches / len(timeline_events) if len(timeline_events) > 0 else 0.0

    return {
        # Primary metrics (CONFIRMED only)
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "hallucination_rate": round(hallucination_rate, 4),
        # Raw counts
        "confirmed_tp": confirmed_tp,
        "confirmed_fp": confirmed_fp,
        "confirmed_fn": confirmed_fn,
        # BUG-006 secondary metrics
        "inferred_tp": inferred_tp,
        "inferred_fn": inferred_fn,
        "inferred_recall": round(inferred_recall, 4),
        # Sprint 4 metrics
        "ioc_precision": round(ioc_precision, 4),
        "ioc_recall": round(ioc_recall, 4),
        "timeline_ordering_accuracy": round(timeline_ordering_accuracy, 4),
    }
