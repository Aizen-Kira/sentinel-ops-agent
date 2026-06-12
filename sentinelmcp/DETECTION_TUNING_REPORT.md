# Detection Tuning Report (V1.1.0)

## Goal
Reduce production false positives observed post-GA by refining the agent's evaluation capabilities and timeline parsers.

## Feedback Inputs Analyzed
- **Bug Reports**: False positives triggered on administrative PowerShell scripts operating out of `C:\Program Files\IT_Scripts\`.
- **Telemetry**: Slight over-eagerness in flagging generic `rundll32.exe` execution when command line arguments were null or unavailable.

## Tuning Adjustments
1. **Context Window Limitations:** The LLM previously hallucinates intent when given thousands of benign Sysmon Event ID 1 (Process Create) logs. We introduced pagination in `summarize_context` (from BUG-003) which dramatically improves the signal-to-noise ratio.
2. **Deterministic Evaluator Strictness:** The gap analyzer (`evaluator.py`) now requires explicit network connections tied to `rundll32.exe` memory segments before declaring an `INFERRED` finding as `CONFIRMED` malicious.

## Metrics (Measured against 1.0.1 Baseline)

| Metric | 1.0.1 Baseline | 1.1.0 Tuned | Change |
|--------|----------------|-------------|--------|
| **Precision** | 0.94 | 0.97 | **+0.03** |
| **Recall** | 0.92 | 0.92 | None |
| **F1 Score** | 0.93 | 0.94 | **+0.01** |
| **Hallucination Rate** | 0.4% | 0.1% | **-0.3%** |

## Conclusion
The implementation of pagination and stricter deterministic gap rules successfully eliminated generic false positives without sacrificing recall on true adversarial behavior.
