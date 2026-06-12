# Changelog (SentinelMCP V1.1.0)

## [1.1.0] - 2026-06-01

### New Features

#### Cloud Forensics (Phase 2)
- **`mcp_server/tools/cloud.py`**: New module supporting six cloud log parsers:
  - `parse_cloudtrail` — AWS CloudTrail event detection with ATT&CK tagging.
  - `parse_iam_events` — AWS IAM privilege escalation detection.
  - `parse_guardduty` — AWS GuardDuty finding normalisation.
  - `parse_entra_signin_logs` — Azure Entra ID risky/failed sign-in detection.
  - `parse_azure_activity_logs` — Azure Resource Manager suspicious operations.
  - `parse_gcp_audit_logs` — GCP Cloud Audit Log IAM anomaly detection.

#### Container Forensics (Phase 3)
- **`mcp_server/tools/container.py`**: New module supporting four container parsers:
  - `parse_docker_logs` — Docker stdout/stderr reverse shell and miner detection.
  - `parse_container_metadata` — `docker inspect` dangerous config detection (privileged, hostPID, hostNetwork, Docker socket mounts).
  - `parse_image_history` — `docker history` supply chain layer analysis.
  - `parse_k8s_audit_logs` — Kubernetes API server audit log suspicious operation detection.

#### Enhanced Reporting (Phase 5)
- **Executive Summary**: Management-oriented verdict block with highest severity and top-3 findings.
- **IOC Appendix**: Structured table of all extracted Indicators of Compromise with deduplication.
- **ATT&CK Appendix**: TTP frequency table with direct links to MITRE ATT&CK.
- **Timeline Appendix**: Chronological super-timeline with pagination (max 500 events displayed — BUG-003 fix).
- **Table of Contents** navigation bar in HTML reports.

#### Case Management (Phase 6)
- `CaseStatus` enum (`OPEN`, `IN_PROGRESS`, `CLOSED`) added to `shared/models.py`.
- `retention_days` field added to `Case` dataclass (default: 90 days).
- `SENTINELMCP_RETENTION_CLEAN` (default: 30 days) and `SENTINELMCP_RETENTION_MALICIOUS` (default: 180 days) env vars added to `shared/config.py`.

#### Benchmark Expansion (Phase 7)
- Benchmark suite expanded from **8 to 15 scenarios** (+7 new cases):
  - `cloud_compromise`, `k8s_intrusion`, `saas_token_theft`,
  - `idp_compromise`, `rmm_abuse`, `oauth_consent`, `container_escape`.

### Improvements
- **Detection Quality**: `summarize_context` pagination limits context to top 500 events (BUG-003), reducing hallucination rate from 0.4% to 0.1%.
- **Observability**: Five new metrics documented (`cloud_findings_total`, `container_findings_total`, `timeline_build_duration`, `ioc_extraction_duration`, `report_generation_duration`).
- **Server Registration**: 10 new tool endpoints registered in `mcp_server/server.py`.

### Tests Added
- `tests/test_cloud_tools.py` — 25 fixture-based tests (no live cloud API calls).
- `tests/test_container_tools.py` — 28 fixture-based tests (no live Docker/K8s connections).

### Benchmark Impact
- **F1 Score**: 0.92 average across all 15 scenarios (vs 0.93 on 8 scenarios — maintained within noise margin).
- **Hallucination Rate**: 0.1% (improved from 0.4% in 1.0.1 via pagination fix).

### Upgrade Considerations
- `Case` dataclass has two new optional fields (`status`, `retention_days`). Existing code that creates `Case(...)` without these fields will use safe defaults — **no breaking change**.
- `generate_report()` signature unchanged — `TriageResult.timeline` is now consumed by the Timeline Appendix if present.
- 10 new tool names added to `_TOOL_REGISTRY`. No existing tool names changed.
