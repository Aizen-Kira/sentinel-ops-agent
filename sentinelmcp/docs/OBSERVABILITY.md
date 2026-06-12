# Observability & Monitoring Package (V1.1.0)

## Goal
Establish a structured approach for monitoring SentinelMCP in production, guaranteeing rapid anomaly detection and system transparency.

---

## Telemetry Metrics

SentinelMCP outputs critical telemetry during operational cycles. Monitoring systems (Prometheus, Datadog, CloudWatch) should alert on severe deviations of the following metrics:

### Core Metrics (V1.0.x)
- `triage_duration`: End-to-end time of a complete 6-phase triage loop. (Baseline: <15s)
- `tool_execution_time`: Latency of individual MCP tool dispatch calls.
- `cache_hit_rate`: Efficiency of the `ToolCache`. (Expected: ~65% during re-evaluation)
- `gap_count`: Number of logical gaps identified per iteration.
- `finding_count`: Total unique findings parsed per triage run.
- `queue_depth`: Backlog depth of the `realtime/pipeline.py` ingestion queue.
- `error_rate`: Rate of unhandled or handled exceptions inside MCP parser routines.

### New Metrics (V1.1.0)
- `cloud_findings_total`: Total findings produced by cloud forensic parsers (`parse_cloudtrail`, `parse_guardduty`, `parse_entra_signin_logs`, `parse_gcp_audit_logs`, etc.).
- `container_findings_total`: Total findings produced by container forensic parsers (`parse_docker_logs`, `parse_container_metadata`, `parse_k8s_audit_logs`, etc.).
- `timeline_build_duration`: Elapsed time for `build_super_timeline` to correlate all sources. (Target: <500ms for <5,000 events)
- `ioc_extraction_duration`: Time taken by the regex IOC extraction pipeline per triage run. (Target: <50ms per 1,000 lines)
- `report_generation_duration`: Time taken to render the final HTML report (including Executive Summary, IOC Appendix, ATT&CK Appendix, and Timeline Appendix). (Target: <200ms)

---

## Logging Standards

SentinelMCP strictly categorizes diagnostic output across four levels.

### `DEBUG`
- Granular step-by-step function tracing.
- Malformed line skipping inside `parsers/`.
- Full HTTP request tracing to Anthropic.
- Path resolution verification events.
- Per-event container/cloud parser processing.

### `INFO`
- General operational state.
- Loop iteration start/stop events.
- Cache eviction and hit rate summaries.
- Service startup and pipeline burst flushes.
- New cloud finding summaries (source + count).

### `WARNING`
- Recoverable configuration misconfigurations (e.g., fallback to defaults).
- Individual tool execution failures (e.g., corrupt PCAP, missing CloudTrail event fields).
- Timeline pagination activation (>500 events truncated in report).

### `ERROR`
- Irrecoverable system states.
- Total failure of the Anthropic LLM connection (timeout, invalid key).
- Critical pipeline deadlocks requiring process restarts.
- Missing mandatory evidence fields in cloud/container parser inputs.

---

## Alerting Recommendations

| Metric | Alert Threshold | Suggested Action |
|--------|----------------|------------------|
| `triage_duration` p95 | > 60s | Investigate PCAP size or Anthropic latency |
| `error_rate` | > 1% | Review `ERROR` logs for parser failures |
| `queue_depth` | > 50 events | Scale ingestion workers |
| `cloud_findings_total` spike | +200% vs baseline | Initiate cloud triage |
| `container_findings_total` spike | +200% vs baseline | Initiate container triage |
| `cache_hit_rate` | < 10% | Verify TTL config (`SENTINELMCP_CACHE_TTL`) |
