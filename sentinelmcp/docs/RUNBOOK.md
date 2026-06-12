# Incident Response Runbook

This runbook supports administrators and operators in resolving production issues with SentinelMCP.

## 1. Startup Failure
**Symptom:** `sentinelmcp` immediately exits or MCP server refuses connections.
**Resolution:**
1. Verify Python version (`>=3.10`).
2. Verify `SENTINELMCP_API_KEY` is accurately set in the environment or Docker compose file.
3. Validate that `SENTINELMCP_ALLOWED_PATHS` exists and the `sentinel` OS user possesses read-access.

## 2. API Authentication Failure
**Symptom:** Client receives HTTP 401/403 connecting to the FastMCP SSE endpoint.
**Resolution:**
1. Check the client headers for `x-api-key`.
2. Confirm the key exactly matches the server's `SENTINELMCP_API_KEY` environment variable. (Whitespace padded keys will fail).

## 3. Cache Corruption / Deadlocks
**Symptom:** Loop iterations hang indefinitely or tools return wildly inaccurate duplicated data.
**Resolution:**
1. Send a SIGTERM to the pipeline.
2. If running via Docker, restart the container (`docker restart sentinelmcp-server`) to flush the in-memory `ToolCache`.
3. Check `STABILITY_REPORT.md` references; deadlocks usually imply severe host-level resource contention.

## 4. Parser Failure
**Symptom:** High `error_rate` logged regarding `mcp_server/parsers/*`.
**Resolution:**
1. Check the `WARNING` and `DEBUG` logs for malformed tabular output.
2. The forensic tooling (e.g., Volatility, tshark) may have encountered an unsupported artifact format. Validate the evidence manually.
3. The pipeline handles parser failures gracefully and records the error in the context without breaking the triage.

## 5. Benchmark Regression
**Symptom:** `pytest` benchmark scoring falls drastically (e.g., F1 < 0.90).
**Resolution:**
1. Ensure the dataset matches the schemas (`known_iocs`, `timeline_events`). 
2. If the LLM prompt was altered, revert to the V1.0.0 baseline prompt inside `agent/loop.py`.

## 6. Timeline Corruption
**Symptom:** Events in `build_super_timeline` are wildly out of order.
**Resolution:**
1. Validate the local system's `timezone` configurations (always utilize UTC natively).
2. Manually verify the timestamps inside the generated `mftdump` or `pslist` artifacts.

## 7. Deployment Rollback
**Symptom:** V1.1.0 update corrupts the pipeline.
**Resolution:**
1. In local environments: `pip install sentinelmcp==1.0.0`.
2. In Docker: alter `docker-compose.yml` to specify `image: sentinelmcp:v1.0.0` and run `docker-compose up -d`.
