# Post-GA Production Findings

## 1. Tshark Conversation Timeout
**Source:** Operator Feedback (SOC Tier 2)
**Summary:** Large PCAP files (>2GB) passed to `tshark_conversations` occasionally timeout before completion, causing the MCP server to return an empty array rather than an error context.
**Severity:** High
**Impact:** Analysts miss lateral movement indicators hiding in large PCAPs. LLM mistakenly assumes there is no network traffic.
**Recommended Action:** Increase the default timeout parameter in `tshark_conversations` wrapper and properly bubble up `TimeoutError` so the Triage logic handles it gracefully.

## 2. API Key Exposure in Unhandled Exception
**Source:** Incident Reports
**Summary:** If the Anthropic API connection abruptly resets during the `agent/loop.py` triage phase, the raw `HTTPException` can occasionally write the full context (including headers) to `DEBUG` logs, which may contain fragments of the API key.
**Severity:** Critical
**Impact:** Secret exposure in local operator logs.
**Recommended Action:** Implement a regex scrubber in the central logging formatter to permanently mask `x-api-key` strings from any stack trace output.

## 3. Excessive Context Bloat on Long Timelines
**Source:** Telemetry Dashboards
**Summary:** The `build_super_timeline` tool outputs massive strings for active domain controllers (10,000+ events per hour), causing the LLM context window to exceed its limits and drop findings.
**Severity:** Medium
**Impact:** Slower triage duration and occasional LLM token exhaustion errors.
**Recommended Action:** Implement pagination or hard-truncation (top 500 events) within the parser returning to MCP.

## 4. Typo in Operations Guide
**Source:** Documentation Feedback
**Summary:** `SENTINELMCP_BURST_THRESHOLD` is misspelled in one subsection of `OPERATIONS.md`.
**Severity:** Low
**Impact:** Minor operator confusion.
**Recommended Action:** Fix typo.
