# Defect Triage & Patch Candidates (1.0.1)

## Critical Priority (Target: 1.0.1)

### BUG-001: API Key Exposure in Unhandled Exception
- **Type:** Security / Authentication
- **Action:** Implementing an overriding log filter in `shared/config.py` (or central logger) to regex mask `sk-ant-api03.*` from all tracebacks. 

## High Priority (Target: 1.0.1)

### BUG-002: Tshark Conversation Timeout
- **Type:** False Negative Regression
- **Action:** The wrapper in `mcp_server/parsers/network_parsers.py` must be patched to capture `subprocess.TimeoutExpired` and return a structured error message (`"Error: PCAP analysis timed out. Recommend manual investigation."`) rather than an empty list.

## Medium Priority (Target: 1.0.2+)

### BUG-003: Excessive Context Bloat on Long Timelines
- **Type:** Workflow Disruption
- **Action:** Deferred to 1.0.2. Requires a slight architectural adjustment to the `summarize_context` loop to chunk timeline events effectively.

## Low Priority (Target: 1.0.1 - Trivial)

### DOC-001: Typo in Operations Guide
- **Type:** Documentation
- **Action:** Correct spelling of `SENTINELMCP_BURST_THRESHOLD` in `docs/OPERATIONS.md`.
