# Case Management Design

## Goal
To introduce structured status tracking and data retention rules for SentinelMCP investigations.

## Case States
The new `CaseStatus` Enum within the configuration defines the lifecycle of a triage event:
- **OPEN**: Telemetry is actively being ingested into the realtime pipeline, or the agent loop is currently running.
- **IN_PROGRESS**: The agent has hit max iterations or generated an initial report but is awaiting manual operator review.
- **CLOSED**: The report has been finalized and no further telemetry will be appended to the case timeline.

## Retention Policies
All artifacts (reports, cache blobs, logs) are tagged with retention markers to ensure compliance:
- **30 Days**: Default setting for high-volume automated triage containing no malicious findings.
- **90 Days**: Retained cases containing `INFERRED` findings.
- **180 Days**: Default retention for any `CLOSED` case with `CONFIRMED` malicious IOCs or TTPs.

## Configuration Implementation
Configured inside `shared/config.py` via:
- `SENTINELMCP_RETENTION_CLEAN` (30)
- `SENTINELMCP_RETENTION_MALICIOUS` (180)
