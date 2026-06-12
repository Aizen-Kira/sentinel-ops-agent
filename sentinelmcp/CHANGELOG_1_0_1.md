# Changelog (SentinelMCP V1.0.1)

## [1.0.1] - 2026-06-15

### Security Fixes
- **[BUG-001] API Key Exposure in Unhandled Exception**: Implemented a global log filter preventing the `anthropic` client's HTTP traceback from inadvertently logging `x-api-key` headers into `stderr` during API outages. 

### Bug Fixes
- **[BUG-002] Tshark Conversation Timeout**: Increased default `subprocess` timeout allocations for PCAPs >2GB. Wrapped execution in a strict `TimeoutExpired` exception block, returning structured findings (`"Error: PCAP analysis timed out. Recommend manual investigation."`) rather than failing silently with an empty list.
- **[DOC-001] Operations Guide Typo**: Fixed a typo regarding the spelling of the `SENTINELMCP_BURST_THRESHOLD` environment variable in the Operations Guide.

### Operational & Benchmark Impact
- **Benchmark Impact**: Zero regressions observed. Test suites confirm F1 and Hallucination rates remain completely stable. 
- **Operational Impact**: Eliminates silent context drops on massive network captures. Operators will now receive explicit timeout notifications for extremely large datasets.

*(Medium priority finding BUG-003 has been deferred to V1.0.2).*
