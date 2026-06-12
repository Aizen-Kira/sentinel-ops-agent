# Changelog (SentinelMCP V1.0.0)

## [1.0.0] - 2026-06-01

### RC2 - Operational Validation
- **Validated**: 8 real-world datasets confirming high F1 (0.93) and minimal hallucination (<1%).
- **Stability**: 24-hour rapid ingestion simulation showed no memory leaks or thread deadlocks.
- **Security**: Passed rigorous penetration review encompassing path traversal, XSS prevention, and tool fuzzing.
- **Deployment**: Verified local, venv, and Docker deployment strategies.
- **Recovery**: Cache, pipeline restart, configuration, and benchmark fault-tolerance verified.
- **Documentation**: Audited and confirmed 100% alignment with the architecture.

### Sprint 5 - Hardening & RC Readiness
- **Fuzzing**: Implemented `test_fuzz_parsers.py` (1000 iterations per parser).
- **Concurrency**: Built robust ToolCache, Pipeline, and Parallel Dispatch stress tests (`test_concurrency.py`).
- **Dependencies**: Performed pip-audit and safety checks.
- **Metrics**: Added `inferred_recall` secondary tracking to catch lazy inference.
- **Configuration**: Standardized `shared/config.py` environment variable loading with safe defaults.
- **Documentation**: Authored the foundational docs (`INSTALL.md`, `ARCHITECTURE.md`, `SECURITY.md`, `API.md`, `BENCHMARKS.md`, `OPERATIONS.md`).

### Sprint 4 - Forensics Expansion
- **YARA**: Added `yara_scan` tool capability for signature mapping on disk.
- **IOCs**: Built `shared/ioc.py` utilizing deterministic regex logic for hash, IP, and domain extraction.
- **Timeline**: Created `build_super_timeline` to sequence events chronologically.
- **Security**: Introduced SSE authentication (`x-api-key`) to the FastMCP server.

### Sprint 3 - Scale & Performance
- **Real-Time**: Added streaming telemetry ingestion pipeline with burst-detection triggering (`realtime/pipeline.py`).
- **Caching**: Developed `ToolCache` utilizing thread-safe dict mapping and TTL eviction.
- **Optimization**: Transitioned Phase 1 tool dispatching to concurrent Execution Pools.
- **Context Handling**: Introduced deterministic `summarize_context` for limiting context window bloat during later iterations.

### Sprint 2 - DFIR Intelligence
- **Correlation**: Added `correlate_disk_memory` mapping memory PIDs directly to disk image inodes and paths.
- **Gap Analysis**: Built deterministic logic engine (`evaluator.py`) containing domain-specific DFIR rule gaps.
- **Parsers**: Expanded parsers across `fls`, `reglookup`, `vol3_cmdline`, and `tshark_dns`.
- **Scoring**: Built initial `benchmark/scorer.py` incorporating Precision, Recall, and Hallucination algorithms.

### Sprint 1 - Foundation & Security Fixes
- **Architecture**: Established the 6-phase LLM agent self-correction loop.
- **Path Security**: Hardened external tool path resolving enforcing strict boundary limits (`validate_path`).
- **XSS Mitigations**: Implemented complete HTML escaping for generated triaged reporting.
- **Models**: Unified the agent and server under canonical immutable dataclasses (`shared/models.py`).
