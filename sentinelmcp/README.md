# SentinelMCP

AI-powered DFIR triage agent built on FastMCP and Claude.

## Architecture

- **CLI**: `agent/agent.py` — argument parsing, Case construction
- **Loop**: `agent/loop.py` — 6-phase self-correction loop (max 8 iterations)
- **Evaluator**: `agent/evaluator.py` — pure-Python gap analysis (no LLM)
- **Reporter**: `agent/reporter.py` — XSS-safe HTML report generation
- **MCP Server**: `mcp_server/server.py` — 15 FastMCP tools
- **Parsers**: `mcp_server/parsers/` — typed CLI output parsers
- **Shared Models**: `shared/models.py` — 25+ canonical dataclasses
- **Security**: `shared/security.py` — path validation allowlist
- **Benchmark**: `benchmark/` — F1/hallucination scoring harness
- **Realtime**: `realtime/` — Sysmon/Defender XDR streaming pipeline

## Sprint 1 Bug Fixes Implemented

| Bug | Severity | Fix |
|-----|----------|-----|
| BUG-001 | CRITICAL | `shared/security.py::validate_path()` called in all 4 tool files |
| BUG-002 | HIGH | `datetime.utcnow()` → `datetime.now(timezone.utc).replace(tzinfo=None)` in `correlate.py` |
| BUG-003 | HIGH | `html.escape()` on all strings in `reporter.py` |
| BUG-004 | MEDIUM | Tool failure entries appended to `accumulated_context` in `loop.py` |

## Installation

```bash
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
```

## Usage

```bash
sentinelmcp --disk /evidence/disk.E01 --memory /evidence/mem.dmp \
            --pcap /evidence/capture.pcap \
            --description "Lateral movement investigation" \
            --output report.html
```
