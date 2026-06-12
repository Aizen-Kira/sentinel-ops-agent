# SentinelMCP Operations Guide

## Overview
SentinelMCP is designed to be deployed as a headless service or run locally as a CLI application for rapid DFIR triage.

## Configuration
Configuration is managed via environment variables to facilitate containerized and cloud-native deployments.

### Environment Variables
- `SENTINELMCP_MAX_ITERATIONS` (default: 8): Maximum loop cycles before the agent forces a report.
- `SENTINELMCP_CACHE_TTL` (default: 3600): TTL in seconds for the in-memory tool cache.
- `SENTINELMCP_API_KEY` (default: ""): The API key required to connect to the MCP server over SSE.
- `SENTINELMCP_LOG_LEVEL` (default: "INFO"): Logging verbosity (DEBUG, INFO, WARNING, ERROR).
- `SENTINELMCP_ALLOWED_PATHS`: A semicolon-separated list of directories the MCP tools are allowed to access.
- `SENTINELMCP_BURST_THRESHOLD` (default: 10): Number of events to trigger a real-time triage burst.
- `SENTINELMCP_BURST_WINDOW` (default: 30.0): Window in seconds for burst detection.

## Real-time Pipeline
SentinelMCP includes a real-time ingestion pipeline (`realtime/pipeline.py`) capable of parsing streaming events from SIEMs or EDRs (e.g., Sysmon).
- Ingests events asynchronously.
- Triggers a full triage loop when anomalous burst thresholds are met.

## Execution
Run a standalone case:
```bash
sentinelmcp --disk /evidence/disk.E01 --memory /evidence/mem.dmp --pcap /evidence/capture.pcap --description "Ransomware outbreak" --output report.html
```

Or run the MCP server independently:
```bash
python -m mcp_server.server
```
