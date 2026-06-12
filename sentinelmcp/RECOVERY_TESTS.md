# Backup & Recovery Tests

## Goal
Ensure SentinelMCP recovers gracefully from unexpected failures, corruption, or resource loss.

## Test Scenarios & Results

### 1. Cache Loss
- **Scenario:** The in-memory `ToolCache` is forcefully cleared (simulating a service restart or RAM flush) mid-investigation.
- **Behavior:** The agent's `call_mcp_tools` function detects the cache miss and gracefully re-dispatches the tool execution to the MCP Server.
- **Result:** Minimal latency hit; investigation completes successfully. **PASS**.

### 2. Unexpected Service Restart
- **Scenario:** The realtime pipeline is interrupted (SIGTERM/SIGKILL) while processing an event burst.
- **Behavior:** `realtime/pipeline.py` maintains state within the queue. Unprocessed events in the immediate burst window are lost (expected in in-memory queues), but new events trigger a fresh triage immediately upon restart.
- **Result:** System recovers instantly without entering a locked or corrupted state. **PASS**.

### 3. Benchmark Corruption
- **Scenario:** The `ground_truth.json` files are malformed (e.g., invalid JSON format).
- **Behavior:** `pytest` suite gracefully skips the broken benchmark or fails the explicit test case, printing a clear parsing error. It does not crash the test runner.
- **Result:** Benchmark harness is robust. **PASS**.

### 4. Configuration Corruption
- **Scenario:** Environment variables are supplied with invalid types (e.g., `SENTINELMCP_MAX_ITERATIONS="not_a_number"`).
- **Behavior:** `shared/config.py` catches the `ValueError`, logs a warning, and falls back to the safe default (8). 
- **Result:** System starts normally utilizing safe defaults. **PASS**.

## Verdict
SentinelMCP displays strong fault tolerance and recoverability characteristics. All recovery requirements for RC2 are met.
