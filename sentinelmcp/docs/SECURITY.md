# Security Model

SentinelMCP is built with a zero-trust mindset, assuming that forensic evidence may contain malicious payloads or attempts to exploit the parser.

## Architecture Security
1. **Path Validation (`shared/security.py`)**: 
   - Strict validation of all input paths provided to the MCP server.
   - Prevents path traversal vulnerabilities.
   - Restricts file access to specific, allowed root directories.
2. **SSE Authentication (`mcp_server/auth.py`)**: 
   - All connections to the MCP SSE endpoint are guarded by API key authentication.
   - Prevents unauthorized triggering of forensic tool workflows over the network.
3. **HTML Output Escaping (`agent/reporter.py`)**:
   - The final HTML report generation explicitly escapes all user-controlled and LLM-produced strings using `html.escape()`.
   - Protects against Cross-Site Scripting (XSS) via poisoned event logs or finding titles.

## Dependency Security
Dependencies are continuously audited using `pip-audit` and `safety` to ensure the core execution environment is free of known CVEs.

## Execution Isolation
SentinelMCP relies on external forensic tools (Volatility, tshark). Ensure that the host running these tools is properly isolated from the production network, as executing malicious memory dumps or disk images can present significant risks.
