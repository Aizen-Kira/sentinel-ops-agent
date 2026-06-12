# Security Patch Review (1.0.1)

## Overview
A routine post-GA security audit was conducted against SentinelMCP's runtime environment, dependencies, and operational logs.

## 1. Dependency Audit (`pip-audit`)
- **Action:** Executed `pip-audit` against the V1.0.0 `requirements-lock.txt`.
- **Results:** 0 CVEs detected in core dependencies (`fastmcp`, `anthropic`, `pydantic`). No bumps required.

## 2. Container Image Audit
- **Action:** Scanned the `sentinelmcp:rc2` base image (`python:3.11-slim`) using Trivy.
- **Results:** Several low-severity OS-level CVEs (e.g., `libssl` micro-patches) found in the base Debian image.
- **Remediation (1.0.1):** Updated `Dockerfile` to pull the latest `python:3.11-slim` SHA digest.

## 3. Secret Exposure Review
- **Action:** Reviewed operator debug logs submitted post-GA.
- **Results:** Discovered that unhandled `HTTPException` stack traces from the `anthropic` library could inadvertently print the HTTP headers, which includes the API key.
- **Remediation (1.0.1):** Addressed via BUG-001. Stack traces are now intercepted by a custom logging formatter that regex-scrubs sensitive key patterns before writing to `stderr` or `syslog`.
