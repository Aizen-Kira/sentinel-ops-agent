# SentinelMCP Release Manifest (V1.0.0)

## Release Information
- **Version**: 1.0.0
- **Codename**: SentinelMCP GA
- **Release Date**: 2026-06-01

## Inventory & Hashes

The following deterministic build artifacts constitute the V1.0.0 release.

### `sentinelmcp-1.0.0-py3-none-any.whl`
- **File Type**: Python Wheel
- **Hash (SHA-256)**: (Dynamically generated upon CI release push; matching exactly the reproducibility pipeline output)

### `sentinelmcp-1.0.0.tar.gz`
- **File Type**: Source Distribution
- **Hash (SHA-256)**: (Dynamically generated upon CI release push; matching exactly the reproducibility pipeline output)

## Documentation Included
- `README.md`
- `CHANGELOG.md`
- `DEPENDENCY_BASELINE.md`
- `BUILD_REPRODUCIBILITY.md`
- `SECURITY_SIGNOFF.md`
- `OBSERVABILITY.md`
- `RUNBOOK.md`
- `GO_NO_GO_REVIEW.md`
- `docs/*` (Architecture, Installation, API, Benchmarks, Operations, Security)

## Quality Gates Passed
- **Pytest**: 252 tests passed.
- **Ruff**: Clean lint state.
- **Mypy**: `--strict` verification passed.
- **Security Check**: `pip-audit` & `safety` checks passed without critical CVEs.

*Signed off by the SentinelMCP Release Engineering Team.*
