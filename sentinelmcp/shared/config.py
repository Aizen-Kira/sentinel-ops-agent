"""Centralized runtime configuration (FEATURE-019).

All settings are loaded from environment variables with safe defaults.
No secrets are logged; API keys are masked in repr output.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SentinelConfig:
    """Immutable runtime configuration for SentinelMCP.

    Every field is populated from the corresponding environment variable
    (prefixed with ``SENTINELMCP_``) or falls back to the default value.
    """

    max_iterations: int = 8
    cache_ttl: int = 3600
    api_key: str = ""
    log_level: str = "INFO"
    allowed_paths: list[str] = field(default_factory=list)

    # Extended settings
    burst_threshold: int = 10
    burst_window_seconds: float = 30.0
    parallel_workers: int = 4
    # V1.1.0 — Case Management retention policies (PHASE 6)
    retention_clean_days: int = 30
    retention_malicious_days: int = 180

    def __repr__(self) -> str:
        """Mask secrets in repr output."""
        masked_key = "***" if self.api_key else "(unset)"
        return (
            f"SentinelConfig(max_iterations={self.max_iterations}, "
            f"cache_ttl={self.cache_ttl}, "
            f"api_key={masked_key}, "
            f"log_level={self.log_level!r}, "
            f"allowed_paths={self.allowed_paths!r}, "
            f"burst_threshold={self.burst_threshold}, "
            f"burst_window_seconds={self.burst_window_seconds}, "
            f"parallel_workers={self.parallel_workers}, "
            f"retention_clean_days={self.retention_clean_days}, "
            f"retention_malicious_days={self.retention_malicious_days})"
        )


def _parse_paths(raw: str) -> list[str]:
    """Split a colon/semicolon-delimited path list into individual paths."""
    if not raw.strip():
        return []
    separator = ";" if ";" in raw else ":"
    return [p.strip() for p in raw.split(separator) if p.strip()]


def load_config() -> SentinelConfig:
    """Build a SentinelConfig from environment variables.

    Env vars (all optional):
        SENTINELMCP_MAX_ITERATIONS  — int, default 8
        SENTINELMCP_CACHE_TTL       — int (seconds), default 3600
        SENTINELMCP_API_KEY         — str, default ""
        SENTINELMCP_LOG_LEVEL       — str, default "INFO"
        SENTINELMCP_ALLOWED_PATHS   — semicolon-separated path list
        SENTINELMCP_BURST_THRESHOLD — int, default 10
        SENTINELMCP_BURST_WINDOW    — float (seconds), default 30.0
        SENTINELMCP_PARALLEL_WORKERS — int, default 4
    """

    def _int(key: str, default: int) -> int:
        raw = os.environ.get(key, "")
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            logger.warning("Invalid int for %s=%r; using default %d", key, raw, default)
            return default

    def _float(key: str, default: float) -> float:
        raw = os.environ.get(key, "")
        if not raw:
            return default
        try:
            return float(raw)
        except ValueError:
            logger.warning("Invalid float for %s=%r; using default %s", key, raw, default)
            return default

    cfg = SentinelConfig(
        max_iterations=_int("SENTINELMCP_MAX_ITERATIONS", 8),
        cache_ttl=_int("SENTINELMCP_CACHE_TTL", 3600),
        api_key=os.environ.get("SENTINELMCP_API_KEY", ""),
        log_level=os.environ.get("SENTINELMCP_LOG_LEVEL", "INFO").upper(),
        allowed_paths=_parse_paths(os.environ.get("SENTINELMCP_ALLOWED_PATHS", "")),
        burst_threshold=_int("SENTINELMCP_BURST_THRESHOLD", 10),
        burst_window_seconds=_float("SENTINELMCP_BURST_WINDOW", 30.0),
        parallel_workers=_int("SENTINELMCP_PARALLEL_WORKERS", 4),
        retention_clean_days=_int("SENTINELMCP_RETENTION_CLEAN", 30),
        retention_malicious_days=_int("SENTINELMCP_RETENTION_MALICIOUS", 180),
    )

    logger.debug("Configuration loaded: %s", cfg)
    return cfg


# Module-level singleton
_config: SentinelConfig | None = None


def get_config() -> SentinelConfig:
    """Return the module-level config singleton (lazy-loaded)."""
    global _config  # noqa: PLW0603
    if _config is None:
        _config = load_config()
    return _config


def get_allowed_roots() -> list[Path]:
    """Return ALLOWED_PATHS as resolved Path objects for use with validate_path."""
    return [Path(p).resolve() for p in get_config().allowed_paths]
