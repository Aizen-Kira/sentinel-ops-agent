"""Container Forensics Tools (V1.1.0 — PHASE 3).

Supports Docker logs, container metadata, image history,
and Kubernetes audit logs. All outputs normalised to
Finding-compatible dicts with ATT&CK tagging and IOC extraction.
"""
from __future__ import annotations

import html
import json
import logging
import re
from typing import Any

from shared.ioc import extract_iocs

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ATT&CK mappings for container threats
# ---------------------------------------------------------------------------

_DOCKER_TTP_MAP: dict[str, list[str]] = {
    "privileged": ["T1611"],           # Escape to Host
    "hostPID": ["T1611"],
    "hostNetwork": ["T1599"],          # Network Boundary Bridging
    "hostIPC": ["T1611"],
    "cap_sys_admin": ["T1611"],
    "cap_net_admin": ["T1599"],
    "/var/run/docker.sock": ["T1552.007"],  # Container API
    "/host": ["T1611"],
    "root": ["T1078.003"],             # Valid Accounts: Local Accounts
}

_K8S_RISKY_VERBS = {"exec", "portforward", "proxy", "create", "delete", "patch", "get"}
_K8S_RISKY_RESOURCES = {"secrets", "clusterrolebindings", "rolebindings", "pods/exec"}
_K8S_TTP_MAP: dict[str, str] = {
    "exec": "T1609",       # Container Administration Command
    "portforward": "T1572", # Protocol Tunneling
    "create": "T1610",     # Deploy Container
    "delete": "T1485",     # Data Destruction
    "secrets": "T1552.007", # Credentials from Cloud
}


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


# ---------------------------------------------------------------------------
# Docker log parser
# ---------------------------------------------------------------------------


def parse_docker_logs(
    container_id: str,
    log_lines: list[str],
) -> list[dict[str, Any]]:
    """Parse Docker container stdout/stderr log lines for suspicious activity.

    Detects common shell escape, reverse shell, and credential-dumping patterns.

    Args:
        container_id: The short or full container ID (used in evidence strings).
        log_lines: List of raw log line strings from ``docker logs``.

    Returns:
        List of Finding-compatible dicts (empty if no anomalies found).
    """
    _SUSPICIOUS = re.compile(
        r"(bash\s+-i|/dev/tcp|nc\s+-e|python.*pty|perl.*socket|"
        r"curl.*\|.*sh|wget.*\|.*sh|chmod\s+\+x|"
        r"base64\s+--decode|eval\s+\$|"
        r"cat\s+/etc/shadow|cat\s+/etc/passwd|"
        r"cryptominer|xmrig|minerd)",
        re.IGNORECASE,
    )

    findings: list[dict[str, Any]] = []
    for i, line in enumerate(log_lines):
        line = line.strip()
        if not line:
            continue
        m = _SUSPICIOUS.search(line)
        if m:
            iocs = [{"type": x.type, "value": x.value} for x in extract_iocs(line)]
            findings.append({
                "title": f"Container: Suspicious Command in {_e(container_id[:12])}",
                "description": (
                    f"Suspicious pattern '{_e(m.group())}' detected in container "
                    f"'{_e(container_id[:12])}' log at line {i + 1}."
                ),
                "severity": "high",
                "source_tools": ["parse_docker_logs"],
                "evidence": [f"Line {i + 1}: {_e(line[:200])}"],
                "ttp_ids": ["T1059.004"],  # Unix Shell
                "ioc_type": None,
                "ioc_value": None,
                "extracted_iocs": iocs,
                "timeline_event": {
                    "timestamp": "",  # Docker logs may lack timestamps
                    "source": "docker_logs",
                    "category": "container_execution",
                    "description": f"Suspicious shell pattern in container {container_id[:12]}",
                    "evidence": line[:200],
                },
            })

    logger.debug("parse_docker_logs(%s): %d findings", container_id[:12], len(findings))
    return findings


# ---------------------------------------------------------------------------
# Container metadata / inspect parser
# ---------------------------------------------------------------------------


def parse_container_metadata(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse ``docker inspect`` output for dangerous security configurations.

    Args:
        metadata: A single container inspect dict (as returned by docker inspect).

    Returns:
        List of Finding-compatible dicts for each dangerous config detected.
    """
    findings: list[dict[str, Any]] = []
    host_config = metadata.get("HostConfig") or {}
    name = str(metadata.get("Name", "unknown")).lstrip("/")
    image = str(metadata.get("Config", {}).get("Image", "unknown"))
    created = str(metadata.get("Created", ""))

    def _flag(config_key: str, value: Any) -> None:
        ttp_ids = _DOCKER_TTP_MAP.get(config_key, ["T1611"])
        findings.append({
            "title": f"Container Misconfiguration: {_e(config_key)} in {_e(name)}",
            "description": (
                f"Container '{_e(name)}' (image: {_e(image)}) has dangerous "
                f"setting '{_e(config_key)}' = {_e(repr(value))}."
            ),
            "severity": "critical",
            "source_tools": ["parse_container_metadata"],
            "evidence": [
                f"Container: {_e(name)}",
                f"Image: {_e(image)}",
                f"Created: {_e(created)}",
                f"Setting: {_e(config_key)} = {_e(repr(value))}",
            ],
            "ttp_ids": ttp_ids,
            "ioc_type": None,
            "ioc_value": None,
            "extracted_iocs": [],
            "timeline_event": {
                "timestamp": created,
                "source": "docker_inspect",
                "category": "container_config",
                "description": f"Dangerous config {config_key} in {name}",
                "evidence": image,
            },
        })

    if host_config.get("Privileged"):
        _flag("privileged", True)
    if host_config.get("PidMode") == "host":
        _flag("hostPID", "host")
    if host_config.get("NetworkMode") == "host":
        _flag("hostNetwork", "host")
    if host_config.get("IpcMode") == "host":
        _flag("hostIPC", "host")

    # Check dangerous volume mounts
    binds: list[str] = host_config.get("Binds") or []
    for bind in binds:
        for dangerous_path in ("/var/run/docker.sock", "/host", "/proc", "/sys"):
            if dangerous_path in bind:
                _flag(dangerous_path, bind)

    # Check dangerous capabilities
    cap_add: list[str] = host_config.get("CapAdd") or []
    for cap in cap_add:
        cap_lower = cap.lower().replace("cap_", "cap_")
        for dangerous_cap in ("cap_sys_admin", "cap_net_admin", "cap_sys_ptrace"):
            if cap_lower == dangerous_cap:
                _flag(dangerous_cap, cap)

    return findings


# ---------------------------------------------------------------------------
# Container image history parser
# ---------------------------------------------------------------------------


def parse_image_history(
    image_name: str,
    history: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Parse ``docker history`` output for suspicious layer commands.

    Args:
        image_name: The image name/tag (for evidence context).
        history: List of layer dicts (each with a ``CreatedBy`` key).

    Returns:
        Finding-compatible dicts for any suspicious layer commands.
    """
    _SUSPICIOUS_LAYER = re.compile(
        r"(curl\s+https?://|wget\s+https?://|"
        r"pip\s+install|npm\s+install|"
        r"chmod\s+777|chmod\s+\+s|"
        r"eval\s+\$|base64\s+--decode|"
        r"/dev/tcp|nc\s+-e|"
        r"apt-get\s+install.*netcat|"
        r"RUN\s+.*&&\s*rm\s+-rf\s+/var)",
        re.IGNORECASE,
    )

    findings: list[dict[str, Any]] = []
    for layer in history:
        cmd = str(layer.get("CreatedBy", ""))
        created = str(layer.get("Created", ""))
        size = layer.get("Size", 0)
        m = _SUSPICIOUS_LAYER.search(cmd)
        if m:
            findings.append({
                "title": f"Image Layer Risk: {_e(image_name)}",
                "description": (
                    f"Suspicious command detected in image '{_e(image_name)}' layer: "
                    f"'{_e(m.group())}'."
                ),
                "severity": "high",
                "source_tools": ["parse_image_history"],
                "evidence": [
                    f"Image: {_e(image_name)}",
                    f"LayerCmd: {_e(cmd[:200])}",
                    f"Created: {_e(created)}",
                    f"Size: {_e(size)}",
                ],
                "ttp_ids": ["T1195.001"],  # Supply Chain Compromise: Compromise SW Dependencies
                "ioc_type": None,
                "ioc_value": None,
                "extracted_iocs": [],
                "timeline_event": {
                    "timestamp": created,
                    "source": "docker_history",
                    "category": "image_build",
                    "description": f"Suspicious layer in {image_name}",
                    "evidence": cmd[:200],
                },
            })

    return findings


# ---------------------------------------------------------------------------
# Kubernetes audit log parser
# ---------------------------------------------------------------------------


def parse_k8s_audit_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse Kubernetes API server audit logs for suspicious operations.

    Args:
        logs: List of K8s audit log entry dicts (JSON format from the API server).

    Returns:
        Finding-compatible dicts for suspicious API calls.
    """
    findings: list[dict[str, Any]] = []
    for log in logs:
        verb = str(log.get("verb", "")).lower()
        resource = str((log.get("objectRef") or {}).get("resource", "")).lower()
        subresource = str((log.get("objectRef") or {}).get("subresource", "")).lower()
        namespace = str((log.get("objectRef") or {}).get("namespace", ""))
        user = str((log.get("user") or {}).get("username", ""))
        source_ip = str((log.get("sourceIPs") or [""])[0])
        request_time = str(log.get("requestReceivedTimestamp", ""))
        ua = str(log.get("userAgent", ""))
        response_code = log.get("responseStatus", {}).get("code", 200)

        full_resource = f"{resource}/{subresource}" if subresource else resource
        is_risky_verb = verb in _K8S_RISKY_VERBS
        is_risky_resource = any(r in full_resource for r in _K8S_RISKY_RESOURCES)
        # 'list'/'get' on secrets are only risky; 'list' on non-sensitive resources is fine
        if verb == "get" and resource not in ("secrets",):
            continue
        if not (is_risky_verb and is_risky_resource):
            continue

        # Subresource 'exec' always maps to T1609 regardless of outer verb
        if subresource == "exec":
            ttp_id = "T1609"
        else:
            ttp_id = _K8S_TTP_MAP.get(verb, _K8S_TTP_MAP.get(resource, "T1609"))

        # Exec into a pod is especially critical
        severity = "critical" if subresource == "exec" else "high"

        iocs = [{"type": x.type, "value": x.value} for x in extract_iocs(source_ip)]

        findings.append({
            "title": f"K8s Audit: {_e(verb.upper())} {_e(full_resource)}",
            "description": (
                f"Kubernetes API call '{_e(verb)}' on resource '{_e(full_resource)}' "
                f"in namespace '{_e(namespace)}' by user '{_e(user)}' from {_e(source_ip)}. "
                f"UserAgent: {_e(ua[:60])}."
            ),
            "severity": severity,
            "source_tools": ["parse_k8s_audit_logs"],
            "evidence": [
                f"Verb: {_e(verb)}",
                f"Resource: {_e(full_resource)}",
                f"Namespace: {_e(namespace)}",
                f"User: {_e(user)}",
                f"SourceIP: {_e(source_ip)}",
                f"UserAgent: {_e(ua[:80])}",
                f"ResponseCode: {_e(response_code)}",
                f"Time: {_e(request_time)}",
            ],
            "ttp_ids": [ttp_id],
            "ioc_type": "ip" if source_ip else None,
            "ioc_value": source_ip or None,
            "extracted_iocs": iocs,
            "timeline_event": {
                "timestamp": request_time,
                "source": "k8s_audit",
                "category": "container_orchestration",
                "description": f"K8s {verb} {full_resource} by {user}",
                "evidence": json.dumps(log)[:200],
            },
        })

    logger.debug("parse_k8s_audit_logs: %d findings", len(findings))
    return findings
