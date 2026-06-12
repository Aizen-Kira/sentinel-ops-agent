"""Tests for mcp_server/tools/cloud.py (V1.1.0)."""
from __future__ import annotations

import pytest

from mcp_server.tools.cloud import (
    parse_azure_activity_logs,
    parse_cloudtrail,
    parse_entra_signin_logs,
    parse_gcp_audit_logs,
    parse_guardduty,
    parse_iam_events,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CLOUDTRAIL_STOP_LOGGING = {
    "eventName": "StopLogging",
    "eventTime": "2024-11-01T03:00:00Z",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.10",
    "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker"},
}

CLOUDTRAIL_CLEAN = {
    "eventName": "DescribeVpcs",
    "eventTime": "2024-11-01T04:00:00Z",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "10.0.0.1",
    "userIdentity": {"arn": "arn:aws:iam::123456789012:user/devops"},
}

IAM_CREATE_KEY = {
    "eventName": "CreateAccessKey",
    "eventTime": "2024-11-01T03:05:00Z",
    "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker"},
    "requestParameters": {"userName": "victim_user"},
}

GUARDDUTY_HIGH = {
    "title": "Recon:IAMUser/MaliciousIPCaller.Custom",
    "description": "API from a custom threat list IP.",
    "type": "Recon:IAMUser",
    "severity": 7.5,
    "updatedAt": "2024-11-01T03:10:00Z",
    "service": {
        "action": {
            "networkConnectionAction": {
                "remoteIpDetails": {"ipAddressV4": "198.51.100.9"},
            }
        }
    },
}

ENTRA_RISKY = {
    "userPrincipalName": "alice@contoso.com",
    "ipAddress": "185.220.101.5",
    "createdDateTime": "2024-11-01T03:00:00Z",
    "appDisplayName": "Azure Portal",
    "location": {"city": "Moscow", "countryOrRegion": "RU"},
    "riskEventTypes": ["impossibleTravel"],
    "status": {"errorCode": 0},
}

ENTRA_CLEAN = {
    "userPrincipalName": "bob@contoso.com",
    "ipAddress": "10.0.0.5",
    "createdDateTime": "2024-11-01T09:00:00Z",
    "appDisplayName": "Teams",
    "location": {"city": "Seattle", "countryOrRegion": "US"},
    "riskEventTypes": [],
    "status": {"errorCode": 0},
}

AZURE_ACTIVITY_DELETE_POLICY = {
    "operationName": {"value": "Microsoft.Authorization/policies/delete"},
    "caller": "attacker@contoso.com",
    "eventTimestamp": "2024-11-01T03:15:00Z",
    "resourceId": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Authorization",
    "level": "Warning",
    "status": {"value": "Succeeded"},
}

GCP_SET_IAM = {
    "timestamp": "2024-11-01T03:20:00Z",
    "protoPayload": {
        "methodName": "SetIamPolicy",
        "serviceName": "iam.googleapis.com",
        "resourceName": "projects/my-project",
        "authenticationInfo": {"principalEmail": "attacker@iam.gserviceaccount.com"},
        "requestMetadata": {"callerIp": "198.51.100.20"},
    },
}


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

class TestParseCloudtrail:
    def test_suspicious_event_produces_finding(self) -> None:
        findings = parse_cloudtrail([CLOUDTRAIL_STOP_LOGGING])
        assert len(findings) == 1
        f = findings[0]
        assert "StopLogging" in f["title"]
        assert "T1562.008" in f["ttp_ids"]
        assert f["severity"] == "high"

    def test_ioc_extracted_from_source_ip(self) -> None:
        findings = parse_cloudtrail([CLOUDTRAIL_STOP_LOGGING])
        assert findings[0]["ioc_type"] == "ip"
        assert findings[0]["ioc_value"] == "203.0.113.10"

    def test_clean_event_produces_info_finding(self) -> None:
        findings = parse_cloudtrail([CLOUDTRAIL_CLEAN])
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
        assert findings[0]["ttp_ids"] == []

    def test_timeline_event_populated(self) -> None:
        findings = parse_cloudtrail([CLOUDTRAIL_STOP_LOGGING])
        te = findings[0]["timeline_event"]
        assert te["source"] == "aws_cloudtrail"
        assert te["timestamp"] == "2024-11-01T03:00:00Z"

    def test_html_injection_in_event_name_escaped(self) -> None:
        evil = {**CLOUDTRAIL_STOP_LOGGING, "eventName": "<script>alert(1)</script>"}
        findings = parse_cloudtrail([evil])
        assert "<script>" not in findings[0]["title"]

    def test_empty_events_returns_empty(self) -> None:
        assert parse_cloudtrail([]) == []

    def test_multiple_events(self) -> None:
        findings = parse_cloudtrail([CLOUDTRAIL_STOP_LOGGING, CLOUDTRAIL_CLEAN])
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# IAM Events
# ---------------------------------------------------------------------------

class TestParseIamEvents:
    def test_high_risk_action_detected(self) -> None:
        findings = parse_iam_events([IAM_CREATE_KEY])
        assert len(findings) == 1
        assert "CreateAccessKey" in findings[0]["title"]
        assert findings[0]["severity"] == "high"

    def test_benign_event_filtered(self) -> None:
        benign = {"eventName": "ListUsers", "eventTime": "2024-01-01T00:00:00Z",
                  "userIdentity": {"arn": "arn:aws:iam::123:user/admin"}}
        assert parse_iam_events([benign]) == []

    def test_target_user_in_evidence(self) -> None:
        findings = parse_iam_events([IAM_CREATE_KEY])
        evidence_str = " ".join(findings[0]["evidence"])
        assert "victim_user" in evidence_str

    def test_ttp_ids_assigned(self) -> None:
        findings = parse_iam_events([IAM_CREATE_KEY])
        assert "T1136.003" in findings[0]["ttp_ids"]


# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------

class TestParseGuardduty:
    def test_high_severity_mapped_to_critical(self) -> None:
        findings = parse_guardduty([GUARDDUTY_HIGH])
        assert findings[0]["severity"] == "critical"

    def test_recon_ttp_tag(self) -> None:
        findings = parse_guardduty([GUARDDUTY_HIGH])
        assert "T1595" in findings[0]["ttp_ids"]

    def test_source_ip_extracted(self) -> None:
        findings = parse_guardduty([GUARDDUTY_HIGH])
        assert findings[0]["ioc_value"] == "198.51.100.9"

    def test_empty_returns_empty(self) -> None:
        assert parse_guardduty([]) == []


# ---------------------------------------------------------------------------
# Entra ID
# ---------------------------------------------------------------------------

class TestParseEntraSigninLogs:
    def test_risky_signin_detected(self) -> None:
        findings = parse_entra_signin_logs([ENTRA_RISKY])
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_clean_signin_filtered(self) -> None:
        assert parse_entra_signin_logs([ENTRA_CLEAN]) == []

    def test_ip_ioc_extracted(self) -> None:
        findings = parse_entra_signin_logs([ENTRA_RISKY])
        assert findings[0]["ioc_value"] == "185.220.101.5"

    def test_ttp_tagged(self) -> None:
        findings = parse_entra_signin_logs([ENTRA_RISKY])
        assert "T1078.004" in findings[0]["ttp_ids"]

    def test_failed_signin_also_detected(self) -> None:
        failed = {**ENTRA_CLEAN, "status": {"errorCode": 50126}}
        findings = parse_entra_signin_logs([failed])
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"


# ---------------------------------------------------------------------------
# Azure Activity Logs
# ---------------------------------------------------------------------------

class TestParseAzureActivityLogs:
    def test_policy_delete_flagged(self) -> None:
        findings = parse_azure_activity_logs([AZURE_ACTIVITY_DELETE_POLICY])
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_benign_read_filtered(self) -> None:
        read_op = {
            "operationName": {"value": "Microsoft.Compute/virtualMachines/read"},
            "caller": "devops@contoso.com",
            "eventTimestamp": "2024-01-01T09:00:00Z",
            "resourceId": "/subscriptions/abc/vms/vm1",
            "level": "Informational",
            "status": {"value": "Succeeded"},
        }
        assert parse_azure_activity_logs([read_op]) == []

    def test_caller_in_evidence(self) -> None:
        findings = parse_azure_activity_logs([AZURE_ACTIVITY_DELETE_POLICY])
        evidence_str = " ".join(findings[0]["evidence"])
        assert "attacker@contoso.com" in evidence_str


# ---------------------------------------------------------------------------
# GCP Audit Logs
# ---------------------------------------------------------------------------

class TestParseGcpAuditLogs:
    def test_set_iam_policy_flagged(self) -> None:
        findings = parse_gcp_audit_logs([GCP_SET_IAM])
        assert len(findings) == 1
        assert "SetIamPolicy" in findings[0]["title"]
        assert findings[0]["severity"] == "high"

    def test_ttp_ids_assigned(self) -> None:
        findings = parse_gcp_audit_logs([GCP_SET_IAM])
        assert "T1078.004" in findings[0]["ttp_ids"]

    def test_caller_ip_extracted(self) -> None:
        findings = parse_gcp_audit_logs([GCP_SET_IAM])
        assert findings[0]["ioc_value"] == "198.51.100.20"

    def test_benign_method_filtered(self) -> None:
        benign = {
            "timestamp": "2024-01-01T09:00:00Z",
            "protoPayload": {
                "methodName": "storage.objects.list",
                "serviceName": "storage.googleapis.com",
                "resourceName": "projects/my-project/buckets/logs",
                "authenticationInfo": {"principalEmail": "svc@project.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "10.0.0.1"},
            },
        }
        assert parse_gcp_audit_logs([benign]) == []

    def test_empty_logs_returns_empty(self) -> None:
        assert parse_gcp_audit_logs([]) == []
