"""Cloud Forensics Tools (V1.1.0).

Supports AWS CloudTrail, IAM events, GuardDuty findings,
Azure Entra ID sign-in logs, Activity Logs, and GCP Audit Logs.
All output is normalised into Finding-compatible dicts.
"""
from __future__ import annotations

import html
import json
import logging
import re
from typing import Any

from shared.ioc import extract_iocs

logger = logging.getLogger(__name__)

_CLOUDTRAIL_TTP_MAP: dict[str, list[str]] = {
    "AssumeRole": ["T1078.004"],
    "GetCallerIdentity": ["T1033"],
    "ListBuckets": ["T1619"],
    "PutBucketPolicy": ["T1537"],
    "CreateAccessKey": ["T1136.003"],
    "DeleteTrail": ["T1562.008"],
    "StopLogging": ["T1562.008"],
    "GetSecretValue": ["T1555"],
    "DescribeInstances": ["T1580"],
    "RunInstances": ["T1578.002"],
}

_ENTRA_RISKY_EVENTS = {
    "unfamiliarFeatures", "anonymizedIPAddress", "maliciousIPAddress",
    "impossibleTravel", "leakedCredentials",
}


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def parse_cloudtrail(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse AWS CloudTrail records into normalised findings."""
    findings: list[dict[str, Any]] = []
    for ev in events:
        event_name = str(ev.get("eventName", ""))
        source_ip = str(ev.get("sourceIPAddress", ""))
        user_arn = ev.get("userIdentity", {}).get("arn", "") or ""
        event_time = str(ev.get("eventTime", ""))
        region = str(ev.get("awsRegion", ""))
        error_code = str(ev.get("errorCode", ""))
        ttp_ids = _CLOUDTRAIL_TTP_MAP.get(event_name, [])
        severity = "high" if ttp_ids else ("medium" if error_code else "info")
        raw_text = json.dumps(ev)
        iocs = [{"type": i.type, "value": i.value} for i in extract_iocs(raw_text)]
        evidence = [
            f"EventName: {_e(event_name)}", f"SourceIP: {_e(source_ip)}",
            f"UserARN: {_e(user_arn)}", f"Region: {_e(region)}",
            f"Time: {_e(event_time)}",
        ]
        if error_code:
            evidence.append(f"ErrorCode: {_e(error_code)}")
        findings.append({
            "title": f"CloudTrail: {_e(event_name)}",
            "description": f"AWS API call '{_e(event_name)}' from {_e(source_ip)} by {_e(user_arn or 'unknown')} in {_e(region)}.",
            "severity": severity,
            "source_tools": ["parse_cloudtrail"],
            "evidence": evidence,
            "ttp_ids": ttp_ids,
            "ioc_type": "ip" if source_ip else None,
            "ioc_value": source_ip or None,
            "extracted_iocs": iocs,
            "timeline_event": {
                "timestamp": event_time, "source": "aws_cloudtrail",
                "category": "cloud_api",
                "description": f"{event_name} by {user_arn or source_ip}",
                "evidence": raw_text[:200],
            },
        })
    logger.debug("parse_cloudtrail: %d findings", len(findings))
    return findings


def parse_iam_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse IAM-specific CloudTrail events for privilege escalation."""
    high_risk = {
        "CreateAccessKey", "DeleteAccessKey", "AttachUserPolicy", "AttachRolePolicy",
        "PutUserPolicy", "PutRolePolicy", "CreateUser", "DeleteUser", "AddUserToGroup",
    }
    results: list[dict[str, Any]] = []
    for ev in events:
        event_name = str(ev.get("eventName", ""))
        if event_name not in high_risk:
            continue
        params = ev.get("requestParameters") or {}
        target = params.get("userName") or params.get("roleName") or "unknown"
        actor_arn = ev.get("userIdentity", {}).get("arn", "unknown")
        event_time = str(ev.get("eventTime", ""))
        results.append({
            "title": f"IAM: High-Risk Action — {_e(event_name)}",
            "description": f"Privileged IAM action '{_e(event_name)}' on '{_e(str(target))}' by '{_e(str(actor_arn))}'.",
            "severity": "high",
            "source_tools": ["parse_iam_events"],
            "evidence": [f"Action: {_e(event_name)}", f"Target: {_e(str(target))}", f"Actor: {_e(str(actor_arn))}", f"Time: {_e(event_time)}"],
            "ttp_ids": _CLOUDTRAIL_TTP_MAP.get(event_name, ["T1078.004"]),
            "ioc_type": None, "ioc_value": None, "extracted_iocs": [],
            "timeline_event": {
                "timestamp": event_time, "source": "aws_iam",
                "category": "privilege_escalation",
                "description": f"IAM {event_name} on {str(target)}",
                "evidence": json.dumps(ev)[:200],
            },
        })
    return results


def parse_guardduty(findings_raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse AWS GuardDuty findings into normalised findings."""
    results: list[dict[str, Any]] = []
    for gd in findings_raw:
        title = str(gd.get("title", "GuardDuty Finding"))
        description = str(gd.get("description", ""))
        gd_type = str(gd.get("type", ""))
        severity_num = float(gd.get("severity", 0))
        updated_at = str(gd.get("updatedAt", ""))
        severity = "critical" if severity_num >= 7 else ("high" if severity_num >= 4 else "medium")
        src_ip = ""
        action = gd.get("service", {}).get("action", {})
        for k in ("networkConnectionAction", "portProbeAction"):
            if k in action:
                src_ip = action[k].get("remoteIpDetails", {}).get("ipAddressV4", "")
                break
        ttp_ids: list[str] = []
        if "Recon" in gd_type:
            ttp_ids = ["T1595"]
        elif "Backdoor" in gd_type:
            ttp_ids = ["T1205"]
        elif "CryptoCurrency" in gd_type:
            ttp_ids = ["T1496"]
        results.append({
            "title": f"GuardDuty: {_e(title)}",
            "description": _e(description),
            "severity": severity,
            "source_tools": ["parse_guardduty"],
            "evidence": [f"Type: {_e(gd_type)}", f"Severity: {_e(severity_num)}", f"Updated: {_e(updated_at)}", f"SourceIP: {_e(src_ip)}"],
            "ttp_ids": ttp_ids,
            "ioc_type": "ip" if src_ip else None,
            "ioc_value": src_ip or None,
            "extracted_iocs": [{"type": "ip", "value": src_ip}] if src_ip else [],
            "timeline_event": {
                "timestamp": updated_at, "source": "aws_guardduty",
                "category": "cloud_threat", "description": title, "evidence": description[:200],
            },
        })
    return results


def parse_entra_signin_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse Azure Entra ID sign-in logs for anomalous authentication."""
    results: list[dict[str, Any]] = []
    for log in logs:
        user_principal = str(log.get("userPrincipalName", ""))
        ip_address = str(log.get("ipAddress", ""))
        risk_event_types: list[str] = log.get("riskEventTypes", [])
        created_at = str(log.get("createdDateTime", ""))
        error_code = (log.get("status") or {}).get("errorCode", 0)
        app_display = str(log.get("appDisplayName", ""))
        location = log.get("location") or {}
        city = location.get("city", "")
        country = location.get("countryOrRegion", "")
        location_str = ", ".join(filter(None, [city, country]))
        is_risky = bool(set(risk_event_types) & _ENTRA_RISKY_EVENTS)
        is_failed = bool(error_code)
        if not is_risky and not is_failed:
            continue
        results.append({
            "title": f"Entra ID: {'Risky' if is_risky else 'Failed'} Sign-In — {_e(user_principal)}",
            "description": f"{'Anomalous' if is_risky else 'Failed'} sign-in for '{_e(user_principal)}' from {_e(ip_address)} ({_e(location_str)}) to '{_e(app_display)}'.",
            "severity": "high" if is_risky else "low",
            "source_tools": ["parse_entra_signin_logs"],
            "evidence": [f"User: {_e(user_principal)}", f"IP: {_e(ip_address)}", f"Location: {_e(location_str)}", f"App: {_e(app_display)}", f"RiskEvents: {_e(', '.join(risk_event_types) or 'none')}", f"ErrorCode: {_e(error_code)}"],
            "ttp_ids": ["T1078.004"] if is_risky else [],
            "ioc_type": "ip" if ip_address else None,
            "ioc_value": ip_address or None,
            "extracted_iocs": [{"type": "ip", "value": ip_address}] if ip_address else [],
            "timeline_event": {
                "timestamp": created_at, "source": "azure_entra",
                "category": "authentication",
                "description": f"{'Risky' if is_risky else 'Failed'} sign-in by {user_principal}",
                "evidence": json.dumps(log)[:200],
            },
        })
    return results


def parse_azure_activity_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse Azure Activity Logs for suspicious resource operations."""
    _HIGH_RISK_OPS = re.compile(r"(delete|purge|rotate|disable|create.*policy|assign.*role)", re.IGNORECASE)
    results: list[dict[str, Any]] = []
    for log in logs:
        operation = str((log.get("operationName") or {}).get("value", ""))
        caller = str(log.get("caller", ""))
        event_timestamp = str(log.get("eventTimestamp", ""))
        resource_id = str(log.get("resourceId", ""))
        level = str(log.get("level", "Informational"))
        status = str((log.get("status") or {}).get("value", ""))
        is_high_risk = bool(_HIGH_RISK_OPS.search(operation))
        if not is_high_risk and level not in ("Warning", "Error"):
            continue
        ttp_ids: list[str] = []
        if "role" in operation.lower():
            ttp_ids = ["T1078.004"]
        results.append({
            "title": f"Azure Activity: {_e(operation)}",
            "description": f"Suspicious Azure operation '{_e(operation)}' by '{_e(caller)}' on '{_e(resource_id)}'.",
            "severity": "high" if is_high_risk else "medium",
            "source_tools": ["parse_azure_activity_logs"],
            "evidence": [f"Operation: {_e(operation)}", f"Caller: {_e(caller)}", f"Resource: {_e(resource_id)}", f"Status: {_e(status)}", f"Time: {_e(event_timestamp)}"],
            "ttp_ids": ttp_ids,
            "ioc_type": None, "ioc_value": None, "extracted_iocs": [],
            "timeline_event": {
                "timestamp": event_timestamp, "source": "azure_activity",
                "category": "cloud_operation",
                "description": f"{operation} by {caller}", "evidence": resource_id,
            },
        })
    return results


def parse_gcp_audit_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse GCP Cloud Audit Logs for privileged operations."""
    _SENSITIVE = {
        "SetIamPolicy", "CreateServiceAccount", "CreateServiceAccountKey",
        "DeleteServiceAccount", "DisableServiceAccount", "SetBucketIamPolicy",
    }
    results: list[dict[str, Any]] = []
    for log in logs:
        proto = log.get("protoPayload") or {}
        method = str(proto.get("methodName", ""))
        method_short = method.split(".")[-1] if "." in method else method
        if method_short not in _SENSITIVE:
            continue
        caller_ip = str((proto.get("requestMetadata") or {}).get("callerIp", ""))
        principal = str((proto.get("authenticationInfo") or {}).get("principalEmail", ""))
        timestamp = str(log.get("timestamp", ""))
        resource_name = str(proto.get("resourceName", ""))
        ttp_ids = ["T1078.004", "T1548"] if "IamPolicy" in method else ["T1136.003"]
        results.append({
            "title": f"GCP Audit: {_e(method_short)}",
            "description": f"Sensitive GCP operation '{_e(method)}' on '{_e(resource_name)}' by '{_e(principal)}' from {_e(caller_ip)}.",
            "severity": "high",
            "source_tools": ["parse_gcp_audit_logs"],
            "evidence": [f"Method: {_e(method)}", f"Principal: {_e(principal)}", f"CallerIP: {_e(caller_ip)}", f"Resource: {_e(resource_name)}", f"Time: {_e(timestamp)}"],
            "ttp_ids": ttp_ids,
            "ioc_type": "ip" if caller_ip else None,
            "ioc_value": caller_ip or None,
            "extracted_iocs": [{"type": "ip", "value": caller_ip}] if caller_ip else [],
            "timeline_event": {
                "timestamp": timestamp, "source": "gcp_audit",
                "category": "cloud_iam",
                "description": f"{method_short} by {principal}", "evidence": resource_name,
            },
        })
    return results
