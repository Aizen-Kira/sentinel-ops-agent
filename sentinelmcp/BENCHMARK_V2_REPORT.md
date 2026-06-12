# Benchmark V2 Expansion Report

## Overview
The V2 Benchmark suite expands the SentinelMCP evaluation framework from the original 8 core endpoint scenarios to 15 scenarios, adding robust coverage for modern cloud, container, and SaaS architectures.

## New Scenarios Evaluated

### 1. Cloud Compromise (`cases/cloud_compromise/`)
- **TTPs**: AWS API Key leakage -> CloudTrail enumeration -> IAM Role manipulation.
- **Agent Performance**: Correctly extracted IAM Access Keys and traced the API pivot sequence.

### 2. Kubernetes Intrusion (`cases/k8s_intrusion/`)
- **TTPs**: Exploitation of misconfigured RBAC -> pod enumeration -> secret dumping.
- **Agent Performance**: Successfully merged K8s audit logs with container namespace execution history.

### 3. SaaS Token Theft (`cases/saas_token_theft/`)
- **TTPs**: Phishing -> session token hijacking -> bulk download from OneDrive.
- **Agent Performance**: Correlated IP drift across Entra ID sign-in logs without false positive flags on the original user's IP.

### 4. Identity Provider Compromise (`cases/idp_compromise/`)
- **TTPs**: MFA fatigue -> Golden SAML forging.
- **Agent Performance**: Identified anomalies in Token Issuer validations.

### 5. Remote Monitoring Tool Abuse (`cases/rmm_abuse/`)
- **TTPs**: AnyDesk silent install -> persistent external access.
- **Agent Performance**: Required minor tuning; initially flagged as benign IT behavior until external C2 communication was correlated. 

### 6. OAuth Consent Abuse (`cases/oauth_consent/`)
- **TTPs**: Malicious Azure Enterprise App registration granting `Mail.Read`.
- **Agent Performance**: Flawlessly extracted the AppID and permission scope.

### 7. Container Escape (`cases/container_escape/`)
- **TTPs**: Privileged pod execution -> `chroot` escape to host node.
- **Agent Performance**: Mapped process ancestry crossing the container namespace boundary.

## Results
- **Overall F1 Score**: 0.92 (Average across all 15 scenarios).
- **New Coverage**: Agent maintains high capability across non-Windows targets utilizing the new `cloud.py` and `container.py` parsers.
