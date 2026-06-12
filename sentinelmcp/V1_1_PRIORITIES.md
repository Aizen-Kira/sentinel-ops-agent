# V1.1.0 Feature Priorities

## Priority Ranking Methodology
Items are ranked by balancing operational value against implementation complexity and maintenance burden, focusing on broadening coverage of modern architectures without regressing existing endpoint detections.

## 1. Cloud Forensics Integration (High Value, Medium Complexity)
**Value:** Expanding DFIR capabilities to AWS, Azure, and GCP logs captures critical identity and access threat vectors currently invisible to the agent.
**Implementation:** Straightforward addition to the fastMCP server via `cloud.py` mimicking existing log ingestion structures.
**Maintenance:** Low. Static JSON-based cloud logs are highly structured and parse predictably.

## 2. Reporting Enhancements (High Value, Low Complexity)
**Value:** Reformatting the HTML output to include Executive Summaries and dedicated IOC/Timeline appendices drastically improves readability for SOC analysts and management.
**Implementation:** Refactoring `agent/reporter.py` using existing Jinja/HTML string formatting.
**Maintenance:** Low.

## 3. Container Forensics (Medium Value, High Complexity)
**Value:** Coverage for Docker and Kubernetes intrusions allows for triage of modern stateless workloads.
**Implementation:** Creating `container.py` to parse ephemeral logs and metadata. Complexity arises from matching short-lived container IDs across logs.
**Maintenance:** Medium.

## 4. Benchmark Expansion (High Value, Low Complexity)
**Value:** Expanding the testing harness to 15 cases (adding SaaS, Cloud, and Container scenarios) prevents future regressions.
**Implementation:** Writing new ground truth and telemetry artifacts in `benchmark/cases/`.
**Maintenance:** Low.

## 5. Case Management (Medium Value, Low Complexity)
**Value:** Enforcing structured retention periods and status tracking for long-running investigations.
**Implementation:** Extending `shared/config.py` and tracking data within models.
**Maintenance:** Low.
