"""HTML report generator — V1.1.0 Enhanced Reporting (PHASE 5).

Sections:
  - Executive Summary   (management-oriented)
  - Analyst Findings    (CONFIRMED / INFERRED / UNSUPPORTED)
  - IOC Appendix        (structured indicators table)
  - ATT&CK Appendix     (TTP frequency table)
  - Timeline Appendix   (chronological super-timeline events)

ALL LLM-produced and user-controlled strings are escaped with html.escape()
before insertion into the report template (XSS prevention — BUG-003 fix).
"""
from __future__ import annotations

import html
from collections import Counter
from datetime import timezone, datetime
from typing import Any

from shared.models import Case, Finding, FindingStatus, IOC, TriageResult

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

_STATUS_COLORS: dict[str, str] = {
    "CONFIRMED": "#16a34a",
    "INFERRED": "#ca8a04",
    "UNSUPPORTED": "#dc2626",
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _e(value: object) -> str:
    """Escape a value for safe HTML insertion."""
    return html.escape(str(value), quote=True)


def _finding_card(f: Finding) -> str:
    sev_color = _SEVERITY_COLORS.get(f.severity, "#6b7280")
    status_color = _STATUS_COLORS.get(f.status.value, "#6b7280")
    evidence_items = "".join(
        f"<li><code>{_e(ev)}</code></li>" for ev in f.evidence
    ) or "<li><em>No evidence recorded.</em></li>"
    ioc_row = ""
    if f.ioc_type and f.ioc_value:
        ioc_row = (
            f'<p><strong>IOC:</strong> <span class="ioc-type">{_e(f.ioc_type)}</span> '
            f'— <code>{_e(f.ioc_value)}</code></p>'
        )
    ttp_row = ""
    if f.ttp_ids:
        badges = " ".join(
            f'<span class="ttp-badge"><a href="https://attack.mitre.org/techniques/'
            f'{_e(t.replace(".", "/"))}" target="_blank">{_e(t)}</a></span>'
            for t in f.ttp_ids
        )
        ttp_row = f"<p><strong>TTPs:</strong> {badges}</p>"
    return f"""
    <div class="finding" id="finding-{_e(f.id[:8])}">
      <div class="finding-header">
        <span class="severity-badge" style="background:{sev_color}">{_e(f.severity.upper())}</span>
        <span class="status-badge" style="background:{status_color}">{_e(f.status.value)}</span>
        <h3>{_e(f.title)}</h3>
      </div>
      <p class="description">{_e(f.description)}</p>
      {ioc_row}
      {ttp_row}
      <details>
        <summary>Evidence ({len(f.evidence)} item(s))</summary>
        <ul class="evidence-list">{evidence_items}</ul>
      </details>
      <p class="source-tools">
        <strong>Sources:</strong> {_e(', '.join(f.source_tools) or 'none')}
      </p>
    </div>"""


def _executive_summary_html(
    result: TriageResult,
    confirmed: list[Finding],
    inferred: list[Finding],
) -> str:
    """Management-oriented summary block."""
    highest_sev = "none"
    if confirmed:
        sev_sorted = sorted(confirmed, key=lambda f: _SEVERITY_RANK.get(f.severity, 99))
        highest_sev = sev_sorted[0].severity if sev_sorted else "none"

    verdict = (
        "COMPROMISED" if confirmed else
        "SUSPICIOUS — FURTHER INVESTIGATION RECOMMENDED" if inferred else
        "NO MALICIOUS ACTIVITY DETECTED"
    )
    verdict_color = "#dc2626" if confirmed else ("#ca8a04" if inferred else "#16a34a")

    top_findings = confirmed[:3] if confirmed else inferred[:3]
    top_list = "".join(
        f"<li><strong>{_e(f.severity.upper())}</strong> — {_e(f.title)}</li>"
        for f in top_findings
    ) or "<li>No significant findings.</li>"

    return f"""
    <section id="exec-summary">
      <h2>Executive Summary</h2>
      <div class="exec-verdict" style="border-left: 4px solid {verdict_color}; padding: .75rem 1rem; background:#1e293b; margin-bottom:1rem;">
        <span style="color:{verdict_color}; font-weight:700; font-size:1.1rem;">{_e(verdict)}</span>
      </div>
      <table>
        <tr><th>Confirmed Findings</th><th>Inferred Findings</th><th>Highest Severity</th><th>Triage Iterations</th></tr>
        <tr>
          <td style="color:#16a34a; font-weight:700">{_e(len(confirmed))}</td>
          <td style="color:#ca8a04; font-weight:700">{_e(len(inferred))}</td>
          <td style="color:{_SEVERITY_COLORS.get(highest_sev, '#6b7280')}; font-weight:700">{_e(highest_sev.upper())}</td>
          <td>{_e(len(result.iterations))}</td>
        </tr>
      </table>
      <h3>Top Findings</h3>
      <ul>{top_list}</ul>
    </section>"""


def _ioc_appendix_html(findings: list[Finding]) -> str:
    """Structured IOC table from all findings."""
    rows: list[str] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        # Primary IOC from the finding itself
        if f.ioc_type and f.ioc_value:
            key = (f.ioc_type, f.ioc_value)
            if key not in seen:
                seen.add(key)
                rows.append(
                    f"<tr><td><span class='ioc-type'>{_e(f.ioc_type)}</span></td>"
                    f"<td><code>{_e(f.ioc_value)}</code></td>"
                    f"<td>{_e(f.severity.upper())}</td>"
                    f"<td>{_e(f.title[:60])}</td></tr>"
                )
        # Extracted IOCs
        for ioc in f.extracted_iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                rows.append(
                    f"<tr><td><span class='ioc-type'>{_e(ioc.type)}</span></td>"
                    f"<td><code>{_e(ioc.value)}</code></td>"
                    f"<td>{_e(f.severity.upper())}</td>"
                    f"<td>{_e(f.title[:60])}</td></tr>"
                )
    if not rows:
        return '<section id="ioc-appendix"><h2>IOC Appendix</h2><p>No IOCs extracted.</p></section>'
    table_body = "\n".join(rows)
    return f"""
    <section id="ioc-appendix">
      <h2>IOC Appendix</h2>
      <table>
        <tr><th>Type</th><th>Value</th><th>Severity</th><th>Source Finding</th></tr>
        {table_body}
      </table>
    </section>"""


def _attack_appendix_html(findings: list[Finding]) -> str:
    """ATT&CK TTP frequency table."""
    ttp_counter: Counter[str] = Counter()
    ttp_finding_map: dict[str, str] = {}
    for f in findings:
        for t in f.ttp_ids:
            ttp_counter[t] += 1
            if t not in ttp_finding_map:
                ttp_finding_map[t] = f.title
    if not ttp_counter:
        return '<section id="attack-appendix"><h2>ATT&amp;CK Appendix</h2><p>No TTPs mapped.</p></section>'
    rows = "".join(
        f"<tr><td><a href='https://attack.mitre.org/techniques/{_e(t.replace('.', '/'))}"
        f"' target='_blank' class='ttp-badge'>{_e(t)}</a></td>"
        f"<td>{_e(count)}</td><td>{_e(ttp_finding_map[t][:60])}</td></tr>"
        for t, count in ttp_counter.most_common()
    )
    return f"""
    <section id="attack-appendix">
      <h2>ATT&amp;CK Appendix</h2>
      <table>
        <tr><th>Technique ID</th><th>Frequency</th><th>First Seen In</th></tr>
        {rows}
      </table>
    </section>"""


def _timeline_appendix_html(timeline: dict[str, Any] | None) -> str:
    """Chronological super-timeline events appendix."""
    if not timeline or not timeline.get("events"):
        return '<section id="timeline-appendix"><h2>Timeline Appendix</h2><p>No timeline data.</p></section>'
    events: list[dict[str, Any]] = timeline["events"]
    # Paginate: display at most 500 events (BUG-003 fix for context bloat)
    displayed = events[:500]
    total = len(events)
    rows = "".join(
        f"<tr><td><code>{_e(ev.get('timestamp', ''))}</code></td>"
        f"<td><span class='ioc-type'>{_e(ev.get('source', ''))}</span></td>"
        f"<td>{_e(ev.get('category', ''))}</td>"
        f"<td>{_e(ev.get('description', '')[:120])}</td></tr>"
        for ev in displayed
    )
    truncation_note = (
        f"<p><em>Showing {len(displayed)} of {total} events. "
        f"Full timeline available in raw output.</em></p>"
        if total > 500 else ""
    )
    return f"""
    <section id="timeline-appendix">
      <h2>Timeline Appendix</h2>
      {truncation_note}
      <table>
        <tr><th>Timestamp</th><th>Source</th><th>Category</th><th>Description</th></tr>
        {rows}
      </table>
    </section>"""


_CSS = """
body { font-family: system-ui, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }
h1 { color: #38bdf8; }
h2 { color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom:.4rem; margin-top:2rem; }
h3 { color: #cbd5e1; margin-top:1rem; }
.meta { color: #64748b; font-size: .9rem; margin-bottom: 2rem; }
.finding { background: #1e293b; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
.finding-header { display: flex; align-items: center; gap: .5rem; margin-bottom: .5rem; }
.finding-header h3 { margin: 0; font-size: 1rem; color: #f1f5f9; }
.severity-badge, .status-badge { border-radius: 4px; padding: 2px 8px; font-size: .75rem;
  font-weight: 700; color: #fff; text-transform: uppercase; }
.description { color: #cbd5e1; margin: .4rem 0; }
.evidence-list { font-size: .85rem; color: #94a3b8; }
.evidence-list code { background: #0f172a; padding: 1px 4px; border-radius: 3px; }
.source-tools { font-size: .8rem; color: #64748b; }
.ioc-type { background: #7c3aed; color: #fff; border-radius: 4px; padding: 1px 6px; font-size:.75rem; }
.ttp-badge { background: #0e7490; color: #fff; border-radius: 4px; padding: 1px 6px;
  font-size:.75rem; text-decoration:none; }
.ttp-badge:hover { background: #155e75; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; margin-top:.5rem; }
th, td { border: 1px solid #334155; padding: .5rem .75rem; text-align: left; }
th { background: #1e293b; color: #94a3b8; }
summary { cursor: pointer; color: #38bdf8; }
.exec-verdict { border-radius: 6px; }
nav.toc { background: #1e293b; border-radius:8px; padding:1rem 1.5rem; margin-bottom:2rem; }
nav.toc ul { margin:0; padding-left:1.2rem; }
nav.toc a { color: #38bdf8; text-decoration:none; }
nav.toc a:hover { text-decoration:underline; }
"""


def generate_report(result: TriageResult, case: Case) -> str:
    """Generate a full HTML triage report with all V1.1.0 appendices.

    Sections:
      - Executive Summary
      - Analyst Findings (CONFIRMED / INFERRED / UNSUPPORTED)
      - IOC Appendix
      - ATT&CK Appendix
      - Timeline Appendix
      - Iteration Log

    All user-controlled and LLM-produced strings are HTML-escaped.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    confirmed = [f for f in result.findings if f.status == FindingStatus.CONFIRMED]
    inferred = [f for f in result.findings if f.status == FindingStatus.INFERRED]
    unsupported = [f for f in result.findings if f.status == FindingStatus.UNSUPPORTED]

    # Analyst Findings sections
    analyst_sections: list[str] = []
    for label, group in [("Confirmed", confirmed), ("Inferred", inferred), ("Unsupported", unsupported)]:
        if group:
            cards = "".join(_finding_card(f) for f in group)
            analyst_sections.append(
                f'<section id="findings-{label.lower()}"><h2>{label} Findings ({len(group)})</h2>{cards}</section>'
            )
    analyst_html = "\n".join(analyst_sections) or "<p>No findings produced.</p>"

    iteration_rows = "".join(
        f"<tr><td>{_e(log.iteration)}</td><td>{_e(', '.join(log.tools_called))}</td>"
        f"<td>{_e(log.findings_count)}</td><td>{_e(log.gaps_count)}</td></tr>"
        for log in result.iterations
    )

    exec_html = _executive_summary_html(result, confirmed, inferred)
    ioc_html = _ioc_appendix_html(result.findings)
    attack_html = _attack_appendix_html(result.findings)
    timeline_html = _timeline_appendix_html(result.timeline)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentinelMCP Triage Report — {_e(result.case_id)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>SentinelMCP Triage Report</h1>
  <div class="meta">
    <strong>Case ID:</strong> {_e(result.case_id)} &nbsp;|&nbsp;
    <strong>Status:</strong> {_e(case.status.value if hasattr(case, 'status') else 'OPEN')} &nbsp;|&nbsp;
    <strong>Generated:</strong> {_e(now)} &nbsp;|&nbsp;
    <strong>Description:</strong> {_e(case.description or "N/A")}
  </div>

  <nav class="toc">
    <strong>Contents</strong>
    <ul>
      <li><a href="#exec-summary">Executive Summary</a></li>
      <li><a href="#findings-confirmed">Confirmed Findings</a></li>
      <li><a href="#findings-inferred">Inferred Findings</a></li>
      <li><a href="#ioc-appendix">IOC Appendix</a></li>
      <li><a href="#attack-appendix">ATT&amp;CK Appendix</a></li>
      <li><a href="#timeline-appendix">Timeline Appendix</a></li>
    </ul>
  </nav>

  {exec_html}

  <section id="analyst-findings">
    <h2>Analyst Findings</h2>
    {analyst_html}
  </section>

  {ioc_html}
  {attack_html}
  {timeline_html}

  <section id="iteration-log">
    <h2>Iteration Log</h2>
    <table>
      <tr><th>#</th><th>Tools Called</th><th>Findings</th><th>Gaps</th></tr>
      {iteration_rows}
    </table>
  </section>
</body>
</html>"""
