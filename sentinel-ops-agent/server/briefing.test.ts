import { describe, expect, it } from "vitest";
import type { IncidentListItem, AlertStats } from "./db";
import { buildExecutiveBrief } from "./briefing";
import { renderHtmlEmail, type BriefingContent } from "./lib/briefing/briefingService";
import { escapeHtml } from "@shared/html";

const createStats = (overrides: Partial<AlertStats> = {}): AlertStats => ({
  total: 8,
  critical: 2,
  high: 3,
  medium: 2,
  low: 1,
  open: 4,
  acknowledged: 1,
  escalated: 2,
  dismissed: 1,
  ...overrides,
});

const createIncident = (
  overrides: Partial<IncidentListItem>
): IncidentListItem => ({
  id: overrides.id ?? 1,
  incidentId: overrides.incidentId ?? "INC-001",
  title: overrides.title ?? "Coordinated intrusion progressing to data exfiltration",
  severity: overrides.severity ?? "critical",
  status: overrides.status ?? "investigating",
  rootCause:
    overrides.rootCause ??
    "Coordinated intrusion progressing to data exfiltration. Confidence 91%.",
  affectedAssets:
    overrides.affectedAssets ?? ["WEB-SERVER-01", "DB-SERVER-02", "EXTERNAL-IP"],
  mitreAttackTactics:
    overrides.mitreAttackTactics ??
    ["TA0006 Credential Access", "TA0008 Lateral Movement", "TA0010 Exfiltration"],
  killChain:
    overrides.killChain ??
    [
      "Credential Access: Suspicious Failed Login Attempts targeting WEB-SERVER-01",
      "Lateral Movement: Internal Pivot to Secondary Asset targeting DB-SERVER-02",
      "Exfiltration: Sensitive Data Leaving the Network targeting EXTERNAL-IP",
    ],
  remediationSteps:
    overrides.remediationSteps ??
    ["Block the outbound transfer path and quarantine the source asset."],
  createdAt: overrides.createdAt ?? new Date("2026-04-09T00:00:00.000Z"),
  updatedAt: overrides.updatedAt ?? new Date("2026-04-09T00:03:00.000Z"),
  investigationId: overrides.investigationId ?? null,
  alertCount: overrides.alertCount ?? 4,
  latestAlertAt:
    overrides.latestAlertAt ?? new Date("2026-04-09T00:03:00.000Z"),
  affectedAssetCount: overrides.affectedAssetCount ?? 3,
  confidenceScore: overrides.confidenceScore ?? 0.91,
  businessImpactScore: overrides.businessImpactScore ?? 88,
  storyline:
    overrides.storyline ??
    [
      "Credential Access: Suspicious Failed Login Attempts targeting WEB-SERVER-01",
      "Lateral Movement: Internal Pivot to Secondary Asset targeting DB-SERVER-02",
      "Exfiltration: Sensitive Data Leaving the Network targeting EXTERNAL-IP",
    ],
});

describe("executive brief generator", () => {
  it("builds a critical brief from high-impact incidents", () => {
    const brief = buildExecutiveBrief({
      incidents: [createIncident({ incidentId: "INC-CEO-1" })],
      stats: createStats(),
      openIncidentCount: 1,
    });

    expect(brief.riskLevel).toBe("critical");
    expect(brief.headline).toContain("operational risk");
    expect(brief.topIncidents[0]?.incidentId).toBe("INC-CEO-1");
    expect(brief.urgentDecision).toContain("Approve");
    expect(brief.decisionsNeeded.length).toBeGreaterThan(0);
  });

  it("builds a stable brief when there are no active incidents", () => {
    const brief = buildExecutiveBrief({
      incidents: [],
      stats: createStats({ critical: 0, open: 0 }),
      openIncidentCount: 0,
    });

    expect(brief.riskLevel).toBe("stable");
    expect(brief.topIncidents).toHaveLength(0);
    expect(brief.urgentDecision).toContain("No executive containment decision");
  });
});

describe("HTML escaping", () => {
  it("escapes raw HTML metacharacters", () => {
    expect(escapeHtml(`<script a="1">&'</script>`)).toBe(
      "&lt;script a=&quot;1&quot;&gt;&amp;&#39;&lt;/script&gt;"
    );
  });

  it("escapes dynamic briefing fields before rendering HTML email", () => {
    const briefing: BriefingContent = {
      executiveSummary: `Summary <img src=x onerror="alert(1)"> & follow-up`,
      businessImpact: `Impact "quoted" & <b>bold</b>`,
      riskOverview: {
        score: 99,
        label: `Critical <script>`,
        rationale: "not rendered",
      },
      timelineHighlights: [],
      recommendedActions: [
        {
          title: `Contain <host> & rotate "keys"`,
          urgency: "immediate",
          ownerRole: `CISO & "Legal"`,
        },
      ],
      currentStatus: "active",
      nextSteps: `Next <step> & confirm`,
      generatedAt: "2026-06-09T00:00:00.000Z",
      isStale: false,
    };

    const html = renderHtmlEmail(briefing, 42);

    expect(html).not.toContain(`<img src=x`);
    expect(html).not.toContain(`<script>`);
    expect(html).not.toContain(`<host>`);
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; follow-up");
    expect(html).toContain("Contain &lt;host&gt; &amp; rotate &quot;keys&quot;");
    expect(html).toContain("CISO &amp; &quot;Legal&quot;");
  });
});
