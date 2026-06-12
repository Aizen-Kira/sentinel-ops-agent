import { describe, expect, it } from "vitest";
import type { Alert } from "../drizzle/schema";
import {
  buildIncidentDraft,
  deriveIncidentOperationalScores,
  selectCorrelatedAlerts,
  shouldCreateIncident,
} from "../shared/correlation";

const createAlert = (overrides: Partial<Alert>): Alert => ({
  id: overrides.id ?? 1,
  eventId: overrides.eventId ?? `EVT-${overrides.id ?? 1}`,
  severity: overrides.severity ?? "high",
  title: overrides.title ?? "Alert",
  description: overrides.description ?? "Description",
  source: overrides.source ?? "203.0.113.45",
  target: overrides.target ?? "WEB-SERVER-01",
  eventType: overrides.eventType ?? "failed_login",
  rawData: overrides.rawData ?? null,
  status: overrides.status ?? "open",
  assignedTo: overrides.assignedTo ?? null,
  createdAt: overrides.createdAt ?? new Date("2026-04-09T00:00:00.000Z"),
  updatedAt: overrides.updatedAt ?? new Date("2026-04-09T00:00:00.000Z"),
  incidentId: overrides.incidentId ?? null,
});

describe("correlation intelligence", () => {
  it("groups alerts that share a scenario and attack path", () => {
    const anchor = createAlert({
      id: 1,
      eventType: "failed_login",
      rawData: { scenarioId: "SCN-1" },
      target: "MAIL-SERVER",
    });
    const related = createAlert({
      id: 2,
      eventType: "privilege_escalation",
      source: "MAIL-SERVER",
      target: "MAIL-SERVER",
      rawData: { scenarioId: "SCN-1" },
      createdAt: new Date("2026-04-09T00:01:00.000Z"),
    });
    const unrelated = createAlert({
      id: 3,
      eventType: "ddos_attack",
      source: "198.51.100.10",
      target: "EXTERNAL-IP",
      rawData: { scenarioId: "SCN-2" },
    });

    const selected = selectCorrelatedAlerts(anchor, [related, unrelated]);

    expect(selected.map((alert) => alert.id)).toEqual([1, 2]);
  });

  it("builds an incident storyline and elevated severity for multi-stage chains", () => {
    const alerts = [
      createAlert({
        id: 1,
        eventType: "failed_login",
        target: "MAIL-SERVER",
        rawData: { scenarioId: "SCN-1" },
      }),
      createAlert({
        id: 2,
        eventType: "lateral_movement",
        source: "MAIL-SERVER",
        target: "DB-SERVER-02",
        severity: "critical",
        rawData: { scenarioId: "SCN-1" },
        createdAt: new Date("2026-04-09T00:01:00.000Z"),
      }),
      createAlert({
        id: 3,
        eventType: "data_exfiltration",
        source: "DB-SERVER-02",
        target: "EXTERNAL-IP",
        severity: "critical",
        rawData: { scenarioId: "SCN-1" },
        createdAt: new Date("2026-04-09T00:02:00.000Z"),
      }),
    ];

    const draft = buildIncidentDraft(alerts);

    expect(shouldCreateIncident(alerts)).toBe(true);
    expect(draft.title).toContain("data exfiltration");
    expect(draft.severity).toBe("critical");
    expect(draft.killChain.length).toBeGreaterThanOrEqual(3);
    expect(draft.remediationSteps.length).toBeGreaterThan(0);
  });

  it("derives high operational scores for critical multi-alert incidents", () => {
    const scores = deriveIncidentOperationalScores(
      {
        severity: "critical",
        affectedAssets: ["WEB-SERVER-01", "DB-SERVER-02", "EXTERNAL-IP"],
        killChain: [
          "Credential Access: Failed login targeting WEB-SERVER-01",
          "Lateral Movement: Suspicious movement targeting DB-SERVER-02",
          "Exfiltration: Data leaving EXTERNAL-IP",
        ],
        mitreAttackTactics: [
          "TA0006 Credential Access",
          "TA0008 Lateral Movement",
          "TA0010 Exfiltration",
        ],
        rootCause: "Coordinated intrusion progressing to data exfiltration.",
      },
      4
    );

    expect(scores.confidenceScore).toBeGreaterThan(0.7);
    expect(scores.businessImpactScore).toBeGreaterThan(70);
    expect(scores.blastRadius).toBe(3);
  });
});
