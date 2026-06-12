import type { Alert, Incident } from "../drizzle/schema";

type EventIntelligence = {
  family: string;
  tactic: string;
  phase: string;
  phaseOrder: number;
  remediationSteps: string[];
};

export type IncidentOperationalScores = {
  confidenceScore: number;
  businessImpactScore: number;
  blastRadius: number;
  storyline: string[];
};

export type IncidentDraft = {
  title: string;
  severity: Incident["severity"];
  status: Incident["status"];
  affectedAssets: string[];
  mitreAttackTactics: string[];
  rootCause: string;
  killChain: string[];
  remediationSteps: string[];
  confidenceScore: number;
  businessImpactScore: number;
  blastRadius: number;
  relatedAlertIds: number[];
};

const HIGH_VALUE_ASSET_PATTERN = /(PROD|DB|AD|MAIL|BACKUP|FILE)/i;

export const EVENT_INTELLIGENCE: Record<string, EventIntelligence> = {
  failed_login: {
    family: "credential abuse",
    tactic: "TA0006 Credential Access",
    phase: "Credential Access",
    phaseOrder: 2,
    remediationSteps: [
      "Lock the affected account and enforce a password reset.",
      "Review MFA coverage for the targeted identity and access path.",
    ],
  },
  port_scan: {
    family: "reconnaissance",
    tactic: "TA0043 Reconnaissance",
    phase: "Reconnaissance",
    phaseOrder: 1,
    remediationSteps: [
      "Block the scanning source at the edge and monitor for retries.",
      "Review exposed services on the targeted asset.",
    ],
  },
  lateral_movement: {
    family: "lateral movement",
    tactic: "TA0008 Lateral Movement",
    phase: "Lateral Movement",
    phaseOrder: 4,
    remediationSteps: [
      "Isolate the pivot host from the internal network.",
      "Inspect east-west authentication and RDP/SMB activity for the host pair.",
    ],
  },
  data_exfiltration: {
    family: "exfiltration",
    tactic: "TA0010 Exfiltration",
    phase: "Exfiltration",
    phaseOrder: 5,
    remediationSteps: [
      "Block the outbound transfer path and quarantine the source asset.",
      "Review recent access to sensitive data stores touched by the host.",
    ],
  },
  privilege_escalation: {
    family: "privilege escalation",
    tactic: "TA0004 Privilege Escalation",
    phase: "Privilege Escalation",
    phaseOrder: 3,
    remediationSteps: [
      "Revoke elevated sessions and rotate privileged credentials.",
      "Audit recent policy changes and administrative actions on the host.",
    ],
  },
  malware_detected: {
    family: "malware execution",
    tactic: "TA0005 Defense Evasion",
    phase: "Execution",
    phaseOrder: 3,
    remediationSteps: [
      "Quarantine the infected endpoint and collect the malware artifact.",
      "Review adjacent hosts for the same indicator set.",
    ],
  },
  ddos_attack: {
    family: "service disruption",
    tactic: "TA0040 Impact",
    phase: "Impact",
    phaseOrder: 5,
    remediationSteps: [
      "Rate-limit or null-route the abusive source traffic.",
      "Scale or fail over the internet-facing service if customer impact is rising.",
    ],
  },
  sql_injection: {
    family: "application compromise",
    tactic: "TA0001 Initial Access",
    phase: "Initial Access",
    phaseOrder: 2,
    remediationSteps: [
      "Block the attacking source and review vulnerable query paths.",
      "Rotate database credentials exposed to the targeted application tier.",
    ],
  },
};

const SEVERITY_RANK: Record<Alert["severity"], number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const clamp = (value: number, min: number, max: number) =>
  Math.min(max, Math.max(min, value));

const capitalize = (value: string) =>
  value.length > 0 ? value[0].toUpperCase() + value.slice(1) : value;

const uniqueStrings = (values: string[]) => Array.from(new Set(values));

const asString = (value: unknown): string | null =>
  typeof value === "string" && value.trim().length > 0 ? value.trim() : null;

export const parseStringArray = (value: unknown): string[] =>
  Array.isArray(value)
    ? value
        .map(asString)
        .filter((item): item is string => item !== null)
    : [];

const readRawDataString = (rawData: unknown, key: string): string | null => {
  if (!rawData || typeof rawData !== "object" || Array.isArray(rawData)) {
    return null;
  }

  return asString((rawData as Record<string, unknown>)[key]);
};

const getPrimaryAsset = (alerts: Alert[]) =>
  alerts
    .flatMap((alert) => [asString(alert.target), asString(alert.source)])
    .find((asset): asset is string => asset !== null) ?? "multiple assets";

const getSharedSource = (alerts: Alert[]) => {
  const counts = new Map<string, number>();

  for (const alert of alerts) {
    counts.set(alert.source, (counts.get(alert.source) ?? 0) + 1);
  }

  const ordered = Array.from(counts.entries()).sort((left, right) => right[1] - left[1]);
  return ordered[0]?.[0] ?? null;
};

const hasEventType = (alerts: Alert[], eventType: string) =>
  alerts.some((alert) => alert.eventType === eventType);

const getHighestSeverity = (alerts: Alert[]): Incident["severity"] => {
  let highest: Alert["severity"] = "low";

  for (const alert of alerts) {
    if (SEVERITY_RANK[alert.severity] > SEVERITY_RANK[highest]) {
      highest = alert.severity;
    }
  }

  const uniqueEventTypes = new Set(alerts.map((alert) => alert.eventType)).size;

  if (highest === "high" && uniqueEventTypes >= 3) {
    return "critical";
  }

  return highest;
};

const getIncidentStatus = (alerts: Alert[]): Incident["status"] => {
  if (alerts.length === 0) return "open";
  if (alerts.every((alert) => alert.status === "dismissed")) return "resolved";
  if (
    alerts.some(
      (alert) =>
        alert.status === "acknowledged" || alert.status === "escalated"
    )
  ) {
    return "investigating";
  }
  return "open";
};

export const selectCorrelatedAlerts = (
  anchor: Alert,
  candidates: Alert[],
  windowMinutes: number = 90
): Alert[] => {
  const anchorTime = new Date(anchor.createdAt).getTime();
  const scenarioId = readRawDataString(anchor.rawData, "scenarioId");

  const related = candidates.filter((candidate) => {
    const candidateTime = new Date(candidate.createdAt).getTime();
    const withinWindow =
      Math.abs(candidateTime - anchorTime) <= windowMinutes * 60 * 1000;
    if (!withinWindow) return false;

    const candidateScenarioId = readRawDataString(candidate.rawData, "scenarioId");
    if (scenarioId && candidateScenarioId && scenarioId === candidateScenarioId) {
      return true;
    }

    const sharedSource = candidate.source === anchor.source;
    const sharedTarget =
      !!anchor.target &&
      !!candidate.target &&
      candidate.target === anchor.target;
    const pivotHost =
      (!!anchor.target && candidate.source === anchor.target) ||
      (!!candidate.target && candidate.target === anchor.source);
    const sharedFamily =
      sharedSource &&
      EVENT_INTELLIGENCE[candidate.eventType]?.family ===
        EVENT_INTELLIGENCE[anchor.eventType]?.family;

    return sharedSource || sharedTarget || pivotHost || sharedFamily;
  });

  const deduped = new Map<number, Alert>();
  for (const alert of [anchor, ...related]) {
    deduped.set(alert.id, alert);
  }

  return Array.from(deduped.values()).sort(
    (left, right) =>
      new Date(left.createdAt).getTime() - new Date(right.createdAt).getTime()
  );
};

export const shouldCreateIncident = (alerts: Alert[]): boolean => {
  if (alerts.length === 0) return false;
  const highestSeverity = getHighestSeverity(alerts);
  if (alerts.length >= 2) return true;
  return highestSeverity === "critical";
};

const buildIncidentTitle = (alerts: Alert[]) => {
  if (hasEventType(alerts, "data_exfiltration") && hasEventType(alerts, "lateral_movement")) {
    return "Coordinated intrusion progressing to data exfiltration";
  }

  if (hasEventType(alerts, "failed_login") && hasEventType(alerts, "privilege_escalation")) {
    return "Credential abuse campaign with privilege escalation";
  }

  if (hasEventType(alerts, "sql_injection") && hasEventType(alerts, "lateral_movement")) {
    return "Application compromise spreading into internal systems";
  }

  if (hasEventType(alerts, "malware_detected") && hasEventType(alerts, "lateral_movement")) {
    return "Malware-driven lateral movement across enterprise assets";
  }

  if (hasEventType(alerts, "ddos_attack")) {
    return "Service disruption campaign against internet-facing systems";
  }

  const primaryFamily =
    EVENT_INTELLIGENCE[alerts[0]?.eventType]?.family ?? "suspicious activity";
  return `${capitalize(primaryFamily)} affecting ${getPrimaryAsset(alerts)}`;
};

export const deriveIncidentOperationalScores = (
  incident: Pick<
    Incident,
    "severity" | "affectedAssets" | "killChain" | "mitreAttackTactics" | "rootCause"
  >,
  alertCount: number
): IncidentOperationalScores => {
  const affectedAssets = parseStringArray(incident.affectedAssets);
  const storyline = parseStringArray(incident.killChain);
  const tactics = parseStringArray(incident.mitreAttackTactics);
  const blastRadius = uniqueStrings(affectedAssets).length;
  const severityWeight = SEVERITY_RANK[incident.severity];

  const confidenceScore = clamp(
    0.42 +
      severityWeight * 0.08 +
      Math.min(alertCount, 6) * 0.05 +
      Math.min(storyline.length, 5) * 0.04 +
      Math.min(tactics.length, 4) * 0.03,
    0.4,
    0.99
  );

  const highValueAssetCount = affectedAssets.filter((asset) =>
    HIGH_VALUE_ASSET_PATTERN.test(asset)
  ).length;
  const impactFromStory =
    /exfiltration|privilege|lateral|malware|impact/i.test(incident.rootCause ?? "")
      ? 12
      : 0;

  const businessImpactScore = clamp(
    18 +
      severityWeight * 14 +
      Math.min(alertCount, 8) * 5 +
      blastRadius * 7 +
      highValueAssetCount * 8 +
      impactFromStory,
    10,
    100
  );

  return {
    confidenceScore,
    businessImpactScore,
    blastRadius,
    storyline,
  };
};

export const buildIncidentDraft = (alerts: Alert[]): IncidentDraft => {
  const sortedAlerts = [...alerts].sort(
    (left, right) =>
      new Date(left.createdAt).getTime() - new Date(right.createdAt).getTime()
  );
  const highestSeverity = getHighestSeverity(sortedAlerts);
  const affectedAssets = uniqueStrings(
    sortedAlerts.flatMap((alert) =>
      [asString(alert.source), asString(alert.target)].filter(
        (item): item is string => item !== null
      )
    )
  );

  const groupedByPhase = new Map<string, Alert>();
  for (const alert of sortedAlerts) {
    const intelligence = EVENT_INTELLIGENCE[alert.eventType];
    const phase = intelligence?.phase ?? "Investigation";
    if (!groupedByPhase.has(phase)) {
      groupedByPhase.set(phase, alert);
    }
  }

  const killChain = Array.from(groupedByPhase.entries())
    .sort((left, right) => {
      const leftOrder = EVENT_INTELLIGENCE[left[1].eventType]?.phaseOrder ?? 99;
      const rightOrder = EVENT_INTELLIGENCE[right[1].eventType]?.phaseOrder ?? 99;
      return leftOrder - rightOrder;
    })
    .map(([phase, alert]) => `${phase}: ${alert.title} targeting ${alert.target ?? alert.source}`);

  const mitigationSteps = uniqueStrings(
    sortedAlerts.flatMap(
      (alert) => EVENT_INTELLIGENCE[alert.eventType]?.remediationSteps ?? []
    )
  ).slice(0, 5);

  const tactics = uniqueStrings(
    sortedAlerts
      .map((alert) => EVENT_INTELLIGENCE[alert.eventType]?.tactic ?? null)
      .filter((item): item is string => item !== null)
  );

  const sharedSource = getSharedSource(sortedAlerts);
  const draftScores = deriveIncidentOperationalScores(
    {
      severity: highestSeverity,
      affectedAssets,
      killChain,
      mitreAttackTactics: tactics,
      rootCause: "",
    },
    sortedAlerts.length
  );

  const rootCause = [
    `${buildIncidentTitle(sortedAlerts)}.`,
    sharedSource
      ? `The correlated activity is anchored to ${sharedSource}`
      : "The correlated activity spans multiple initiators",
    `and touches ${draftScores.blastRadius} asset${draftScores.blastRadius === 1 ? "" : "s"}.`,
    `Confidence ${Math.round(draftScores.confidenceScore * 100)}% with a projected business impact score of ${Math.round(draftScores.businessImpactScore)}.`,
  ].join(" ");

  return {
    title: buildIncidentTitle(sortedAlerts),
    severity: highestSeverity,
    status: getIncidentStatus(sortedAlerts),
    affectedAssets,
    mitreAttackTactics: tactics,
    rootCause,
    killChain,
    remediationSteps: mitigationSteps,
    confidenceScore: draftScores.confidenceScore,
    businessImpactScore: draftScores.businessImpactScore,
    blastRadius: draftScores.blastRadius,
    relatedAlertIds: sortedAlerts.map((alert) => alert.id),
  };
};
