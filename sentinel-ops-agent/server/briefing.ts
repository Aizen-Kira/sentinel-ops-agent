import type { Metric } from "../drizzle/schema";
import { parseStringArray } from "@shared/correlation";
import type { AlertStats, IncidentListItem } from "./db";
import { enhanceExecutiveBriefWithAI, type AIExecutionSource } from "./_core/ai";
import {
  getAlertStats,
  getIncidents,
  getLatestMetric,
  getOpenIncidentCount,
} from "./db";

type ExecutiveRiskLevel = "stable" | "elevated" | "critical";

export type ExecutiveBriefIncident = {
  incidentId: string;
  title: string;
  severity: IncidentListItem["severity"];
  status: IncidentListItem["status"];
  confidenceScore: number;
  businessImpactScore: number;
  affectedAssets: string[];
  storyline: string[];
  customerImpact: string;
  recommendedAction: string;
};

export type ExecutiveBrief = {
  generatedAt: Date;
  riskLevel: ExecutiveRiskLevel;
  headline: string;
  summary: string;
  urgentDecision: string;
  activeIncidentCount: number;
  criticalAlertCount: number;
  affectedAssetCount: number;
  businessRiskScore: number;
  topIncidents: ExecutiveBriefIncident[];
  keyPoints: string[];
  decisionsNeeded: string[];
  watchItems: string[];
  generatedBy: {
    mode: "ai-assisted" | "rule-based";
    provider: AIExecutionSource;
    model: string;
  };
};

const ASSET_LABELS = [
  { pattern: /(PROD|WEB|EXTERNAL-IP)/i, label: "customer-facing services" },
  { pattern: /(DB)/i, label: "sensitive data stores" },
  { pattern: /(AD|MAIL)/i, label: "identity and communications systems" },
  { pattern: /(BACKUP)/i, label: "resilience and recovery systems" },
  { pattern: /(FILE)/i, label: "internal document repositories" },
];

const clamp = (value: number, min: number, max: number) =>
  Math.min(max, Math.max(min, value));

const unique = (values: string[]) => Array.from(new Set(values));

const formatSeverity = (severity: string) =>
  severity.length > 0 ? severity[0].toUpperCase() + severity.slice(1) : severity;

const toMetricCounts = (
  metric: Metric | undefined,
  stats: AlertStats,
  openIncidentCount: number
) => ({
  openIncidentCount: metric?.openIncidentCount ?? openIncidentCount,
  criticalAlertCount: metric?.criticalAlertCount ?? stats.critical,
});

const classifyRiskLevel = (
  businessRiskScore: number,
  activeIncidentCount: number
): ExecutiveRiskLevel => {
  if (businessRiskScore >= 75 || activeIncidentCount >= 3) return "critical";
  if (businessRiskScore >= 45 || activeIncidentCount >= 1) return "elevated";
  return "stable";
};

const getBusinessExposure = (assets: string[]) => {
  const matched = unique(
    ASSET_LABELS.filter(({ pattern }) =>
      assets.some((asset) => pattern.test(asset))
    ).map(({ label }) => label)
  );

  if (matched.length === 0) return "internal operations";
  if (matched.length === 1) return matched[0];
  if (matched.length === 2) return `${matched[0]} and ${matched[1]}`;
  return `${matched[0]}, ${matched[1]}, and ${matched[2]}`;
};

const buildCustomerImpact = (incident: IncidentListItem) => {
  const affectedAssets = parseStringArray(incident.affectedAssets);
  const storyline = incident.storyline.join(" ").toLowerCase();

  if (/exfiltration/.test(storyline) || affectedAssets.some((asset) => /DB/i.test(asset))) {
    return "Potential exposure of sensitive business or customer data is the main concern.";
  }

  if (/impact|ddos/.test(storyline) || affectedAssets.some((asset) => /(PROD|WEB|EXTERNAL-IP)/i.test(asset))) {
    return "There is elevated risk of service disruption for customer-facing systems.";
  }

  if (affectedAssets.some((asset) => /(AD|MAIL)/i.test(asset))) {
    return "The main business risk is degraded employee access and communications.";
  }

  return "The immediate impact is operational, with customer exposure not yet confirmed.";
};

const buildRecommendedAction = (incident: IncidentListItem) => {
  const remediationSteps = parseStringArray(incident.remediationSteps);
  return remediationSteps[0] ?? "Approve immediate containment and incident-owner assignment.";
};

export function buildExecutiveBrief(options: {
  incidents: IncidentListItem[];
  stats: AlertStats;
  metric?: Metric;
  openIncidentCount: number;
}): ExecutiveBrief {
  const activeIncidents = options.incidents.filter(
    (incident) => incident.status !== "resolved"
  );
  const topIncidents = [...activeIncidents]
    .sort((left, right) => right.businessImpactScore - left.businessImpactScore)
    .slice(0, 3);
  const allAffectedAssets = unique(
    activeIncidents.flatMap((incident) => parseStringArray(incident.affectedAssets))
  );
  const businessRiskScore =
    topIncidents.length > 0
      ? Math.round(
          clamp(
            topIncidents.reduce(
              (total, incident) => total + incident.businessImpactScore,
              0
            ) / topIncidents.length,
            0,
            100
          )
        )
      : 8;
  const metricCounts = toMetricCounts(
    options.metric,
    options.stats,
    options.openIncidentCount
  );
  const riskLevel = classifyRiskLevel(
    businessRiskScore,
    metricCounts.openIncidentCount
  );
  const exposure = getBusinessExposure(allAffectedAssets);
  const leadIncident = topIncidents[0];

  const topIncidentBriefs: ExecutiveBriefIncident[] = topIncidents.map(
    (incident) => ({
      incidentId: incident.incidentId,
      title: incident.title,
      severity: incident.severity,
      status: incident.status,
      confidenceScore: incident.confidenceScore,
      businessImpactScore: incident.businessImpactScore,
      affectedAssets: parseStringArray(incident.affectedAssets),
      storyline: incident.storyline,
      customerImpact: buildCustomerImpact(incident),
      recommendedAction: buildRecommendedAction(incident),
    })
  );

  const headline = leadIncident
    ? `${formatSeverity(leadIncident.severity)} operational risk centered on ${exposure}.`
    : "No active security incidents are currently threatening business operations.";

  const summary = leadIncident
    ? `We are tracking ${metricCounts.openIncidentCount} active incident${metricCounts.openIncidentCount === 1 ? "" : "s"} across ${allAffectedAssets.length || 0} asset${allAffectedAssets.length === 1 ? "" : "s"}. The highest-priority issue is "${leadIncident.title}", which carries an estimated business impact score of ${Math.round(leadIncident.businessImpactScore)}/100 and ${Math.round(leadIncident.confidenceScore * 100)}% confidence.`
    : `Alert volume is present but not currently clustered into an active business-threatening incident. Critical alerts are at ${metricCounts.criticalAlertCount}, and the overall risk posture is ${riskLevel}.`;

  const urgentDecision = leadIncident
    ? `Approve the immediate containment action for ${leadIncident.incidentId}: ${buildRecommendedAction(leadIncident)}`
    : "No executive containment decision is required right now; continue monitoring and keep comms on standby.";

  const keyPoints = [
    leadIncident
      ? `${leadIncident.incidentId} is the lead incident, with likely exposure focused on ${getBusinessExposure(parseStringArray(leadIncident.affectedAssets))}.`
      : "No lead incident is currently active.",
    metricCounts.criticalAlertCount > 0
      ? `${metricCounts.criticalAlertCount} critical alert${metricCounts.criticalAlertCount === 1 ? "" : "s"} are contributing to the current risk picture.`
      : "No critical alerts are active right now.",
    allAffectedAssets.length > 0
      ? `${allAffectedAssets.length} distinct asset${allAffectedAssets.length === 1 ? "" : "s"} are in the current blast radius.`
      : "No verified blast radius is currently active.",
  ];

  const decisionsNeeded = topIncidentBriefs.length > 0
    ? topIncidentBriefs.map(
        (incident) => `${incident.incidentId}: ${incident.recommendedAction}`
      )
    : ["No immediate executive approvals are pending."];

  const watchItems = [
    leadIncident
      ? `Watch for expansion beyond ${getBusinessExposure(parseStringArray(leadIncident.affectedAssets))}.`
      : "Watch for any new correlated incident crossing into production or identity systems.",
    metricCounts.openIncidentCount > 1
      ? "Track whether multiple incidents are converging into a broader coordinated campaign."
      : "Track whether the active alert stream begins to cluster into a coordinated campaign.",
    riskLevel === "critical"
      ? "Prepare internal stakeholder communications if containment slows or customer-facing systems degrade."
      : "Maintain standby communications and revisit customer messaging only if impact indicators rise.",
  ];

  return {
    generatedAt: new Date(),
    riskLevel,
    headline,
    summary,
    urgentDecision,
    activeIncidentCount: metricCounts.openIncidentCount,
    criticalAlertCount: metricCounts.criticalAlertCount,
    affectedAssetCount: allAffectedAssets.length,
    businessRiskScore,
    topIncidents: topIncidentBriefs,
    keyPoints,
    decisionsNeeded,
    watchItems,
    generatedBy: {
      mode: "rule-based",
      provider: "heuristic",
      model: "sentinel-rules-v1",
    },
  };
}

export async function generateExecutiveBrief(): Promise<ExecutiveBrief> {
  const [incidents, stats, metric, openIncidentCount] = await Promise.all([
    getIncidents(25, 0),
    getAlertStats(),
    getLatestMetric(),
    getOpenIncidentCount(),
  ]);

  const baseBrief = buildExecutiveBrief({
    incidents,
    stats,
    metric,
    openIncidentCount,
  });

  return enhanceExecutiveBriefWithAI(baseBrief);
}
