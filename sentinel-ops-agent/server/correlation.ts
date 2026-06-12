import { nanoid } from "nanoid";
import type { Alert, Incident } from "../drizzle/schema";
import {
  buildIncidentDraft,
  selectCorrelatedAlerts,
  shouldCreateIncident,
} from "@shared/correlation";
import {
  assignAlertsToIncident,
  createIncident,
  getAlertById,
  getAlertsByIncidentId,
  getIncidentById,
  getRecentAlertsForCorrelation,
  updateIncidentById,
} from "./db";

export type CorrelationResult = {
  alert: Alert;
  incident: Incident;
};

const buildInvestigationLineItems = (label: string, values: string[]) =>
  values.length > 0
    ? `${label}:\n${values.map((value) => `- ${value}`).join("\n")}`
    : "";

export async function correlateAlertToIncident(
  alert: Alert
): Promise<CorrelationResult | null> {
  const candidates = await getRecentAlertsForCorrelation(alert, 90, 50);
  const cluster = selectCorrelatedAlerts(alert, candidates, 90);

  if (!shouldCreateIncident(cluster)) {
    return null;
  }

  const draft = buildIncidentDraft(cluster);
  const existingIncidentIds = Array.from(
    new Set(
      cluster
        .map((candidate) => candidate.incidentId)
        .filter((incidentId): incidentId is number => incidentId !== null)
    )
  );

  let incident = existingIncidentIds.length
    ? await getIncidentById(existingIncidentIds[0])
    : undefined;

  if (incident) {
    await updateIncidentById(incident.id, {
      title: draft.title,
      severity: draft.severity,
      status: draft.status,
      affectedAssets: draft.affectedAssets,
      mitreAttackTactics: draft.mitreAttackTactics,
      rootCause: draft.rootCause,
      killChain: draft.killChain,
      remediationSteps: draft.remediationSteps,
    });
  } else {
    incident = await createIncident({
      incidentId: `INC-${nanoid(12)}`,
      title: draft.title,
      severity: draft.severity,
      status: draft.status,
      affectedAssets: draft.affectedAssets,
      mitreAttackTactics: draft.mitreAttackTactics,
      rootCause: draft.rootCause,
      killChain: draft.killChain,
      remediationSteps: draft.remediationSteps,
    });
  }

  await assignAlertsToIncident(draft.relatedAlertIds, incident.id);

  const refreshedAlert = await getAlertById(alert.id);
  const refreshedIncident = await getIncidentById(incident.id);

  if (!refreshedAlert || !refreshedIncident) {
    return null;
  }

  return {
    alert: refreshedAlert,
    incident: refreshedIncident,
  };
}

export async function refreshCorrelationForAlert(
  alertId: number
): Promise<Incident | null> {
  const alert = await getAlertById(alertId);
  if (!alert) return null;

  if (!alert.incidentId) {
    const correlation = await correlateAlertToIncident(alert);
    return correlation?.incident ?? null;
  }

  const incidentAlerts = await getAlertsByIncidentId(alert.incidentId);
  if (incidentAlerts.length === 0) {
    return null;
  }

  const draft = buildIncidentDraft(incidentAlerts);
  await updateIncidentById(alert.incidentId, {
    title: draft.title,
    severity: draft.severity,
    status: draft.status,
    affectedAssets: draft.affectedAssets,
    mitreAttackTactics: draft.mitreAttackTactics,
    rootCause: draft.rootCause,
    killChain: draft.killChain,
    remediationSteps: draft.remediationSteps,
  });

  return (await getIncidentById(alert.incidentId)) ?? null;
}

export function buildInvestigationCorrelationContext(alerts: Alert[]): string {
  if (alerts.length === 0) return "";

  const draft = buildIncidentDraft(alerts);
  return [
    "Correlated incident context:",
    `Title: ${draft.title}`,
    `Projected confidence: ${Math.round(draft.confidenceScore * 100)}%`,
    `Business impact score: ${Math.round(draft.businessImpactScore)}/100`,
    buildInvestigationLineItems("Storyline", draft.killChain),
    buildInvestigationLineItems("Recommended actions", draft.remediationSteps),
  ]
    .filter((section) => section.length > 0)
    .join("\n");
}
