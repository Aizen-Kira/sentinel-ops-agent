import type { Alert, Investigation } from "../drizzle/schema";

export const REALTIME_EVENT_TYPES = [
  "realtime.ready",
  "alert.created",
  "alert.updated",
  "investigation.started",
  "investigation.job.queued",
  "investigation.stage",
  "investigation.step",
  "investigation.completed",
  "investigation.failed",
  "response.action.proposed",
  "response.action.approved",
  "response.action.executed",
  "report.generation.started",
  "report.generation.progress",
  "report.generation.completed",
  "report.generation.failed",
] as const;

export type RealtimeEventType = (typeof REALTIME_EVENT_TYPES)[number];

export type RealtimeConnectionStatus =
  | "connecting"
  | "connected"
  | "reconnecting"
  | "disconnected";

export type RealtimeReadyEvent = {
  type: "realtime.ready";
  connectedAt: Date;
};

export type AlertCreatedRealtimeEvent = {
  type: "alert.created";
  alert: Alert;
};

export type AlertUpdatedRealtimeEvent = {
  type: "alert.updated";
  alert: Alert;
  previousSeverity?: Alert["severity"];
  previousStatus?: Alert["status"];
};

export type InvestigationStartedRealtimeEvent = {
  type: "investigation.started";
  investigation: Investigation;
};

export type InvestigationJobQueuedRealtimeEvent = {
  type: "investigation.job.queued";
  investigationId: string;
  jobId: string;
  queuedAt: Date;
};

export type InvestigationStageRealtimeEvent = {
  type: "investigation.stage";
  investigationId: string;
  stage:
    | "evidence_extraction"
    | "hypothesis"
    | "missing_data"
    | "recommended_actions";
  result: Record<string, unknown>;
  index: number;
  totalStages: number;
};

export type InvestigationStepRealtimeEvent = {
  type: "investigation.step";
  investigationId: string;
  step: string;
  index: number;
  totalSteps?: number;
  source: "system" | "analysis";
};

export type InvestigationCompletedRealtimeEvent = {
  type: "investigation.completed";
  investigationId: string;
  conclusion: string;
  confidence: number;
  steps: string[];
  completedAt: Date;
  provider: "ollama" | "forge" | "heuristic";
  model: string;
  localMode: boolean;
  playbookId?: string | null;
  jobId?: string | null;
};

export type InvestigationFailedRealtimeEvent = {
  type: "investigation.failed";
  investigationId: string;
  error: string;
  failedAt: Date;
};

export type ResponseActionProposedRealtimeEvent = {
  type: "response.action.proposed";
  actionId: string;
  investigationId: string;
  actionType: "ticket" | "disable_user" | "isolate_host" | "block_ioc";
  status: "proposed";
};

export type ResponseActionApprovedRealtimeEvent = {
  type: "response.action.approved";
  actionId: string;
  investigationId: string;
  actionType: "ticket" | "disable_user" | "isolate_host" | "block_ioc";
  status: "approved";
};

export type ResponseActionExecutedRealtimeEvent = {
  type: "response.action.executed";
  actionId: string;
  investigationId: string;
  actionType: "ticket" | "disable_user" | "isolate_host" | "block_ioc";
  status: "executed" | "failed";
};

export type ReportGenerationStartedRealtimeEvent = {
  type: "report.generation.started";
  investigationId: string;
  reportId: string;
};

export type ReportGenerationProgressRealtimeEvent = {
  type: "report.generation.progress";
  investigationId: string;
  reportId: string;
  step: string;
  index: number;
  totalSteps: number;
};

export type ReportGenerationCompletedRealtimeEvent = {
  type: "report.generation.completed";
  investigationId: string;
  reportId: string;
  format: "markdown" | "pdf";
};

export type ReportGenerationFailedRealtimeEvent = {
  type: "report.generation.failed";
  investigationId: string;
  reportId: string;
  error: string;
};

export type RealtimeEvent =
  | RealtimeReadyEvent
  | AlertCreatedRealtimeEvent
  | AlertUpdatedRealtimeEvent
  | InvestigationStartedRealtimeEvent
  | InvestigationJobQueuedRealtimeEvent
  | InvestigationStageRealtimeEvent
  | InvestigationStepRealtimeEvent
  | InvestigationCompletedRealtimeEvent
  | InvestigationFailedRealtimeEvent
  | ResponseActionProposedRealtimeEvent
  | ResponseActionApprovedRealtimeEvent
  | ResponseActionExecutedRealtimeEvent
  | ReportGenerationStartedRealtimeEvent
  | ReportGenerationProgressRealtimeEvent
  | ReportGenerationCompletedRealtimeEvent
  | ReportGenerationFailedRealtimeEvent;

export const REALTIME_RECONNECT_DELAY_MS = 2_000;
export const REALTIME_HEARTBEAT_MS = 20_000;
