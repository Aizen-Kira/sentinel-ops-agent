import { nanoid } from "nanoid";
import type { InvestigationJob, RealtimeEventRecord } from "../../drizzle/schema";
import {
  createInvestigationReport,
  getInvestigationByInvestigationId,
  getInvestigationJobsByInvestigationId,
  getLatestInvestigationReport,
  getRealtimeEventsAfterCursor,
  updateInvestigationReport,
} from "../db";
import { publishRealtimeEvent } from "./realtime";

const DEFAULT_TENANT_ID = "default";

const normalizeArray = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

const parseEnvelope = (record: RealtimeEventRecord) => {
  if (!record.payload || typeof record.payload !== "object") {
    return null;
  }

  const payload = record.payload as {
    event?: Record<string, unknown>;
    scope?: { investigationId?: string | null };
  };

  return payload;
};

const isInvestigationEvent = (
  record: RealtimeEventRecord,
  investigationId: string
) => {
  const payload = parseEnvelope(record);
  if (!payload) return false;
  if (payload.scope?.investigationId === investigationId) return true;
  return payload.event?.investigationId === investigationId;
};

const extractLatestJobArtifact = (jobs: InvestigationJob[]) => {
  const latestJob = jobs[0];
  return latestJob?.artifact && typeof latestJob.artifact === "object"
    ? (latestJob.artifact as Record<string, unknown>)
    : {};
};

const buildMarkdownReport = (options: {
  investigationId: string;
  timeline: RealtimeEventRecord[];
  jobArtifact: Record<string, unknown>;
}) => {
  const playbook =
    options.jobArtifact.playbook && typeof options.jobArtifact.playbook === "object"
      ? (options.jobArtifact.playbook as Record<string, unknown>)
      : {};

  const stages = Array.isArray(options.jobArtifact.stages)
    ? (options.jobArtifact.stages as Array<Record<string, unknown>>)
    : [];

  const steps = normalizeArray(options.jobArtifact.steps);
  const reasoning =
    typeof options.jobArtifact.reasoning === "string"
      ? options.jobArtifact.reasoning
      : "";
  const confidence =
    typeof options.jobArtifact.confidence === "number"
      ? options.jobArtifact.confidence
      : 0;

  const timelineLines = options.timeline.map((record) => {
    const payload = parseEnvelope(record);
    const event = payload?.event ?? {};
    const type = typeof event.type === "string" ? event.type : record.topic;
    return `- ${record.createdAt.toISOString()} :: ${type}`;
  });

  return [
    `# Incident Report: ${options.investigationId}`,
    "",
    "## Summary",
    `- Confidence: ${Math.round(confidence * 100)}%`,
    `- Playbook: ${typeof playbook.playbookId === "string" ? playbook.playbookId : "n/a"}`,
    `- Local Analyst Mode: ${options.jobArtifact.localMode ? "yes" : "no"}`,
    "",
    "## Reasoning",
    reasoning || "No reasoning artifact was stored.",
    "",
    "## Playbook Outputs",
    `- Confidence Drivers: ${normalizeArray(playbook.confidenceDrivers).join("; ") || "n/a"}`,
    `- Missing Evidence: ${normalizeArray(playbook.missingEvidence).join("; ") || "n/a"}`,
    `- Containment Steps: ${normalizeArray(playbook.containmentSteps).join("; ") || "n/a"}`,
    "",
    "## Local Analyst Stages",
    ...(stages.length > 0
      ? stages.map((stage) => {
          const name =
            typeof stage.stage === "string" ? stage.stage : "unknown_stage";
          return `- ${name}: ${JSON.stringify(stage.result ?? {}, null, 2)}`;
        })
      : ["- No local analyst stage artifacts were stored."]),
    "",
    "## Streamed Steps",
    ...(steps.length > 0 ? steps.map((step) => `- ${step}`) : ["- None recorded."]),
    "",
    "## Timeline",
    ...(timelineLines.length > 0 ? timelineLines : ["- No realtime events were stored."]),
  ].join("\n");
};

export async function startInvestigationReportGeneration(options: {
  investigationId: string;
  requestedByUserId: number;
}) {
  const report = await createInvestigationReport({
    id: `REP-${nanoid(12)}`,
    investigationId: options.investigationId,
    status: "pending",
    format: "markdown",
    content: null,
  });

  void runReportGeneration(report.id, options.investigationId, options.requestedByUserId);

  return report;
}

async function runReportGeneration(
  reportId: string,
  investigationId: string,
  requestedByUserId: number
) {
  const investigation = await getInvestigationByInvestigationId(investigationId);
  if (!investigation) {
    await updateInvestigationReport(reportId, {
      status: "failed",
      content: "Investigation not found.",
    });
    return;
  }

  const allowedUserIds = [investigation.userId, requestedByUserId];

  try {
    await updateInvestigationReport(reportId, {
      status: "running",
    });
    await publishRealtimeEvent(
      {
        type: "report.generation.started",
        investigationId,
        reportId,
      },
      {
        scope: {
          investigationId,
          allowedUserIds,
        },
      }
    );

    await publishRealtimeEvent(
      {
        type: "report.generation.progress",
        investigationId,
        reportId,
        step: "Loading persisted realtime timeline for this investigation.",
        index: 1,
        totalSteps: 3,
      },
      {
        scope: {
          investigationId,
          allowedUserIds,
        },
      }
    );

    const storedEvents = await getRealtimeEventsAfterCursor({
      tenantId: DEFAULT_TENANT_ID,
      limit: 1000,
    });
    const timeline = storedEvents.filter((record) =>
      isInvestigationEvent(record, investigationId)
    );

    await publishRealtimeEvent(
      {
        type: "report.generation.progress",
        investigationId,
        reportId,
        step: "Collecting investigation job artifacts and playbook outputs.",
        index: 2,
        totalSteps: 3,
      },
      {
        scope: {
          investigationId,
          allowedUserIds,
        },
      }
    );

    const jobs = await getInvestigationJobsByInvestigationId(investigationId);
    const markdown = buildMarkdownReport({
      investigationId,
      timeline,
      jobArtifact: extractLatestJobArtifact(jobs),
    });

    await publishRealtimeEvent(
      {
        type: "report.generation.progress",
        investigationId,
        reportId,
        step: "Compiling markdown report artifact.",
        index: 3,
        totalSteps: 3,
      },
      {
        scope: {
          investigationId,
          allowedUserIds,
        },
      }
    );

    await updateInvestigationReport(reportId, {
      status: "completed",
      content: markdown,
    });

    await publishRealtimeEvent(
      {
        type: "report.generation.completed",
        investigationId,
        reportId,
        format: "markdown",
      },
      {
        scope: {
          investigationId,
          allowedUserIds,
        },
      }
    );
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Report generation failed";
    await updateInvestigationReport(reportId, {
      status: "failed",
      content: message,
    });
    await publishRealtimeEvent(
      {
        type: "report.generation.failed",
        investigationId,
        reportId,
        error: message,
      },
      {
        scope: {
          investigationId,
          allowedUserIds,
        },
      }
    );
  }
}

export async function getInvestigationReportArtifact(investigationId: string) {
  return getLatestInvestigationReport(investigationId);
}
