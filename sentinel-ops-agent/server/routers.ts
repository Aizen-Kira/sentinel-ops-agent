import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { z } from "zod";
import { nanoid } from "nanoid";
import { getSessionCookieClearOptions } from "./_core/cookies";
import { assertNotSelfApproval } from "./_core/authorization";
import { systemRouter } from "./_core/systemRouter";
import {
  approveActionProcedure,
  manageAlertsProcedure,
  publicProcedure,
  router,
  viewInvestigationProcedure,
} from "./_core/trpc";
import { generateExecutiveBrief } from "./briefing";
import {
  createAlert,
  createAlertAction,
  createIncident,
  createInvestigation,
  createResponseAction,
  getAlertById,
  getAlertStats,
  getAlertTimeline,
  getAlerts,
  getIncidents,
  getInvestigationByInvestigationId,
  getInvestigations,
  getInvestigationJobById,
  getLatestMetric,
  getOpenIncidentCount,
  getResponseActionById,
  getResponseActionsByInvestigationId,
  searchAlerts,
  updateAlertSeverity,
  updateAlertStatus,
  updateInvestigationByInvestigationId,
  updateResponseAction,
} from "./db";
import {
  correlateAlertToIncident,
  refreshCorrelationForAlert,
} from "./correlation";
import {
  connectorEnvelopeToAlert,
  generateBatchConnectorEvents,
  replayConnectorEvents,
  type ConnectorEnvelope,
} from "./eventGenerator";
import { enqueueInvestigationJob } from "./_core/investigationWorker";
import { getInvestigationReportArtifact, startInvestigationReportGeneration } from "./_core/reporting";
import { publishRealtimeEvent } from "./_core/realtime";
import { splunkHec } from "./lib/splunk/splunkHec";
import { splunkSearch } from "./lib/splunk/splunkSearch";
import { scoreIncident } from "./lib/risk/riskScorer";
import { buildTimeline } from "./lib/timeline/timelineBuilder";
import { ACTION_LIBRARY, getRecommendations } from "./lib/response/recommendationEngine";
import { generateBriefing, renderHtmlEmail, type BriefingContent } from "./lib/briefing/briefingService";
import type { EnrichmentResult } from "./lib/agents/investigationTypes";

const connectorEventSchema: z.ZodType<ConnectorEnvelope> = z.object({
  source: z.enum(["siem", "edr", "identity", "cloud"]),
  raw: z.record(z.string(), z.unknown()),
  normalized: z.object({
    eventId: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    title: z.string(),
    description: z.string().optional().nullable(),
    source: z.string(),
    target: z.string().optional().nullable(),
    eventType: z.string(),
    rawData: z.record(z.string(), z.unknown()).optional().nullable(),
    status: z.enum(["open", "acknowledged", "escalated", "dismissed"]).optional(),
  }),
});

const filterInvestigationsForUser = <T extends { userId: number }>(
  items: T[],
  userId: number,
  isAdmin: boolean
) => (isAdmin ? items : items.filter((item) => item.userId === userId));

const getInvestigationOrThrow = async (
  investigationId: string,
  userId: number,
  isAdmin: boolean
) => {
  const investigation = await getInvestigationByInvestigationId(investigationId);
  if (!investigation) {
    throw new TRPCError({
      code: "NOT_FOUND",
      message: "Investigation not found",
    });
  }

  if (!isAdmin && investigation.userId !== userId) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "You do not have access to this investigation",
    });
  }

  return investigation;
};

const createAlertFromConnectorEnvelope = async (event: ConnectorEnvelope) => {
  const createdAlert = await createAlert(connectorEnvelopeToAlert(event));
  const correlation = await correlateAlertToIncident(createdAlert);
  const realtimeAlert = correlation?.alert ?? createdAlert;
  await publishRealtimeEvent(
    {
      type: "alert.created",
      alert: realtimeAlert,
    },
    {
      scope: {
        requiredCapabilities: ["canManageAlerts"],
      },
    }
  );
  return realtimeAlert;
};

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      ctx.res.clearCookie(COOKIE_NAME, getSessionCookieClearOptions(ctx.req));
      return {
        success: true,
      } as const;
    }),
  }),

  alerts: router({
    list: manageAlertsProcedure
      .input(
        z.object({
          limit: z.number().default(100),
          offset: z.number().default(0),
        })
      )
      .query(async ({ input }) => getAlerts(input.limit, input.offset)),

    getById: manageAlertsProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => getAlertById(input.id)),

    create: manageAlertsProcedure
      .input(
        z.object({
          eventId: z.string(),
          severity: z.enum(["critical", "high", "medium", "low"]),
          title: z.string(),
          description: z.string().optional(),
          source: z.string(),
          target: z.string().optional(),
          eventType: z.string(),
          rawData: z.record(z.string(), z.unknown()).optional(),
        })
      )
      .mutation(async ({ input }) => {
        const createdAlert = await createAlert({
          eventId: input.eventId,
          severity: input.severity,
          title: input.title,
          description: input.description,
          source: input.source,
          target: input.target,
          eventType: input.eventType,
          rawData: input.rawData,
          status: "open",
        });
        const correlation = await correlateAlertToIncident(createdAlert);
        const realtimeAlert = correlation?.alert ?? createdAlert;
        await publishRealtimeEvent(
          {
            type: "alert.created",
            alert: realtimeAlert,
          },
          {
            scope: {
              requiredCapabilities: ["canManageAlerts"],
            },
          }
        );
        return realtimeAlert;
      }),

    updateStatus: manageAlertsProcedure
      .input(
        z.object({
          id: z.number(),
          status: z.enum(["open", "acknowledged", "escalated", "dismissed"]),
          reason: z.string().optional(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const alert = await getAlertById(input.id);
        if (!alert) throw new Error("Alert not found");

        await updateAlertStatus(input.id, input.status);
        await createAlertAction({
          alertId: input.id,
          actionType:
            input.status === "acknowledged"
              ? "acknowledged"
              : input.status === "escalated"
                ? "escalated"
                : input.status === "dismissed"
                  ? "dismissed"
                  : "acknowledged",
          newValue: input.status,
          reason: input.reason,
          userId: ctx.user!.id,
        });
        await refreshCorrelationForAlert(input.id);

        const updatedAlert = await getAlertById(input.id);
        if (updatedAlert) {
          await publishRealtimeEvent(
            {
              type: "alert.updated",
              alert: updatedAlert,
              previousSeverity: alert.severity,
              previousStatus: alert.status,
            },
            {
              scope: {
                requiredCapabilities: ["canManageAlerts"],
              },
            }
          );
        }

        return { success: true };
      }),

    updateSeverity: manageAlertsProcedure
      .input(
        z.object({
          id: z.number(),
          severity: z.enum(["critical", "high", "medium", "low"]),
          reason: z.string().optional(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const alert = await getAlertById(input.id);
        if (!alert) throw new Error("Alert not found");

        await updateAlertSeverity(input.id, input.severity);
        await createAlertAction({
          alertId: input.id,
          actionType: "severity_changed",
          previousValue: alert.severity,
          newValue: input.severity,
          reason: input.reason,
          userId: ctx.user!.id,
        });
        await refreshCorrelationForAlert(input.id);

        const updatedAlert = await getAlertById(input.id);
        if (updatedAlert) {
          await publishRealtimeEvent(
            {
              type: "alert.updated",
              alert: updatedAlert,
              previousSeverity: alert.severity,
              previousStatus: alert.status,
            },
            {
              scope: {
                requiredCapabilities: ["canManageAlerts"],
              },
            }
          );
        }

        return { success: true };
      }),

    stats: manageAlertsProcedure.query(async () => getAlertStats()),

    search: manageAlertsProcedure
      .input(
        z.object({
          query: z.string().optional(),
          severity: z.enum(["critical", "high", "medium", "low"]).optional(),
          status: z.enum(["open", "acknowledged", "escalated", "dismissed"]).optional(),
          eventType: z.string().optional(),
          limit: z.number().default(100),
          offset: z.number().default(0),
        })
      )
      .query(async ({ input }) => searchAlerts(input)),
  }),

  investigations: router({
    list: viewInvestigationProcedure
      .input(
        z.object({
          limit: z.number().default(50),
          offset: z.number().default(0),
        })
      )
      .query(async ({ input, ctx }) => {
        const results = await getInvestigations(input.limit, input.offset);
        return filterInvestigationsForUser(
          results,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );
      }),

    create: viewInvestigationProcedure
      .input(
        z.object({
          alertIds: z.array(z.number()),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const investigationId = `INV-${nanoid(12)}`;
        const investigation = await createInvestigation({
          investigationId,
          alertIds: input.alertIds,
          status: "in_progress",
          reasoningSteps: [],
          userId: ctx.user!.id,
        });

        await publishRealtimeEvent(
          {
            type: "investigation.started",
            investigation,
          },
          {
            scope: {
              investigationId,
              allowedUserIds: [ctx.user!.id],
              requiredCapabilities: ["canApproveAction"],
            },
          }
        );

        return investigation;
      }),

    streamReasoning: viewInvestigationProcedure
      .input(
        z.object({
          investigationId: z.string(),
          alertIds: z.array(z.number()),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const investigation = await getInvestigationOrThrow(
          input.investigationId,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );

        await updateInvestigationByInvestigationId(input.investigationId, {
          alertIds: input.alertIds,
          status: "in_progress",
          executedAt: new Date(),
        });

        const job = await enqueueInvestigationJob(investigation.investigationId);
        return {
          jobId: job.id,
          investigationId: investigation.investigationId,
          status: job.status,
        };
      }),

    getJob: viewInvestigationProcedure
      .input(
        z.object({
          jobId: z.string(),
        })
      )
      .query(async ({ input, ctx }) => {
        const job = await getInvestigationJobById(input.jobId);
        if (!job) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "Investigation job not found",
          });
        }

        await getInvestigationOrThrow(
          job.investigationId,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );

        return job;
      }),

    generateReport: viewInvestigationProcedure
      .input(
        z.object({
          investigationId: z.string(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        await getInvestigationOrThrow(
          input.investigationId,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );

        const report = await startInvestigationReportGeneration({
          investigationId: input.investigationId,
          requestedByUserId: ctx.user!.id,
        });

        return {
          reportId: report.id,
          investigationId: input.investigationId,
          status: report.status,
        };
      }),

    getReport: viewInvestigationProcedure
      .input(
        z.object({
          investigationId: z.string(),
        })
      )
      .query(async ({ input, ctx }) => {
        await getInvestigationOrThrow(
          input.investigationId,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );

        return getInvestigationReportArtifact(input.investigationId);
      }),
  }),

  responseActions: router({
    list: viewInvestigationProcedure
      .input(
        z.object({
          investigationId: z.string(),
        })
      )
      .query(async ({ input, ctx }) => {
        await getInvestigationOrThrow(
          input.investigationId,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );
        return getResponseActionsByInvestigationId(input.investigationId);
      }),

    proposeAction: viewInvestigationProcedure
      .input(
        z.object({
          investigationId: z.string(),
          actionType: z.enum([
            "ticket",
            "disable_user",
            "isolate_host",
            "block_ioc",
          ]),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const investigation = await getInvestigationOrThrow(
          input.investigationId,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );

        const action = await createResponseAction({
          id: `ACT-${nanoid(12)}`,
          investigationId: input.investigationId,
          actionType: input.actionType,
          proposedBy: ctx.user!.id,
          status: "proposed",
        });

        await publishRealtimeEvent(
          {
            type: "response.action.proposed",
            actionId: action.id,
            investigationId: action.investigationId,
            actionType: action.actionType,
            status: "proposed",
          },
          {
            scope: {
              investigationId: action.investigationId,
              allowedUserIds: [investigation.userId, ctx.user!.id],
              requiredCapabilities: ["canApproveAction"],
            },
          }
        );

        return action;
      }),

    approveAction: approveActionProcedure
      .input(
        z.object({
          actionId: z.string(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const action = await getResponseActionById(input.actionId);
        if (!action) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "Response action not found",
          });
        }

        const investigation = await getInvestigationByInvestigationId(
          action.investigationId
        );
        const allowedUserIds = investigation ? [investigation.userId, ctx.user!.id] : [ctx.user!.id];

        assertNotSelfApproval(ctx.user!, action.proposedBy, {
          action: "responseActions.approveAction",
          resource: action.id,
        });

        await updateResponseAction(action.id, {
          approvedBy: ctx.user!.id,
          status: "approved",
        });

        await publishRealtimeEvent(
          {
            type: "response.action.approved",
            actionId: action.id,
            investigationId: action.investigationId,
            actionType: action.actionType,
            status: "approved",
          },
          {
            scope: {
              investigationId: action.investigationId,
              allowedUserIds,
              requiredCapabilities: ["canApproveAction"],
            },
          }
        );

        return { success: true };
      }),

    executeAction: approveActionProcedure
      .input(
        z.object({
          actionId: z.string(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const action = await getResponseActionById(input.actionId);
        if (!action) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "Response action not found",
          });
        }
        if (!action.approvedBy || action.status !== "approved") {
          throw new TRPCError({
            code: "PRECONDITION_FAILED",
            message: "Response action must be approved before execution",
          });
        }

        const investigation = await getInvestigationByInvestigationId(
          action.investigationId
        );
        const allowedUserIds = investigation ? [investigation.userId, ctx.user!.id] : [ctx.user!.id];
        const executedAt = new Date();

        await updateResponseAction(action.id, {
          status: "executed",
          executedAt,
        });

        await publishRealtimeEvent(
          {
            type: "response.action.executed",
            actionId: action.id,
            investigationId: action.investigationId,
            actionType: action.actionType,
            status: "executed",
          },
          {
            scope: {
              investigationId: action.investigationId,
              allowedUserIds,
              requiredCapabilities: ["canApproveAction"],
            },
          }
        );

        return { success: true };
      }),
  }),

  incidents: router({
    list: manageAlertsProcedure
      .input(
        z.object({
          limit: z.number().default(50),
          offset: z.number().default(0),
        })
      )
      .query(async ({ input }) => getIncidents(input.limit, input.offset)),

    create: manageAlertsProcedure
      .input(
        z.object({
          title: z.string(),
          severity: z.enum(["critical", "high", "medium", "low"]),
          affectedAssets: z.array(z.string()),
          mitreAttackTactics: z.array(z.string()).optional(),
          rootCause: z.string().optional(),
          remediationSteps: z.array(z.string()).optional(),
        })
      )
      .mutation(async ({ input }) => {
        const incidentId = `INC-${nanoid(12)}`;
        return createIncident({
          incidentId,
          title: input.title,
          severity: input.severity,
          status: "open",
          affectedAssets: input.affectedAssets,
          mitreAttackTactics: input.mitreAttackTactics,
          rootCause: input.rootCause,
          remediationSteps: input.remediationSteps,
        });
      }),
  }),

  metrics: router({
    latest: manageAlertsProcedure.query(async () => {
      const metric = await getLatestMetric();
      if (metric) return metric;

      const stats = await getAlertStats();
      const openIncidents = await getOpenIncidentCount();

      return {
        id: 0,
        timestamp: new Date(),
        mttd: "0.00" as any,
        mtta: "0.00" as any,
        mttr: "0.00" as any,
        openIncidentCount: openIncidents,
        criticalAlertCount: stats.critical,
        highAlertCount: stats.high,
        mediumAlertCount: stats.medium,
        lowAlertCount: stats.low,
        acknowledgedCount: stats.acknowledged,
        dismissedCount: stats.dismissed,
      };
    }),

    timeline: manageAlertsProcedure
      .input(
        z.object({
          hours: z.number().min(1).max(48).default(24),
        })
      )
      .query(async ({ input }) => getAlertTimeline(input.hours)),
  }),

  briefings: router({
    ceo: manageAlertsProcedure.query(async () => generateExecutiveBrief()),
  }),

  history: router({
    investigations: viewInvestigationProcedure
      .input(
        z.object({
          limit: z.number().default(50),
          offset: z.number().default(0),
        })
      )
      .query(async ({ input, ctx }) => {
        const results = await getInvestigations(input.limit, input.offset);
        return filterInvestigationsForUser(
          results,
          ctx.user!.id,
          ctx.user!.role === "admin"
        );
      }),
  }),

  events: router({
    generate: manageAlertsProcedure
      .input(
        z.object({
          count: z.number().min(1).max(10).default(1),
        })
      )
      .mutation(async ({ input }) => {
        const alerts = [];
        const generatedEvents = generateBatchConnectorEvents(input.count);
        for (const event of generatedEvents) {
          const created = await createAlertFromConnectorEnvelope(event);
          alerts.push(created);
        }
        return { created: alerts.length, alerts };
      }),

    import: manageAlertsProcedure
      .input(
        z.object({
          events: z.array(connectorEventSchema),
          intervalMs: z.number().min(0).max(10_000).default(0),
        })
      )
      .mutation(async ({ input }) => {
        void replayConnectorEvents(
          input.events,
          async (event) => {
            await createAlertFromConnectorEnvelope(event);
          },
          { intervalMs: input.intervalMs }
        );

        return {
          accepted: input.events.length,
          intervalMs: input.intervalMs,
        };
      }),
  }),

  query: router({
    search: manageAlertsProcedure
      .input(
        z.object({
          keyword: z.string().optional(),
          severity: z.enum(["critical", "high", "medium", "low"]).optional(),
          eventType: z.string().optional(),
          source: z.string().optional(),
          status: z.enum(["open", "acknowledged", "escalated", "dismissed"]).optional(),
          limit: z.number().default(50),
          offset: z.number().default(0),
        })
      )
      .query(async ({ input }) => {
        const result = await searchAlerts(input);
        return {
          results: result.alerts,
          total: result.total,
        };
      }),
  }),

  // ─── Splunk integration ────────────────────────────────────────────────────
  splunk: router({
    healthcheck: manageAlertsProcedure.query(async () => {
      return splunkSearch.healthcheck();
    }),

    search: manageAlertsProcedure
      .input(z.object({
        spl: z.string().min(1),
        earliest: z.string().optional(),
        latest: z.string().optional(),
        maxCount: z.number().int().min(1).max(10000).optional(),
      }))
      .query(async ({ input }) => {
        return splunkSearch.search(input.spl, {
          earliest: input.earliest,
          latest: input.latest,
          maxCount: input.maxCount,
        });
      }),

    ingest: manageAlertsProcedure
      .input(z.object({
        events: z.array(z.object({
          time: z.number().optional(),
          host: z.string().optional(),
          source: z.string().optional(),
          sourcetype: z.string().optional(),
          index: z.string().optional(),
          event: z.record(z.string(), z.unknown()),
        })).min(1),
      }))
      .mutation(async ({ input }) => {
        await splunkHec.sendBatch(input.events);
        await splunkHec.flush();
        return { ingested: input.events.length };
      }),
  }),

  // ─── Risk scoring ──────────────────────────────────────────────────────────
  risk: router({
    score: manageAlertsProcedure
      .input(z.object({
        incidentId: z.number().int().positive(),
        severity: z.number().min(0).max(100),
        frequency: z.number().min(0).max(100),
        assetCriticality: z.number().min(0).max(100),
      }))
      .mutation(async ({ input }) => {
        return scoreIncident(input.incidentId, {
          severity: input.severity,
          frequency: input.frequency,
          assetCriticality: input.assetCriticality,
        });
      }),
  }),

  // ─── Attack timeline ───────────────────────────────────────────────────────
  timeline: router({
    getByIncident: manageAlertsProcedure
      .input(z.object({ incidentId: z.number().int().positive() }))
      .query(async ({ input }) => {
        return buildTimeline(input.incidentId);
      }),
  }),

  // ─── Response action recommendations & approvals ───────────────────────────
  approvals: router({
    getRecommendations: manageAlertsProcedure
      .input(z.object({
        incidentId: z.number().int().positive(),
        mitreAttackIds: z.array(z.string()).optional(),
        requiresEscalation: z.boolean().optional(),
        riskScore: z.number().min(0).max(100).optional(),
      }))
      .query(async ({ input }) => {
        // When enrichment data is provided, score-boost the library
        if (input.mitreAttackIds) {
          const mockEnrichment: EnrichmentResult = {
            summary: "",
            attackVector: "",
            affectedAssets: [],
            iocs: [],
            mitreAttackIds: input.mitreAttackIds,
            recommendedSeverity: "high",
            requiresEscalation: input.requiresEscalation ?? false,
            rawSplunkEventCount: 0,
          };
          return getRecommendations(mockEnrichment, input.riskScore ?? 50);
        }
        return ACTION_LIBRARY;
      }),
  }),

  // ─── Extended briefings (CISO HTML + per-incident generate) ───────────────
  // Note: briefings.ceo already exists above — these add new procedures
  cisoBriefings: router({
    generate: manageAlertsProcedure
      .input(z.object({ incidentId: z.number().int().positive() }))
      .mutation(async ({ input }) => {
        // Mock enrichment & risk — in production fetch from DB
        const mockEnrichment: EnrichmentResult = {
          summary: "Ransomware attack detected across corporate network",
          attackVector: "Phishing → credential compromise → lateral movement → encryption",
          affectedAssets: ["fileserver-02.corp", "dc-001.corp"],
          iocs: [{ type: "ip", value: "185.220.101.42", confidence: "high", context: "C2" }],
          mitreAttackIds: ["T1566.001", "T1486"],
          recommendedSeverity: "critical",
          requiresEscalation: true,
          escalationReason: "Active ransomware deployment",
          rawSplunkEventCount: 200,
        };
        const mockRisk = {
          score: 92, severityFactor: 95, frequencyFactor: 90,
          assetCriticalityFactor: 88, llmRationale: null, scoringMethod: "formula-only" as const,
        };

        const content = await generateBriefing({
          incidentId: input.incidentId,
          incidentTitle: `Ransomware Incident #${input.incidentId}`,
          incidentUpdatedAt: new Date(),
          enrichment: mockEnrichment,
          riskScore: mockRisk,
          approvalStatus: { pending: 3, approved: 1, rejected: 0 },
        });

        return { incidentId: input.incidentId, content, generatedAt: new Date() };
      }),

    exportHtml: manageAlertsProcedure
      .input(z.object({
        incidentId: z.number().int().positive(),
        briefing: z.object({
          executiveSummary: z.string(),
          businessImpact: z.string(),
          riskOverview: z.object({ score: z.number(), label: z.string(), rationale: z.string() }),
          timelineHighlights: z.array(z.object({ timestamp: z.string(), description: z.string(), significance: z.string() })),
          recommendedActions: z.array(z.object({ title: z.string(), urgency: z.enum(["immediate", "within24h", "planned"]), ownerRole: z.string() })),
          currentStatus: z.string(),
          nextSteps: z.string(),
          generatedAt: z.string(),
          isStale: z.boolean(),
        }),
      }))
      .query(({ input }) => {
        const html = renderHtmlEmail(input.briefing as BriefingContent, input.incidentId);
        return { html };
      }),
  }),
});

export type AppRouter = typeof appRouter;
