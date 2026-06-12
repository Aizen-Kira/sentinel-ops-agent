import {
  asc,
  and,
  desc,
  eq,
  gt,
  gte,
  inArray,
  like,
  or,
  sql,
  type SQL,
} from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  InsertUser,
  users,
  alerts,
  incidents,
  investigations,
  investigationJobs,
  investigationReports,
  alertActions,
  iocs,
  metrics,
  realtimeEvents,
  responseActions,
  Alert,
  Incident,
  Investigation,
  InvestigationJob,
  InvestigationReport,
  AlertAction,
  IOC,
  Metric,
  RealtimeEventRecord,
  ResponseAction,
} from "../drizzle/schema";
import {
  deriveIncidentOperationalScores,
  parseStringArray,
} from "@shared/correlation";
import { ENV } from "./_core/env";

let _db: ReturnType<typeof drizzle> | null = null;

export type AlertStats = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open: number;
  acknowledged: number;
  escalated: number;
  dismissed: number;
};

export type AlertSearchFilters = {
  query?: string;
  keyword?: string;
  severity?: Alert["severity"];
  status?: Alert["status"];
  eventType?: string;
  source?: string;
  limit?: number;
  offset?: number;
};

export type InvestigationListItem = Investigation & {
  analystName: string | null;
  analystEmail: string | null;
};

export type InvestigationJobArtifact = Record<string, unknown> | null;

export type IncidentListItem = Incident & {
  alertCount: number;
  latestAlertAt: Date | null;
  affectedAssetCount: number;
  confidenceScore: number;
  businessImpactScore: number;
  storyline: string[];
};

export type AlertTimelinePoint = {
  bucketStart: string;
  label: string;
  alertCount: number;
};

const toNumber = (value: unknown): number => {
  if (typeof value === "number") return value;
  if (typeof value === "string") return Number(value);
  return 0;
};

const formatBucketKey = (date: Date): string => {
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  const hours = `${date.getHours()}`.padStart(2, "0");
  return `${year}-${month}-${day} ${hours}:00:00`;
};

const formatBucketLabel = (date: Date): string =>
  date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

const buildZeroTimeline = (hours: number): AlertTimelinePoint[] => {
  const normalizedHours = Math.max(1, Math.min(hours, 48));
  const points: AlertTimelinePoint[] = [];
  const cursor = new Date();
  cursor.setMinutes(0, 0, 0);
  cursor.setHours(cursor.getHours() - (normalizedHours - 1));

  for (let i = 0; i < normalizedHours; i++) {
    const bucket = new Date(cursor);
    bucket.setHours(cursor.getHours() + i);
    points.push({
      bucketStart: bucket.toISOString(),
      label: formatBucketLabel(bucket),
      alertCount: 0,
    });
  }

  return points;
};

const buildAlertWhereClause = (
  filters: AlertSearchFilters
): SQL<unknown> | undefined => {
  const conditions: SQL<unknown>[] = [];
  const textQuery = (filters.query ?? filters.keyword)?.trim();

  if (textQuery) {
    const pattern = `%${textQuery}%`;
    conditions.push(
      or(
        like(alerts.title, pattern),
        like(alerts.description, pattern),
        like(alerts.source, pattern),
        like(alerts.target, pattern),
        like(alerts.eventId, pattern)
      )!
    );
  }

  if (filters.severity) {
    conditions.push(eq(alerts.severity, filters.severity));
  }

  if (filters.status) {
    conditions.push(eq(alerts.status, filters.status));
  }

  if (filters.eventType) {
    conditions.push(eq(alerts.eventType, filters.eventType));
  }

  if (filters.source?.trim()) {
    conditions.push(like(alerts.source, `%${filters.source.trim()}%`));
  }

  if (conditions.length === 0) {
    return undefined;
  }

  return conditions.length === 1 ? conditions[0] : and(...conditions);
};

export async function getDb() {
  if (ENV.nodeEnv === "test" && !process.env.DATABASE_URL) {
    return null;
  }

  if (!_db && ENV.databaseUrl) {
    try {
      _db = drizzle(ENV.databaseUrl);
    } catch {
      console.warn("[Database] Failed to connect");
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user");
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db
    .select()
    .from(users)
    .where(eq(users.openId, openId))
    .limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export async function getUserById(id: number) {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return result[0];
}

// Alert queries
export async function createAlert(alert: typeof alerts.$inferInsert): Promise<Alert> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(alerts).values(alert);
  const result = await db
    .select()
    .from(alerts)
    .where(eq(alerts.eventId, alert.eventId))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create alert");
  return result[0];
}

export async function getAlerts(
  limit: number = 100,
  offset: number = 0
): Promise<Alert[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(alerts)
    .orderBy(desc(alerts.createdAt))
    .limit(limit)
    .offset(offset);
}

export async function getAlertById(id: number): Promise<Alert | undefined> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db.select().from(alerts).where(eq(alerts.id, id)).limit(1);
  return result[0];
}

export async function getAlertsByIds(ids: number[]): Promise<Alert[]> {
  const db = await getDb();
  if (!db || ids.length === 0) return [];

  return db
    .select()
    .from(alerts)
    .where(inArray(alerts.id, ids))
    .orderBy(desc(alerts.createdAt));
}

export async function getAlertsByIncidentId(
  incidentId: number
): Promise<Alert[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(alerts)
    .where(eq(alerts.incidentId, incidentId))
    .orderBy(desc(alerts.createdAt));
}

export async function getRecentAlertsForCorrelation(
  anchor: Alert,
  windowMinutes: number = 90,
  limit: number = 50
): Promise<Alert[]> {
  const db = await getDb();
  if (!db) return [];

  const start = new Date(anchor.createdAt);
  start.setMinutes(start.getMinutes() - windowMinutes);

  const endpointConditions = [eq(alerts.source, anchor.source)];

  if (anchor.target) {
    endpointConditions.push(eq(alerts.target, anchor.target));
    endpointConditions.push(eq(alerts.source, anchor.target));
    endpointConditions.push(eq(alerts.target, anchor.source));
  }

  if (anchor.incidentId) {
    endpointConditions.push(eq(alerts.incidentId, anchor.incidentId));
  }

  return db
    .select()
    .from(alerts)
    .where(
      and(gte(alerts.createdAt, start), or(...endpointConditions))
    )
    .orderBy(desc(alerts.createdAt))
    .limit(limit);
}

export async function updateAlertStatus(
  id: number,
  status: Alert["status"]
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db.update(alerts).set({ status }).where(eq(alerts.id, id));
}

export async function updateAlertSeverity(
  id: number,
  severity: Alert["severity"]
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db.update(alerts).set({ severity }).where(eq(alerts.id, id));
}

// Investigation queries
export async function createInvestigation(
  investigation: typeof investigations.$inferInsert
): Promise<Investigation> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(investigations).values(investigation);
  const result = await db
    .select()
    .from(investigations)
    .where(eq(investigations.investigationId, investigation.investigationId))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create investigation");
  return result[0];
}

export async function getInvestigations(
  limit: number = 50,
  offset: number = 0
): Promise<InvestigationListItem[]> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db
    .select()
    .from(investigations)
    .leftJoin(users, eq(investigations.userId, users.id))
    .orderBy(desc(investigations.createdAt))
    .limit(limit)
    .offset(offset);

  return rows.map(({ investigations: investigation, users: analyst }) => ({
    ...investigation,
    analystName: analyst?.name ?? null,
    analystEmail: analyst?.email ?? null,
  }));
}

export async function getInvestigationByInvestigationId(
  investigationId: string
): Promise<Investigation | undefined> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db
    .select()
    .from(investigations)
    .where(eq(investigations.investigationId, investigationId))
    .limit(1);

  return result[0];
}

export async function updateInvestigation(
  id: number,
  data: Partial<typeof investigations.$inferInsert>
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db.update(investigations).set(data).where(eq(investigations.id, id));
}

export async function updateInvestigationByInvestigationId(
  investigationId: string,
  data: Partial<typeof investigations.$inferInsert>
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db
    .update(investigations)
    .set(data)
    .where(eq(investigations.investigationId, investigationId));
}

// Durable realtime event outbox queries
export async function createRealtimeEventRecord(
  record: typeof realtimeEvents.$inferInsert
): Promise<RealtimeEventRecord> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(realtimeEvents).values(record);
  const result = await db
    .select()
    .from(realtimeEvents)
    .where(eq(realtimeEvents.id, record.id))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create realtime event record");
  return result[0];
}

export async function getRealtimeEventsAfterCursor(options: {
  cursor?: string | null;
  tenantId?: string;
  limit?: number;
}): Promise<RealtimeEventRecord[]> {
  const db = await getDb();
  if (!db) return [];

  const limit = Math.max(1, Math.min(options.limit ?? 200, 1000));
  const tenantId = options.tenantId ?? "default";

  const query = db
    .select()
    .from(realtimeEvents)
    .where(
      options.cursor
        ? and(
            eq(realtimeEvents.tenantId, tenantId),
            gt(realtimeEvents.id, options.cursor)
          )
        : eq(realtimeEvents.tenantId, tenantId)
    )
    .orderBy(asc(realtimeEvents.createdAt), asc(realtimeEvents.id))
    .limit(limit);

  return query;
}

export async function markRealtimeEventsReplayed(ids: string[]): Promise<void> {
  const db = await getDb();
  if (!db || ids.length === 0) return;

  await db
    .update(realtimeEvents)
    .set({ replayed: true })
    .where(inArray(realtimeEvents.id, ids));
}

// Investigation job queue queries
export async function createInvestigationJob(
  job: typeof investigationJobs.$inferInsert
): Promise<InvestigationJob> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(investigationJobs).values(job);
  const result = await db
    .select()
    .from(investigationJobs)
    .where(eq(investigationJobs.id, job.id))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create investigation job");
  return result[0];
}

export async function getInvestigationJobById(
  id: string
): Promise<InvestigationJob | undefined> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db
    .select()
    .from(investigationJobs)
    .where(eq(investigationJobs.id, id))
    .limit(1);

  return result[0];
}

export async function getInvestigationJobsByInvestigationId(
  investigationId: string
): Promise<InvestigationJob[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(investigationJobs)
    .where(eq(investigationJobs.investigationId, investigationId))
    .orderBy(desc(investigationJobs.createdAt));
}

export async function getNextPendingInvestigationJob(): Promise<
  InvestigationJob | undefined
> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db
    .select()
    .from(investigationJobs)
    .where(eq(investigationJobs.status, "pending"))
    .orderBy(asc(investigationJobs.createdAt))
    .limit(1);

  return result[0];
}

export async function updateInvestigationJob(
  id: string,
  data: Partial<typeof investigationJobs.$inferInsert>
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db.update(investigationJobs).set(data).where(eq(investigationJobs.id, id));
}

// Human-in-the-loop response rail queries
export async function createResponseAction(
  action: typeof responseActions.$inferInsert
): Promise<ResponseAction> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(responseActions).values(action);
  const result = await db
    .select()
    .from(responseActions)
    .where(eq(responseActions.id, action.id))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create response action");
  return result[0];
}

export async function getResponseActionById(
  id: string
): Promise<ResponseAction | undefined> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db
    .select()
    .from(responseActions)
    .where(eq(responseActions.id, id))
    .limit(1);

  return result[0];
}

export async function getResponseActionsByInvestigationId(
  investigationId: string
): Promise<ResponseAction[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(responseActions)
    .where(eq(responseActions.investigationId, investigationId))
    .orderBy(desc(responseActions.createdAt));
}

export async function updateResponseAction(
  id: string,
  data: Partial<typeof responseActions.$inferInsert>
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db.update(responseActions).set(data).where(eq(responseActions.id, id));
}

// Investigation report queries
export async function createInvestigationReport(
  report: typeof investigationReports.$inferInsert
): Promise<InvestigationReport> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(investigationReports).values(report);
  const result = await db
    .select()
    .from(investigationReports)
    .where(eq(investigationReports.id, report.id))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create investigation report");
  return result[0];
}

export async function getLatestInvestigationReport(
  investigationId: string
): Promise<InvestigationReport | undefined> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db
    .select()
    .from(investigationReports)
    .where(eq(investigationReports.investigationId, investigationId))
    .orderBy(desc(investigationReports.createdAt))
    .limit(1);

  return result[0];
}

export async function updateInvestigationReport(
  id: string,
  data: Partial<typeof investigationReports.$inferInsert>
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db
    .update(investigationReports)
    .set(data)
    .where(eq(investigationReports.id, id));
}

// Incident queries
export async function createIncident(
  incident: typeof incidents.$inferInsert
): Promise<Incident> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(incidents).values(incident);
  const result = await db
    .select()
    .from(incidents)
    .where(eq(incidents.incidentId, incident.incidentId))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create incident");
  return result[0];
}

export async function getIncidentById(id: number): Promise<Incident | undefined> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db.select().from(incidents).where(eq(incidents.id, id)).limit(1);
  return result[0];
}

export async function updateIncidentById(
  id: number,
  data: Partial<typeof incidents.$inferInsert>
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  await db.update(incidents).set(data).where(eq(incidents.id, id));
}

export async function assignAlertsToIncident(
  alertIds: number[],
  incidentId: number
): Promise<void> {
  const db = await getDb();
  if (!db || alertIds.length === 0) return;

  await db
    .update(alerts)
    .set({ incidentId })
    .where(inArray(alerts.id, alertIds));
}

export async function getIncidents(
  limit: number = 50,
  offset: number = 0
): Promise<IncidentListItem[]> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db
    .select()
    .from(incidents)
    .orderBy(desc(incidents.createdAt))
    .limit(limit)
    .offset(offset);

  return Promise.all(
    rows.map(async (incident) => {
      const incidentAlerts = await getAlertsByIncidentId(incident.id);
      const derived = deriveIncidentOperationalScores(incident, incidentAlerts.length);
      const affectedAssetCount =
        parseStringArray(incident.affectedAssets).length || derived.blastRadius;

      return {
        ...incident,
        alertCount: incidentAlerts.length,
        latestAlertAt: incidentAlerts[0]?.createdAt ?? null,
        affectedAssetCount,
        confidenceScore: derived.confidenceScore,
        businessImpactScore: derived.businessImpactScore,
        storyline: derived.storyline,
      };
    })
  );
}

// Alert action queries
export async function createAlertAction(
  action: typeof alertActions.$inferInsert
): Promise<AlertAction> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(alertActions).values(action);
  const result = await db
    .select()
    .from(alertActions)
    .orderBy(desc(alertActions.id))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create alert action");
  return result[0];
}

export async function getAlertActions(
  alertId: number
): Promise<AlertAction[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(alertActions)
    .where(eq(alertActions.alertId, alertId))
    .orderBy(desc(alertActions.createdAt));
}

// IOC queries
export async function createIOC(ioc: typeof iocs.$inferInsert): Promise<IOC> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(iocs).values(ioc);
  const result = await db
    .select()
    .from(iocs)
    .where(eq(iocs.iocId, ioc.iocId))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create IOC");
  return result[0];
}

export async function getIOCsByIncident(incidentId: number): Promise<IOC[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(iocs)
    .where(eq(iocs.incidentId, incidentId))
    .orderBy(desc(iocs.severity));
}

// Metrics queries
export async function createMetric(
  metric: typeof metrics.$inferInsert
): Promise<Metric> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  await db.insert(metrics).values(metric);
  const result = await db
    .select()
    .from(metrics)
    .orderBy(desc(metrics.id))
    .limit(1);

  if (!result[0]) throw new Error("Failed to create metric");
  return result[0];
}

export async function getLatestMetric(): Promise<Metric | undefined> {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db
    .select()
    .from(metrics)
    .orderBy(desc(metrics.timestamp))
    .limit(1);

  return result[0];
}

// Aggregation queries
export async function getAlertStats(): Promise<AlertStats> {
  const db = await getDb();
  if (!db)
    return {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      open: 0,
      acknowledged: 0,
      escalated: 0,
      dismissed: 0,
    };

  const [row] = await db
    .select({
      total: sql<string>`count(*)`,
      critical:
        sql<string>`coalesce(sum(case when ${alerts.severity} = 'critical' then 1 else 0 end), 0)`,
      high:
        sql<string>`coalesce(sum(case when ${alerts.severity} = 'high' then 1 else 0 end), 0)`,
      medium:
        sql<string>`coalesce(sum(case when ${alerts.severity} = 'medium' then 1 else 0 end), 0)`,
      low:
        sql<string>`coalesce(sum(case when ${alerts.severity} = 'low' then 1 else 0 end), 0)`,
      open:
        sql<string>`coalesce(sum(case when ${alerts.status} = 'open' then 1 else 0 end), 0)`,
      acknowledged:
        sql<string>`coalesce(sum(case when ${alerts.status} = 'acknowledged' then 1 else 0 end), 0)`,
      escalated:
        sql<string>`coalesce(sum(case when ${alerts.status} = 'escalated' then 1 else 0 end), 0)`,
      dismissed:
        sql<string>`coalesce(sum(case when ${alerts.status} = 'dismissed' then 1 else 0 end), 0)`,
    })
    .from(alerts);

  return {
    total: toNumber(row?.total),
    critical: toNumber(row?.critical),
    high: toNumber(row?.high),
    medium: toNumber(row?.medium),
    low: toNumber(row?.low),
    open: toNumber(row?.open),
    acknowledged: toNumber(row?.acknowledged),
    escalated: toNumber(row?.escalated),
    dismissed: toNumber(row?.dismissed),
  };
}

export async function getOpenIncidentCount(): Promise<number> {
  const db = await getDb();
  if (!db) return 0;

  const [row] = await db
    .select({
      value: sql<string>`count(*)`,
    })
    .from(incidents)
    .where(
      or(
        eq(incidents.status, "open"),
        eq(incidents.status, "investigating")
      )
    );

  return toNumber(row?.value);
}

export async function searchAlerts(filters: AlertSearchFilters): Promise<{
  alerts: Alert[];
  total: number;
}> {
  const db = await getDb();
  if (!db) {
    return { alerts: [], total: 0 };
  }

  const limit = Math.max(1, Math.min(filters.limit ?? 100, 500));
  const offset = Math.max(0, filters.offset ?? 0);
  const whereClause = buildAlertWhereClause(filters);

  const countQuery = db
    .select({
      value: sql<string>`count(*)`,
    })
    .from(alerts);

  const resultQuery = db.select().from(alerts);

  const [countRow] = await (
    whereClause ? countQuery.where(whereClause) : countQuery
  );
  const results = await (
    whereClause ? resultQuery.where(whereClause) : resultQuery
  )
    .orderBy(desc(alerts.createdAt))
    .limit(limit)
    .offset(offset);

  return {
    alerts: results,
    total: toNumber(countRow?.value),
  };
}

export async function getAlertTimeline(
  hours: number = 24
): Promise<AlertTimelinePoint[]> {
  const db = await getDb();
  if (!db) {
    return buildZeroTimeline(hours);
  }

  const normalizedHours = Math.max(1, Math.min(hours, 48));
  const start = new Date();
  start.setMinutes(0, 0, 0);
  start.setHours(start.getHours() - (normalizedHours - 1));

  const bucketExpr = sql<string>`DATE_FORMAT(${alerts.createdAt}, '%Y-%m-%d %H:00:00')`;
  const rows = await db
    .select({
      bucketStart: bucketExpr,
      alertCount: sql<string>`count(*)`,
    })
    .from(alerts)
    .where(gte(alerts.createdAt, start))
    .groupBy(bucketExpr);

  const counts = new Map(
    rows.map((row) => [row.bucketStart, toNumber(row.alertCount)])
  );

  return buildZeroTimeline(normalizedHours).map((point) => {
    const bucketDate = new Date(point.bucketStart);
    const bucketKey = formatBucketKey(bucketDate);
    return {
      ...point,
      alertCount: counts.get(bucketKey) ?? 0,
    };
  });
}
