import {
  int,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  varchar,
  boolean,
  json,
  decimal,
  index,
} from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "analyst", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Security alerts from data stream
 * Represents individual security events detected by the monitoring system
 */
export const alerts = mysqlTable(
  "alerts",
  {
    id: int("id").autoincrement().primaryKey(),
    eventId: varchar("eventId", { length: 64 }).notNull().unique(),
    severity: mysqlEnum("severity", ["critical", "high", "medium", "low"])
      .notNull()
      .default("medium"),
    title: varchar("title", { length: 255 }).notNull(),
    description: text("description"),
    source: varchar("source", { length: 128 }).notNull(), // IP, hostname, service
    target: varchar("target", { length: 128 }), // IP, hostname, service
    eventType: varchar("eventType", { length: 64 }).notNull(), // failed_login, port_scan, lateral_movement, data_exfiltration, etc.
    rawData: json("rawData"), // Additional event metadata
    status: mysqlEnum("status", ["open", "acknowledged", "escalated", "dismissed"])
      .notNull()
      .default("open"),
    assignedTo: int("assignedTo"), // User ID
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
    incidentId: int("incidentId"), // Link to grouped incident
  },
  (table) => ({
    severityIdx: index("severity_idx").on(table.severity),
    statusIdx: index("status_idx").on(table.status),
    createdAtIdx: index("createdAt_idx").on(table.createdAt),
    incidentIdx: index("incident_idx").on(table.incidentId),
  })
);

export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = typeof alerts.$inferInsert;

/**
 * Grouped incidents from correlated alerts
 * Represents a security incident composed of multiple related alerts
 */
export const incidents = mysqlTable(
  "incidents",
  {
    id: int("id").autoincrement().primaryKey(),
    incidentId: varchar("incidentId", { length: 64 }).notNull().unique(),
    title: varchar("title", { length: 255 }).notNull(),
    severity: mysqlEnum("severity", ["critical", "high", "medium", "low"])
      .notNull()
      .default("high"),
    status: mysqlEnum("status", ["open", "investigating", "contained", "resolved"])
      .notNull()
      .default("open"),
    rootCause: text("rootCause"), // AI-generated root cause analysis
    affectedAssets: json("affectedAssets"), // Array of affected IPs, hostnames, services
    mitreAttackTactics: json("mitreAttackTactics"), // Array of MITRE ATT&CK tactic IDs
    killChain: json("killChain"), // Array of event progression steps
    remediationSteps: json("remediationSteps"), // Array of recommended actions
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
    investigationId: int("investigationId"), // Link to AI investigation
  },
  (table) => ({
    severityIdx: index("incident_severity_idx").on(table.severity),
    statusIdx: index("incident_status_idx").on(table.status),
    createdAtIdx: index("incident_createdAt_idx").on(table.createdAt),
  })
);

export type Incident = typeof incidents.$inferSelect;
export type InsertIncident = typeof incidents.$inferInsert;

/**
 * AI investigations and reasoning traces
 * Stores the streaming investigation process and conclusions
 */
export const investigations = mysqlTable(
  "investigations",
  {
    id: int("id").autoincrement().primaryKey(),
    investigationId: varchar("investigationId", { length: 64 }).notNull().unique(),
    alertIds: json("alertIds"), // Array of alert IDs being investigated
    status: mysqlEnum("status", ["in_progress", "completed", "failed"])
      .notNull()
      .default("in_progress"),
    reasoningSteps: json("reasoningSteps"), // Array of streaming reasoning steps
    conclusion: text("conclusion"), // Final summary and recommendations
    confidenceScore: decimal("confidenceScore", { precision: 3, scale: 2 }), // 0.00 to 1.00
    executedAt: timestamp("executedAt"),
    completedAt: timestamp("completedAt"),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    userId: int("userId").notNull(), // Analyst who triggered investigation
  },
  (table) => ({
    statusIdx: index("investigation_status_idx").on(table.status),
    createdAtIdx: index("investigation_createdAt_idx").on(table.createdAt),
    userIdx: index("investigation_user_idx").on(table.userId),
  })
);

export type Investigation = typeof investigations.$inferSelect;
export type InsertInvestigation = typeof investigations.$inferInsert;

/**
 * Durable realtime event spine / outbox.
 * Every publishable event is written here before being fanned out over SSE.
 */
export const realtimeEvents = mysqlTable(
  "realtime_events",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    tenantId: varchar("tenant_id", { length: 64 }).notNull().default("default"),
    topic: varchar("topic", { length: 128 }).notNull(),
    payload: json("payload"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    replayed: boolean("replayed").notNull().default(false),
  },
  (table) => ({
    topicIdx: index("realtime_events_topic_idx").on(table.topic),
    tenantIdx: index("realtime_events_tenant_idx").on(table.tenantId),
    createdAtIdx: index("realtime_events_created_at_idx").on(table.createdAt),
  })
);

export type RealtimeEventRecord = typeof realtimeEvents.$inferSelect;
export type InsertRealtimeEventRecord = typeof realtimeEvents.$inferInsert;

/**
 * Background investigation job queue.
 * Jobs hold the durable execution state for long-running AI analysis.
 */
export const investigationJobs = mysqlTable(
  "investigation_jobs",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    investigationId: varchar("investigation_id", { length: 64 }).notNull(),
    status: mysqlEnum("status", ["pending", "running", "done", "failed"])
      .notNull()
      .default("pending"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    artifact: json("artifact"),
  },
  (table) => ({
    investigationIdx: index("investigation_jobs_investigation_idx").on(
      table.investigationId
    ),
    statusIdx: index("investigation_jobs_status_idx").on(table.status),
    createdAtIdx: index("investigation_jobs_created_at_idx").on(table.createdAt),
  })
);

export type InvestigationJob = typeof investigationJobs.$inferSelect;
export type InsertInvestigationJob = typeof investigationJobs.$inferInsert;

/**
 * Alert triage action audit trail
 * Tracks all manual actions taken on alerts (acknowledge, escalate, dismiss, severity changes)
 */
export const alertActions = mysqlTable(
  "alert_actions",
  {
    id: int("id").autoincrement().primaryKey(),
    alertId: int("alertId").notNull(),
    actionType: mysqlEnum("actionType", [
      "acknowledged",
      "escalated",
      "dismissed",
      "severity_changed",
      "assigned",
    ]).notNull(),
    previousValue: varchar("previousValue", { length: 64 }),
    newValue: varchar("newValue", { length: 64 }),
    reason: text("reason"),
    userId: int("userId").notNull(), // Analyst who performed action
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  (table) => ({
    alertIdx: index("action_alert_idx").on(table.alertId),
    userIdx: index("action_user_idx").on(table.userId),
    createdAtIdx: index("action_createdAt_idx").on(table.createdAt),
  })
);

export type AlertAction = typeof alertActions.$inferSelect;
export type InsertAlertAction = typeof alertActions.$inferInsert;

/**
 * Human-in-the-loop response rail.
 * Every response action requires proposal, approval, and explicit execution.
 */
export const responseActions = mysqlTable(
  "response_actions",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    investigationId: varchar("investigation_id", { length: 64 }).notNull(),
    actionType: mysqlEnum("action_type", [
      "ticket",
      "disable_user",
      "isolate_host",
      "block_ioc",
    ]).notNull(),
    proposedBy: int("proposed_by").notNull(),
    approvedBy: int("approved_by"),
    status: mysqlEnum("status", ["proposed", "approved", "executed", "failed"])
      .notNull()
      .default("proposed"),
    executedAt: timestamp("executed_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => ({
    investigationIdx: index("response_actions_investigation_idx").on(
      table.investigationId
    ),
    statusIdx: index("response_actions_status_idx").on(table.status),
    proposedByIdx: index("response_actions_proposed_by_idx").on(table.proposedBy),
  })
);

export type ResponseAction = typeof responseActions.$inferSelect;
export type InsertResponseAction = typeof responseActions.$inferInsert;

/**
 * Indicators of compromise (IOCs)
 * IP addresses, domains, file hashes, etc. linked to incidents
 */
export const iocs = mysqlTable(
  "iocs",
  {
    id: int("id").autoincrement().primaryKey(),
    iocId: varchar("iocId", { length: 64 }).notNull().unique(),
    incidentId: int("incidentId").notNull(),
    type: mysqlEnum("type", ["ip", "domain", "hash", "email", "url", "file_path"])
      .notNull(),
    value: varchar("value", { length: 512 }).notNull(),
    severity: mysqlEnum("severity", ["critical", "high", "medium", "low"])
      .notNull()
      .default("medium"),
    firstSeen: timestamp("firstSeen").defaultNow().notNull(),
    lastSeen: timestamp("lastSeen").defaultNow().notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  (table) => ({
    incidentIdx: index("ioc_incident_idx").on(table.incidentId),
    typeIdx: index("ioc_type_idx").on(table.type),
  })
);

export type IOC = typeof iocs.$inferSelect;
export type InsertIOC = typeof iocs.$inferInsert;

/**
 * Metrics snapshots for KPI dashboard
 * Aggregated statistics captured at regular intervals
 */
export const metrics = mysqlTable(
  "metrics",
  {
    id: int("id").autoincrement().primaryKey(),
    timestamp: timestamp("timestamp").defaultNow().notNull(),
    mttd: decimal("mttd", { precision: 10, scale: 2 }), // Mean Time To Detect (minutes)
    mtta: decimal("mtta", { precision: 10, scale: 2 }), // Mean Time To Acknowledge (minutes)
    mttr: decimal("mttr", { precision: 10, scale: 2 }), // Mean Time To Resolve (minutes)
    openIncidentCount: int("openIncidentCount").notNull().default(0),
    criticalAlertCount: int("criticalAlertCount").notNull().default(0),
    highAlertCount: int("highAlertCount").notNull().default(0),
    mediumAlertCount: int("mediumAlertCount").notNull().default(0),
    lowAlertCount: int("lowAlertCount").notNull().default(0),
    acknowledgedCount: int("acknowledgedCount").notNull().default(0),
    dismissedCount: int("dismissedCount").notNull().default(0),
  },
  (table) => ({
    timestampIdx: index("metrics_timestamp_idx").on(table.timestamp),
  })
);

export type Metric = typeof metrics.$inferSelect;
export type InsertMetric = typeof metrics.$inferInsert;

/**
 * Persisted investigation reports generated from the stored event stream.
 */
export const investigationReports = mysqlTable(
  "investigation_reports",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    investigationId: varchar("investigation_id", { length: 64 }).notNull(),
    status: mysqlEnum("status", ["pending", "running", "completed", "failed"])
      .notNull()
      .default("pending"),
    format: mysqlEnum("format", ["markdown", "pdf"]).notNull().default("markdown"),
    content: text("content"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
  },
  (table) => ({
    investigationIdx: index("investigation_reports_investigation_idx").on(
      table.investigationId
    ),
    statusIdx: index("investigation_reports_status_idx").on(table.status),
  })
);

export type InvestigationReport = typeof investigationReports.$inferSelect;
export type InsertInvestigationReport = typeof investigationReports.$inferInsert;
