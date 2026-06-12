import { nanoid } from "nanoid";
import type { InsertAlert } from "../drizzle/schema";
import { sanitizeLogValue } from "./_core/logSanitization";

const EVENT_TYPES = [
  "failed_login",
  "port_scan",
  "lateral_movement",
  "data_exfiltration",
  "privilege_escalation",
  "malware_detected",
  "ddos_attack",
  "sql_injection",
] as const;

type EventType = (typeof EVENT_TYPES)[number];
type Severity = "critical" | "high" | "medium" | "low";
export type ConnectorSource = "siem" | "edr" | "identity" | "cloud";

export type NormalizedConnectorEvent = Omit<InsertAlert, "status"> & {
  status?: InsertAlert["status"];
};

export type ConnectorEnvelope = {
  source: ConnectorSource;
  raw: Record<string, unknown>;
  normalized: NormalizedConnectorEvent;
};

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

const SOURCE_IPS = [
  "192.168.1.45",
  "10.0.0.88",
  "192.168.2.15",
  "192.168.1.78",
  "10.1.1.50",
  "172.16.0.25",
  "203.0.113.45",
  "198.51.100.10",
] as const;

const TARGET_SYSTEMS = [
  "AD-SERVER-01",
  "PROD-NETWORK",
  "DB-SERVER-02",
  "EXTERNAL-IP",
  "WEB-SERVER-01",
  "MAIL-SERVER",
  "FILE-SERVER-03",
  "BACKUP-SYSTEM",
] as const;

const EVENT_TEMPLATES: Record<
  EventType,
  {
    title: string;
    description: string;
    baseSeverity: Severity;
    connectorSource: ConnectorSource;
  }
> = {
  failed_login: {
    title: "Suspicious Failed Login Attempts",
    description: "Multiple failed authentication attempts detected from source IP",
    baseSeverity: "high",
    connectorSource: "identity",
  },
  port_scan: {
    title: "Port Scan Detected",
    description: "Network reconnaissance activity targeting multiple ports",
    baseSeverity: "high",
    connectorSource: "siem",
  },
  lateral_movement: {
    title: "Lateral Movement Detected",
    description: "Suspicious connection attempt between internal systems",
    baseSeverity: "critical",
    connectorSource: "edr",
  },
  data_exfiltration: {
    title: "Unusual Data Transfer",
    description: "Large data transfer to external IP detected",
    baseSeverity: "critical",
    connectorSource: "cloud",
  },
  privilege_escalation: {
    title: "Privilege Escalation Attempt",
    description: "Unauthorized privilege elevation detected",
    baseSeverity: "critical",
    connectorSource: "identity",
  },
  malware_detected: {
    title: "Malware Signature Match",
    description: "Known malware signature detected in network traffic",
    baseSeverity: "critical",
    connectorSource: "edr",
  },
  ddos_attack: {
    title: "DDoS Attack Detected",
    description: "Distributed denial of service attack in progress",
    baseSeverity: "critical",
    connectorSource: "cloud",
  },
  sql_injection: {
    title: "SQL Injection Attempt",
    description: "Potential SQL injection attack detected",
    baseSeverity: "high",
    connectorSource: "siem",
  },
};

type ScenarioBuilder = () => ConnectorEnvelope[];

const pick = <T>(values: readonly T[]): T =>
  values[Math.floor(Math.random() * values.length)];

const maybePromoteSeverity = (severity: Severity): Severity => {
  if (Math.random() >= 0.12) return severity;
  const currentIndex = SEVERITIES.indexOf(severity);
  if (currentIndex <= 0) return severity;
  return SEVERITIES[currentIndex - 1];
};

const createConnectorEvent = (options: {
  eventType: EventType;
  source: string;
  target: string;
  scenarioId?: string;
  scenarioName?: string;
  sequence?: number;
  stepCount?: number;
  title?: string;
  description?: string;
  timestamp?: Date;
}): ConnectorEnvelope => {
  const template = EVENT_TEMPLATES[options.eventType];
  const timestamp = options.timestamp ?? new Date();
  const connectorEventId = `CNE-${nanoid(12)}`;
  const normalized: NormalizedConnectorEvent = {
    eventId: `EVT-${nanoid(12)}`,
    severity: maybePromoteSeverity(template.baseSeverity),
    title: options.title ?? template.title,
    description: options.description ?? template.description,
    source: options.source,
    target: options.target,
    eventType: options.eventType,
    rawData: {
      connectorSource: template.connectorSource,
      connectorEventId,
      scenarioId: options.scenarioId,
      scenarioName: options.scenarioName,
      sequence: options.sequence,
      stepCount: options.stepCount,
      timestamp: timestamp.toISOString(),
    },
  };

  return {
    source: template.connectorSource,
    raw: {
      connectorEventId,
      occurredAt: timestamp.toISOString(),
      sensor: `${template.connectorSource.toUpperCase()}-${options.target}`,
      actor: options.source,
      resource: options.target,
      eventType: options.eventType,
      severity: normalized.severity,
      scenarioId: options.scenarioId,
      scenarioName: options.scenarioName,
      telemetry: {
        protocol: Math.random() > 0.5 ? "TCP" : "UDP",
        port: Math.floor(Math.random() * 65535),
        packets: Math.floor(Math.random() * 10000),
        bytes: Math.floor(Math.random() * 1_000_000),
        country: ["US", "CN", "RU", "KP", "IR"][Math.floor(Math.random() * 5)],
      },
    },
    normalized,
  };
};

export const connectorEnvelopeToAlert = (event: ConnectorEnvelope): InsertAlert => ({
  ...event.normalized,
  rawData: {
    connector: event,
    ...(event.normalized.rawData && typeof event.normalized.rawData === "object"
      ? (event.normalized.rawData as Record<string, unknown>)
      : {}),
  },
  status: event.normalized.status ?? "open",
});

const buildCredentialAbuseScenario: ScenarioBuilder = () => {
  const scenarioId = `SCN-${nanoid(10)}`;
  const entrySource = pick(SOURCE_IPS);
  const initialTarget = pick(["MAIL-SERVER", "WEB-SERVER-01", "AD-SERVER-01"]);
  const pivotTarget = pick(["FILE-SERVER-03", "DB-SERVER-02", "BACKUP-SYSTEM"]);
  const scenarioName = "Credential abuse to data exfiltration";
  const startedAt = Date.now();

  return [
    createConnectorEvent({
      eventType: "failed_login",
      source: entrySource,
      target: initialTarget,
      scenarioId,
      scenarioName,
      sequence: 1,
      stepCount: 4,
      timestamp: new Date(startedAt),
    }),
    createConnectorEvent({
      eventType: "privilege_escalation",
      source: initialTarget,
      target: initialTarget,
      scenarioId,
      scenarioName,
      sequence: 2,
      stepCount: 4,
      title: "Privilege Escalation on Compromised Host",
      description: "Elevated access granted immediately after repeated authentication failures.",
      timestamp: new Date(startedAt + 45_000),
    }),
    createConnectorEvent({
      eventType: "lateral_movement",
      source: initialTarget,
      target: pivotTarget,
      scenarioId,
      scenarioName,
      sequence: 3,
      stepCount: 4,
      title: "Internal Pivot to Secondary Asset",
      description: "The newly compromised host is reaching laterally into adjacent infrastructure.",
      timestamp: new Date(startedAt + 90_000),
    }),
    createConnectorEvent({
      eventType: "data_exfiltration",
      source: pivotTarget,
      target: "EXTERNAL-IP",
      scenarioId,
      scenarioName,
      sequence: 4,
      stepCount: 4,
      title: "Sensitive Data Leaving the Network",
      description: "Outbound transfer volume spiked after privileged access and lateral movement.",
      timestamp: new Date(startedAt + 135_000),
    }),
  ];
};

const buildWebCompromiseScenario: ScenarioBuilder = () => {
  const scenarioId = `SCN-${nanoid(10)}`;
  const attacker = pick(SOURCE_IPS);
  const appTier = pick(["WEB-SERVER-01", "PROD-NETWORK"]);
  const dataTier = pick(["DB-SERVER-02", "FILE-SERVER-03"]);
  const scenarioName = "Web compromise spreading inward";
  const startedAt = Date.now();

  return [
    createConnectorEvent({
      eventType: "sql_injection",
      source: attacker,
      target: "WEB-SERVER-01",
      scenarioId,
      scenarioName,
      sequence: 1,
      stepCount: 4,
      timestamp: new Date(startedAt),
    }),
    createConnectorEvent({
      eventType: "privilege_escalation",
      source: "WEB-SERVER-01",
      target: appTier,
      scenarioId,
      scenarioName,
      sequence: 2,
      stepCount: 4,
      title: "Application Tier Privilege Escalation",
      description: "Post-exploitation activity elevated privileges on the web-facing tier.",
      timestamp: new Date(startedAt + 45_000),
    }),
    createConnectorEvent({
      eventType: "lateral_movement",
      source: appTier,
      target: dataTier,
      scenarioId,
      scenarioName,
      sequence: 3,
      stepCount: 4,
      title: "East-West Movement Toward Data Tier",
      description: "Access expanded from the compromised application tier to a protected data system.",
      timestamp: new Date(startedAt + 90_000),
    }),
    createConnectorEvent({
      eventType: "data_exfiltration",
      source: dataTier,
      target: "EXTERNAL-IP",
      scenarioId,
      scenarioName,
      sequence: 4,
      stepCount: 4,
      title: "Outbound Exfiltration From Protected Dataset",
      description: "The data tier is sending unusually large outbound traffic immediately after lateral movement.",
      timestamp: new Date(startedAt + 135_000),
    }),
  ];
};

const buildMalwarePivotScenario: ScenarioBuilder = () => {
  const scenarioId = `SCN-${nanoid(10)}`;
  const source = pick(SOURCE_IPS);
  const initialVictim = pick(["MAIL-SERVER", "FILE-SERVER-03"]);
  const directoryTier = "AD-SERVER-01";
  const scenarioName = "Malware infection driving internal pivoting";
  const startedAt = Date.now();

  return [
    createConnectorEvent({
      eventType: "malware_detected",
      source,
      target: initialVictim,
      scenarioId,
      scenarioName,
      sequence: 1,
      stepCount: 4,
      timestamp: new Date(startedAt),
    }),
    createConnectorEvent({
      eventType: "lateral_movement",
      source: initialVictim,
      target: directoryTier,
      scenarioId,
      scenarioName,
      sequence: 2,
      stepCount: 4,
      title: "Malware Pivot Into Directory Services",
      description: "Malware execution was followed by suspicious movement toward identity infrastructure.",
      timestamp: new Date(startedAt + 45_000),
    }),
    createConnectorEvent({
      eventType: "privilege_escalation",
      source: directoryTier,
      target: directoryTier,
      scenarioId,
      scenarioName,
      sequence: 3,
      stepCount: 4,
      title: "Privileged Access on Directory Services",
      description: "Administrative permissions were escalated on the directory tier after malware pivoting.",
      timestamp: new Date(startedAt + 90_000),
    }),
    createConnectorEvent({
      eventType: "data_exfiltration",
      source: directoryTier,
      target: "EXTERNAL-IP",
      scenarioId,
      scenarioName,
      sequence: 4,
      stepCount: 4,
      title: "Directory Data Exfiltration Channel Opened",
      description: "Sensitive directory data appears to be leaving the environment over an unapproved channel.",
      timestamp: new Date(startedAt + 135_000),
    }),
  ];
};

const SCENARIO_BUILDERS: ScenarioBuilder[] = [
  buildCredentialAbuseScenario,
  buildWebCompromiseScenario,
  buildMalwarePivotScenario,
];

export function generateRandomConnectorEvent(): ConnectorEnvelope {
  const eventType = pick(EVENT_TYPES);
  const sourceIp = pick(SOURCE_IPS);
  const target = pick(TARGET_SYSTEMS);

  return createConnectorEvent({
    eventType,
    source: sourceIp,
    target,
  });
}

export function generateBatchConnectorEvents(count: number): ConnectorEnvelope[] {
  const events: ConnectorEnvelope[] = [];

  while (events.length < count) {
    const scenarioEvents = pick(SCENARIO_BUILDERS)();
    for (const event of scenarioEvents) {
      events.push(event);
      if (events.length === count) {
        break;
      }
    }
  }

  return events;
}

export async function replayConnectorEvents(
  events: ConnectorEnvelope[],
  onEvent: (event: ConnectorEnvelope) => Promise<void>,
  options: { intervalMs?: number } = {}
): Promise<void> {
  const intervalMs = Math.max(0, options.intervalMs ?? 0);

  for (const event of events) {
    await onEvent(event);
    if (intervalMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }
}

/**
 * Simulates a continuous stream of security events
 * Generates connector-shaped alerts in short scenario bursts, then pauses before the next chain
 */
export async function startEventStream(
  onEvent: (event: ConnectorEnvelope) => Promise<void>
): Promise<() => void> {
  let isRunning = true;
  let pendingScenarioEvents: ConnectorEnvelope[] = [];

  const generateNextEvent = async () => {
    if (!isRunning) return;

    if (pendingScenarioEvents.length === 0) {
      pendingScenarioEvents = generateBatchConnectorEvents(
        4 + Math.floor(Math.random() * 2)
      );
    }

    try {
      const event = pendingScenarioEvents.shift();
      if (!event) return;
      await onEvent(event);
    } catch (error) {
      console.error(
        "[EventStream] Failed to generate connector event:",
        sanitizeLogValue(error)
      );
    }

    const delay =
      pendingScenarioEvents.length > 0
        ? 6_000 + Math.random() * 6_000
        : 30_000 + Math.random() * 45_000;

    setTimeout(generateNextEvent, delay);
  };

  generateNextEvent();

  return () => {
    isRunning = false;
  };
}
