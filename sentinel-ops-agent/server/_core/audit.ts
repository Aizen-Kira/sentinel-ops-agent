import { sanitizeLogValue } from "./logSanitization";

export type AuditEventType =
  | "login_success"
  | "login_failure"
  | "logout"
  | "permission_denied"
  | "admin_action"
  | "security_config_change";

export type AuditEvent = {
  type: AuditEventType;
  timestamp?: string;
  actorUserId?: number | null;
  actorOpenId?: string | null;
  role?: string | null;
  action?: string;
  resource?: string;
  outcome: "success" | "failure";
  reason?: string;
  metadata?: Record<string, unknown>;
};

const auditEvents: AuditEvent[] = [];

let auditWriter: (event: AuditEvent) => void = (event) => {
  console.info("[Audit]", sanitizeLogValue(event));
};

export function auditLog(event: AuditEvent): AuditEvent {
  const timestampedEvent: AuditEvent = {
    ...event,
    timestamp: event.timestamp ?? new Date().toISOString(),
  };
  const sanitizedEvent = sanitizeLogValue(timestampedEvent) as AuditEvent;
  auditEvents.push(sanitizedEvent);
  auditWriter(sanitizedEvent);
  return sanitizedEvent;
}

export function getAuditEvents(): AuditEvent[] {
  return [...auditEvents];
}

export function clearAuditEvents(): void {
  auditEvents.length = 0;
}

export function setAuditWriterForTests(
  writer: ((event: AuditEvent) => void) | null
): void {
  auditWriter = writer ?? ((event) => {
    console.info("[Audit]", sanitizeLogValue(event));
  });
}
