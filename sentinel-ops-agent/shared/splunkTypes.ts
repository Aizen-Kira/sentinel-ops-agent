// shared/splunkTypes.ts
// Types shared between the server lib layer and the React client components.
// Keep this file free of Node.js-only imports so it can be bundled by Vite.

// ─── Splunk Timeline ──────────────────────────────────────────────────────────

export type MitreTactic =
  | "Reconnaissance" | "Initial Access" | "Execution" | "Persistence"
  | "Privilege Escalation" | "Defense Evasion" | "Credential Access"
  | "Discovery" | "Lateral Movement" | "Collection" | "Command and Control"
  | "Exfiltration" | "Impact";

export interface TimelineEvent {
  id: string;
  timestamp: Date;
  host: string;
  sourceIp?: string;
  destIp?: string;
  user?: string;
  process?: string;
  eventType: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  mitreTactic?: MitreTactic;
  mitreTechniqueId?: string;
  mitreTechniqueName?: string;
  rawEvent: Record<string, string>;
  attackStage?: number;
}

export interface TimelineStage {
  stage: number;
  name: string;
  tactic?: MitreTactic;
  events: TimelineEvent[];
  firstSeen: Date;
  lastSeen: Date;
}

export interface IncidentTimeline {
  incidentId: number;
  totalEvents: number;
  stages: TimelineStage[];
  ungroupedEvents: TimelineEvent[];
  timespan: { start: Date; end: Date } | null;
}

// ─── Briefing ─────────────────────────────────────────────────────────────────

export interface BriefingContent {
  executiveSummary: string;
  businessImpact: string;
  riskOverview: { score: number; label: string; rationale: string };
  timelineHighlights: Array<{ timestamp: string; description: string; significance: string }>;
  recommendedActions: Array<{ title: string; urgency: "immediate" | "within24h" | "planned"; ownerRole: string }>;
  currentStatus: string;
  nextSteps: string;
  generatedAt: string;
  isStale: boolean;
}

// ─── Response Recommendations ─────────────────────────────────────────────────

export interface ResponseAction {
  id: string;
  title: string;
  description: string;
  mitreTechniqueId: string;
  priority: 1 | 2 | 3 | 4 | 5;
  estimatedTimeMinutes: number;
  requiresApproval: boolean;
  automated: boolean;
  category: "containment" | "eradication" | "recovery" | "detection";
}
