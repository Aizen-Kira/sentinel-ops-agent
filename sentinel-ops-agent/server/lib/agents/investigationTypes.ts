// lib/agents/investigationTypes.ts
// Shared FSM types for the Splunk-native Investigation Agent
// These types are used by the timeline builder, risk scorer, recommendation engine, and briefing service.

// ─── FSM State ────────────────────────────────────────────────────────────────

export type AgentState = "IDLE" | "ANALYZING" | "ENRICHED" | "ESCALATED" | "FAILED";

// ─── IOC (Indicator of Compromise) ───────────────────────────────────────────

export interface IOC {
  type: "ip" | "domain" | "hash" | "user" | "file" | "registry";
  value: string;
  confidence: "low" | "medium" | "high";
  context: string;
}

// ─── Enrichment Result (LLM output + Splunk event metadata) ──────────────────

export interface EnrichmentResult {
  summary: string;
  attackVector: string;
  affectedAssets: string[];
  iocs: IOC[];
  mitreAttackIds: string[];
  recommendedSeverity: "low" | "medium" | "high" | "critical";
  requiresEscalation: boolean;
  escalationReason?: string;
  rawSplunkEventCount: number;
}

// ─── Agent Run Record (matches agent_runs DB table) ───────────────────────────

export interface AgentRunRecord {
  id: number;
  incidentId: number;
  state: AgentState;
  inputSnapshot?: unknown;
  outputSnapshot?: unknown;
  error?: string;
  startedAt: Date;
  completedAt?: Date;
}
