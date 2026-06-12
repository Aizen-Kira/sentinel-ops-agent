// lib/timeline/timelineBuilder.ts
import { splunkSearch } from "../splunk/splunkSearch";
import type { MitreTactic, TimelineEvent, TimelineStage, IncidentTimeline } from "@shared/splunkTypes";

export type { MitreTactic, TimelineEvent, TimelineStage, IncidentTimeline };

const SEVERITY_MAP: Record<string, TimelineEvent["severity"]> = {
  "1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical",
  low: "low", medium: "medium", high: "high", critical: "critical", info: "info",
};

const STAGE_TACTIC_MAP: Record<number, { name: string; tactic: MitreTactic }> = {
  1: { name: "Reconnaissance", tactic: "Reconnaissance" },
  2: { name: "Initial Access", tactic: "Initial Access" },
  3: { name: "C2 Establishment", tactic: "Command and Control" },
  4: { name: "Lateral Movement", tactic: "Lateral Movement" },
  5: { name: "Impact / Encryption", tactic: "Impact" },
};

function parseEvent(row: Record<string, string>, index: number): TimelineEvent {
  const stageNum = row["attack_stage"] ? parseInt(row["attack_stage"], 10) : undefined;
  return {
    id: row["_cd"] ?? `event-${index}`,
    timestamp: new Date(row["_time"] ?? Date.now()),
    host: row["host"] ?? "unknown",
    sourceIp: row["src_ip"] ?? row["src"] ?? undefined,
    destIp: row["dest_ip"] ?? row["dest"] ?? undefined,
    user: row["user"] ?? undefined,
    process: row["process"] ?? row["process_name"] ?? undefined,
    eventType: row["event_type"] ?? row["EventCode"] ?? "unknown",
    severity: SEVERITY_MAP[row["severity"]?.toLowerCase() ?? "info"] ?? "info",
    mitreTactic: row["mitre_tactic"] as MitreTactic | undefined,
    mitreTechniqueId: row["mitre_technique_id"] ?? undefined,
    mitreTechniqueName: row["mitre_technique_name"] ?? undefined,
    attackStage: stageNum,
    rawEvent: row,
  };
}

export async function buildTimeline(incidentId: number): Promise<IncidentTimeline> {
  const spl = `index=${process.env.SPLUNK_INDEX ?? "main"} incident_id=${incidentId} | sort _time | head 1000`;
  const result = await splunkSearch.search(spl, { earliest: "-30d" });

  const events = result.rows.map(parseEvent).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  if (events.length === 0) {
    return { incidentId, totalEvents: 0, stages: [], ungroupedEvents: [], timespan: null };
  }

  // Group by attack stage
  const stageMap = new Map<number, TimelineEvent[]>();
  const ungrouped: TimelineEvent[] = [];

  for (const event of events) {
    if (event.attackStage !== undefined && !isNaN(event.attackStage)) {
      const arr = stageMap.get(event.attackStage) ?? [];
      arr.push(event);
      stageMap.set(event.attackStage, arr);
    } else if (event.mitreTactic) {
      // Try to infer stage from tactic
      const stageEntry = Object.entries(STAGE_TACTIC_MAP).find(([, v]) => v.tactic === event.mitreTactic);
      if (stageEntry) {
        const s = parseInt(stageEntry[0], 10);
        const arr = stageMap.get(s) ?? [];
        arr.push(event);
        stageMap.set(s, arr);
      } else {
        ungrouped.push(event);
      }
    } else {
      ungrouped.push(event);
    }
  }

  const stages: TimelineStage[] = Array.from(stageMap.entries())
    .sort(([a], [b]) => a - b)
    .map(([stage, stageEvents]) => ({
      stage,
      name: STAGE_TACTIC_MAP[stage]?.name ?? `Stage ${stage}`,
      tactic: STAGE_TACTIC_MAP[stage]?.tactic,
      events: stageEvents,
      firstSeen: stageEvents[0]!.timestamp,
      lastSeen: stageEvents[stageEvents.length - 1]!.timestamp,
    }));

  const allTimestamps = events.map((e) => e.timestamp.getTime());
  return {
    incidentId,
    totalEvents: events.length,
    stages,
    ungroupedEvents: ungrouped,
    timespan: {
      start: new Date(Math.min(...allTimestamps)),
      end: new Date(Math.max(...allTimestamps)),
    },
  };
}
