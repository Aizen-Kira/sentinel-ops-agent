// components/IncidentTimeline.tsx
import React, { useState } from "react";
import type { IncidentTimeline, TimelineEvent, TimelineStage } from "@shared/splunkTypes";

interface EventRowProps {
  event: TimelineEvent;
}

const SEVERITY_STYLES: Record<string, string> = {
  info: "bg-slate-100 text-slate-700 border-slate-300",
  low: "bg-green-50 text-green-800 border-green-300",
  medium: "bg-yellow-50 text-yellow-800 border-yellow-300",
  high: "bg-orange-50 text-orange-800 border-orange-400",
  critical: "bg-red-50 text-red-800 border-red-400",
};

function EventRow({ event }: EventRowProps) {
  const [expanded, setExpanded] = useState(false);
  const style = SEVERITY_STYLES[event.severity] ?? SEVERITY_STYLES.info;

  return (
    <div className={`border-l-4 pl-3 py-2 mb-1 rounded-r cursor-pointer ${style}`} onClick={() => setExpanded(!expanded)}>
      <div className="flex items-center gap-3 text-sm">
        <span className="font-mono text-xs opacity-70">{event.timestamp.toISOString().replace("T", " ").slice(0, 19)}</span>
        <span className="font-semibold">{event.eventType}</span>
        <span className="opacity-70">{event.host}</span>
        {event.mitreTechniqueId && (
          <a
            href={`https://attack.mitre.org/techniques/${event.mitreTechniqueId.replace(".", "/")}`}
            target="_blank" rel="noopener noreferrer"
            className="text-blue-600 text-xs underline"
            onClick={(e) => e.stopPropagation()}
          >
            {event.mitreTechniqueId}
          </a>
        )}
        <span className="ml-auto text-xs opacity-60">{expanded ? "▲" : "▼"}</span>
      </div>
      {expanded && (
        <div className="mt-2 text-xs font-mono bg-black/5 rounded p-2 space-y-1">
          {event.sourceIp && <div><span className="opacity-60">src_ip:</span> {event.sourceIp}</div>}
          {event.destIp && <div><span className="opacity-60">dest_ip:</span> {event.destIp}</div>}
          {event.user && <div><span className="opacity-60">user:</span> {event.user}</div>}
          {event.process && <div><span className="opacity-60">process:</span> {event.process}</div>}
          {event.mitreTechniqueName && <div><span className="opacity-60">technique:</span> {event.mitreTechniqueName}</div>}
        </div>
      )}
    </div>
  );
}

interface StageGroupProps {
  stage: TimelineStage;
}

function StageGroup({ stage }: StageGroupProps) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="mb-6">
      <button
        className="flex items-center gap-2 w-full text-left mb-2 font-semibold text-sm text-gray-700 hover:text-gray-900"
        onClick={() => setCollapsed(!collapsed)}
      >
        <span className="bg-gray-800 text-white text-xs px-2 py-0.5 rounded-full">Stage {stage.stage}</span>
        <span>{stage.name}</span>
        {stage.tactic && <span className="text-xs font-normal text-gray-500">MITRE: {stage.tactic}</span>}
        <span className="ml-auto text-xs text-gray-400">{stage.events.length} events</span>
        <span className="text-gray-400">{collapsed ? "▶" : "▼"}</span>
      </button>
      {!collapsed && (
        <div className="ml-4">
          {stage.events.map((evt: TimelineEvent) => <EventRow key={evt.id} event={evt} />)}
        </div>
      )}
    </div>
  );
}

interface IncidentTimelineProps {
  timeline: IncidentTimeline;
  isLoading?: boolean;
}

export function IncidentTimeline({ timeline, isLoading }: IncidentTimelineProps) {
  if (isLoading) {
    return <div className="animate-pulse text-sm text-gray-500 p-4">Loading timeline...</div>;
  }

  if (timeline.totalEvents === 0) {
    return <div className="text-sm text-gray-500 p-4">No timeline events found for this incident.</div>;
  }

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-gray-900">Attack Timeline</h3>
        <div className="text-xs text-gray-500">
          {timeline.totalEvents} events
          {timeline.timespan && (
            <> &nbsp;·&nbsp; {Math.round((timeline.timespan.end.getTime() - timeline.timespan.start.getTime()) / 60000)} min span</>
          )}
        </div>
      </div>

      {timeline.stages.map((stage: TimelineStage) => <StageGroup key={stage.stage} stage={stage} />)}

      {timeline.ungroupedEvents.length > 0 && (
        <div className="mb-6">
          <div className="text-sm font-semibold text-gray-600 mb-2">Other Events ({timeline.ungroupedEvents.length})</div>
          {timeline.ungroupedEvents.map((evt: TimelineEvent) => <EventRow key={evt.id} event={evt} />)}
        </div>
      )}
    </div>
  );
}

// ─── RiskBadge ────────────────────────────────────────────────────────────────

interface RiskBadgeProps {
  score: number;
  showLabel?: boolean;
  size?: "sm" | "md" | "lg";
}

export function RiskBadge({ score, showLabel = true, size = "md" }: RiskBadgeProps) {
  const clamped = Math.min(100, Math.max(0, score));
  let bg: string, text: string, label: string;

  if (clamped <= 25) { bg = "bg-green-100"; text = "text-green-800"; label = "Low"; }
  else if (clamped <= 50) { bg = "bg-amber-100"; text = "text-amber-800"; label = "Medium"; }
  else if (clamped <= 75) { bg = "bg-orange-100"; text = "text-orange-800"; label = "High"; }
  else { bg = "bg-red-100"; text = "text-red-800"; label = "Critical"; }

  const sizeClass = size === "sm" ? "text-xs px-1.5 py-0.5" : size === "lg" ? "text-base px-4 py-2" : "text-sm px-2.5 py-1";

  return (
    <span className={`inline-flex items-center gap-1.5 font-semibold rounded-full ${bg} ${text} ${sizeClass}`}>
      <span className="font-bold">{clamped}</span>
      {showLabel && <span>{label}</span>}
    </span>
  );
}
