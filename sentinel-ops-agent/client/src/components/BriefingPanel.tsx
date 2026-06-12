// components/BriefingPanel.tsx
import React from "react";
import { DemoModeNotice } from "@/components/DemoModeNotice";
import type { BriefingContent } from "@shared/splunkTypes";

interface BriefingPanelProps {
  briefing: BriefingContent | null;
  incidentId: number;
  onGenerate: () => Promise<void>;
  onExportHtml: () => void;
  isGenerating?: boolean;
}

export function BriefingPanel({ briefing, incidentId, onGenerate, onExportHtml, isGenerating }: BriefingPanelProps) {
  const score = briefing?.riskOverview.score ?? 0;
  const scoreColor = score >= 76 ? "text-red-700 bg-red-50 border-red-200"
    : score >= 51 ? "text-orange-700 bg-orange-50 border-orange-200"
    : score >= 26 ? "text-amber-700 bg-amber-50 border-amber-200"
    : "text-green-700 bg-green-50 border-green-200";

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="font-bold text-gray-900 text-lg">Executive Briefing</h3>
          <p className="text-xs text-gray-500 mt-0.5">CISO-level summary for non-technical stakeholders</p>
        </div>
        <div className="flex gap-2">
          {briefing && (
            <button onClick={onExportHtml}
              className="text-xs px-3 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
              📧 Export HTML
            </button>
          )}
          <button onClick={onGenerate} disabled={isGenerating}
            className="text-xs px-4 py-2 bg-slate-900 text-white rounded-lg hover:bg-slate-800 disabled:opacity-50 transition-colors">
            {isGenerating ? "Generating..." : briefing ? "↻ Regenerate" : "✦ Generate Briefing"}
          </button>
        </div>
      </div>

      <DemoModeNotice className="mb-5 border-sky-200 bg-sky-50 text-sky-900 shadow-none">
        CISO briefings can use mock content when the external LLM key is not configured.
      </DemoModeNotice>

      {!briefing && !isGenerating && (
        <div className="text-center py-12 text-gray-400">
          <div className="text-4xl mb-3">📋</div>
          <div className="text-sm">No briefing generated yet.</div>
          <div className="text-xs mt-1">Click Generate to create an executive summary.</div>
        </div>
      )}

      {isGenerating && (
        <div className="text-center py-12">
          <div className="animate-spin text-3xl mb-3">⚙️</div>
          <div className="text-sm text-gray-500">Analyzing incident and generating briefing...</div>
        </div>
      )}

      {briefing && !isGenerating && (
        <div className="space-y-5">
          {briefing.isStale && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-sm text-amber-800 flex items-center gap-2">
              ⚠️ This briefing may be outdated — the incident was updated after it was generated.
            </div>
          )}

          <div className={`inline-flex items-center gap-3 border rounded-xl px-4 py-3 ${scoreColor}`}>
            <span className="text-3xl font-bold">{score}</span>
            <div>
              <div className="font-semibold text-sm">{briefing.riskOverview.label} Risk</div>
              <div className="text-xs opacity-80">{briefing.riskOverview.rationale}</div>
            </div>
          </div>

          <section>
            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Situation Summary</h4>
            <p className="text-sm text-gray-700 leading-relaxed">{briefing.executiveSummary}</p>
          </section>

          <section>
            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Business Impact</h4>
            <p className="text-sm text-gray-700 leading-relaxed">{briefing.businessImpact}</p>
          </section>

          <section>
            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Decisions Required</h4>
            <div className="space-y-2">
              {briefing.recommendedActions.map((action: BriefingContent["recommendedActions"][number], i: number) => (
                <div key={i} className="flex items-start gap-3 border border-gray-100 rounded-lg p-3">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded whitespace-nowrap mt-0.5 ${action.urgency === "immediate" ? "bg-red-100 text-red-700" : action.urgency === "within24h" ? "bg-orange-100 text-orange-700" : "bg-gray-100 text-gray-600"}`}>
                    {action.urgency === "immediate" ? "NOW" : action.urgency === "within24h" ? "24h" : "PLAN"}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-gray-900">{action.title}</div>
                    <div className="text-xs text-gray-500">Owner: {action.ownerRole}</div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="border-t border-gray-100 pt-4">
            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Next Steps</h4>
            <p className="text-sm text-gray-700">{briefing.nextSteps}</p>
          </section>

          <div className="text-xs text-gray-400 pt-2">
            Generated {new Date(briefing.generatedAt).toLocaleString()} · Incident #{incidentId}
          </div>
        </div>
      )}
    </div>
  );
}
