// components/ResponseRecommendations.tsx
import React, { useState } from "react";
import { DemoModeNotice } from "@/components/DemoModeNotice";
import type { ResponseAction } from "@shared/splunkTypes";

const PRIORITY_LABELS: Record<number, { label: string; bg: string; text: string }> = {
  1: { label: "P1 Critical", bg: "bg-red-100",    text: "text-red-800" },
  2: { label: "P2 High",     bg: "bg-orange-100", text: "text-orange-800" },
  3: { label: "P3 Medium",   bg: "bg-yellow-100", text: "text-yellow-800" },
  4: { label: "P4 Low",      bg: "bg-blue-100",   text: "text-blue-800" },
  5: { label: "P5 Info",     bg: "bg-gray-100",   text: "text-gray-700" },
};

const CATEGORY_ICONS: Record<string, string> = {
  containment: "🛡️", eradication: "🔥", recovery: "♻️", detection: "🔍",
};

interface ResponseRecommendationsProps {
  actions: ResponseAction[];
  incidentId: number;
  onSubmitApproval?: (action: ResponseAction) => void;
}

export function ResponseRecommendations({ actions, incidentId, onSubmitApproval }: ResponseRecommendationsProps) {
  return (
    <div className="space-y-3">
      <h3 className="font-semibold text-gray-900 mb-4">Recommended Response Actions</h3>
      <DemoModeNotice className="mb-4 border-sky-200 bg-sky-50 text-sky-900 shadow-none">
        Recommendation scoring can use hardcoded enrichment when live incident enrichment is not provided.
      </DemoModeNotice>
      {actions.map((action) => {
        const p = PRIORITY_LABELS[action.priority] ?? PRIORITY_LABELS[5]!;
        return (
          <div key={action.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
            <div className="flex items-start gap-3">
              <span className="text-xl">{CATEGORY_ICONS[action.category] ?? "⚡"}</span>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${p.bg} ${p.text}`}>{p.label}</span>
                  <span className="font-medium text-gray-900 text-sm">{action.title}</span>
                  {action.automated && <span className="text-xs bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">Auto</span>}
                </div>
                <p className="text-xs text-gray-600 mb-2">{action.description}</p>
                <div className="flex items-center gap-4 text-xs text-gray-500">
                  <a href={`https://attack.mitre.org/techniques/${action.mitreTechniqueId.replace(".", "/")}`}
                    target="_blank" rel="noopener noreferrer"
                    className="text-blue-600 hover:underline">{action.mitreTechniqueId}</a>
                  <span>~{action.estimatedTimeMinutes} min</span>
                  {action.requiresApproval && <span className="text-amber-600 font-medium">⚠ Requires Approval</span>}
                </div>
              </div>
              {action.requiresApproval && onSubmitApproval && (
                <button
                  onClick={() => onSubmitApproval(action)}
                  className="text-xs bg-blue-600 text-white px-3 py-1.5 rounded hover:bg-blue-700 transition-colors whitespace-nowrap"
                >
                  Submit for Approval
                </button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── ApprovalModal ────────────────────────────────────────────────────────────

interface ApprovalModalProps {
  action: ResponseAction;
  approvalId: number;
  currentVersion: number;
  onDecide: (decision: "APPROVED" | "REJECTED" | "MODIFIED", modified?: Record<string, unknown>) => void;
  onClose: () => void;
}

export function ApprovalModal({ action, approvalId, currentVersion, onDecide, onClose }: ApprovalModalProps) {
  const [mode, setMode] = useState<"review" | "modify">("review");
  const [modifiedDescription, setModifiedDescription] = useState(action.description);

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-bold text-gray-900">Review Response Action</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-700 text-xl">✕</button>
        </div>

        <div className="bg-gray-50 rounded-lg p-4 mb-4">
          <div className="font-semibold text-sm text-gray-900 mb-1">{action.title}</div>
          <div className="text-xs text-gray-600 mb-2">{action.description}</div>
          <div className="text-xs text-gray-500">
            MITRE: {action.mitreTechniqueId} · Est. {action.estimatedTimeMinutes} min
          </div>
        </div>

        {mode === "modify" && (
          <div className="mb-4">
            <label className="text-xs font-medium text-gray-700 block mb-1">Modified Description</label>
            <textarea
              className="w-full border border-gray-300 rounded p-2 text-sm resize-none"
              rows={3}
              value={modifiedDescription}
              onChange={(e) => setModifiedDescription(e.target.value)}
            />
          </div>
        )}

        <div className="flex gap-2 justify-end">
          <button onClick={() => setMode(mode === "modify" ? "review" : "modify")}
            className="text-xs px-3 py-2 border border-gray-300 rounded hover:bg-gray-50">
            {mode === "modify" ? "Cancel Edit" : "✏ Modify"}
          </button>
          <button onClick={() => onDecide("REJECTED")}
            className="text-xs px-3 py-2 bg-red-100 text-red-700 rounded hover:bg-red-200">
            Reject
          </button>
          <button
            onClick={() => mode === "modify"
              ? onDecide("MODIFIED", { ...action, description: modifiedDescription })
              : onDecide("APPROVED")}
            className="text-xs px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
            {mode === "modify" ? "Approve Modified" : "✓ Approve"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── ApprovalHistory ─────────────────────────────────────────────────────────

interface ApprovalRecord {
  id: number; status: string; recommendedAction: { title: string };
  decidedAt?: string; createdAt: string; approverId?: number;
}

export function ApprovalHistory({ records }: { records: ApprovalRecord[] }) {
  const STATUS_STYLE: Record<string, string> = {
    PENDING:  "bg-yellow-100 text-yellow-800",
    APPROVED: "bg-green-100 text-green-800",
    REJECTED: "bg-red-100 text-red-800",
    MODIFIED: "bg-blue-100 text-blue-800",
  };

  return (
    <div>
      <h4 className="font-semibold text-sm text-gray-900 mb-3">Approval History</h4>
      {records.length === 0 && <p className="text-xs text-gray-500">No approvals recorded yet.</p>}
      <div className="space-y-2">
        {records.map((r) => (
          <div key={r.id} className="flex items-center gap-3 text-xs border-b border-gray-100 pb-2">
            <span className={`px-2 py-0.5 rounded-full font-medium ${STATUS_STYLE[r.status] ?? "bg-gray-100 text-gray-700"}`}>{r.status}</span>
            <span className="text-gray-700">{r.recommendedAction.title}</span>
            <span className="text-gray-400 ml-auto">{r.decidedAt ? new Date(r.decidedAt).toLocaleString() : "Pending"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
