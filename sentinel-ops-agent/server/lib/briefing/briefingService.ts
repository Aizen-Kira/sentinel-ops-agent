// lib/briefing/briefingService.ts
// Assembles CISO-level briefings. Exports JSON and HTML email.

import { escapeHtml } from "@shared/html";
import type { BriefingContent } from "@shared/splunkTypes";
import type { EnrichmentResult } from "../agents/investigationTypes";
import type { RiskScore } from "../risk/riskScorer";

export type { BriefingContent };

interface BriefingInput {
  incidentId: number;
  incidentTitle: string;
  incidentUpdatedAt: Date;
  enrichment: EnrichmentResult;
  riskScore: RiskScore;
  approvalStatus: { pending: number; approved: number; rejected: number };
}

async function generateWithLLM(input: BriefingInput): Promise<BriefingContent> {
  const prompt = `You are a CISO briefing a non-technical board of directors. Write a briefing about the following security incident.
Use plain English, no technical jargon. Focus on business impact and recommended decisions.

Incident: ${input.incidentTitle} (#${input.incidentId})
Risk Score: ${input.riskScore.score}/100
Summary: ${input.enrichment.summary}
Attack Vector: ${input.enrichment.attackVector}
Affected Assets: ${input.enrichment.affectedAssets.join(", ")}
Requires Escalation: ${input.enrichment.requiresEscalation}
MITRE Techniques: ${input.enrichment.mitreAttackIds.join(", ")}
IOCs Found: ${input.enrichment.iocs.length}
Approvals: ${input.approvalStatus.pending} pending, ${input.approvalStatus.approved} approved

Return ONLY a JSON object matching this structure exactly (no markdown backticks):
{
  "executiveSummary": "2-3 sentence overview for board",
  "businessImpact": "What this means for the business in plain English",
  "riskOverview": { "score": ${input.riskScore.score}, "label": "Critical|High|Medium|Low", "rationale": "plain English rationale" },
  "timelineHighlights": [{ "timestamp": "ISO string", "description": "what happened", "significance": "why it matters" }],
  "recommendedActions": [{ "title": "action", "urgency": "immediate|within24h|planned", "ownerRole": "who should do this" }],
  "currentStatus": "one sentence current state",
  "nextSteps": "what happens next",
  "generatedAt": "${new Date().toISOString()}",
  "isStale": false
}`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": process.env.ANTHROPIC_API_KEY ?? "",
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 2000,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!response.ok) throw new Error(`Briefing LLM failed: ${response.status}`);
  const data = await response.json() as { content: Array<{ type: string; text: string }> };
  const text = data.content.find((c) => c.type === "text")?.text ?? "";

  try {
    return JSON.parse(text) as BriefingContent;
  } catch {
    throw new Error(`Malformed briefing output: ${text.slice(0, 200)}`);
  }
}

function mockBriefing(input: BriefingInput): BriefingContent {
  const label = input.riskScore.score >= 76 ? "Critical" : input.riskScore.score >= 51 ? "High" : "Medium";
  return {
    executiveSummary: `[MOCK] A serious cybersecurity incident (Incident #${input.incidentId}) has been detected affecting our network infrastructure. The attack appears to be a targeted ransomware operation that has compromised multiple systems. Our security team is actively responding.`,
    businessImpact: "File servers and workstations may be temporarily unavailable. Customer data appears unaffected at this time, but business operations on affected systems should be suspended until containment is confirmed.",
    riskOverview: { score: input.riskScore.score, label, rationale: input.riskScore.llmRationale ?? "High-risk incident requiring immediate executive attention." },
    timelineHighlights: [
      { timestamp: new Date(Date.now() - 4 * 3600_000).toISOString(), description: "Initial suspicious activity detected", significance: "First signs of unauthorized access" },
      { timestamp: new Date(Date.now() - 2 * 3600_000).toISOString(), description: "Lateral movement across internal network", significance: "Threat actor gained broader access" },
      { timestamp: new Date(Date.now() - 1 * 3600_000).toISOString(), description: "File encryption activity detected", significance: "Active ransomware deployment confirmed" },
    ],
    recommendedActions: [
      { title: "Authorize isolation of compromised systems", urgency: "immediate", ownerRole: "CTO / CISO" },
      { title: "Notify cyber insurance carrier", urgency: "within24h", ownerRole: "CFO / Legal" },
      { title: "Engage external incident response firm", urgency: "within24h", ownerRole: "CISO" },
      { title: "Prepare stakeholder communications", urgency: "planned", ownerRole: "Communications / Legal" },
    ],
    currentStatus: "Active incident in progress. Containment measures underway pending executive approval.",
    nextSteps: "Awaiting board approval on containment actions. Full forensic investigation to begin within 24 hours.",
    generatedAt: new Date().toISOString(),
    isStale: false,
  };
}

export async function generateBriefing(input: BriefingInput): Promise<BriefingContent> {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn("[BriefingService] ANTHROPIC_API_KEY not set - using mock briefing");
    return mockBriefing(input);
  }
  try {
    return await generateWithLLM(input);
  } catch (err) {
    console.warn("[BriefingService] LLM failed, using mock:", err);
    return mockBriefing(input);
  }
}

const urgencyLabel = (urgency: BriefingContent["recommendedActions"][number]["urgency"]) =>
  urgency === "immediate" ? "IMMEDIATE" : urgency === "within24h" ? "Within 24h" : "Planned";

const urgencyColor = (urgency: BriefingContent["recommendedActions"][number]["urgency"]) =>
  urgency === "immediate" ? "#dc2626" : urgency === "within24h" ? "#ea580c" : "#374151";

export function renderHtmlEmail(briefing: BriefingContent, incidentId: number): string {
  const { score, label } = briefing.riskOverview;
  const normalizedScore = Number.isFinite(score) ? score : 0;
  const scoreColor = normalizedScore >= 76 ? "#dc2626" : normalizedScore >= 51 ? "#ea580c" : normalizedScore >= 26 ? "#d97706" : "#16a34a";
  const generatedAt = new Date(briefing.generatedAt).toLocaleString();
  const actionRows = briefing.recommendedActions.map((action, index) => `
          <tr style="border-bottom:1px solid #f1f5f9;background:${index % 2 === 0 ? "white" : "#fafafa"};">
            <td style="padding:10px 12px;font-size:13px;">${escapeHtml(action.title)}</td>
            <td style="padding:10px 12px;font-size:12px;color:${urgencyColor(action.urgency)};font-weight:600;">${urgencyLabel(action.urgency)}</td>
            <td style="padding:10px 12px;font-size:13px;color:#64748b;">${escapeHtml(action.ownerRole)}</td>
          </tr>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Incident Briefing #${incidentId}</title></head>
<body style="font-family: Georgia, serif; max-width: 640px; margin: 0 auto; padding: 20px; color: #1a1a1a; background: #f9f9f9;">
  <div style="background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <div style="background: #0f172a; color: white; padding: 24px 32px;">
      <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 2px; opacity: 0.7; margin-bottom: 8px;">CONFIDENTIAL - EXECUTIVE BRIEFING</div>
      <h1 style="margin: 0; font-size: 22px; font-weight: 600;">Security Incident #${incidentId}</h1>
      <div style="margin-top: 8px; font-size: 13px; opacity: 0.7;">Generated ${escapeHtml(generatedAt)}</div>
    </div>
    ${briefing.isStale ? `<div style="background:#fef3c7;color:#92400e;padding:10px 32px;font-size:13px;">Warning: This briefing may be outdated. The incident has been updated since this was generated.</div>` : ""}
    <div style="padding: 32px;">
      <div style="display:inline-block;background:${scoreColor}20;color:${scoreColor};border:2px solid ${scoreColor};border-radius:8px;padding:8px 20px;font-size:24px;font-weight:700;margin-bottom:24px;">${escapeHtml(normalizedScore)} - ${escapeHtml(label)}</div>
      <h2 style="font-size:16px;color:#0f172a;margin:0 0 8px;">Situation Summary</h2>
      <p style="color:#374151;line-height:1.6;margin:0 0 24px;">${escapeHtml(briefing.executiveSummary)}</p>
      <h2 style="font-size:16px;color:#0f172a;margin:0 0 8px;">Business Impact</h2>
      <p style="color:#374151;line-height:1.6;margin:0 0 24px;">${escapeHtml(briefing.businessImpact)}</p>
      <h2 style="font-size:16px;color:#0f172a;margin:0 0 12px;">Decisions Required</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
        <thead><tr style="background:#f1f5f9;"><th style="text-align:left;padding:8px 12px;font-size:12px;color:#64748b;">ACTION</th><th style="text-align:left;padding:8px 12px;font-size:12px;color:#64748b;">URGENCY</th><th style="text-align:left;padding:8px 12px;font-size:12px;color:#64748b;">OWNER</th></tr></thead>
        <tbody>
          ${actionRows}
        </tbody>
      </table>
      <h2 style="font-size:16px;color:#0f172a;margin:0 0 8px;">Next Steps</h2>
      <p style="color:#374151;line-height:1.6;margin:0;">${escapeHtml(briefing.nextSteps)}</p>
    </div>
    <div style="background:#f8fafc;padding:16px 32px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;">
      This briefing was auto-generated by Sentinel Ops Platform. For questions contact your CISO.
    </div>
  </div>
</body></html>`;
}
