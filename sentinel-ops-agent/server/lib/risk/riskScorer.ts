// lib/risk/riskScorer.ts
// Weighted formula + LLM rationale. Falls back to formula-only if LLM fails.

export interface RiskFactors {
  severity: number;         // 0–100
  frequency: number;        // 0–100
  assetCriticality: number; // 0–100
}

export interface RiskScore {
  score: number; // 0–100 integer, formula-derived
  severityFactor: number;
  frequencyFactor: number;
  assetCriticalityFactor: number;
  llmRationale: string | null;
  scoringMethod: "formula+llm" | "formula-only";
}

function deterministicScore(factors: RiskFactors): number {
  const raw = factors.severity * 0.4 + factors.frequency * 0.3 + factors.assetCriticality * 0.3;
  return Math.min(100, Math.max(0, Math.round(raw)));
}

async function getLLMRationale(incidentId: number, factors: RiskFactors, score: number): Promise<string> {
  const prompt = `You are a cybersecurity risk analyst. An incident (#${incidentId}) has been scored ${score}/100 based on:
- Severity: ${factors.severity}/100
- Frequency: ${factors.frequency}/100
- Asset Criticality: ${factors.assetCriticality}/100

Write 2–3 plain-English sentences explaining why this score makes sense for a non-technical executive. No jargon. Focus on business impact.`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": process.env.ANTHROPIC_API_KEY ?? "",
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 300,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!response.ok) throw new Error(`LLM rationale failed: ${response.status}`);
  const data = await response.json() as { content: Array<{ type: string; text: string }> };
  return data.content.find((c) => c.type === "text")?.text ?? "";
}

export async function scoreIncident(incidentId: number, factors: RiskFactors): Promise<RiskScore> {
  const score = deterministicScore(factors);

  if (!process.env.ANTHROPIC_API_KEY) {
    return {
      score,
      severityFactor: factors.severity,
      frequencyFactor: factors.frequency,
      assetCriticalityFactor: factors.assetCriticality,
      llmRationale: `[MOCK] This incident scored ${score}/100 due to ${score >= 75 ? "high" : "moderate"} severity and asset exposure. Immediate review recommended.`,
      scoringMethod: "formula-only",
    };
  }

  try {
    const rationale = await getLLMRationale(incidentId, factors, score);
    return {
      score,
      severityFactor: factors.severity,
      frequencyFactor: factors.frequency,
      assetCriticalityFactor: factors.assetCriticality,
      llmRationale: rationale,
      scoringMethod: "formula+llm",
    };
  } catch (err) {
    console.warn("[RiskScorer] LLM rationale failed, using formula-only:", err);
    return {
      score,
      severityFactor: factors.severity,
      frequencyFactor: factors.frequency,
      assetCriticalityFactor: factors.assetCriticality,
      llmRationale: null,
      scoringMethod: "formula-only",
    };
  }
}

export function getSeverityLabel(score: number): { label: string; color: string } {
  if (score <= 25) return { label: "Low", color: "green" };
  if (score <= 50) return { label: "Medium", color: "amber" };
  if (score <= 75) return { label: "High", color: "orange" };
  return { label: "Critical", color: "red" };
}
