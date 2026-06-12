import type { Alert } from "../../drizzle/schema";
import type { ExecutiveBrief } from "../briefing";
import {
  EVENT_INTELLIGENCE,
  buildIncidentDraft,
  parseStringArray,
} from "@shared/correlation";
import {
  extractTextFromInvokeResult,
  invokeLLM,
  invokeLLMWithProvider,
  isOllamaPrimaryProvider,
  type LLMProvider,
} from "./llm";

export type AIExecutionSource = LLMProvider | "heuristic";
export type PlaybookId =
  | "credential_abuse"
  | "web_compromise"
  | "malware_pivot"
  | "insider_misuse"
  | "cloud_identity_abuse";
export type LocalAnalystStageName =
  | "evidence_extraction"
  | "hypothesis"
  | "missing_data"
  | "recommended_actions";

export type PlaybookArtifact = {
  playbookId: PlaybookId;
  confidenceDrivers: string[];
  missingEvidence: string[];
  containmentSteps: string[];
  summary: string;
};

export type LocalAnalystStageArtifact = {
  stage: LocalAnalystStageName;
  result: Record<string, unknown>;
  provider: "ollama";
  model: string;
};

export type GeneratedText = {
  text: string;
  provider: AIExecutionSource;
  model: string;
  usedFallback: boolean;
  localMode: boolean;
  playbook: PlaybookArtifact;
  stages: LocalAnalystStageArtifact[];
};

const HEURISTIC_MODEL = "sentinel-playbooks-v2";
const LOCAL_STAGE_ORDER: LocalAnalystStageName[] = [
  "evidence_extraction",
  "hypothesis",
  "missing_data",
  "recommended_actions",
];

const unique = (values: string[]) => Array.from(new Set(values));

const safeJoin = (values: string[], fallback: string) =>
  values.length > 0 ? values.join(", ") : fallback;

const normalizeStringArray = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];

const normalizeString = (value: unknown, fallback = ""): string =>
  typeof value === "string" && value.trim().length > 0 ? value.trim() : fallback;

const extractJsonObject = (text: string): Record<string, unknown> => {
  const fenced = text.match(/```json\s*([\s\S]*?)```/i)?.[1];
  const candidate = fenced ?? text.match(/\{[\s\S]*\}/)?.[0] ?? text;
  const parsed = JSON.parse(candidate);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Expected a JSON object");
  }
  return parsed as Record<string, unknown>;
};

const buildSharedSignals = (alerts: Alert[]) => {
  const draft = buildIncidentDraft(alerts);
  const eventFamilies = unique(
    alerts.map(
      (alert) => EVENT_INTELLIGENCE[alert.eventType]?.family ?? "suspicious activity"
    )
  );
  const tactics = parseStringArray(draft.mitreAttackTactics);
  const assets = parseStringArray(draft.affectedAssets);
  const eventTypes = unique(alerts.map((alert) => alert.eventType));
  return {
    draft,
    eventFamilies,
    tactics,
    assets,
    eventTypes,
  };
};

const classifyPlaybook = (alerts: Alert[]): PlaybookId => {
  const { eventTypes } = buildSharedSignals(alerts);
  const loweredEndpoints = alerts
    .flatMap((alert) => [alert.source, alert.target ?? ""])
    .map((value) => value.toLowerCase());

  if (
    eventTypes.includes("failed_login") ||
    eventTypes.includes("privilege_escalation")
  ) {
    return "credential_abuse";
  }

  if (eventTypes.includes("sql_injection")) {
    return "web_compromise";
  }

  if (eventTypes.includes("malware_detected")) {
    return "malware_pivot";
  }

  if (
    loweredEndpoints.some((value) =>
      ["cloud", "aws", "azure", "gcp", "okta", "entra"].some((needle) =>
        value.includes(needle)
      )
    )
  ) {
    return "cloud_identity_abuse";
  }

  if (eventTypes.includes("data_exfiltration")) {
    return "insider_misuse";
  }

  return "credential_abuse";
};

const buildPlaybookArtifact = (
  playbookId: PlaybookId,
  alerts: Alert[]
): PlaybookArtifact => {
  const { draft, eventFamilies, tactics, assets, eventTypes } = buildSharedSignals(alerts);
  const severeAlerts = alerts.filter(
    (alert) => alert.severity === "critical" || alert.severity === "high"
  );

  const registry: Record<PlaybookId, () => PlaybookArtifact> = {
    credential_abuse: () => ({
      playbookId,
      confidenceDrivers: [
        `Authentication and privilege signals align with ${safeJoin(eventTypes, "credential abuse")} activity.`,
        `${severeAlerts.length} high-priority alert${severeAlerts.length === 1 ? "" : "s"} indicate active account misuse.`,
      ],
      missingEvidence: [
        "Validated account ownership for the compromised identity.",
        "Authentication logs showing MFA outcomes and impossible-travel checks.",
      ],
      containmentSteps: [
        `Reset and lock the suspected account set touching ${safeJoin(assets.slice(0, 3), "the affected assets")}.`,
        "Preserve authentication, privilege escalation, and session logs before cleanup.",
      ],
      summary: `${draft.rootCause} The likely attacker path starts with stolen credentials and expands through privileged access.`,
    }),
    web_compromise: () => ({
      playbookId,
      confidenceDrivers: [
        "The sequence begins at an internet-facing application tier.",
        `Observed tactics align with ${safeJoin(tactics.slice(0, 3), "initial access, execution, and lateral movement")}.`,
      ],
      missingEvidence: [
        "Web server access logs and WAF traces for the injection window.",
        "Application deployment or config drift records around the affected service.",
      ],
      containmentSteps: [
        "Isolate the exposed application tier and rotate app/database secrets.",
        "Capture memory, web access logs, and recent deployment artifacts for root-cause validation.",
      ],
      summary: `${draft.rootCause} The intrusion likely started at the web edge and then moved inward toward protected data.`,
    }),
    malware_pivot: () => ({
      playbookId,
      confidenceDrivers: [
        "Malware detection is followed by internal movement and privilege abuse.",
        `The incident affects ${safeJoin(assets.slice(0, 4), "multiple internal assets")} in a staged progression.`,
      ],
      missingEvidence: [
        "Endpoint process tree and hash telemetry from the initial host.",
        "EDR isolation history and persistence findings for the compromised endpoint.",
      ],
      containmentSteps: [
        "Isolate the original endpoint and adjacent pivot targets immediately.",
        "Collect binaries, persistence artifacts, and lateral movement traces before remediation.",
      ],
      summary: `${draft.rootCause} Malware activity appears to be the initial foothold before identity or directory abuse.`,
    }),
    insider_misuse: () => ({
      playbookId,
      confidenceDrivers: [
        "The pattern emphasizes access and data movement more than exploit telemetry.",
        `Event families suggest ${safeJoin(eventFamilies, "anomalous internal activity")} rather than perimeter-first compromise.`,
      ],
      missingEvidence: [
        "HR or identity context validating expected user behavior.",
        "File access and data movement approvals for the assets in scope.",
      ],
      containmentSteps: [
        "Review account entitlements and suspend abnormal bulk access until cleared.",
        "Preserve audit logs, file access history, and approval trails for the data set.",
      ],
      summary: `${draft.rootCause} The available evidence is consistent with misuse of legitimate access or an internal account.`,
    }),
    cloud_identity_abuse: () => ({
      playbookId,
      confidenceDrivers: [
        "Identity-centric signals indicate access abuse in a cloud control plane or IdP path.",
        `The incident blends ${safeJoin(eventTypes, "identity events")} with privilege change indicators.`,
      ],
      missingEvidence: [
        "Cloud audit trail entries for role, token, or policy changes.",
        "Identity provider session telemetry and conditional access decisions.",
      ],
      containmentSteps: [
        "Revoke active sessions, rotate tokens, and review recent role grants.",
        "Snapshot cloud audit logs and identity policy changes before rollback.",
      ],
      summary: `${draft.rootCause} The available signal looks like cloud identity abuse rather than host-first compromise.`,
    }),
  };

  return registry[playbookId]();
};

const buildPlaybookFallback = (alerts: Alert[], playbook: PlaybookArtifact) => {
  if (alerts.length === 0) {
    return [
      "1. No alert evidence was available for analysis.",
      "2. Re-run the investigation after selecting at least one alert with source and target context.",
      "Conclusion: Investigation could not start because no alerts were provided. Confidence 15.",
    ].join("\n");
  }

  const { draft, assets, eventFamilies } = buildSharedSignals(alerts);

  return [
    `1. Selected playbook: ${playbook.playbookId}. The alert set clusters into a ${draft.severity} incident titled "${draft.title}".`,
    `2. Confidence drivers: ${safeJoin(playbook.confidenceDrivers, "correlated alert progression and asset overlap")}.`,
    `3. Missing evidence: ${safeJoin(playbook.missingEvidence, "additional telemetry is still required")}.`,
    `4. Containment actions: ${safeJoin(playbook.containmentSteps, "isolate affected assets and preserve evidence")}.`,
    `Conclusion: ${playbook.summary} Prioritize ${safeJoin(assets.slice(0, 3), "the affected assets")} and validate ${safeJoin(eventFamilies, "the suspected attack chain")}. Confidence ${Math.round(
      draft.confidenceScore * 100
    )}.`,
  ].join("\n");
};

const stagePrompt = (stage: LocalAnalystStageName, options: {
  playbook: PlaybookArtifact;
  alertContext: string;
  correlationContext: string;
  priorStageContext: string;
}) => {
  const base = [
    `Selected playbook: ${options.playbook.playbookId}`,
    `Playbook summary: ${options.playbook.summary}`,
    "",
    "Alert context:",
    options.alertContext,
    "",
    "Correlation context:",
    options.correlationContext,
    "",
    options.priorStageContext,
  ]
    .filter((value) => value.trim().length > 0)
    .join("\n");

  const prompts: Record<LocalAnalystStageName, string> = {
    evidence_extraction: [
      "Return valid JSON only.",
      'Schema: {"findings": string[], "entities": string[], "signals": string[]}',
      base,
      "Extract only grounded evidence from the supplied alerts.",
    ].join("\n"),
    hypothesis: [
      "Return valid JSON only.",
      'Schema: {"hypothesis": string, "rationale": string[], "playbook_alignment": string}',
      base,
      "State the most likely attack hypothesis and why it fits the evidence.",
    ].join("\n"),
    missing_data: [
      "Return valid JSON only.",
      'Schema: {"missing_data": string[], "validation_steps": string[]}',
      base,
      "List the missing data required to confirm or disprove the hypothesis.",
    ].join("\n"),
    recommended_actions: [
      "Return valid JSON only.",
      'Schema: {"recommended_actions": string[], "priority": string}',
      base,
      "Recommend immediate analyst actions grounded in the available evidence.",
    ].join("\n"),
  };

  return prompts[stage];
};

const validateLocalStageResult = (
  stage: LocalAnalystStageName,
  input: Record<string, unknown>
): Record<string, unknown> => {
  switch (stage) {
    case "evidence_extraction":
      return {
        findings: normalizeStringArray(input.findings),
        entities: normalizeStringArray(input.entities),
        signals: normalizeStringArray(input.signals),
      };
    case "hypothesis":
      return {
        hypothesis: normalizeString(input.hypothesis, "Hypothesis unavailable."),
        rationale: normalizeStringArray(input.rationale),
        playbook_alignment: normalizeString(
          input.playbook_alignment,
          "Playbook alignment not stated."
        ),
      };
    case "missing_data":
      return {
        missing_data: normalizeStringArray(input.missing_data),
        validation_steps: normalizeStringArray(input.validation_steps),
      };
    case "recommended_actions":
      return {
        recommended_actions: normalizeStringArray(input.recommended_actions),
        priority: normalizeString(input.priority, "high"),
      };
  }
};

const buildLocalAnalystConclusion = (
  alerts: Alert[],
  playbook: PlaybookArtifact,
  stages: LocalAnalystStageArtifact[]
) => {
  const { draft, assets } = buildSharedSignals(alerts);
  const stageMap = new Map(stages.map((stage) => [stage.stage, stage.result]));
  const evidence = stageMap.get("evidence_extraction") ?? {};
  const hypothesis = stageMap.get("hypothesis") ?? {};
  const missingData = stageMap.get("missing_data") ?? {};
  const actions = stageMap.get("recommended_actions") ?? {};

  return [
    `1. Evidence extraction surfaced ${safeJoin(normalizeStringArray(evidence.findings), "limited confirmed findings")} across ${safeJoin(assets.slice(0, 4), "multiple assets")}.`,
    `2. Working hypothesis: ${normalizeString(hypothesis.hypothesis, playbook.summary)}`,
    `3. Missing data still needed: ${safeJoin(normalizeStringArray(missingData.missing_data), "additional validation telemetry")}.`,
    `4. Recommended actions: ${safeJoin(normalizeStringArray(actions.recommended_actions), safeJoin(playbook.containmentSteps, "containment actions"))}.`,
    `Conclusion: ${playbook.summary} Local Analyst Mode prioritized ${safeJoin(
      playbook.containmentSteps.slice(0, 2),
      "containment and evidence preservation"
    )}. Confidence ${Math.round(draft.confidenceScore * 100)}.`,
  ].join("\n");
};

const runLocalAnalystStages = async (options: {
  alerts: Alert[];
  alertContext: string;
  correlationContext: string;
  playbook: PlaybookArtifact;
  onStage?: (
    stage: LocalAnalystStageArtifact,
    index: number,
    totalStages: number
  ) => Promise<void> | void;
}) => {
  const stages: LocalAnalystStageArtifact[] = [];
  let priorStageContext = "";

  for (let index = 0; index < LOCAL_STAGE_ORDER.length; index += 1) {
    const stageName = LOCAL_STAGE_ORDER[index];
    const response = await invokeLLMWithProvider("ollama", {
      messages: [
        {
          role: "system",
          content:
            "You are Sentinel Local Analyst Mode. Stay strictly grounded in the supplied alerts, return valid JSON only, and do not invent tools or external evidence.",
        },
        {
          role: "user",
          content: stagePrompt(stageName, {
            playbook: options.playbook,
            alertContext: options.alertContext,
            correlationContext: options.correlationContext,
            priorStageContext,
          }),
        },
      ],
      maxTokens: 900,
    });

    const parsed = validateLocalStageResult(
      stageName,
      extractJsonObject(extractTextFromInvokeResult(response))
    );

    const artifact: LocalAnalystStageArtifact = {
      stage: stageName,
      result: parsed,
      provider: "ollama",
      model: response.model,
    };

    stages.push(artifact);
    priorStageContext = [
      priorStageContext,
      `${stageName}:`,
      JSON.stringify(parsed, null, 2),
    ]
      .filter(Boolean)
      .join("\n");

    await options.onStage?.(artifact, index + 1, LOCAL_STAGE_ORDER.length);
  }

  return stages;
};

const findLineValue = (text: string, label: string) => {
  const match = text.match(new RegExp(`^${label}:\\s*(.+)$`, "im"));
  return match?.[1]?.trim() ?? "";
};

const collectPrefixedLines = (text: string, prefix: string) =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith(`${prefix}:`))
    .map((line) => line.slice(prefix.length + 1).trim())
    .filter((line) => line.length > 0);

export const parseExecutiveBriefRewrite = (text: string) => {
  const headline = findLineValue(text, "HEADLINE");
  const summary = findLineValue(text, "SUMMARY");
  const urgentDecision = findLineValue(text, "URGENT_DECISION");
  const keyPoints = collectPrefixedLines(text, "KEY_POINT");
  const watchItems = collectPrefixedLines(text, "WATCH_ITEM");

  return {
    headline,
    summary,
    urgentDecision,
    keyPoints,
    watchItems,
    isUsable:
      headline.length > 0 &&
      summary.length > 0 &&
      urgentDecision.length > 0 &&
      keyPoints.length > 0 &&
      watchItems.length > 0,
  };
};

export async function generateInvestigationAnalysis(options: {
  alerts: Alert[];
  alertContext: string;
  correlationContext: string;
  onStage?: (
    stage: LocalAnalystStageArtifact,
    index: number,
    totalStages: number
  ) => Promise<void> | void;
}): Promise<GeneratedText> {
  const playbookId = classifyPlaybook(options.alerts);
  const playbook = buildPlaybookArtifact(playbookId, options.alerts);

  if (isOllamaPrimaryProvider()) {
    try {
      const stages = await runLocalAnalystStages({
        ...options,
        playbook,
      });
      const model = stages[stages.length - 1]?.model ?? "ollama";
      return {
        text: buildLocalAnalystConclusion(options.alerts, playbook, stages),
        provider: "ollama",
        model,
        usedFallback: false,
        localMode: true,
        playbook,
        stages,
      };
    } catch {
      return {
        text: buildPlaybookFallback(options.alerts, playbook),
        provider: "heuristic",
        model: HEURISTIC_MODEL,
        usedFallback: true,
        localMode: false,
        playbook,
        stages: [],
      };
    }
  }

  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content:
            "You are a security operations center analyst. Analyze correlated security alerts, follow the supplied Sentinel playbook, explain the likely attack progression in concise numbered steps, and end with a single conclusion line that includes 'Confidence <0-100>'.",
        },
        {
          role: "user",
          content: [
            "Investigate these security alerts and provide reasoning steps.",
            "",
            `Selected playbook: ${playbook.playbookId}`,
            `Confidence drivers: ${playbook.confidenceDrivers.join(" | ")}`,
            `Missing evidence: ${playbook.missingEvidence.join(" | ")}`,
            `Containment steps: ${playbook.containmentSteps.join(" | ")}`,
            "",
            options.alertContext,
            "",
            options.correlationContext,
            "",
            "Return 4-6 numbered steps followed by one final conclusion line.",
          ].join("\n"),
        },
      ],
      maxTokens: 1400,
    });

    const text = extractTextFromInvokeResult(response).trim();
    if (text.length === 0) {
      throw new Error("LLM returned an empty investigation analysis");
    }

    return {
      text,
      provider: response.provider,
      model: response.model,
      usedFallback: false,
      localMode: false,
      playbook,
      stages: [],
    };
  } catch {
    return {
      text: buildPlaybookFallback(options.alerts, playbook),
      provider: "heuristic",
      model: HEURISTIC_MODEL,
      usedFallback: true,
      localMode: false,
      playbook,
      stages: [],
    };
  }
}

export async function enhanceExecutiveBriefWithAI(
  brief: ExecutiveBrief
): Promise<ExecutiveBrief> {
  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content:
            "You are preparing a concise cyber-risk executive brief for a startup CEO. Keep the language direct, business-oriented, and grounded in the supplied facts. Do not invent new incidents or numbers.",
        },
        {
          role: "user",
          content: [
            "Rewrite this executive brief into sharper CEO language.",
            "Return exactly these labels on separate lines:",
            "HEADLINE:",
            "SUMMARY:",
            "URGENT_DECISION:",
            "KEY_POINT: (repeat 3 times)",
            "WATCH_ITEM: (repeat 3 times)",
            "",
            JSON.stringify(
              {
                riskLevel: brief.riskLevel,
                activeIncidentCount: brief.activeIncidentCount,
                criticalAlertCount: brief.criticalAlertCount,
                affectedAssetCount: brief.affectedAssetCount,
                businessRiskScore: brief.businessRiskScore,
                headline: brief.headline,
                summary: brief.summary,
                urgentDecision: brief.urgentDecision,
                keyPoints: brief.keyPoints,
                watchItems: brief.watchItems,
                topIncidents: brief.topIncidents.map((incident) => ({
                  incidentId: incident.incidentId,
                  title: incident.title,
                  severity: incident.severity,
                  status: incident.status,
                  confidenceScore: incident.confidenceScore,
                  businessImpactScore: incident.businessImpactScore,
                  customerImpact: incident.customerImpact,
                  recommendedAction: incident.recommendedAction,
                })),
              },
              null,
              2
            ),
          ].join("\n"),
        },
      ],
      maxTokens: 900,
    });

    const rewritten = parseExecutiveBriefRewrite(
      extractTextFromInvokeResult(response)
    );

    if (!rewritten.isUsable) {
      throw new Error("AI executive brief rewrite was incomplete");
    }

    return {
      ...brief,
      headline: rewritten.headline,
      summary: rewritten.summary,
      urgentDecision: rewritten.urgentDecision,
      keyPoints: rewritten.keyPoints.slice(0, 3),
      watchItems: rewritten.watchItems.slice(0, 3),
      generatedBy: {
        mode: "ai-assisted",
        provider: response.provider,
        model: response.model,
      },
    };
  } catch {
    return {
      ...brief,
      generatedBy: {
        mode: "rule-based",
        provider: "heuristic",
        model: HEURISTIC_MODEL,
      },
    };
  }
}
