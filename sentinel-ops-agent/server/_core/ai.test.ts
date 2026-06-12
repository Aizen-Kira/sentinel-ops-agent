import { afterEach, describe, expect, it, vi } from "vitest";
import type { Alert } from "../../drizzle/schema";
import { generateInvestigationAnalysis, parseExecutiveBriefRewrite } from "./ai";
import { ENV } from "./env";

const baseAlert: Alert = {
  id: 1,
  eventId: "EVT-1",
  severity: "critical",
  title: "Suspicious Failed Login Attempts",
  description: "Repeated login failures detected",
  source: "EXTERNAL-IP",
  target: "WEB-SERVER-01",
  eventType: "failed_login",
  rawData: { scenarioId: "SCN-1" },
  status: "open",
  assignedTo: null,
  incidentId: null,
  createdAt: new Date("2026-04-09T00:00:00.000Z"),
  updatedAt: new Date("2026-04-09T00:00:00.000Z"),
};

const previousEnv = {
  aiProvider: ENV.aiProvider,
  ollamaModel: ENV.ollamaModel,
  ollamaBaseUrl: ENV.ollamaBaseUrl,
  forgeApiKey: ENV.forgeApiKey,
  forgeApiUrl: ENV.forgeApiUrl,
  cloudModel: ENV.cloudModel,
};

afterEach(() => {
  ENV.aiProvider = previousEnv.aiProvider;
  ENV.ollamaModel = previousEnv.ollamaModel;
  ENV.ollamaBaseUrl = previousEnv.ollamaBaseUrl;
  ENV.forgeApiKey = previousEnv.forgeApiKey;
  ENV.forgeApiUrl = previousEnv.forgeApiUrl;
  ENV.cloudModel = previousEnv.cloudModel;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("local AI adapter", () => {
  it("falls back to heuristic investigation analysis when no provider is configured", async () => {
    ENV.aiProvider = "auto";
    ENV.ollamaModel = "";
    ENV.forgeApiKey = "";

    const result = await generateInvestigationAnalysis({
      alerts: [baseAlert],
      alertContext: "Event EVT-1: Suspicious Failed Login Attempts",
      correlationContext: "Correlated incident context: Credential access activity",
    });

    expect(result.provider).toBe("heuristic");
    expect(result.model).toBe("sentinel-playbooks-v2");
    expect(result.text).toContain("Conclusion:");
    expect(result.playbook.playbookId).toBe("credential_abuse");
  });

  it("parses AI executive rewrites from labeled text", () => {
    const parsed = parseExecutiveBriefRewrite(
      [
        "HEADLINE: Critical risk remains centered on customer-facing systems.",
        "SUMMARY: One active incident is driving elevated business risk.",
        "URGENT_DECISION: Approve containment on the exposed asset path.",
        "KEY_POINT: Customer-facing systems remain in scope.",
        "KEY_POINT: Confidence is high based on correlated evidence.",
        "KEY_POINT: Containment is time-sensitive.",
        "WATCH_ITEM: Monitor for spread into identity systems.",
        "WATCH_ITEM: Monitor for service degradation.",
        "WATCH_ITEM: Prepare stakeholder communications if impact rises.",
      ].join("\n")
    );

    expect(parsed.isUsable).toBe(true);
    expect(parsed.keyPoints).toHaveLength(3);
    expect(parsed.watchItems).toHaveLength(3);
  });
});
