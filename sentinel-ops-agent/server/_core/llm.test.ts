import { afterEach, describe, expect, it, vi } from "vitest";
import { ENV } from "./env";
import { extractTextFromInvokeResult, invokeLLM } from "./llm";

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

describe("LLM provider adapter", () => {
  it("uses Ollama when configured", async () => {
    ENV.aiProvider = "ollama";
    ENV.ollamaModel = "llama3.2";
    ENV.ollamaBaseUrl = "http://127.0.0.1:11434";

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          model: "llama3.2",
          created_at: "2026-04-09T00:00:00.000Z",
          done_reason: "stop",
          message: {
            role: "assistant",
            content: "1. Local analysis.\nConclusion: Contain now. Confidence 88.",
          },
          prompt_eval_count: 42,
          eval_count: 18,
        }),
      })
    );

    const result = await invokeLLM({
      messages: [
        { role: "system", content: "You are a SOC analyst." },
        { role: "user", content: "Analyze this incident." },
      ],
    });

    expect(result.provider).toBe("ollama");
    expect(result.model).toBe("llama3.2");
    expect(extractTextFromInvokeResult(result)).toContain("Confidence 88");
  });

  it("falls back to forge when auto mode cannot reach Ollama", async () => {
    ENV.aiProvider = "auto";
    ENV.ollamaModel = "llama3.2";
    ENV.ollamaBaseUrl = "http://127.0.0.1:11434";
    ENV.forgeApiKey = "test-key";
    ENV.cloudModel = "gemini-2.5-flash";

    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("connect ECONNREFUSED"))
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: "forge-1",
          created: 1712620800,
          model: "gemini-2.5-flash",
          choices: [
            {
              index: 0,
              message: {
                role: "assistant",
                content: "1. Cloud fallback.\nConclusion: Investigate further. Confidence 72.",
              },
              finish_reason: "stop",
            },
          ],
          usage: {
            prompt_tokens: 100,
            completion_tokens: 20,
            total_tokens: 120,
          },
        }),
      });
    vi.stubGlobal("fetch", fetchMock);

    const result = await invokeLLM({
      messages: [
        { role: "system", content: "You are a SOC analyst." },
        { role: "user", content: "Analyze this incident." },
      ],
    });

    expect(result.provider).toBe("forge");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(extractTextFromInvokeResult(result)).toContain("Confidence 72");
  });
});
