// tests/splunk.test.ts
// Unit tests: HEC batching logic + search polling loop

import { describe, it, expect, vi, beforeEach } from "vitest";
import { SplunkHecClient } from "./lib/splunk/splunkHec";
import { SplunkSearchClient } from "./lib/splunk/splunkSearch";

// ─── HEC Tests ────────────────────────────────────────────────────────────────

describe("SplunkHecClient — batching", () => {
  beforeEach(() => {
    // Remove HEC URL to force mock mode
    delete process.env.SPLUNK_HEC_URL;
  });

  it("queues events and flushes when batch size is reached", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const client = new SplunkHecClient({ maxBatchSize: 3, flushIntervalMs: 60_000, maxRetries: 0 });

    await client.send({ event: { msg: "evt1" } });
    await client.send({ event: { msg: "evt2" } });
    // Third send should trigger auto-flush
    await client.send({ event: { msg: "evt3" } });

    // Mock mode flushes to console.log
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("Flushing 3 events"),
      expect.any(Array)
    );
    consoleSpy.mockRestore();
  });

  it("sendBatch flushes immediately when over threshold", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const client = new SplunkHecClient({ maxBatchSize: 2, flushIntervalMs: 60_000, maxRetries: 0 });

    await client.sendBatch([
      { event: { id: 1 } },
      { event: { id: 2 } },
      { event: { id: 3 } },
    ]);

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it("manual flush sends all queued events", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const client = new SplunkHecClient({ maxBatchSize: 100, flushIntervalMs: 60_000, maxRetries: 0 });

    await client.send({ event: { msg: "a" } });
    await client.send({ event: { msg: "b" } });
    await client.flush();

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it("does nothing on flush when queue is empty", async () => {
    const client = new SplunkHecClient({ maxBatchSize: 10, flushIntervalMs: 60_000, maxRetries: 0 });
    await expect(client.flush()).resolves.toBeUndefined();
  });
});

// ─── Search Tests ──────────────────────────────────────────────────────────────

describe("SplunkSearchClient — mock mode", () => {
  beforeEach(() => {
    delete process.env.SPLUNK_HEC_URL;
  });

  it("returns mock results without network call", async () => {
    const client = new SplunkSearchClient();
    const result = await client.search("index=main | head 10");
    expect(result.rows).toBeInstanceOf(Array);
    expect(result.rows.length).toBeGreaterThan(0);
    expect(result.fields).toContain("_time");
  });

  it("healthcheck returns mock mode status", async () => {
    const client = new SplunkSearchClient();
    const health = await client.healthcheck();
    expect(health.ok).toBe(true);
    expect(health.mode).toBe("mock");
  });
});

// ─── Integration: HEC retry logic simulation ─────────────────────────────────

describe("SplunkHecClient — retry logic", () => {
  it("retries on failure and succeeds on second attempt", async () => {
    process.env.SPLUNK_HEC_URL = "https://mock-splunk.test/collector";
    process.env.SPLUNK_HEC_TOKEN = "test-token";

    let callCount = 0;
    vi.stubGlobal("fetch", vi.fn(async () => {
      callCount++;
      if (callCount < 2) throw new Error("Network error");
      return { ok: true, text: async () => "" };
    }));

    const client = new SplunkHecClient({ maxBatchSize: 10, flushIntervalMs: 60_000, maxRetries: 3 });
    await client.send({ event: { test: true } });
    await client.flush();

    expect(callCount).toBe(2);
    vi.unstubAllGlobals();
    delete process.env.SPLUNK_HEC_URL;
    delete process.env.SPLUNK_HEC_TOKEN;
  });
});
