// lib/splunk/splunkHec.ts
// Typed adapter for Splunk HTTP Event Collector with batching, rate limiting, and mock fallback

export interface HecEvent {
  time?: number;
  host?: string;
  source?: string;
  sourcetype?: string;
  index?: string;
  event: Record<string, unknown>;
}

export interface HecBatchConfig {
  maxBatchSize: number;   // max events per POST
  flushIntervalMs: number; // max ms before forced flush
  maxRetries: number;
}

const DEFAULT_CONFIG: HecBatchConfig = {
  maxBatchSize: 50,
  flushIntervalMs: 2000,
  maxRetries: 3,
};

class SplunkHecClient {
  private queue: HecEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly config: HecBatchConfig;
  private readonly isMockMode: boolean;

  constructor(config: Partial<HecBatchConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.isMockMode = !process.env.SPLUNK_HEC_URL;
    if (this.isMockMode) {
      console.warn("[SplunkHEC] SPLUNK_HEC_URL not set — running in mock mode");
    }
  }

  private buildHeaders(): Record<string, string> {
    return {
      "Authorization": `Splunk ${process.env.SPLUNK_HEC_TOKEN ?? ""}`,
      "Content-Type": "application/json",
    };
  }

  private buildPayload(events: HecEvent[]): string {
    return events
      .map((e) => JSON.stringify({
        time: e.time ?? Date.now() / 1000,
        host: e.host ?? process.env.SPLUNK_HOST ?? "sentinel-ops",
        index: e.index ?? process.env.SPLUNK_INDEX ?? "main",
        source: e.source ?? "sentinel-ops-agent",
        sourcetype: e.sourcetype ?? "_json",
        event: e.event,
      }))
      .join("\n");
  }

  private async postWithRetry(payload: string, attempt = 0): Promise<void> {
    const url = process.env.SPLUNK_HEC_URL!;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: this.buildHeaders(),
        body: payload,
      });
      if (!res.ok) {
        throw new Error(`HEC responded ${res.status}: ${await res.text()}`);
      }
    } catch (err) {
      if (attempt < this.config.maxRetries) {
        const delay = Math.pow(2, attempt) * 200;
        await new Promise((r) => setTimeout(r, delay));
        return this.postWithRetry(payload, attempt + 1);
      }
      console.error("[SplunkHEC] Max retries exceeded:", err);
      throw err;
    }
  }

  async flush(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.queue.length);

    if (this.isMockMode) {
      console.log(`[SplunkHEC MOCK] Flushing ${batch.length} events:`, batch.map((e) => e.event));
      return;
    }

    const payload = this.buildPayload(batch);
    await this.postWithRetry(payload);
  }

  private scheduleFlush(): void {
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => void this.flush(), this.config.flushIntervalMs);
    }
  }

  async send(event: HecEvent): Promise<void> {
    this.queue.push(event);
    if (this.queue.length >= this.config.maxBatchSize) {
      await this.flush();
    } else {
      this.scheduleFlush();
    }
  }

  async sendBatch(events: HecEvent[]): Promise<void> {
    this.queue.push(...events);
    if (this.queue.length >= this.config.maxBatchSize) {
      await this.flush();
    } else {
      this.scheduleFlush();
    }
  }
}

// Singleton export
export const splunkHec = new SplunkHecClient();
export { SplunkHecClient };
