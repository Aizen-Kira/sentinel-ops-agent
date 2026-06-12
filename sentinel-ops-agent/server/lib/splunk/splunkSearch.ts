// lib/splunk/splunkSearch.ts
// Splunk Search REST API: job creation → polling → result fetch pattern

export interface SearchJob {
  sid: string;
  status: "running" | "done" | "failed";
  doneProgress: number; // 0.0–1.0
}

export interface SearchResult {
  fields: string[];
  rows: Record<string, string>[];
  preview: boolean;
}

export interface SearchOptions {
  earliest?: string; // e.g. "-24h"
  latest?: string;   // e.g. "now"
  maxCount?: number;
  pollIntervalMs?: number;
  timeoutMs?: number;
}

const MOCK_RESULTS: SearchResult = {
  fields: ["_time", "host", "source", "event_type", "severity", "user", "dest_ip"],
  rows: [
    { _time: "2024-01-15T10:00:00Z", host: "ws-001", source: "syslog", event_type: "auth_failure", severity: "high", user: "jdoe", dest_ip: "192.168.1.10" },
    { _time: "2024-01-15T10:01:30Z", host: "ws-001", source: "syslog", event_type: "lateral_move", severity: "critical", user: "jdoe", dest_ip: "192.168.1.20" },
    { _time: "2024-01-15T10:03:00Z", host: "dc-001", source: "winevent", event_type: "credential_dump", severity: "critical", user: "SYSTEM", dest_ip: "192.168.1.1" },
  ],
  preview: false,
};

class SplunkSearchClient {
  private readonly isMockMode: boolean;
  private readonly baseUrl: string;

  constructor() {
    this.isMockMode = !process.env.SPLUNK_HEC_URL;
    const host = process.env.SPLUNK_HOST ?? "localhost";
    const port = process.env.SPLUNK_PORT ?? "8089";
    this.baseUrl = `https://${host}:${port}/services`;
  }

  private buildHeaders(): Record<string, string> {
    return {
      "Authorization": `Splunk ${process.env.SPLUNK_HEC_TOKEN ?? ""}`,
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    };
  }

  private async createJob(spl: string, options: SearchOptions): Promise<string> {
    const body = new URLSearchParams({
      search: spl.startsWith("search ") ? spl : `search ${spl}`,
      output_mode: "json",
      earliest_time: options.earliest ?? "-24h",
      latest_time: options.latest ?? "now",
      count: String(options.maxCount ?? 500),
    });

    const res = await fetch(`${this.baseUrl}/search/jobs`, {
      method: "POST",
      headers: this.buildHeaders(),
      body: body.toString(),
    });

    if (!res.ok) throw new Error(`Failed to create search job: ${res.status}`);
    const data = await res.json() as { sid: string };
    return data.sid;
  }

  private async pollJobStatus(sid: string): Promise<SearchJob> {
    const res = await fetch(`${this.baseUrl}/search/jobs/${sid}?output_mode=json`, {
      headers: this.buildHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to poll job ${sid}: ${res.status}`);
    const data = await res.json() as { entry: Array<{ content: { dispatchState: string; doneProgress: number } }> };
    const content = data.entry[0]?.content;
    const dispatchState = content?.dispatchState ?? "FAILED";
    return {
      sid,
      status: dispatchState === "DONE" ? "done" : dispatchState === "FAILED" ? "failed" : "running",
      doneProgress: content?.doneProgress ?? 0,
    };
  }

  private async fetchResults(sid: string, maxCount: number): Promise<SearchResult> {
    const res = await fetch(
      `${this.baseUrl}/search/jobs/${sid}/results?output_mode=json&count=${maxCount}`,
      { headers: this.buildHeaders() }
    );
    if (!res.ok) throw new Error(`Failed to fetch results for ${sid}: ${res.status}`);
    const data = await res.json() as { fields: Array<{ name: string }>; results: Record<string, string>[] };
    return {
      fields: data.fields.map((f) => f.name),
      rows: data.results,
      preview: false,
    };
  }

  async search(spl: string, options: SearchOptions = {}): Promise<SearchResult> {
    if (this.isMockMode) {
      console.log(`[SplunkSearch MOCK] SPL: ${spl}`);
      await new Promise((r) => setTimeout(r, 50)); // simulate latency
      return MOCK_RESULTS;
    }

    const pollInterval = options.pollIntervalMs ?? 1000;
    const timeout = options.timeoutMs ?? 30_000;
    const maxCount = options.maxCount ?? 500;

    const sid = await this.createJob(spl, options);
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      const job = await this.pollJobStatus(sid);
      if (job.status === "done") return this.fetchResults(sid, maxCount);
      if (job.status === "failed") throw new Error(`Splunk job ${sid} failed`);
      await new Promise((r) => setTimeout(r, pollInterval));
    }

    throw new Error(`Splunk job ${sid} timed out after ${timeout}ms`);
  }

  async healthcheck(): Promise<{ ok: boolean; mode: "live" | "mock"; latencyMs?: number }> {
    if (this.isMockMode) return { ok: true, mode: "mock" };
    const start = Date.now();
    try {
      const res = await fetch(`${this.baseUrl}/server/info?output_mode=json`, {
        headers: this.buildHeaders(),
      });
      return { ok: res.ok, mode: "live", latencyMs: Date.now() - start };
    } catch {
      return { ok: false, mode: "live", latencyMs: Date.now() - start };
    }
  }
}

export const splunkSearch = new SplunkSearchClient();
export { SplunkSearchClient };
