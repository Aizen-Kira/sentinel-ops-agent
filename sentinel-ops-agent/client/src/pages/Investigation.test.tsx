import React from "react";
import superjson from "superjson";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { Toaster } from "@/components/ui/sonner";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Investigation from "./Investigation";

const alerts = [
  {
    id: 1,
    eventId: "EVT-1",
    severity: "high",
    title: "Suspicious failed login attempts",
    description: "Repeated failed login activity detected.",
    source: "10.0.0.8",
    target: "AD-SERVER-01",
    eventType: "failed_login",
    rawData: { indicator: "failed-login-burst" },
    status: "open",
    assignedTo: null,
    createdAt: new Date("2026-04-11T09:00:00.000Z"),
    updatedAt: new Date("2026-04-11T09:00:00.000Z"),
    incidentId: null,
  },
];

const mockUtils = {
  alerts: {
    list: { setData: vi.fn() },
    getById: { setData: vi.fn() },
    stats: { invalidate: vi.fn() },
    search: { invalidate: vi.fn() },
  },
  incidents: {
    list: { invalidate: vi.fn() },
  },
  briefings: {
    ceo: { invalidate: vi.fn() },
  },
  metrics: {
    latest: { invalidate: vi.fn() },
    timeline: { invalidate: vi.fn() },
  },
  investigations: {
    list: { setData: vi.fn(), invalidate: vi.fn() },
    getReport: { invalidate: vi.fn() },
  },
  history: {
    investigations: { setData: vi.fn(), invalidate: vi.fn() },
  },
  query: {
    search: { invalidate: vi.fn() },
  },
};

let currentJobData: Record<string, unknown> | undefined;
let currentReportData: Record<string, unknown> | undefined;

vi.mock("@/components/LazyStreamdown", () => ({
  LazyStreamdown: ({ children }: { children: string }) => <>{children}</>,
}));

vi.mock("framer-motion", () => ({
  AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  motion: new Proxy(
    {},
    {
      get: (_, tag: string) =>
        ({
          children,
          ...props
        }: React.HTMLAttributes<HTMLElement> & { children?: React.ReactNode }) =>
          React.createElement(tag, props, children),
    }
  ),
}));

vi.mock("@/lib/trpc", () => ({
  trpc: {
    useUtils: () => mockUtils,
    alerts: {
      list: {
        useQuery: () => ({
          data: alerts,
        }),
      },
    },
    investigations: {
      create: {
        useMutation: () => ({
          mutateAsync: async () => ({
            investigationId: "INV-1",
            alertIds: [1],
            status: "in_progress",
            reasoningSteps: [],
            createdAt: new Date("2026-04-11T09:00:00.000Z"),
            userId: 1,
          }),
        }),
      },
      streamReasoning: {
        useMutation: () => ({
          mutateAsync: async () => ({
            jobId: "JOB-INV-1",
            investigationId: "INV-1",
            status: "pending",
          }),
        }),
      },
      getJob: {
        useQuery: () => ({
          data: currentJobData,
        }),
      },
      generateReport: {
        useMutation: () => ({
          isPending: false,
          mutateAsync: async () => ({
            reportId: "REP-1",
            investigationId: "INV-1",
            status: "pending",
          }),
        }),
      },
      getReport: {
        useQuery: () => ({
          data: currentReportData,
        }),
      },
    },
  },
}));

class MockEventSource {
  static instances: MockEventSource[] = [];
  onopen: ((event: Event) => void) | null = null;
  onerror: (() => void) | null = null;
  private listeners = new Map<string, Array<(event: MessageEvent<string>) => void>>();

  constructor(public url: string) {
    MockEventSource.instances.push(this);
  }

  addEventListener(type: string, callback: (event: MessageEvent<string>) => void) {
    const current = this.listeners.get(type) ?? [];
    current.push(callback);
    this.listeners.set(type, current);
  }

  close() {
    return undefined;
  }

  emit(type: string, payload: unknown) {
    const callbacks = this.listeners.get(type) ?? [];
    const message = {
      data: superjson.stringify(payload),
    } as MessageEvent<string>;
    callbacks.forEach((callback) => callback(message));
  }

  open() {
    this.onopen?.(new Event("open"));
  }

  fail() {
    this.onerror?.();
  }
}

beforeEach(() => {
  MockEventSource.instances = [];
  currentJobData = undefined;
  currentReportData = undefined;
  vi.stubGlobal("EventSource", MockEventSource as unknown as typeof EventSource);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("Investigation", () => {
  it("launches an investigation and shows the SSE connection", async () => {
    render(
      <>
        <Toaster />
        <Investigation />
      </>
    );

    await act(async () => {
      MockEventSource.instances[0]?.open();
    });
    expect(await screen.findByText("Live")).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("checkbox")[0]);
    fireEvent.click(screen.getByRole("button", { name: /start investigation/i }));

    expect(
      await screen.findByText("Investigation accepted and queued for background analysis.")
    ).toBeInTheDocument();
    expect(screen.getByText("JOB-INV-1")).toBeInTheDocument();
  });

  it("shows reconnecting state and reconnects after a disconnect", async () => {
    vi.useFakeTimers();

    render(<Investigation />);

    await act(async () => {
      MockEventSource.instances[0]?.open();
    });
    expect(screen.getByText("Live")).toBeInTheDocument();

    await act(async () => {
      MockEventSource.instances[0]?.fail();
    });
    expect(screen.getByText("Reconnecting")).toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(2000);
    });
    await act(async () => {
      MockEventSource.instances[1]?.open();
    });

    expect(screen.getByText("Live")).toBeInTheDocument();
  }, 10000);

  it("renders streamed reasoning completion in Local Analyst Mode", async () => {
    render(<Investigation />);

    const source = MockEventSource.instances[0];
    await act(async () => {
      source?.open();
    });
    expect(await screen.findByText("Live")).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("checkbox")[0]);
    fireEvent.click(screen.getByRole("button", { name: /start investigation/i }));
    expect(await screen.findByText("JOB-INV-1")).toBeInTheDocument();

    source.emit("investigation.job.queued", {
      type: "investigation.job.queued",
      investigationId: "INV-1",
      jobId: "JOB-INV-1",
      queuedAt: new Date("2026-04-11T09:01:00.000Z"),
    });
    source.emit("investigation.stage", {
      type: "investigation.stage",
      investigationId: "INV-1",
      stage: "evidence_extraction",
      result: {
        findings: ["Failed logins clustered around one identity."],
      },
      index: 1,
      totalStages: 4,
    });
    source.emit("investigation.step", {
      type: "investigation.step",
      investigationId: "INV-1",
      step: "Background worker correlated authentication activity with privilege abuse.",
      index: 2,
      totalSteps: 5,
      source: "analysis",
    });
    source.emit("investigation.completed", {
      type: "investigation.completed",
      investigationId: "INV-1",
      conclusion:
        "Conclusion: Stolen credentials were likely used to access AD-SERVER-01. Confidence 82.",
      confidence: 0.82,
      steps: [
        "Background worker correlated authentication activity with privilege abuse.",
      ],
      completedAt: new Date("2026-04-11T09:02:00.000Z"),
      provider: "ollama",
      model: "sentinel-local-1",
      localMode: true,
      playbookId: "credential_abuse",
      jobId: "JOB-INV-1",
    });

    expect(await screen.findByText("Investigation Conclusion")).toBeInTheDocument();
    expect(screen.getByText("Local Analyst Mode")).toBeInTheDocument();
    expect(screen.getByText("credential_abuse")).toBeInTheDocument();
    expect(
      screen.getByText(/stolen credentials were likely used to access ad-server-01/i)
    ).toBeInTheDocument();
  });
});
