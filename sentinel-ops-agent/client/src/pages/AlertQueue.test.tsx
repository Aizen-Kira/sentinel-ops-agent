import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { Toaster } from "@/components/ui/sonner";
import { describe, expect, it, vi } from "vitest";
import AlertQueue from "./AlertQueue";

const alerts = [
  {
    id: 1,
    eventId: "EVT-1",
    severity: "high",
    title: "Credential abuse suspected",
    description: "Repeated failed login activity followed by privilege change.",
    source: "10.0.0.8",
    target: "AD-SERVER-01",
    eventType: "failed_login",
    rawData: { indicator: "failed-login-burst" },
    status: "open",
    assignedTo: null,
    createdAt: new Date("2026-04-11T09:00:00.000Z"),
    updatedAt: new Date("2026-04-11T09:00:00.000Z"),
    incidentId: 1,
  },
];

vi.mock("@/hooks/useRealtime", () => ({
  useRealtime: () => ({
    status: "connected",
    isConnected: true,
  }),
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
    alerts: {
      list: {
        useQuery: () => ({
          data: alerts,
          isLoading: false,
          refetch: vi.fn(),
        }),
      },
      stats: {
        useQuery: () => ({
          data: {
            total: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            open: 1,
            acknowledged: 0,
            escalated: 0,
            dismissed: 0,
          },
        }),
      },
      updateStatus: {
        useMutation: (options?: { onSuccess?: () => void }) => ({
          isPending: false,
          mutateAsync: async () => {
            options?.onSuccess?.();
            return { success: true };
          },
        }),
      },
      updateSeverity: {
        useMutation: (options?: { onSuccess?: () => void }) => ({
          isPending: false,
          mutateAsync: async () => {
            options?.onSuccess?.();
            return { success: true };
          },
        }),
      },
    },
    incidents: {
      list: {
        useQuery: () => ({
          data: [
            {
              id: 1,
              incidentId: "INC-1",
              title: "Credential abuse campaign",
              severity: "high",
              status: "investigating",
              rootCause: "Compromised credentials were used against domain services.",
              affectedAssets: ["AD-SERVER-01"],
              remediationSteps: ["Reset the account and isolate the host."],
              alertCount: 1,
              affectedAssetCount: 1,
              confidenceScore: 0.88,
              businessImpactScore: 72,
              createdAt: new Date("2026-04-11T09:00:00.000Z"),
            },
          ],
        }),
      },
    },
  },
}));

describe("AlertQueue", () => {
  it("supports the visible alert triage flow", async () => {
    render(
      <>
        <Toaster />
        <AlertQueue />
      </>
    );

    expect(screen.getByText("Live")).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /credential abuse suspected/i })
    );

    expect(screen.getByText(/repeated failed login activity/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /acknowledge/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /acknowledge/i }));

    expect(await screen.findByText("Alert status updated")).toBeInTheDocument();
  });
});
