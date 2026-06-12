import { afterEach, describe, expect, it } from "vitest";
import type { User } from "../../drizzle/schema";
import {
  clearRealtimeClients,
  getRealtimeClientCount,
  publishRealtimeEvent,
  registerRealtimeClient,
  serializeRealtimeEvent,
} from "./realtime";

const mockUser: User = {
  id: 99,
  openId: "realtime-test-user",
  email: "realtime@example.com",
  name: "Realtime Test",
  loginMethod: "test",
  role: "user",
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

afterEach(() => {
  clearRealtimeClients();
});

describe("realtime transport", () => {
  it("serializes named SSE events", () => {
    const payload = serializeRealtimeEvent(
      {
        type: "realtime.ready",
        connectedAt: new Date("2026-04-09T00:00:00.000Z"),
      },
      "evt-1"
    );

    expect(payload).toContain("id: evt-1");
    expect(payload).toContain("event: realtime.ready");
    expect(payload).toContain("data:");
  });

  it("broadcasts realtime events to connected clients", async () => {
    const writes: string[] = [];
    const client = registerRealtimeClient({
      user: mockUser,
      write: (chunk) => {
        writes.push(chunk);
      },
    });

    const delivered = await publishRealtimeEvent({
      type: "alert.created",
      alert: {
        id: 1,
        eventId: "EVT-123",
        severity: "high",
        title: "Test alert",
        description: "Description",
        source: "10.0.0.1",
        target: "WEB-01",
        eventType: "failed_login",
        rawData: null,
        status: "open",
        assignedTo: null,
        createdAt: new Date("2026-04-09T00:00:00.000Z"),
        updatedAt: new Date("2026-04-09T00:00:00.000Z"),
        incidentId: null,
      },
    });

    expect(delivered).toBe(1);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toContain("event: alert.created");

    client.disconnect();
    expect(getRealtimeClientCount()).toBe(0);
  });

  it("drops clients whose writers fail", async () => {
    registerRealtimeClient({
      user: mockUser,
      write: () => {
        throw new Error("socket closed");
      },
    });

    const delivered = await publishRealtimeEvent({
      type: "realtime.ready",
      connectedAt: new Date("2026-04-09T00:00:00.000Z"),
    });

    expect(delivered).toBe(0);
    expect(getRealtimeClientCount()).toBe(0);
  });
});
