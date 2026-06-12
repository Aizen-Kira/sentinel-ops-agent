import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import type { User } from "../drizzle/schema";

const mockUser: User = {
  id: 1,
  openId: "test-user",
  email: "test@example.com",
  name: "Test User",
  loginMethod: "test",
  role: "user",
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

function createMockContext(user: User | null = mockUser): TrpcContext {
  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

describe("Alerts Router", () => {
  it("should list alerts", async () => {
    const ctx = createMockContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.alerts.list({ limit: 10, offset: 0 });

    expect(Array.isArray(result)).toBe(true);
  });

  it("should require authentication for listing alerts", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.alerts.list({ limit: 10, offset: 0 });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("should get alert stats", async () => {
    const ctx = createMockContext();
    const caller = appRouter.createCaller(ctx);

    const stats = await caller.alerts.stats();

    expect(stats).toHaveProperty("total");
    expect(stats).toHaveProperty("critical");
    expect(stats).toHaveProperty("high");
    expect(stats).toHaveProperty("medium");
    expect(stats).toHaveProperty("low");
    expect(stats).toHaveProperty("open");
    expect(stats).toHaveProperty("acknowledged");
    expect(stats).toHaveProperty("escalated");
    expect(stats).toHaveProperty("dismissed");
  });

  it("should require authentication for alert stats", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.alerts.stats();
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("should require authentication for creating alerts", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.alerts.create({
        eventId: "TEST-001",
        severity: "critical",
        title: "Test Alert",
        source: "192.168.1.1",
        eventType: "test",
      });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("should require authentication for updating alert status", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.alerts.updateStatus({
        id: 1,
        status: "acknowledged",
      });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("should require authentication for updating alert severity", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.alerts.updateSeverity({
        id: 1,
        severity: "high",
      });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });
});

describe("Investigations Router", () => {
  it("should list investigations", async () => {
    const ctx = createMockContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.investigations.list({ limit: 10, offset: 0 });

    expect(Array.isArray(result)).toBe(true);
  });

  it("should require authentication for listing investigations", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.investigations.list({ limit: 10, offset: 0 });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("should require authentication for creating investigations", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.investigations.create({
        alertIds: [1, 2, 3],
      });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });
});

describe("Incidents Router", () => {
  it("should list incidents", async () => {
    const ctx = createMockContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.incidents.list({ limit: 10, offset: 0 });

    expect(Array.isArray(result)).toBe(true);
  });

  it("should require authentication for listing incidents", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.incidents.list({ limit: 10, offset: 0 });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("should require authentication for creating incidents", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.incidents.create({
        title: "Test Incident",
        severity: "high",
        affectedAssets: ["192.168.1.1"],
      });
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });
});

describe("Metrics Router", () => {
  it("should get latest metrics", async () => {
    const ctx = createMockContext();
    const caller = appRouter.createCaller(ctx);

    const metrics = await caller.metrics.latest();

    expect(metrics).toHaveProperty("openIncidentCount");
    expect(metrics).toHaveProperty("criticalAlertCount");
    expect(metrics).toHaveProperty("highAlertCount");
    expect(metrics).toHaveProperty("mediumAlertCount");
    expect(metrics).toHaveProperty("lowAlertCount");
  });

  it("should require authentication for latest metrics", async () => {
    const ctx = createMockContext(null);
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.metrics.latest();
      expect.fail("Should have thrown unauthorized error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });
});
