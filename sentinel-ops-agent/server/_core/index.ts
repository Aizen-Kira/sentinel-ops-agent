import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import type { Request, Response } from "express";
import type { User } from "../../drizzle/schema";
import { registerOAuthRoutes } from "./oauth";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { correlateAlertToIncident } from "../correlation";
import { createAlert } from "../db";
import {
  connectorEnvelopeToAlert,
  startEventStream,
} from "../eventGenerator";
import {
  publishRealtimeEvent,
  replayRealtimeEvents,
  registerRealtimeClient,
  writeRealtimeComment,
  writeRealtimeEvent,
} from "./realtime";
import { sdk } from "./sdk";
import { REALTIME_HEARTBEAT_MS } from "@shared/realtime";
import { serveStatic, setupVite } from "./vite";
import { hasCapability } from "./capabilities";
import { startInvestigationWorker } from "./investigationWorker";
import { ENV } from "./env";
import { sanitizeLogValue } from "./logSanitization";

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

const buildRealtimeFilter = (user: User) => async (envelope: {
  scope?: {
    allowedUserIds?: number[];
    requiredCapabilities?: string[];
  };
}) => {
  if (!envelope.scope) {
    return true;
  }

  const allowedByUser =
    envelope.scope.allowedUserIds?.includes(user.id) ?? false;
  const allowedByCapability =
    envelope.scope.requiredCapabilities?.some((capability) =>
      hasCapability(user, capability as Parameters<typeof hasCapability>[1])
    ) ?? false;

  if (envelope.scope.allowedUserIds || envelope.scope.requiredCapabilities) {
    return allowedByUser || allowedByCapability;
  }

  return true;
};

async function handleRealtimeConnection(
  req: Request,
  res: Response,
  options: { replayOnly?: boolean } = {}
) {
  let user: User;

  try {
    user = await sdk.authenticateRequest(req);
  } catch {
    console.warn("[Realtime] Authentication failed");
    res.status(401).end("Unauthorized");
    return;
  }

  res.status(200);
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  const write = (chunk: string) => {
    if (res.writableEnded || res.destroyed) {
      throw new Error("Realtime response already closed");
    }
    res.write(chunk);
  };

  const filter = buildRealtimeFilter(user);
  const replayCursor =
    typeof req.query.cursor === "string"
      ? req.query.cursor
      : typeof req.headers["last-event-id"] === "string"
        ? req.headers["last-event-id"]
        : null;

  await replayRealtimeEvents({
    cursor: replayCursor,
    write,
    filter,
  });

  if (options.replayOnly) {
    res.end();
    return;
  }

  const { disconnect } = registerRealtimeClient({ user, write, filter });
  writeRealtimeComment(write, "connected");
  writeRealtimeEvent(write, {
    type: "realtime.ready",
    connectedAt: new Date(),
  });

  let closed = false;
  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    disconnect();
    req.off("close", cleanup);
    req.off("end", cleanup);
    if (!res.writableEnded) {
      res.end();
    }
  };

  const heartbeat = setInterval(() => {
    try {
      writeRealtimeComment(write, `heartbeat ${Date.now()}`);
    } catch {
      console.warn("[Realtime] Heartbeat failed");
      cleanup();
    }
  }, REALTIME_HEARTBEAT_MS);

  req.on("close", cleanup);
  req.on("end", cleanup);
}

async function startServer() {
  const app = express();
  const server = createServer(app);
  // Configure body parser with larger size limit for file uploads
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));
  // OAuth callback under /api/oauth/callback
  registerOAuthRoutes(app);
  app.get("/api/realtime", (req, res) => {
    void handleRealtimeConnection(req, res);
  });
  app.get("/api/realtime/replay", (req, res) => {
    void handleRealtimeConnection(req, res, { replayOnly: true });
  });
  // tRPC API
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
    })
  );
  // development mode uses Vite, production mode uses static files
  if (ENV.nodeEnv === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);

  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }

  const shouldStartDemoStream =
    ENV.nodeEnv === "development" ||
    process.env.ENABLE_DEMO_EVENT_STREAM === "true";

  startInvestigationWorker();

  if (shouldStartDemoStream) {
    await startEventStream(async (connectorEvent) => {
      const createdAlert = await createAlert(connectorEnvelopeToAlert(connectorEvent));
      const correlation = await correlateAlertToIncident(createdAlert);
      await publishRealtimeEvent(
        {
          type: "alert.created",
          alert: correlation?.alert ?? createdAlert,
        },
        {
          scope: {
            requiredCapabilities: ["canManageAlerts"],
          },
        }
      );
    });
    console.log("[Realtime] Demo event stream enabled");
  }

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}

startServer().catch((error) => {
  console.error("[Startup] Failed to start server", sanitizeLogValue(error));
});
