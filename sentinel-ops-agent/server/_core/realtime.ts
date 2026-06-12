import { nanoid } from "nanoid";
import superjson from "superjson";
import type { User } from "../../drizzle/schema";
import {
  createRealtimeEventRecord,
  getRealtimeEventsAfterCursor,
  markRealtimeEventsReplayed,
} from "../db";
import type { RealtimeEventRecord } from "../../drizzle/schema";
import type { RealtimeEvent } from "@shared/realtime";

type RealtimeWriter = (chunk: string) => void;

export type RealtimeEventScope = {
  investigationId?: string | null;
  allowedUserIds?: number[];
  requiredCapabilities?: string[];
};

export type RealtimeEnvelope = {
  event: RealtimeEvent;
  scope?: RealtimeEventScope;
};

type RealtimeClient = {
  userId: number;
  tenantId: string;
  write: RealtimeWriter;
  filter?: (envelope: RealtimeEnvelope) => boolean | Promise<boolean>;
};

type PublishOptions = {
  eventId?: string;
  tenantId?: string;
  scope?: RealtimeEventScope;
};

type ReplayOptions = {
  cursor?: string | null;
  tenantId?: string;
  limit?: number;
  write: RealtimeWriter;
  filter?: (envelope: RealtimeEnvelope) => boolean | Promise<boolean>;
};

export interface EventBus {
  publish(event: RealtimeEvent, options?: PublishOptions): Promise<number>;
  registerClient(options: {
    user: User;
    write: RealtimeWriter;
    tenantId?: string;
    filter?: (envelope: RealtimeEnvelope) => boolean | Promise<boolean>;
  }): { clientId: string; disconnect: () => void };
  replay(options: ReplayOptions): Promise<string | null>;
}

const DEFAULT_TENANT_ID = "default";
const realtimeClients = new Map<string, RealtimeClient>();
let eventSequence = 0;

const nextEventId = () =>
  `${Date.now()}-${String(++eventSequence).padStart(6, "0")}`;

const normalizeEnvelope = (payload: unknown): RealtimeEnvelope => {
  if (payload && typeof payload === "object" && "event" in payload) {
    const maybeEnvelope = payload as RealtimeEnvelope;
    if (maybeEnvelope.event) {
      return maybeEnvelope;
    }
  }

  return {
    event: payload as RealtimeEvent,
  };
};

const parseStoredEnvelope = (record: RealtimeEventRecord): RealtimeEnvelope => {
  if (typeof record.payload === "string") {
    try {
      return normalizeEnvelope(JSON.parse(record.payload));
    } catch {
      return normalizeEnvelope(superjson.parse(record.payload));
    }
  }

  return normalizeEnvelope(record.payload);
};

export function serializeRealtimeEvent(
  event: RealtimeEvent,
  eventId: string = nextEventId()
): string {
  return `id: ${eventId}\nevent: ${event.type}\ndata: ${superjson.stringify(event)}\n\n`;
}

export function serializeRealtimeComment(comment: string): string {
  return `: ${comment}\n\n`;
}

const eventBus: EventBus = {
  async publish(event, options = {}) {
    const eventId = options.eventId ?? nextEventId();
    const envelope: RealtimeEnvelope = {
      event,
      ...(options.scope ? { scope: options.scope } : {}),
    };

    try {
      await createRealtimeEventRecord({
        id: eventId,
        tenantId: options.tenantId ?? DEFAULT_TENANT_ID,
        topic: event.type,
        payload: envelope,
        replayed: false,
      });
    } catch {
      console.warn("[Realtime] Failed to persist event, continuing with live fan-out");
    }

    const payload = serializeRealtimeEvent(event, eventId);
    let delivered = 0;

    for (const [clientId, client] of Array.from(realtimeClients.entries())) {
      try {
        if (client.tenantId !== (options.tenantId ?? DEFAULT_TENANT_ID)) {
          continue;
        }

        if (client.filter) {
          const shouldDeliver = await client.filter(envelope);
          if (!shouldDeliver) {
            continue;
          }
        }

        client.write(payload);
        delivered += 1;
      } catch {
        console.warn(
          `[Realtime] Removing disconnected client ${clientId} for user ${client.userId}`
        );
        realtimeClients.delete(clientId);
      }
    }

    return delivered;
  },

  registerClient(options) {
    const clientId = `rt-${nanoid(10)}`;
    realtimeClients.set(clientId, {
      userId: options.user.id,
      tenantId: options.tenantId ?? DEFAULT_TENANT_ID,
      write: options.write,
      filter: options.filter,
    });

    return {
      clientId,
      disconnect: () => {
        realtimeClients.delete(clientId);
      },
    };
  },

  async replay(options) {
    const records = await getRealtimeEventsAfterCursor({
      cursor: options.cursor,
      tenantId: options.tenantId ?? DEFAULT_TENANT_ID,
      limit: options.limit,
    });

    if (records.length === 0) {
      return options.cursor ?? null;
    }

    const replayedIds: string[] = [];
    let lastId = options.cursor ?? null;

    for (const record of records) {
      const envelope = parseStoredEnvelope(record);
      if (options.filter) {
        const shouldDeliver = await options.filter(envelope);
        if (!shouldDeliver) {
          continue;
        }
      }

      options.write(serializeRealtimeEvent(envelope.event, record.id));
      replayedIds.push(record.id);
      lastId = record.id;
    }

    await markRealtimeEventsReplayed(replayedIds);
    return lastId;
  },
};

export function getTenantIdForUser(_user: User): string {
  return DEFAULT_TENANT_ID;
}

export function registerRealtimeClient(options: {
  user: User;
  write: RealtimeWriter;
  tenantId?: string;
  filter?: (envelope: RealtimeEnvelope) => boolean | Promise<boolean>;
}) {
  return eventBus.registerClient(options);
}

export async function publishRealtimeEvent(
  event: RealtimeEvent,
  options?: PublishOptions
): Promise<number> {
  return eventBus.publish(event, options);
}

export async function replayRealtimeEvents(
  options: ReplayOptions
): Promise<string | null> {
  return eventBus.replay(options);
}

export function writeRealtimeEvent(
  write: RealtimeWriter,
  event: RealtimeEvent,
  eventId?: string
): void {
  write(serializeRealtimeEvent(event, eventId));
}

export function writeRealtimeComment(
  write: RealtimeWriter,
  comment: string
): void {
  write(serializeRealtimeComment(comment));
}

export function getRealtimeClientCount(): number {
  return realtimeClients.size;
}

export function clearRealtimeClients(): void {
  realtimeClients.clear();
}
