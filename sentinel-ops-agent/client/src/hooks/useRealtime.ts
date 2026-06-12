import { useEffect, useEffectEvent, useState } from "react";
import superjson from "superjson";
import { trpc } from "@/lib/trpc";
import type { InvestigationListItem } from "../../../server/db";
import type { Alert, Investigation } from "../../../drizzle/schema";
import type {
  AlertCreatedRealtimeEvent,
  AlertUpdatedRealtimeEvent,
  InvestigationCompletedRealtimeEvent,
  InvestigationFailedRealtimeEvent,
  InvestigationJobQueuedRealtimeEvent,
  InvestigationStageRealtimeEvent,
  InvestigationStartedRealtimeEvent,
  InvestigationStepRealtimeEvent,
  ReportGenerationCompletedRealtimeEvent,
  ReportGenerationFailedRealtimeEvent,
  ReportGenerationProgressRealtimeEvent,
  ReportGenerationStartedRealtimeEvent,
  RealtimeConnectionStatus,
  RealtimeEvent,
} from "@shared/realtime";
import {
  REALTIME_EVENT_TYPES,
  REALTIME_RECONNECT_DELAY_MS,
} from "@shared/realtime";

type UseRealtimeOptions = {
  enabled?: boolean;
  investigationId?: string | null;
  onInvestigationStarted?: (event: InvestigationStartedRealtimeEvent) => void;
  onInvestigationJobQueued?: (
    event: InvestigationJobQueuedRealtimeEvent
  ) => void;
  onInvestigationStage?: (event: InvestigationStageRealtimeEvent) => void;
  onInvestigationStep?: (event: InvestigationStepRealtimeEvent) => void;
  onInvestigationCompleted?: (
    event: InvestigationCompletedRealtimeEvent
  ) => void;
  onInvestigationFailed?: (event: InvestigationFailedRealtimeEvent) => void;
  onReportStarted?: (event: ReportGenerationStartedRealtimeEvent) => void;
  onReportProgress?: (event: ReportGenerationProgressRealtimeEvent) => void;
  onReportCompleted?: (event: ReportGenerationCompletedRealtimeEvent) => void;
  onReportFailed?: (event: ReportGenerationFailedRealtimeEvent) => void;
};

const ALERT_LIST_INPUT = {
  limit: 100,
  offset: 0,
} as const;

const INVESTIGATION_LIST_INPUT = {
  limit: 50,
  offset: 0,
} as const;

const upsertAlert = (alerts: Alert[] | undefined, incoming: Alert): Alert[] => {
  const nextAlerts = alerts ? [...alerts] : [];
  const existingIndex = nextAlerts.findIndex((alert) => alert.id === incoming.id);

  if (existingIndex >= 0) {
    nextAlerts[existingIndex] = incoming;
  } else {
    nextAlerts.unshift(incoming);
  }

  return nextAlerts
    .sort(
      (left, right) =>
        new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime()
    )
    .slice(0, ALERT_LIST_INPUT.limit);
};

const upsertInvestigation = (
  investigations: InvestigationListItem[] | undefined,
  investigation: Investigation
): InvestigationListItem[] => {
  const nextInvestigations = investigations ? [...investigations] : [];
  const existingIndex = nextInvestigations.findIndex(
    (item) => item.investigationId === investigation.investigationId
  );
  const nextItem: InvestigationListItem = {
    ...investigation,
    analystName: null,
    analystEmail: null,
  };

  if (existingIndex >= 0) {
    nextInvestigations[existingIndex] = {
      ...nextInvestigations[existingIndex],
      ...nextItem,
    };
  } else {
    nextInvestigations.unshift(nextItem);
  }

  return nextInvestigations
    .sort(
      (left, right) =>
        new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime()
    )
    .slice(0, INVESTIGATION_LIST_INPUT.limit);
};

export function useRealtime(options: UseRealtimeOptions = {}) {
  const utils = trpc.useUtils();
  const [status, setStatus] = useState<RealtimeConnectionStatus>("connecting");
  const {
    enabled = true,
    investigationId,
    onInvestigationStarted,
    onInvestigationJobQueued,
    onInvestigationStage,
    onInvestigationStep,
    onInvestigationCompleted,
    onInvestigationFailed,
    onReportStarted,
    onReportProgress,
    onReportCompleted,
    onReportFailed,
  } = options;

  const handleAlertCreated = useEffectEvent(
    (event: AlertCreatedRealtimeEvent) => {
      utils.alerts.list.setData(ALERT_LIST_INPUT, (current) =>
        upsertAlert(current, event.alert)
      );
      utils.alerts.getById.setData({ id: event.alert.id }, event.alert);
      void utils.incidents.list.invalidate();
      void utils.briefings.ceo.invalidate();
      void utils.alerts.stats.invalidate();
      void utils.metrics.latest.invalidate();
      void utils.metrics.timeline.invalidate();
    }
  );

  const handleAlertUpdated = useEffectEvent(
    (event: AlertUpdatedRealtimeEvent) => {
      utils.alerts.list.setData(ALERT_LIST_INPUT, (current) =>
        upsertAlert(current, event.alert)
      );
      utils.alerts.getById.setData({ id: event.alert.id }, event.alert);
      void utils.incidents.list.invalidate();
      void utils.briefings.ceo.invalidate();
      void utils.alerts.stats.invalidate();
      void utils.metrics.latest.invalidate();
      void utils.metrics.timeline.invalidate();
      void utils.query.search.invalidate();
      void utils.alerts.search.invalidate();
    }
  );

  const handleInvestigationStarted = useEffectEvent(
    (event: InvestigationStartedRealtimeEvent) => {
      utils.investigations.list.setData(INVESTIGATION_LIST_INPUT, (current) =>
        upsertInvestigation(current, event.investigation)
      );
      utils.history.investigations.setData(
        INVESTIGATION_LIST_INPUT,
        (current) => upsertInvestigation(current, event.investigation)
      );
      void utils.briefings.ceo.invalidate();
      void utils.metrics.latest.invalidate();
      onInvestigationStarted?.(event);
    }
  );

  const handleInvestigationCompleted = useEffectEvent(
    (event: InvestigationCompletedRealtimeEvent) => {
      void utils.investigations.list.invalidate();
      void utils.history.investigations.invalidate();
      void utils.briefings.ceo.invalidate();
      void utils.metrics.latest.invalidate();
      onInvestigationCompleted?.(event);
    }
  );

  const handleInvestigationFailed = useEffectEvent(
    (event: InvestigationFailedRealtimeEvent) => {
      void utils.investigations.list.invalidate();
      void utils.history.investigations.invalidate();
      void utils.briefings.ceo.invalidate();
      onInvestigationFailed?.(event);
    }
  );

  const handleEvent = useEffectEvent((event: RealtimeEvent) => {
    switch (event.type) {
      case "alert.created":
        handleAlertCreated(event);
        return;
      case "alert.updated":
        handleAlertUpdated(event);
        return;
      case "investigation.started":
        handleInvestigationStarted(event);
        return;
      case "investigation.job.queued":
        if (!investigationId || event.investigationId === investigationId) {
          onInvestigationJobQueued?.(event);
        }
        return;
      case "investigation.stage":
        if (!investigationId || event.investigationId === investigationId) {
          onInvestigationStage?.(event);
        }
        return;
      case "investigation.step":
        if (!investigationId || event.investigationId === investigationId) {
          onInvestigationStep?.(event);
        }
        return;
      case "investigation.completed":
        handleInvestigationCompleted(event);
        return;
      case "investigation.failed":
        handleInvestigationFailed(event);
        return;
      case "report.generation.started":
        if (!investigationId || event.investigationId === investigationId) {
          onReportStarted?.(event);
        }
        return;
      case "report.generation.progress":
        if (!investigationId || event.investigationId === investigationId) {
          onReportProgress?.(event);
        }
        return;
      case "report.generation.completed":
        if (!investigationId || event.investigationId === investigationId) {
          onReportCompleted?.(event);
        }
        return;
      case "report.generation.failed":
        if (!investigationId || event.investigationId === investigationId) {
          onReportFailed?.(event);
        }
        return;
      default:
        return;
    }
  });

  useEffect(() => {
    if (!enabled || typeof window === "undefined") {
      setStatus("disconnected");
      return;
    }

    let disposed = false;
    let reconnectTimer: number | null = null;
    let source: EventSource | null = null;
    let hasConnected = false;

    const connect = () => {
      if (disposed) return;

      setStatus(hasConnected ? "reconnecting" : "connecting");
      source = new EventSource("/api/realtime", {
        withCredentials: true,
      });

      source.onopen = () => {
        hasConnected = true;
        setStatus("connected");
      };

      for (const eventType of REALTIME_EVENT_TYPES) {
        source.addEventListener(eventType, (message) => {
          const event = superjson.parse<RealtimeEvent>(
            (message as MessageEvent<string>).data
          );
          handleEvent(event);
        });
      }

      source.onerror = () => {
        source?.close();
        source = null;

        if (disposed) return;

        setStatus(hasConnected ? "reconnecting" : "disconnected");
        reconnectTimer = window.setTimeout(connect, REALTIME_RECONNECT_DELAY_MS);
      };
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
      }
      source?.close();
    };
  }, [enabled]);

  return {
    status,
    isConnected: status === "connected",
  };
}
