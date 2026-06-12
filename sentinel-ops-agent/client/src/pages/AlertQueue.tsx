import { useState } from "react";
import {
  AlertCircle,
  Check,
  ChevronDown,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  TrendingUp,
  X,
  Zap,
} from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { ConnectionStatus } from "@/components/ConnectionStatus";
import { DemoModeNotice } from "@/components/DemoModeNotice";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useRealtime } from "@/hooks/useRealtime";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

const ENTER = {
  initial: { opacity: 0, y: 18 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.32, ease: [0.22, 1, 0.36, 1] as const },
};

export default function AlertQueue() {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const { status: realtimeStatus } = useRealtime();

  const { data: alerts = [], isLoading, refetch } = trpc.alerts.list.useQuery({
    limit: 100,
    offset: 0,
  });
  const { data: stats } = trpc.alerts.stats.useQuery();
  const { data: incidents = [] } = trpc.incidents.list.useQuery({
    limit: 5,
    offset: 0,
  });

  const activeIncidents = incidents
    .filter((incident) => incident.status !== "resolved")
    .slice(0, 3);

  const updateStatusMutation = trpc.alerts.updateStatus.useMutation({
    onSuccess: () => {
      toast.success("Alert status updated");
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const updateSeverityMutation = trpc.alerts.updateSeverity.useMutation({
    onSuccess: () => {
      toast.success("Severity updated");
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleAcknowledge = async (id: number) => {
    await updateStatusMutation.mutateAsync({
      id,
      status: "acknowledged",
      reason: "Acknowledged by analyst",
    });
  };

  const handleEscalate = async (id: number) => {
    await updateStatusMutation.mutateAsync({
      id,
      status: "escalated",
      reason: "Escalated for investigation",
    });
  };

  const handleDismiss = async (id: number) => {
    await updateStatusMutation.mutateAsync({
      id,
      status: "dismissed",
      reason: "Dismissed as false positive",
    });
  };

  const handleChangeSeverity = async (
    id: number,
    newSeverity: "critical" | "high" | "medium" | "low"
  ) => {
    await updateSeverityMutation.mutateAsync({
      id,
      severity: newSeverity,
      reason: "Severity adjusted by analyst",
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "border-red-500/30 bg-red-500/12 text-red-200";
      case "high":
        return "border-orange-500/30 bg-orange-500/12 text-orange-200";
      case "medium":
        return "border-amber-500/30 bg-amber-500/12 text-amber-100";
      case "low":
        return "border-sky-500/30 bg-sky-500/12 text-sky-100";
      default:
        return "border-white/12 bg-white/6 text-slate-200";
    }
  };

  const getSeverityGlow = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-400";
      case "high":
        return "bg-orange-400";
      case "medium":
        return "bg-amber-300";
      case "low":
        return "bg-sky-300";
      default:
        return "bg-slate-300";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "open":
        return "border-red-500/20 bg-red-500/10 text-red-200";
      case "acknowledged":
        return "border-amber-500/20 bg-amber-500/10 text-amber-100";
      case "escalated":
        return "border-orange-500/20 bg-orange-500/10 text-orange-200";
      case "dismissed":
        return "border-emerald-500/20 bg-emerald-500/10 text-emerald-200";
      default:
        return "border-white/10 bg-white/5 text-slate-200";
    }
  };

  const getIncidentStatusColor = (status: string) => {
    switch (status) {
      case "investigating":
        return "border-orange-500/20 bg-orange-500/12 text-orange-100";
      case "resolved":
        return "border-emerald-500/20 bg-emerald-500/12 text-emerald-100";
      case "contained":
        return "border-sky-500/20 bg-sky-500/12 text-sky-100";
      default:
        return "border-red-500/20 bg-red-500/12 text-red-100";
    }
  };

  const toStringArray = (value: unknown) =>
    Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [];

  const formatTime = (date: Date) =>
    new Date(date).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
    });

  const alertCount = stats?.total ?? alerts.length;

  return (
    <div className="space-y-6">
      <motion.section
        {...ENTER}
        className="page-hero px-6 py-6 md:px-8 md:py-8"
      >
        <div className="relative space-y-8">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="max-w-3xl space-y-4">
              <div className="section-kicker">Live Security Feed</div>
              <div className="space-y-3">
                <h1 className="max-w-3xl text-3xl font-semibold leading-tight text-white md:text-5xl">
                  Watch raw alerts collapse into incidents while the room is still looking.
                </h1>
                <p className="max-w-2xl text-sm leading-7 text-slate-300 md:text-base">
                  This surface is tuned for the demo: triage live events, see
                  correlated attack stories, and push the highest-risk activity
                  straight into investigation.
                </p>
                <DemoModeNotice>
                  Alert volume can come from the synthetic event stream or seeded ransomware scenario when demo data is enabled.
                </DemoModeNotice>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <ConnectionStatus status={realtimeStatus} />
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetch()}
                disabled={isLoading}
                className="border-white/10 bg-white/6 text-slate-100 hover:bg-white/10"
              >
                <RefreshCw
                  className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
                />
                Refresh Feed
              </Button>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Open Alerts
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {stats?.open ?? 0}
                </span>
                <ShieldAlert className="h-5 w-5 text-red-300/80" />
              </div>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Escalated
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {stats?.escalated ?? 0}
                </span>
                <Zap className="h-5 w-5 text-orange-200/80" />
              </div>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Active Incidents
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {activeIncidents.length}
                </span>
                <Sparkles className="h-5 w-5 text-sky-200/80" />
              </div>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Feed Volume
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {alertCount}
                </span>
                <TrendingUp className="h-5 w-5 text-emerald-200/80" />
              </div>
            </div>
          </div>
        </div>
      </motion.section>

      <motion.section
        {...ENTER}
        transition={{ ...ENTER.transition, delay: 0.06 }}
        className="space-y-4"
      >
        <div className="flex items-end justify-between gap-4">
          <div>
            <div className="section-kicker">Correlated Incidents</div>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Attack stories the judges can understand in one pass
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Alerts are grouped into incidents with confidence, blast radius,
              and the next executive or analyst action.
            </p>
          </div>
        </div>

        {activeIncidents.length > 0 ? (
          <div className="grid gap-4 xl:grid-cols-3">
            {activeIncidents.map((incident, index) => {
              const affectedAssets = toStringArray(incident.affectedAssets);
              const mitigationSteps = toStringArray(incident.remediationSteps);

              return (
                <motion.div
                  key={incident.id}
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.08 + index * 0.05, duration: 0.28 }}
                  className="surface-panel overflow-hidden p-5"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] ${getSeverityColor(
                            incident.severity
                          )}`}
                        >
                          {incident.severity}
                        </span>
                        <span
                          className={`rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em] ${getIncidentStatusColor(
                            incident.status
                          )}`}
                        >
                          {incident.status}
                        </span>
                      </div>
                      <div>
                        <p className="text-xs font-mono text-slate-500">
                          {incident.incidentId}
                        </p>
                        <h3 className="mt-1 text-lg font-semibold leading-7 text-white">
                          {incident.title}
                        </h3>
                      </div>
                    </div>

                    <div className="text-right text-xs text-slate-400">
                      <div>{incident.alertCount} linked alerts</div>
                      <div>{incident.affectedAssetCount} assets</div>
                    </div>
                  </div>

                  <p className="mt-4 text-sm leading-6 text-slate-300">
                    {incident.rootCause || "Correlation narrative pending."}
                  </p>

                  <div className="ambient-divider my-4" />

                  <div className="grid grid-cols-2 gap-3">
                    <div className="surface-panel-muted px-3 py-3">
                      <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                        Confidence
                      </p>
                      <p className="mt-2 text-2xl font-semibold text-white">
                        {Math.round(incident.confidenceScore * 100)}%
                      </p>
                    </div>
                    <div className="surface-panel-muted px-3 py-3">
                      <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                        Business Impact
                      </p>
                      <p className="mt-2 text-2xl font-semibold text-white">
                        {Math.round(incident.businessImpactScore)}
                      </p>
                    </div>
                  </div>

                  {affectedAssets.length > 0 ? (
                    <div className="mt-4">
                      <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                        Assets In Scope
                      </p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {affectedAssets.slice(0, 4).map((asset) => (
                          <span
                            key={asset}
                            className="rounded-full border border-white/8 bg-white/5 px-2.5 py-1 text-xs font-mono text-slate-200"
                          >
                            {asset}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  {mitigationSteps.length > 0 ? (
                    <div className="mt-4 rounded-2xl border border-sky-400/12 bg-sky-400/6 px-4 py-3">
                      <p className="text-[11px] uppercase tracking-[0.18em] text-sky-200/70">
                        Next Action
                      </p>
                      <p className="mt-2 text-sm leading-6 text-slate-100">
                        {mitigationSteps[0]}
                      </p>
                    </div>
                  ) : null}
                </motion.div>
              );
            })}
          </div>
        ) : (
          <Card className="surface-panel p-6 text-sm text-slate-300">
            No correlated incidents are active yet. Generate or stream alerts to
            see the storyline layer come alive.
          </Card>
        )}
      </motion.section>

      <motion.section
        {...ENTER}
        transition={{ ...ENTER.transition, delay: 0.12 }}
        className="space-y-4"
      >
        <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="section-kicker">Alert Feed</div>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Analyst-ready queue
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Scan severity, source, target, and status at a glance, then open a
              row only when you need the underlying evidence and triage controls.
            </p>
          </div>
          <div className="text-sm text-slate-400">
            {isLoading ? "Syncing alerts..." : `${alertCount} alerts in view`}
          </div>
        </div>

        {isLoading && alerts.length === 0 ? (
          <Card className="surface-panel p-10 text-center text-slate-400">
            Loading alerts...
          </Card>
        ) : alerts.length === 0 ? (
          <Card className="surface-panel p-10 text-center text-slate-400">
            No alerts found. The feed is currently quiet.
          </Card>
        ) : (
          <div className="space-y-3">
            {alerts.map((alert, index) => {
              const isExpanded = expandedId === alert.id;

              return (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.02 * index, duration: 0.24 }}
                  className="surface-panel overflow-hidden"
                >
                  <button
                    type="button"
                    onClick={() =>
                      setExpandedId(isExpanded ? null : alert.id)
                    }
                    className="group w-full px-5 py-5 text-left"
                  >
                    <div className="flex items-start gap-4">
                      <div
                        className={`mt-1 h-3 w-3 shrink-0 rounded-full shadow-[0_0_16px_rgba(255,255,255,0.32)] ${getSeverityGlow(
                          alert.severity
                        )}`}
                      />

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] ${getSeverityColor(
                              alert.severity
                            )}`}
                          >
                            {alert.severity}
                          </span>
                          <span className="rounded-full border border-white/8 bg-white/5 px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em] text-slate-300">
                            {alert.eventType}
                          </span>
                          <span
                            className={`rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em] ${getStatusColor(
                              alert.status
                            )}`}
                          >
                            {alert.status}
                          </span>
                        </div>

                        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1.4fr),minmax(0,0.8fr),minmax(0,0.8fr)]">
                          <div className="min-w-0">
                            <h3 className="truncate text-lg font-semibold text-white transition-colors group-hover:text-sky-100">
                              {alert.title}
                            </h3>
                            <p className="mt-1 text-sm text-slate-400">
                              {alert.eventId}
                            </p>
                          </div>
                          <div>
                            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                              Source
                            </p>
                            <p className="mt-2 truncate font-mono text-sm text-slate-200">
                              {alert.source}
                            </p>
                          </div>
                          <div>
                            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                              Target
                            </p>
                            <p className="mt-2 truncate font-mono text-sm text-slate-200">
                              {alert.target || "N/A"}
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="flex shrink-0 items-center gap-3 text-right">
                        <div className="text-xs text-slate-500">
                          {formatTime(alert.createdAt)}
                        </div>
                        <ChevronDown
                          className={`h-4 w-4 text-slate-500 transition-transform ${
                            isExpanded ? "rotate-180" : ""
                          }`}
                        />
                      </div>
                    </div>
                  </button>

                  <AnimatePresence initial={false}>
                    {isExpanded ? (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.22, ease: "easeOut" }}
                        className="overflow-hidden"
                      >
                        <div className="border-t border-white/8 px-5 pb-5 pt-4">
                          <div className="grid gap-5 xl:grid-cols-[1.25fr,0.95fr]">
                            <div className="space-y-4">
                              <div>
                                <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                                  Description
                                </p>
                                <p className="mt-2 text-sm leading-6 text-slate-200">
                                  {alert.description || "No analyst summary has been attached yet."}
                                </p>
                              </div>

                              {alert.rawData ? (
                                <div>
                                  <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                                    Raw Evidence
                                  </p>
                                  <pre className="mt-2 overflow-auto rounded-2xl border border-white/8 bg-black/18 p-4 text-xs leading-6 text-slate-300">
                                    {JSON.stringify(alert.rawData as Record<string, unknown>, null, 2)}
                                  </pre>
                                </div>
                              ) : null}
                            </div>

                            <div className="space-y-4">
                              <div className="surface-panel-muted p-4">
                                <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                                  Triage Actions
                                </p>
                                <div className="mt-3 flex flex-wrap gap-2">
                                  {alert.status !== "acknowledged" ? (
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        void handleAcknowledge(alert.id);
                                      }}
                                      disabled={updateStatusMutation.isPending}
                                      className="border-white/10 bg-white/4 text-slate-100 hover:bg-white/10"
                                    >
                                      <Check className="mr-2 h-3.5 w-3.5" />
                                      Acknowledge
                                    </Button>
                                  ) : null}
                                  {alert.status !== "escalated" ? (
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        void handleEscalate(alert.id);
                                      }}
                                      disabled={updateStatusMutation.isPending}
                                      className="border-white/10 bg-white/4 text-slate-100 hover:bg-white/10"
                                    >
                                      <Zap className="mr-2 h-3.5 w-3.5" />
                                      Escalate
                                    </Button>
                                  ) : null}
                                  {alert.status !== "dismissed" ? (
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        void handleDismiss(alert.id);
                                      }}
                                      disabled={updateStatusMutation.isPending}
                                      className="border-white/10 bg-white/4 text-slate-100 hover:bg-white/10"
                                    >
                                      <X className="mr-2 h-3.5 w-3.5" />
                                      Dismiss
                                    </Button>
                                  ) : null}
                                </div>
                              </div>

                              <div className="surface-panel-muted p-4">
                                <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                                  Change Severity
                                </p>
                                <div className="mt-3 flex flex-wrap gap-2">
                                  {["critical", "high", "medium", "low"].map((sev) => (
                                    <Button
                                      key={sev}
                                      size="sm"
                                      variant={alert.severity === sev ? "default" : "outline"}
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        void handleChangeSeverity(
                                          alert.id,
                                          sev as "critical" | "high" | "medium" | "low"
                                        );
                                      }}
                                      disabled={updateSeverityMutation.isPending}
                                      className={
                                        alert.severity === sev
                                          ? ""
                                          : "border-white/10 bg-white/4 text-slate-100 hover:bg-white/10"
                                      }
                                    >
                                      {sev}
                                    </Button>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    ) : null}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </div>
        )}
      </motion.section>
    </div>
  );
}
