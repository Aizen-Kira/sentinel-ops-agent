import { Suspense, lazy } from "react";
import { BarChart3, TrendingUp, AlertTriangle, Clock } from "lucide-react";
import { motion } from "framer-motion";
import { ConnectionStatus } from "@/components/ConnectionStatus";
import { DemoModeNotice } from "@/components/DemoModeNotice";
import { Card } from "@/components/ui/card";
import { useRealtime } from "@/hooks/useRealtime";
import { trpc } from "@/lib/trpc";

const MetricsCharts = lazy(() => import("@/components/MetricsCharts"));

const ENTER = {
  initial: { opacity: 0, y: 18 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.32, ease: [0.22, 1, 0.36, 1] as const },
};

export default function Metrics() {
  const { status: realtimeStatus } = useRealtime();
  const { data: metrics } = trpc.metrics.latest.useQuery();
  const { data: stats } = trpc.alerts.stats.useQuery();
  const { data: timeline = [] } = trpc.metrics.timeline.useQuery({ hours: 24 });

  const severityData = [
    { name: "Critical", value: stats?.critical || 0, fill: "#f87171" },
    { name: "High", value: stats?.high || 0, fill: "#fb923c" },
    { name: "Medium", value: stats?.medium || 0, fill: "#fbbf24" },
    { name: "Low", value: stats?.low || 0, fill: "#38bdf8" },
  ];

  const statusData = [
    { name: "Open", value: stats?.open || 0, fill: "#f87171" },
    { name: "Acknowledged", value: stats?.acknowledged || 0, fill: "#fbbf24" },
    { name: "Escalated", value: stats?.escalated || 0, fill: "#fb923c" },
    { name: "Dismissed", value: stats?.dismissed || 0, fill: "#34d399" },
  ];

  const timelineData = timeline.map((point) => ({
    time: point.label,
    alerts: point.alertCount,
  }));

  return (
    <div className="space-y-6">
      <motion.section
        {...ENTER}
        className="page-hero px-6 py-6 md:px-8 md:py-8"
      >
        <div className="relative space-y-8">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="max-w-3xl">
              <div className="section-kicker">Operations Metrics</div>
              <h1 className="mt-4 text-3xl font-semibold leading-tight text-white md:text-5xl">
                Show system health, not just charts.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300 md:text-base">
                Keep the KPI surface clean enough for a fast walkthrough while
                still exposing the alert mix, queue pressure, and response speed.
              </p>
              <div className="mt-4">
                <DemoModeNotice>
                  KPI values may be zero-filled or derived from seeded demo alerts when metric snapshots are unavailable.
                </DemoModeNotice>
              </div>
            </div>
            <ConnectionStatus status={realtimeStatus} />
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                MTTD
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {metrics?.mttd || "0"}m
                </span>
                <Clock className="h-5 w-5 text-sky-200/80" />
              </div>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                MTTA
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {metrics?.mtta || "0"}m
                </span>
                <TrendingUp className="h-5 w-5 text-amber-200/80" />
              </div>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                MTTR
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {metrics?.mttr || "0"}m
                </span>
                <Clock className="h-5 w-5 text-emerald-200/80" />
              </div>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Open Incidents
              </p>
              <div className="mt-3 flex items-end justify-between">
                <span className="text-3xl font-semibold text-white">
                  {metrics?.openIncidentCount || 0}
                </span>
                <AlertTriangle className="h-5 w-5 text-red-200/80" />
              </div>
            </div>
          </div>
        </div>
      </motion.section>

      <motion.div {...ENTER} transition={{ ...ENTER.transition, delay: 0.06 }}>
        <Suspense
          fallback={
            <Card className="surface-panel p-10 text-center text-slate-400">
              Loading chart surfaces...
            </Card>
          }
        >
          <MetricsCharts
            timelineData={timelineData}
            severityData={severityData}
            statusData={statusData}
          />
        </Suspense>
      </motion.div>

      <motion.div {...ENTER} transition={{ ...ENTER.transition, delay: 0.14 }}>
        <Card className="surface-panel p-6">
          <div className="flex items-start gap-3">
            <BarChart3 className="mt-0.5 h-5 w-5 text-sky-300" />
            <div>
              <h2 className="text-lg font-semibold text-white">Queue Readout</h2>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Heavy charts now load on demand so this page stays responsive on slower machines.
              </p>
            </div>
          </div>
        </Card>
      </motion.div>
    </div>
  );
}
