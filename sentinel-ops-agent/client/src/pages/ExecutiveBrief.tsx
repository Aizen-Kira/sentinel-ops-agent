import { Building2, ShieldAlert, Activity, TriangleAlert } from "lucide-react";
import { motion } from "framer-motion";
import { ConnectionStatus } from "@/components/ConnectionStatus";
import { DemoModeNotice } from "@/components/DemoModeNotice";
import { Card } from "@/components/ui/card";
import { useRealtime } from "@/hooks/useRealtime";
import { trpc } from "@/lib/trpc";

const RISK_STYLES = {
  stable: {
    badge: "border-emerald-500/25 bg-emerald-500/12 text-emerald-100",
    accent: "text-emerald-200",
  },
  elevated: {
    badge: "border-amber-500/25 bg-amber-500/12 text-amber-100",
    accent: "text-amber-100",
  },
  critical: {
    badge: "border-red-500/25 bg-red-500/12 text-red-100",
    accent: "text-red-100",
  },
} as const;

const ENTER = {
  initial: { opacity: 0, y: 18 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.32, ease: [0.22, 1, 0.36, 1] as const },
};

export default function ExecutiveBrief() {
  const { status: realtimeStatus } = useRealtime();
  const { data: brief, isLoading } = trpc.briefings.ceo.useQuery();

  if (isLoading || !brief) {
    return (
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="flex items-center gap-2 text-3xl font-bold tracking-tight">
              <Building2 className="h-8 w-8 text-sky-400" />
              CEO Brief
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Executive summary of active cyber risk and required decisions
            </p>
          </div>
          <ConnectionStatus status={realtimeStatus} />
        </div>
        <Card className="surface-panel p-8 text-center text-muted-foreground">
          Loading executive brief...
        </Card>
      </div>
    );
  }

  const riskStyle = RISK_STYLES[brief.riskLevel];
  const generatedAt = new Date(brief.generatedAt).toLocaleString();
  const generationLabel =
    brief.generatedBy.mode === "ai-assisted"
      ? `${brief.generatedBy.provider} / ${brief.generatedBy.model}`
      : "rule-based fallback";

  return (
    <div className="space-y-6">
      <motion.section
        {...ENTER}
        className="page-hero px-6 py-6 md:px-8 md:py-8"
      >
        <div className="relative space-y-8">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="max-w-3xl">
              <div className="section-kicker">Executive Briefing</div>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <span
                  className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] ${riskStyle.badge}`}
                >
                  {brief.riskLevel} risk
                </span>
                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-slate-300">
                  {generationLabel}
                </span>
                <span className="text-xs uppercase tracking-[0.18em] text-slate-500">
                  Updated {generatedAt}
                </span>
              </div>
              <div className="mt-4">
                <DemoModeNotice>
                  {brief.generatedBy.mode === "rule-based"
                    ? "This executive brief is using the rule-based fallback when no live AI provider is available."
                    : "AI-assisted copy may still be grounded in seeded or simulated incident data."}
                </DemoModeNotice>
              </div>
              <h1 className="mt-5 max-w-4xl text-3xl font-semibold leading-tight text-white md:text-5xl">
                {brief.headline}
              </h1>
              <p className="mt-4 max-w-3xl text-sm leading-7 text-slate-300 md:text-base">
                {brief.summary}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <ConnectionStatus status={realtimeStatus} />
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-[1.35fr,0.65fr]">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="metric-tile">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                  Active Incidents
                </p>
                <div className="mt-3 flex items-end justify-between">
                  <span className="text-3xl font-semibold text-white">
                    {brief.activeIncidentCount}
                  </span>
                  <ShieldAlert className="h-5 w-5 text-red-200/75" />
                </div>
              </div>
              <div className="metric-tile">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                  Business Risk
                </p>
                <div className="mt-3 flex items-end justify-between">
                  <span className={`text-3xl font-semibold ${riskStyle.accent}`}>
                    {brief.businessRiskScore}
                  </span>
                  <TriangleAlert className="h-5 w-5 text-amber-200/75" />
                </div>
              </div>
              <div className="metric-tile">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                  Assets At Risk
                </p>
                <div className="mt-3 flex items-end justify-between">
                  <span className="text-3xl font-semibold text-white">
                    {brief.affectedAssetCount}
                  </span>
                  <Activity className="h-5 w-5 text-sky-200/75" />
                </div>
              </div>
              <div className="metric-tile">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                  Critical Alerts
                </p>
                <div className="mt-3 flex items-end justify-between">
                  <span className="text-3xl font-semibold text-white">
                    {brief.criticalAlertCount}
                  </span>
                  <ShieldAlert className="h-5 w-5 text-orange-200/75" />
                </div>
              </div>
            </div>

            <div className="rounded-[1.35rem] border border-sky-400/14 bg-sky-400/7 p-5">
              <p className="text-xs uppercase tracking-[0.18em] text-sky-200/72">
                Immediate Decision
              </p>
              <p className="mt-3 text-sm leading-7 text-slate-50">
                {brief.urgentDecision}
              </p>
            </div>
          </div>
        </div>
      </motion.section>

      <div className="grid gap-6 xl:grid-cols-[1.35fr,0.65fr]">
        <motion.section
          {...ENTER}
          transition={{ ...ENTER.transition, delay: 0.06 }}
          className="space-y-4"
        >
          <div>
            <div className="section-kicker">Top Business Risks</div>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Incidents worth executive attention
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              These incident summaries keep the technical evidence visible while
              translating it into operational and customer impact.
            </p>
          </div>

          {brief.topIncidents.length === 0 ? (
            <Card className="surface-panel p-6 text-slate-400">
              No active incidents currently require executive action.
            </Card>
          ) : (
            brief.topIncidents.map((incident, index) => (
              <motion.div
                key={incident.incidentId}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.08 + index * 0.05, duration: 0.28 }}
                className="surface-panel overflow-hidden p-5"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-full border border-white/8 bg-white/5 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                        {incident.incidentId}
                      </span>
                      <span
                        className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] ${
                          RISK_STYLES[
                            incident.businessImpactScore >= 75
                              ? "critical"
                              : incident.businessImpactScore >= 45
                                ? "elevated"
                                : "stable"
                          ].badge
                        }`}
                      >
                        {incident.status}
                      </span>
                    </div>
                    <h3 className="text-xl font-semibold leading-7 text-white">
                      {incident.title}
                    </h3>
                    <p className="text-sm leading-6 text-slate-300">
                      {incident.customerImpact}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-right">
                    <div className="surface-panel-muted px-3 py-3">
                      <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                        Confidence
                      </div>
                      <div className="mt-2 text-lg font-semibold text-white">
                        {Math.round(incident.confidenceScore * 100)}%
                      </div>
                    </div>
                    <div className="surface-panel-muted px-3 py-3">
                      <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                        Impact
                      </div>
                      <div className="mt-2 text-lg font-semibold text-white">
                        {Math.round(incident.businessImpactScore)}/100
                      </div>
                    </div>
                  </div>
                </div>

                {incident.storyline.length > 0 ? (
                  <div className="mt-5">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                      Storyline
                    </p>
                    <div className="mt-3 space-y-2">
                      {incident.storyline.slice(0, 4).map((line) => (
                        <div
                          key={line}
                          className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-sm text-slate-100"
                        >
                          {line}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}

                {incident.affectedAssets.length > 0 ? (
                  <div className="mt-5">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                      Assets In Scope
                    </p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {incident.affectedAssets.slice(0, 6).map((asset) => (
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

                <div className="mt-5 rounded-[1.2rem] border border-sky-400/14 bg-sky-400/7 px-4 py-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-sky-200/70">
                    Recommended Executive Action
                  </p>
                  <p className="mt-2 text-sm leading-6 text-slate-100">
                    {incident.recommendedAction}
                  </p>
                </div>
              </motion.div>
            ))
          )}
        </motion.section>

        <motion.section
          {...ENTER}
          transition={{ ...ENTER.transition, delay: 0.1 }}
          className="space-y-4"
        >
          <Card className="surface-panel p-5">
            <h2 className="text-lg font-semibold text-white">Key Points</h2>
            <div className="mt-4 space-y-3">
              {brief.keyPoints.map((point) => (
                <div
                  key={point}
                  className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-sm leading-6 text-slate-200"
                >
                  {point}
                </div>
              ))}
            </div>
          </Card>

          <Card className="surface-panel p-5">
            <h2 className="text-lg font-semibold text-white">Decisions Needed</h2>
            <div className="mt-4 space-y-3">
              {brief.decisionsNeeded.map((decision) => (
                <div
                  key={decision}
                  className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-sm leading-6 text-slate-100"
                >
                  {decision}
                </div>
              ))}
            </div>
          </Card>

          <Card className="surface-panel p-5">
            <h2 className="text-lg font-semibold text-white">Watch Items</h2>
            <div className="mt-4 space-y-3">
              {brief.watchItems.map((item) => (
                <div
                  key={item}
                  className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-sm leading-6 text-slate-300"
                >
                  {item}
                </div>
              ))}
            </div>
          </Card>
        </motion.section>
      </div>
    </div>
  );
}
