import { startTransition, useEffect, useState } from "react";
import {
  CheckCircle2,
  FileText,
  Loader2,
  Radar,
  Send,
  Sparkles,
} from "lucide-react";
import { motion } from "framer-motion";
import { ConnectionStatus } from "@/components/ConnectionStatus";
import { DemoModeNotice } from "@/components/DemoModeNotice";
import { LazyStreamdown } from "@/components/LazyStreamdown";
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

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const asStringArray = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

export default function Investigation() {
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([]);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [reasoningSteps, setReasoningSteps] = useState<string[]>([]);
  const [conclusion, setConclusion] = useState("");
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [confidence, setConfidence] = useState(0);
  const [analysisSource, setAnalysisSource] = useState("");
  const [localMode, setLocalMode] = useState(false);
  const [playbookId, setPlaybookId] = useState<string>("");
  const [reportId, setReportId] = useState<string | null>(null);
  const [reportStatus, setReportStatus] = useState<
    "idle" | "running" | "completed" | "failed"
  >("idle");
  const [reportProgress, setReportProgress] = useState("");

  const utils = trpc.useUtils();
  const { data: alerts = [] } = trpc.alerts.list.useQuery({ limit: 100, offset: 0 });

  const createInvestigationMutation = trpc.investigations.create.useMutation();
  const queueInvestigationMutation = trpc.investigations.streamReasoning.useMutation();
  const generateReportMutation = trpc.investigations.generateReport.useMutation();

  const jobQuery = trpc.investigations.getJob.useQuery(
    { jobId: jobId ?? "" },
    {
      enabled: Boolean(jobId),
      refetchInterval: isInvestigating ? 1500 : false,
    }
  );

  const reportQuery = trpc.investigations.getReport.useQuery(
    { investigationId: investigationId ?? "" },
    {
      enabled: Boolean(investigationId),
      refetchInterval: reportStatus === "running" ? 2000 : false,
    }
  );

  const { status: realtimeStatus } = useRealtime({
    investigationId,
    onInvestigationJobQueued: (event) => {
      if (event.investigationId !== investigationId) return;
      setJobId(event.jobId);
      setReasoningSteps((previous) =>
        previous.includes("Investigation job queued in the background worker.")
          ? previous
          : [...previous, "Investigation job queued in the background worker."]
      );
    },
    onInvestigationStage: (event) => {
      startTransition(() => {
        setReasoningSteps((previous) => {
          const result = asRecord(event.result);
          const summary =
            asStringArray(result.findings)[0] ??
            asStringArray(result.recommended_actions)[0] ??
            asStringArray(result.missing_data)[0] ??
            (typeof result.hypothesis === "string" ? result.hypothesis : null) ??
            "Stage completed.";
          const nextStep = `Local Analyst Mode / ${event.stage}: ${summary}`;
          return previous.includes(nextStep) ? previous : [...previous, nextStep];
        });
      });
    },
    onInvestigationStep: (event) => {
      startTransition(() => {
        setReasoningSteps((previous) =>
          previous.includes(event.step) ? previous : [...previous, event.step]
        );
      });
    },
    onInvestigationCompleted: (event) => {
      if (event.investigationId !== investigationId) return;
      setConclusion(event.conclusion);
      setConfidence(event.confidence);
      setAnalysisSource(
        event.localMode
          ? `Local Analyst Mode / ${event.model}`
          : `${event.provider} / ${event.model}`
      );
      setLocalMode(event.localMode);
      setPlaybookId(event.playbookId ?? "");
      setIsInvestigating(false);
    },
    onInvestigationFailed: (event) => {
      if (event.investigationId !== investigationId) return;
      setIsInvestigating(false);
      toast.error(`Investigation failed: ${event.error}`);
    },
    onReportStarted: (event) => {
      if (event.investigationId !== investigationId) return;
      setReportId(event.reportId);
      setReportStatus("running");
      setReportProgress("Preparing report workspace...");
    },
    onReportProgress: (event) => {
      if (event.investigationId !== investigationId) return;
      setReportStatus("running");
      setReportProgress(event.step);
    },
    onReportCompleted: (event) => {
      if (event.investigationId !== investigationId) return;
      setReportId(event.reportId);
      setReportStatus("completed");
      setReportProgress("Incident report ready.");
      void utils.investigations.getReport.invalidate({
        investigationId: event.investigationId,
      });
      toast.success("Incident report generated");
    },
    onReportFailed: (event) => {
      if (event.investigationId !== investigationId) return;
      setReportStatus("failed");
      setReportProgress(event.error);
      toast.error(`Report generation failed: ${event.error}`);
    },
  });

  useEffect(() => {
    if (!jobQuery.data) return;

    const artifact = asRecord(jobQuery.data.artifact);
    if (jobQuery.data.status === "done") {
      const reasoning =
        typeof artifact.reasoning === "string" ? artifact.reasoning : "";
      const steps = asStringArray(artifact.steps);
      const artifactConfidence =
        typeof artifact.confidence === "number" ? artifact.confidence : 0;
      const provider =
        typeof artifact.provider === "string" ? artifact.provider : "heuristic";
      const model = typeof artifact.model === "string" ? artifact.model : "unknown";
      const isLocal = artifact.localMode === true;
      const playbook = asRecord(artifact.playbook);

      setConclusion((previous) => previous || reasoning);
      setConfidence((previous) => previous || artifactConfidence);
      setReasoningSteps((previous) => (previous.length > 0 ? previous : steps));
      setAnalysisSource((previous) =>
        previous || (isLocal ? `Local Analyst Mode / ${model}` : `${provider} / ${model}`)
      );
      setLocalMode(isLocal);
      setPlaybookId((previous) =>
        previous || (typeof playbook.playbookId === "string" ? playbook.playbookId : "")
      );
      setIsInvestigating(false);
    }

    if (jobQuery.data.status === "failed") {
      setIsInvestigating(false);
    }
  }, [jobQuery.data]);

  const handleStartInvestigation = async () => {
    if (selectedAlertIds.length === 0) {
      toast.error("Please select at least one alert");
      return;
    }

    setIsInvestigating(true);
    setReasoningSteps([]);
    setConclusion("");
    setConfidence(0);
    setAnalysisSource("");
    setLocalMode(false);
    setPlaybookId("");
    setReportId(null);
    setReportStatus("idle");
    setReportProgress("");

    try {
      const investigation = await createInvestigationMutation.mutateAsync({
        alertIds: selectedAlertIds,
      });

      setInvestigationId(investigation.investigationId);

      const result = await queueInvestigationMutation.mutateAsync({
        investigationId: investigation.investigationId,
        alertIds: selectedAlertIds,
      });

      setJobId(result.jobId);
      setReasoningSteps([
        "Investigation accepted and queued for background analysis.",
      ]);
      toast.success("Investigation queued");
    } catch (error: any) {
      setIsInvestigating(false);
      toast.error(`Investigation failed: ${error.message}`);
    }
  };

  const handleGenerateReport = async () => {
    if (!investigationId) {
      toast.error("Run an investigation first");
      return;
    }

    setReportStatus("running");
    setReportProgress("Queueing incident report generation...");

    try {
      const result = await generateReportMutation.mutateAsync({
        investigationId,
      });
      setReportId(result.reportId);
    } catch (error: any) {
      setReportStatus("failed");
      setReportProgress(error.message);
      toast.error(`Report generation failed: ${error.message}`);
    }
  };

  const handleSelectAlert = (id: number) => {
    setSelectedAlertIds((prev) =>
      prev.includes(id) ? prev.filter((aid) => aid !== id) : [...prev, id]
    );
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
        return "border-white/10 bg-white/5 text-slate-200";
    }
  };

  return (
    <div className="space-y-6">
      <motion.section
        {...ENTER}
        className="page-hero px-6 py-6 md:px-8 md:py-8"
      >
        <div className="relative space-y-8">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="max-w-3xl space-y-4">
              <div className="section-kicker">Live Investigation</div>
              <div className="space-y-3">
                <h1 className="text-3xl font-semibold leading-tight text-white md:text-5xl">
                  Turn a noisy event set into one clear investigation story.
                </h1>
                <p className="max-w-2xl text-sm leading-7 text-slate-300 md:text-base">
                  Choose a cluster of alerts, queue the analyst job, and stream
                  the reasoning path live while the background worker builds the conclusion.
                </p>
                <DemoModeNotice>
                  Investigation analysis may use Local Analyst Mode or deterministic playbook fallback instead of a live LLM provider.
                </DemoModeNotice>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <ConnectionStatus status={realtimeStatus} />
              <div className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs uppercase tracking-[0.18em] text-slate-300">
                {selectedAlertIds.length} selected
              </div>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Available Alerts
              </p>
              <p className="mt-3 text-3xl font-semibold text-white">
                {alerts.length}
              </p>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Investigation State
              </p>
              <p className="mt-3 text-3xl font-semibold text-white">
                {isInvestigating ? "Queued" : investigationId ? "Ready" : "Idle"}
              </p>
            </div>
            <div className="metric-tile">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
                Analysis Engine
              </p>
              <p className="mt-3 text-base font-medium leading-7 text-white">
                {analysisSource || "Queued worker with realtime event spine"}
              </p>
            </div>
          </div>
        </div>
      </motion.section>

      <div className="grid gap-6 xl:grid-cols-[0.9fr,1.25fr]">
        <motion.section
          {...ENTER}
          transition={{ ...ENTER.transition, delay: 0.06 }}
          className="xl:sticky xl:top-6 xl:self-start"
        >
          <Card className="surface-panel overflow-hidden p-5">
            <div className="space-y-4">
              <div>
                <div className="section-kicker">Selection</div>
                <h2 className="mt-3 text-2xl font-semibold text-white">
                  Choose the incident slice
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Pick the alerts you want the analyst to explain. The strongest
                  demo path is a short sequence that clearly escalates.
                </p>
              </div>

              <div className="rounded-2xl border border-white/8 bg-black/10 p-2">
                <div className="max-h-[28rem] space-y-2 overflow-y-auto pr-1">
                  {alerts.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-white/10 px-4 py-8 text-center text-sm text-slate-400">
                      No alerts are available yet.
                    </div>
                  ) : (
                    alerts.map((alert) => {
                      const isSelected = selectedAlertIds.includes(alert.id);
                      return (
                        <label
                          key={alert.id}
                          className={`block cursor-pointer rounded-2xl border px-4 py-3 transition-all ${
                            isSelected
                              ? "border-sky-400/35 bg-sky-400/10 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
                              : "border-white/6 bg-white/3 hover:border-white/12 hover:bg-white/6"
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => handleSelectAlert(alert.id)}
                              className="mt-1"
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
                                <span className="text-xs font-mono text-slate-500">
                                  {alert.eventId}
                                </span>
                              </div>
                              <p className="mt-2 truncate text-sm font-medium text-white">
                                {alert.title}
                              </p>
                              <p className="mt-1 text-xs text-slate-400">
                                {alert.source} {alert.target ? `to ${alert.target}` : ""}
                              </p>
                            </div>
                          </div>
                        </label>
                      );
                    })
                  )}
                </div>
              </div>

              <div className="surface-panel-muted p-4">
                <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                  Launch
                </p>
                <p className="mt-2 text-sm leading-6 text-slate-300">
                  Start with 2 to 4 related alerts for the cleanest storyline.
                </p>
                <Button
                  onClick={handleStartInvestigation}
                  disabled={isInvestigating || selectedAlertIds.length === 0}
                  className="mt-4 w-full gap-2"
                >
                  {isInvestigating ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Queueing Investigation...
                    </>
                  ) : (
                    <>
                      <Send className="h-4 w-4" />
                      Start Investigation
                    </>
                  )}
                </Button>
              </div>
            </div>
          </Card>
        </motion.section>

        <motion.section
          {...ENTER}
          transition={{ ...ENTER.transition, delay: 0.1 }}
          className="space-y-4"
        >
          {!investigationId ? (
            <Card className="surface-panel flex min-h-[32rem] items-center justify-center p-10">
              <div className="max-w-lg text-center">
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-3xl bg-sky-400/10 text-sky-300">
                  <Radar className="h-8 w-8" />
                </div>
                <h2 className="mt-6 text-3xl font-semibold text-white">
                  Investigation workspace is standing by
                </h2>
                <p className="mt-3 text-sm leading-7 text-slate-400">
                  Select alerts on the left and launch the analyst. The queued
                  job state, streamed reasoning, and final conclusion will render here in realtime.
                </p>
              </div>
            </Card>
          ) : (
            <>
              <Card className="surface-panel p-5">
                <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
                  <div>
                    <div className="section-kicker">Reasoning Trace</div>
                    <h2 className="mt-3 text-2xl font-semibold text-white">
                      Streamed analyst narrative
                    </h2>
                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      Background jobs publish progress over the durable event spine,
                      so reconnects and report generation can catch up from stored state.
                    </p>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    <div className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs uppercase tracking-[0.18em] text-slate-300">
                      {investigationId}
                    </div>
                    {jobId ? (
                      <div className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-[11px] uppercase tracking-[0.18em] text-slate-400">
                        {jobId}
                      </div>
                    ) : null}
                  </div>
                </div>

                <div className="mt-6 space-y-3">
                  {reasoningSteps.length === 0 && isInvestigating ? (
                    <div className="flex items-center justify-center rounded-2xl border border-dashed border-white/10 px-6 py-16 text-slate-400">
                      <Loader2 className="mr-3 h-5 w-5 animate-spin" />
                      Waiting for background worker...
                    </div>
                  ) : (
                    reasoningSteps.map((step, idx) => (
                      <motion.div
                        key={`${idx}-${step}`}
                        initial={{ opacity: 0, y: 12 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.24 }}
                        className="relative overflow-hidden rounded-2xl border border-white/8 bg-white/4 px-5 py-4"
                      >
                        <div className="absolute left-0 top-0 h-full w-1 bg-gradient-to-b from-sky-400/80 to-transparent" />
                        <div className="flex gap-4">
                          <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-white/10 bg-sky-400/10 text-sm font-semibold text-sky-200">
                            {idx + 1}
                          </div>
                          <div className="min-w-0 flex-1 text-sm leading-7 text-slate-100">
                            <LazyStreamdown>{step}</LazyStreamdown>
                          </div>
                        </div>
                      </motion.div>
                    ))
                  )}
                </div>
              </Card>

              {conclusion ? (
                <Card className="surface-panel p-5">
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div>
                      <div className="section-kicker">Outcome</div>
                      <h2 className="mt-3 flex items-center gap-2 text-2xl font-semibold text-white">
                        <CheckCircle2 className="h-5 w-5 text-emerald-300" />
                        Investigation Conclusion
                      </h2>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      {analysisSource ? (
                        <div className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs uppercase tracking-[0.18em] text-slate-300">
                          {analysisSource}
                        </div>
                      ) : null}
                      {playbookId ? (
                        <div className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs uppercase tracking-[0.18em] text-slate-300">
                          {playbookId}
                        </div>
                      ) : null}
                    </div>
                  </div>

                  <div className="mt-6 grid gap-4 xl:grid-cols-[0.72fr,1.28fr]">
                    <div className="surface-panel-muted p-4">
                      <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                        Confidence
                      </p>
                      <div className="mt-3 flex items-end justify-between">
                        <span className="text-4xl font-semibold text-white">
                          {Math.round(confidence * 100)}%
                        </span>
                        <Sparkles className="h-5 w-5 text-sky-200/80" />
                      </div>
                      <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/8">
                        <div
                          className="h-full rounded-full bg-[linear-gradient(90deg,rgba(56,189,248,0.92),rgba(96,165,250,0.65))] transition-all"
                          style={{ width: `${confidence * 100}%` }}
                        />
                      </div>
                      {localMode ? (
                        <p className="mt-3 text-xs uppercase tracking-[0.18em] text-emerald-200">
                          Local Analyst Mode
                        </p>
                      ) : null}
                      {localMode ? (
                        <div className="mt-4">
                          <DemoModeNotice compact>
                            Local model output is a demo-friendly analysis path and should be validated against source telemetry.
                          </DemoModeNotice>
                        </div>
                      ) : null}
                    </div>

                    <div className="surface-panel-muted p-4">
                      <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                        Analyst Summary
                      </p>
                      <div className="mt-3 max-h-64 overflow-y-auto text-sm leading-7 text-slate-100">
                        <LazyStreamdown>{conclusion}</LazyStreamdown>
                      </div>
                    </div>
                  </div>

                  <Button
                    className="mt-5 w-full gap-2"
                    variant="default"
                    onClick={handleGenerateReport}
                    disabled={generateReportMutation.isPending || reportStatus === "running"}
                  >
                    {reportStatus === "running" ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Generating Incident Report...
                      </>
                    ) : (
                      <>
                        <FileText className="h-4 w-4" />
                        Generate Incident Report
                      </>
                    )}
                  </Button>

                  {reportProgress ? (
                    <p className="mt-3 text-sm text-slate-400">{reportProgress}</p>
                  ) : null}
                </Card>
              ) : null}

              {reportQuery.data?.content ? (
                <Card className="surface-panel p-5">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <div className="section-kicker">Report Artifact</div>
                      <h2 className="mt-3 text-2xl font-semibold text-white">
                        Timeline-derived incident report
                      </h2>
                    </div>
                    {reportId ? (
                      <div className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs uppercase tracking-[0.18em] text-slate-300">
                        {reportId}
                      </div>
                    ) : null}
                  </div>

                  <div className="mt-6 max-h-[32rem] overflow-y-auto rounded-2xl border border-white/8 bg-black/10 p-5 text-sm leading-7 text-slate-100">
                    <LazyStreamdown>{reportQuery.data.content}</LazyStreamdown>
                  </div>
                </Card>
              ) : null}
            </>
          )}
        </motion.section>
      </div>
    </div>
  );
}
