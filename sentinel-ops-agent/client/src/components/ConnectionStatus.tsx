import type { RealtimeConnectionStatus } from "@shared/realtime";

const STATUS_STYLES: Record<
  RealtimeConnectionStatus,
  { dot: string; label: string }
> = {
  connected: {
    dot: "bg-emerald-400",
    label: "Live",
  },
  connecting: {
    dot: "bg-amber-400 animate-pulse",
    label: "Connecting",
  },
  reconnecting: {
    dot: "bg-amber-400 animate-pulse",
    label: "Reconnecting",
  },
  disconnected: {
    dot: "bg-muted-foreground/50",
    label: "Offline",
  },
};

export function ConnectionStatus({
  status,
}: {
  status: RealtimeConnectionStatus;
}) {
  const style = STATUS_STYLES[status];

  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/4 px-3 py-1.5 text-[11px] font-medium uppercase tracking-[0.18em] text-muted-foreground backdrop-blur-xl">
      <span className={`h-2 w-2 rounded-full shadow-[0_0_14px_rgba(74,222,128,0.55)] ${style.dot}`} />
      <span>{style.label}</span>
    </div>
  );
}
