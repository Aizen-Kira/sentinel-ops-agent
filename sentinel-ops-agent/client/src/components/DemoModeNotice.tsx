import { Info } from "lucide-react";
import type React from "react";
import { DEMO_MODE } from "@/lib/demoMode";
import { cn } from "@/lib/utils";

type DemoModeNoticeProps = {
  children: React.ReactNode;
  className?: string;
  compact?: boolean;
  title?: string;
};

export function DemoModeNotice({
  children,
  className,
  compact = false,
  title = "Demo Mode",
}: DemoModeNoticeProps) {
  if (!DEMO_MODE) {
    return null;
  }

  return (
    <div
      className={cn(
        "inline-flex items-start gap-2 rounded-2xl border border-sky-400/18 bg-sky-400/8 text-sky-100 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]",
        compact ? "px-3 py-2 text-xs" : "px-4 py-3 text-sm",
        className
      )}
      title={`${title}: ${textFromChildren(children)}`}
    >
      <Info className={cn("mt-0.5 shrink-0 text-sky-300", compact ? "h-3.5 w-3.5" : "h-4 w-4")} />
      <span className="leading-5">
        <span className="font-semibold">{title}:</span> {children}
      </span>
    </div>
  );
}

export function DemoModeBadge({ label = "Demo Mode" }: { label?: string }) {
  if (!DEMO_MODE) {
    return null;
  }

  return (
    <span
      className="rounded-full border border-sky-400/20 bg-sky-400/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-sky-100"
      title="This feature is showing demo, mocked, or fallback behavior."
    >
      {label}
    </span>
  );
}

function textFromChildren(children: React.ReactNode): string {
  if (typeof children === "string" || typeof children === "number") {
    return String(children);
  }
  return "This feature is showing demo, mocked, or fallback behavior.";
}
