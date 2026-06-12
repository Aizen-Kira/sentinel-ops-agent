import { Suspense, lazy } from "react";

const Streamdown = lazy(async () => {
  const mod = await import("streamdown");
  return {
    default: mod.Streamdown,
  };
});

export function LazyStreamdown(props: { children: string }) {
  return (
    <Suspense fallback={<div className="text-sm text-slate-400">Rendering...</div>}>
      <Streamdown>{props.children}</Streamdown>
    </Suspense>
  );
}
