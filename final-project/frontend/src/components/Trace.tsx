import type { TraceStep } from "../api/types";

export function Trace({ steps }: { steps: TraceStep[] }) {
  if (steps.length === 0) return null;
  return (
    <div className="mt-4">
      <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
        Source → sink trace
      </div>
      <ol className="space-y-2">
        {steps.map((step, i) => (
          <li key={`${step.file}:${step.line}:${i}`} className="flex gap-3">
            <div className="flex flex-col items-center">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-edge bg-ground text-[10px] text-muted">
                {i + 1}
              </span>
              {i < steps.length - 1 && <span className="w-px flex-1 bg-edge" />}
            </div>
            <div className="pb-1">
              <div className="font-mono text-xs text-ink">
                {step.file}:{step.line}{" "}
                <span className="text-indigo-300">{step.symbol}</span>
              </div>
              {step.note && <div className="text-xs text-muted">{step.note}</div>}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
