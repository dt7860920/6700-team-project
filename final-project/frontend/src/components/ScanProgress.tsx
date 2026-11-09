import type { Scan, StageName, StageStatus } from "../api/types";
import { STAGE_LABELS, STAGE_ORDER } from "../lib/labels";

// Merge the declared stage order with whatever the backend has reported so far,
// so every stage shows and completed ones carry their real status.
function stageStatus(scan: Scan, stage: StageName): StageStatus | "pending" | "active" {
  const done = scan.pipeline.find((s) => s.stage === stage);
  if (done) return done.status;
  // The first not-yet-reported stage while running is the active one.
  const reported = new Set(scan.pipeline.map((s) => s.stage));
  const firstPending = STAGE_ORDER.find((s) => !reported.has(s));
  if (scan.status === "running" && stage === firstPending) return "active";
  return "pending";
}

const DOT: Record<string, string> = {
  ok: "bg-emerald-400 border-emerald-400",
  skipped: "bg-muted/40 border-muted/40",
  failed: "bg-rose-400 border-rose-400",
  active: "bg-accent border-accent animate-pulse",
  pending: "bg-transparent border-edge",
};

export function ScanProgress({ scan }: { scan: Scan }) {
  const pct =
    scan.status === "done"
      ? 100
      : Math.round((scan.pipeline.length / STAGE_ORDER.length) * 100);

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 animate-pulse rounded-full bg-accent" />
          <span className="font-medium capitalize text-ink">{scan.status}</span>
          <span className="font-mono text-xs text-muted">{scan.scan_id}</span>
        </div>
        <span className="text-xs text-muted">{pct}%</span>
      </div>

      {/* progress bar */}
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-ground">
        <div
          className="h-full rounded-full bg-accent transition-all duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>

      {/* live message */}
      {scan.progress && (
        <div className="mt-3 font-mono text-sm text-ink/90">{scan.progress}</div>
      )}

      {/* stage rail */}
      <ol className="mt-4 grid grid-cols-5 gap-2">
        {STAGE_ORDER.map((stage) => {
          const st = stageStatus(scan, stage);
          const done = scan.pipeline.find((s) => s.stage === stage);
          return (
            <li key={stage} className="flex flex-col items-center text-center">
              <span className={`h-3 w-3 rounded-full border ${DOT[st]}`} />
              <span className="mt-1.5 text-[11px] leading-tight text-muted">
                {STAGE_LABELS[stage]}
              </span>
              {done?.summary && (
                <span className="mt-0.5 text-[10px] text-muted/70">{done.summary}</span>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
