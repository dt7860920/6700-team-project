import { useEffect } from "react";
import { useParams } from "react-router-dom";
import type { TargetSummary } from "../api/types";
import { ActivityLog } from "../components/ActivityLog";
import { FindingsList } from "../components/FindingsList";
import { WorkflowGraph } from "../components/WorkflowGraph";
import type { useScan } from "../hooks/useScan";

const STATUS_TONE: Record<string, string> = {
  done: "text-ok",
  failed: "text-sev-critical",
  running: "text-clay",
  queued: "text-muted",
};

interface Props {
  scan: ReturnType<typeof useScan>;
  targets: TargetSummary[];
}

export function ScanPage({ scan, targets }: Props) {
  const { scanId } = useParams();
  const load = scan.load;

  // Load (and start polling) the scan named in the URL, unless it is already
  // the one this controller is tracking (e.g. we just started it).
  useEffect(() => {
    if (scanId && scan.scan?.scan_id !== scanId) load(scanId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const s = scan.scan;
  const running = scan.phase === "starting" || scan.phase === "running";

  const targetName = (id: string) =>
    id === "snippet" ? "Code snippet" : (targets.find((t) => t.target_id === id)?.name ?? id);

  const pct = s ? (s.status === "done" ? 100 : Math.round((s.pipeline.length / 5) * 100)) : 0;

  return (
    <div className="mx-auto max-w-4xl space-y-5 px-4 py-8 md:px-8">
      {/* header */}
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="font-serif text-2xl font-normal text-ink">
          {s ? targetName(s.target_id) : scanId ? "Loading scan…" : "Scan"}
        </h1>
        {s && (
          <div className="flex items-center gap-3 font-mono text-xs">
            <span className={`font-semibold capitalize ${STATUS_TONE[s.status]}`}>{s.status}</span>
            <span className="text-faint">{s.scan_id}</span>
            <span className="text-faint">{pct}%</span>
          </div>
        )}
      </div>

      {scan.error && (
        <div className="card border-sev-critical/40 text-sm text-sev-critical">{scan.error}</div>
      )}

      {s && (
        <>
          {s.progress && (
            <div className="font-mono text-sm text-muted">
              <span className="text-clay">›</span> {s.progress}
            </div>
          )}
          <WorkflowGraph scan={s} />
          <ActivityLog events={s.events} live={running} />
          {scan.phase === "done" && <FindingsList scan={s} findings={scan.findings} />}
        </>
      )}
    </div>
  );
}
