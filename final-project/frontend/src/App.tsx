import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "./api/client";
import type { InfoResponse, TargetSummary } from "./api/types";
import { Composer } from "./components/Composer";
import { FindingsList } from "./components/FindingsList";
import { Sidebar, type ScanSummary } from "./components/Sidebar";
import { WorkflowGraph } from "./components/WorkflowGraph";
import { useScan } from "./hooks/useScan";

const HISTORY_KEY = "ono.history.v1";

function loadHistory(): ScanSummary[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as ScanSummary[]) : [];
  } catch {
    return [];
  }
}

const STATUS_TONE: Record<string, string> = {
  done: "text-ok",
  failed: "text-sev-critical",
  running: "text-clay",
  queued: "text-muted",
};

export default function App() {
  const [info, setInfo] = useState<InfoResponse | null>(null);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [snippet, setSnippet] = useState("");
  const [history, setHistory] = useState<ScanSummary[]>(loadHistory);

  const scan = useScan();

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const [i, t] = await Promise.all([api.info(), api.targets()]);
        if (!alive) return;
        setInfo(i);
        setTargets(t.targets);
        if (t.targets.length > 0) setSelected(t.targets[0].target_id);
      } catch (err) {
        if (!alive) return;
        setLoadError(err instanceof ApiError ? err.detail : "Could not load targets from the API.");
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  // Keep the sidebar history in sync with the active scan record.
  const rec = scan.scan;
  useEffect(() => {
    if (!rec) return;
    setHistory((prev) => {
      const summary: ScanSummary = {
        scan_id: rec.scan_id,
        target_id: rec.target_id,
        status: rec.status,
        created_at: rec.created_at,
      };
      const next = [summary, ...prev.filter((s) => s.scan_id !== rec.scan_id)].slice(0, 30);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      } catch {
        /* storage may be unavailable; history stays in-memory */
      }
      return next;
    });
  }, [rec?.scan_id, rec?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const busy = scan.phase === "starting" || scan.phase === "running";
  const hasScan = scan.scan !== null;

  const onAnalyze = () => {
    if (!selected) return;
    scan.start({ target_id: selected, options: selected === "snippet" ? { snippet } : {} });
  };
  const onNew = () => {
    scan.reset();
    setSnippet("");
  };

  const pct = useMemo(() => {
    if (!scan.scan) return 0;
    return scan.scan.status === "done" ? 100 : Math.round((scan.scan.pipeline.length / 5) * 100);
  }, [scan.scan]);

  return (
    <div className="flex h-screen overflow-hidden">
      <div className="hidden md:flex">
        <Sidebar
          info={info}
          history={history}
          activeScanId={scan.scan?.scan_id ?? null}
          onNew={onNew}
          onSelect={(id) => scan.load(id)}
        />
      </div>

      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-4xl space-y-6 px-4 py-10 md:px-8 md:py-14">
          {loadError && (
            <div className="card border-sev-critical/40 text-sm text-sev-critical">{loadError}</div>
          )}

          <Composer
            targets={targets}
            selected={selected}
            onSelect={setSelected}
            snippet={snippet}
            onSnippet={setSnippet}
            onAnalyze={onAnalyze}
            busy={busy}
            info={info}
          />

          {scan.error && (
            <div className="card border-sev-critical/40 text-sm text-sev-critical">{scan.error}</div>
          )}

          {hasScan && scan.scan && (
            <section className="space-y-3">
              {/* status line */}
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs">
                <span className={`font-semibold capitalize ${STATUS_TONE[scan.scan.status]}`}>
                  {scan.scan.status}
                </span>
                <span className="text-faint">{scan.scan.scan_id}</span>
                <span className="text-faint">{pct}%</span>
                {scan.scan.progress && (
                  <span className="text-muted">
                    <span className="text-clay">›</span> {scan.scan.progress}
                  </span>
                )}
              </div>
              <WorkflowGraph scan={scan.scan} />
            </section>
          )}

          {scan.phase === "done" && scan.scan && (
            <FindingsList scan={scan.scan} findings={scan.findings} />
          )}
        </div>
      </main>
    </div>
  );
}
