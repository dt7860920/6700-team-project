import { useEffect, useState } from "react";
import { Route, Routes, useNavigate } from "react-router-dom";
import { api, ApiError } from "./api/client";
import type { InfoResponse, TargetSummary } from "./api/types";
import { Sidebar, type ScanSummary } from "./components/Sidebar";
import { NewScanPage } from "./pages/NewScanPage";
import { ScanPage } from "./pages/ScanPage";
import { useScan } from "./hooks/useScan";

const HISTORY_KEY = "ono.history.v2";

function loadHistory(): ScanSummary[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as ScanSummary[]) : [];
  } catch {
    return [];
  }
}

export default function App() {
  const navigate = useNavigate();
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

  const targetName = (id: string) =>
    id === "snippet" ? "Code snippet" : (targets.find((t) => t.target_id === id)?.name ?? id);

  // Keep the sidebar history in sync with the active scan record.
  const rec = scan.scan;
  useEffect(() => {
    if (!rec) return;
    setHistory((prev) => {
      const summary: ScanSummary = {
        scan_id: rec.scan_id,
        name: targetName(rec.target_id),
        status: rec.status,
        created_at: rec.created_at,
        findings_count: rec.findings_count,
      };
      const next = [summary, ...prev.filter((s) => s.scan_id !== rec.scan_id)].slice(0, 30);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      } catch {
        /* storage may be unavailable; history stays in-memory */
      }
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rec?.scan_id, rec?.status, rec?.findings_count]);

  const busy = scan.phase === "starting" || scan.phase === "running";

  const onAnalyze = async () => {
    if (!selected) return;
    const started = await scan.start({
      target_id: selected,
      options: selected === "snippet" ? { snippet } : {},
    });
    if (started) navigate(`/scan/${started.scan_id}`);
  };

  const onNew = () => {
    scan.reset();
    navigate("/");
  };

  return (
    <div className="flex h-screen overflow-hidden">
      <div className="hidden md:flex">
        <Sidebar
          history={history}
          activeScanId={scan.scan?.scan_id ?? null}
          onNew={onNew}
          onSelect={(id) => navigate(`/scan/${id}`)}
        />
      </div>

      <main className="flex-1 overflow-y-auto">
        <Routes>
          <Route
            path="/"
            element={
              <NewScanPage
                targets={targets}
                selected={selected}
                onSelect={setSelected}
                snippet={snippet}
                onSnippet={setSnippet}
                onAnalyze={onAnalyze}
                busy={busy}
                info={info}
                loadError={loadError}
              />
            }
          />
          <Route path="/scan/:scanId" element={<ScanPage scan={scan} targets={targets} />} />
        </Routes>
      </main>
    </div>
  );
}
