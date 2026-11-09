import { useEffect, useState } from "react";
import { api, ApiError } from "./api/client";
import type { InfoResponse, TargetSummary } from "./api/types";
import { Header } from "./components/Header";
import { TargetPicker } from "./components/TargetPicker";
import { ScanProgress } from "./components/ScanProgress";
import { FindingsList } from "./components/FindingsList";
import { useScan } from "./hooks/useScan";

export default function App() {
  const [info, setInfo] = useState<InfoResponse | null>(null);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [snippet, setSnippet] = useState("");

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
        setLoadError(
          err instanceof ApiError ? err.detail : "Could not load targets from the API.",
        );
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const busy = scan.phase === "starting" || scan.phase === "running";

  const onAnalyze = () => {
    if (!selected) return;
    scan.start({
      target_id: selected,
      options: selected === "snippet" ? { snippet } : {},
    });
  };

  return (
    <div className="min-h-screen">
      <Header info={info} />
      <main className="mx-auto max-w-3xl space-y-5 px-4 py-6">
        {loadError && (
          <div className="card border-rose-500/40 text-sm text-rose-200">{loadError}</div>
        )}

        <TargetPicker
          targets={targets}
          selected={selected}
          onSelect={setSelected}
          snippet={snippet}
          onSnippet={setSnippet}
          onAnalyze={onAnalyze}
          busy={busy}
        />

        {scan.error && (
          <div className="card border-rose-500/40 text-sm text-rose-200">{scan.error}</div>
        )}

        {scan.scan && scan.phase !== "done" && <ScanProgress scan={scan.scan} />}

        {scan.phase === "done" && scan.scan && (
          <>
            <ScanProgress scan={scan.scan} />
            <FindingsList scan={scan.scan} findings={scan.findings} />
          </>
        )}
      </main>
    </div>
  );
}
