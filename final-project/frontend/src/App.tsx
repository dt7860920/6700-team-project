import { useEffect, useState } from "react";
import { Route, Routes, useNavigate } from "react-router-dom";
import { api, ApiError, redirectToLogin } from "./api/client";
import type { InfoResponse, Me, SourceCheck, TargetSummary } from "./api/types";
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
  const [repoUrl, setRepoUrl] = useState("");
  const [repoCheck, setRepoCheck] = useState<SourceCheck | null>(null);
  const [repoChecking, setRepoChecking] = useState(false);
  const [repoCheckError, setRepoCheckError] = useState<string | null>(null);
  const [authorizedToScan, setAuthorizedToScan] = useState(false);
  const [history, setHistory] = useState<ScanSummary[]>(loadHistory);
  const [me, setMe] = useState<Me | null>(null);

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
        if (i.auth_required) {
          const m = await api.me();
          if (alive) setMe(m);
        }
      } catch (err) {
        if (!alive) return;
        setLoadError(err instanceof ApiError ? err.detail : "Could not load targets from the API.");
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const onSignOut = async () => {
    try {
      await api.logout();
    } finally {
      setMe(null);
    }
  };

  const targetName = (id: string) =>
    id === "snippet" ? "Code snippet" : (targets.find((t) => t.target_id === id)?.name ?? id);

  // Keep the sidebar history in sync with the active scan record.
  const rec = scan.scan;
  useEffect(() => {
    if (!rec) return;
    setHistory((prev) => {
      const summary: ScanSummary = {
        scan_id: rec.scan_id,
        name: rec.target_name ?? targetName(rec.target_id),
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
    const body = selected === "public-github"
      ? { repo_url: repoUrl, authorized_to_scan: authorizedToScan }
      : { target_id: selected, options: selected === "snippet" ? { snippet } : {} };
    const started = await scan.start(body);
    if (started) navigate(`/scan/${started.scan_id}`);
  };

  const onRepoUrl = (value: string) => {
    setRepoUrl(value);
    setRepoCheck(null);
    setRepoCheckError(null);
    setAuthorizedToScan(false);
  };

  const onCheckSource = async () => {
    setRepoChecking(true);
    setRepoCheckError(null);
    setRepoCheck(null);
    try {
      setRepoCheck(await api.checkSource(repoUrl));
    } catch (err) {
      setRepoCheckError(err instanceof ApiError ? err.detail : "Could not check this repository.");
    } finally {
      setRepoChecking(false);
    }
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
          authRequired={!!info?.auth_required}
          me={me}
          onSignIn={redirectToLogin}
          onSignOut={onSignOut}
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
                repoUrl={repoUrl}
                onRepoUrl={onRepoUrl}
                repoCheck={repoCheck}
                repoChecking={repoChecking}
                repoCheckError={repoCheckError}
                onCheckSource={onCheckSource}
                authorizedToScan={authorizedToScan}
                onAuthorizedToScan={setAuthorizedToScan}
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
