import type { Me, ScanStatus } from "../api/types";
import { Logo } from "./Logo";

export interface ScanSummary {
  scan_id: string;
  name: string; // friendly target name (resolved at creation)
  status: ScanStatus;
  created_at: string;
  findings_count: number;
}

const STATUS_DOT: Record<ScanStatus, string> = {
  queued: "bg-faint",
  running: "bg-clay animate-pulse",
  done: "bg-ok",
  failed: "bg-sev-critical",
};

function subtitle(s: ScanSummary): string {
  const t = relTime(s.created_at);
  if (s.status === "running" || s.status === "queued") return `scanning… · ${t}`;
  if (s.status === "failed") return `failed · ${t}`;
  const n = s.findings_count;
  return `${n} finding${n === 1 ? "" : "s"} · ${t}`;
}

function relTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.round(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function GithubMark() {
  return (
    <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden fill="currentColor">
      <path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.5 7.5 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

interface Props {
  history: ScanSummary[];
  activeScanId: string | null;
  onNew: () => void;
  onSelect: (scanId: string) => void;
  authRequired: boolean;
  me: Me | null;
  onSignIn: () => void;
  onSignOut: () => void;
}

export function Sidebar({
  history,
  activeScanId,
  onNew,
  onSelect,
  authRequired,
  me,
  onSignIn,
  onSignOut,
}: Props) {
  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-sand">
      {/* brand */}
      <button
        className="flex items-center gap-2.5 px-4 py-4 text-left"
        onClick={onNew}
        title="Operation: Negative One"
      >
        <Logo size={24} className="text-clay" />
        <div className="leading-tight">
          <div className="font-serif text-[15px] font-semibold text-ink">Negative One</div>
          <div className="text-xs text-muted">Security workbench</div>
        </div>
      </button>

      <div className="px-3 pb-3">
        <button className="btn-soft w-full justify-start" onClick={onNew}>
          <span aria-hidden className="text-base leading-none">＋</span> New scan
        </button>
      </div>

      {/* recents */}
      <div className="flex min-h-0 flex-1 flex-col px-3">
        <div className="px-1 pb-2 text-xs font-medium uppercase tracking-wide text-faint">
          Recent scans
        </div>
        <div className="min-h-0 flex-1 space-y-0.5 overflow-y-auto pb-3">
          {history.length === 0 ? (
            <p className="px-1 text-xs text-faint">No scans yet.</p>
          ) : (
            history.map((s) => {
              const active = s.scan_id === activeScanId;
              return (
                <button
                  key={s.scan_id}
                  onClick={() => onSelect(s.scan_id)}
                  className={`flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left transition ${
                    active ? "bg-claysoft" : "hover:bg-border/50"
                  }`}
                >
                  <span className={`h-2 w-2 shrink-0 rounded-full ${STATUS_DOT[s.status]}`} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px] font-medium text-ink">{s.name}</span>
                    <span className="block truncate text-xs text-faint">{subtitle(s)}</span>
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* account — only shown once the backend reports auth is required */}
      {authRequired && (
        <div className="border-t border-border p-3">
          {me ? (
            <div className="flex items-center gap-2">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-claysoft text-xs font-semibold text-claydeep">
                {me.login.slice(0, 1).toUpperCase()}
              </span>
              <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-ink">
                @{me.login}
              </span>
              <button
                onClick={onSignOut}
                className="text-xs text-muted hover:text-ink"
                title="Sign out"
              >
                Sign out
              </button>
            </div>
          ) : (
            <button className="btn-soft w-full justify-center gap-2" onClick={onSignIn}>
              <GithubMark /> Sign in with GitHub
            </button>
          )}
        </div>
      )}
    </aside>
  );
}
