import type { InfoResponse, ScanStatus } from "../api/types";
import { Logo } from "./Logo";

export interface ScanSummary {
  scan_id: string;
  target_id: string;
  status: ScanStatus;
  created_at: string;
}

const STATUS_DOT: Record<ScanStatus, string> = {
  queued: "bg-faint",
  running: "bg-clay animate-pulse",
  done: "bg-ok",
  failed: "bg-sev-critical",
};

function relTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.round(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

interface Props {
  info: InfoResponse | null;
  history: ScanSummary[];
  activeScanId: string | null;
  onNew: () => void;
  onSelect: (scanId: string) => void;
}

export function Sidebar({ info, history, activeScanId, onNew, onSelect }: Props) {
  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-sand">
      {/* brand */}
      <div className="flex items-center gap-2.5 px-4 py-4">
        <Logo size={24} className="text-clay" />
        <div className="leading-tight">
          <div className="font-serif text-[15px] font-semibold text-ink">Negative One</div>
          <div className="text-xs text-muted">Security workbench</div>
        </div>
      </div>

      <div className="px-3 pb-3">
        <button className="btn-soft w-full justify-start" onClick={onNew}>
          <span aria-hidden className="text-base leading-none">＋</span> New scan
        </button>
      </div>

      {/* history */}
      <div className="flex min-h-0 flex-1 flex-col px-3">
        <div className="px-1 pb-2 text-xs font-medium uppercase tracking-wide text-faint">
          Recents
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
                    <span className="block truncate text-[13px] font-medium text-ink">
                      {s.target_id}
                    </span>
                    <span className="block truncate font-mono text-xs text-faint">
                      {s.scan_id} · {relTime(s.created_at)}
                    </span>
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* footer */}
      {info && (
        <div className="border-t border-border px-4 py-3 text-xs leading-relaxed text-muted">
          <div className="truncate" title={info.model_name}>
            <span className="text-clay">◆</span> {info.model_name}
          </div>
          <div className="text-faint">
            {info.environment} · {info.targets_registered} targets · v{info.version}
          </div>
        </div>
      )}
    </aside>
  );
}
