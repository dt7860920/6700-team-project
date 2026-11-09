import type { TargetSummary } from "../api/types";

interface Props {
  targets: TargetSummary[];
  selected: string | null;
  onSelect: (id: string) => void;
  snippet: string;
  onSnippet: (code: string) => void;
  onAnalyze: () => void;
  busy: boolean;
}

export function TargetPicker({
  targets,
  selected,
  onSelect,
  snippet,
  onSnippet,
  onAnalyze,
  busy,
}: Props) {
  const current = targets.find((t) => t.target_id === selected) ?? null;
  const isSnippet = current?.target_id === "snippet";

  return (
    <div className="card">
      <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-muted">
        Authorized target
      </label>
      <div className="flex flex-col gap-3 sm:flex-row">
        <select
          className="flex-1 rounded-lg border border-edge bg-ground px-3 py-2 text-sm text-ink focus:border-accent focus:outline-none"
          value={selected ?? ""}
          onChange={(e) => onSelect(e.target.value)}
          disabled={busy}
        >
          <option value="" disabled>
            Choose a target…
          </option>
          {targets.map((t) => (
            <option key={t.target_id} value={t.target_id}>
              {t.name} · {t.kind}
            </option>
          ))}
        </select>
        <button className="btn-primary sm:w-40" onClick={onAnalyze} disabled={busy || !selected}>
          {busy ? "Scanning…" : "Analyze"}
        </button>
      </div>

      {current && (
        <div className="mt-3 text-sm text-muted">
          <p>{current.description}</p>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            <span>
              Languages:{" "}
              <span className="text-ink/80">{current.languages.join(", ") || "—"}</span>
            </span>
            {current.source && (
              <a
                href={current.source}
                target="_blank"
                rel="noreferrer"
                className="text-indigo-300 hover:text-indigo-200"
              >
                source ↗
              </a>
            )}
          </div>
        </div>
      )}

      {isSnippet && (
        <textarea
          className="mt-3 h-40 w-full rounded-lg border border-edge bg-ground p-3 font-mono text-xs text-ink focus:border-accent focus:outline-none"
          placeholder="Paste a code snippet to analyze…"
          value={snippet}
          onChange={(e) => onSnippet(e.target.value)}
          disabled={busy}
        />
      )}
    </div>
  );
}
