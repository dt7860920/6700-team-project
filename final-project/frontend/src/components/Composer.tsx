import { useCallback, useRef, useState } from "react";
import type { InfoResponse, TargetSummary } from "../api/types";
import { Logo } from "./Logo";

interface Props {
  targets: TargetSummary[];
  selected: string | null;
  onSelect: (id: string) => void;
  snippet: string;
  onSnippet: (code: string) => void;
  onAnalyze: () => void;
  busy: boolean;
  info: InfoResponse | null;
}

const MAX_SNIPPET = 20_000; // matches ScanOptions.snippet max_length

export function Composer({
  targets,
  selected,
  onSelect,
  snippet,
  onSnippet,
  onAnalyze,
  busy,
  info,
}: Props) {
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const current = targets.find((t) => t.target_id === selected) ?? null;
  const isSnippet = current?.target_id === "snippet";

  const readFile = useCallback(
    (file: File) => {
      const reader = new FileReader();
      reader.onload = () => {
        onSelect("snippet");
        onSnippet(String(reader.result).slice(0, MAX_SNIPPET));
      };
      reader.readAsText(file);
    },
    [onSelect, onSnippet],
  );

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) readFile(file);
  };

  const canAnalyze = !busy && !!selected && (!isSnippet || snippet.trim().length > 0);

  return (
    <div className="mx-auto w-full max-w-2xl">
      {/* greeting */}
      <div className="mb-5 flex items-center justify-center gap-3">
        <Logo size={26} className="text-clay" />
        <h2 className="font-serif text-3xl font-normal text-ink">Let&apos;s find the real ones</h2>
      </div>

      {/* input box */}
      <div
        className={`rounded-[22px] border bg-card shadow-card transition ${
          dragging ? "border-clay ring-2 ring-clay/30" : "border-border"
        }`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        {isSnippet ? (
          <textarea
            className="h-32 w-full resize-none rounded-t-[22px] bg-transparent px-5 pt-4 font-mono text-[13px] text-ink placeholder:text-faint focus:outline-none"
            placeholder="Paste code to analyze, or drop a file…"
            value={snippet}
            onChange={(e) => onSnippet(e.target.value.slice(0, MAX_SNIPPET))}
            disabled={busy}
          />
        ) : (
          <div className="flex h-32 items-center px-5 pt-4 text-[15px] text-muted">
            {current ? (
              <span>
                {dragging ? "Drop a code file to analyze…" : current.description}
              </span>
            ) : (
              <span className="text-faint">Pick a target below, or choose “snippet” to paste code.</span>
            )}
          </div>
        )}

        {/* footer row */}
        <div className="flex items-center justify-between gap-2 px-3 pb-3 pt-1">
          <div className="flex items-center gap-1">
            <button
              type="button"
              className="flex h-9 w-9 items-center justify-center rounded-full text-xl text-muted transition hover:bg-sand hover:text-ink"
              onClick={() => fileRef.current?.click()}
              disabled={busy}
              title="Attach a code file"
              aria-label="Attach a code file"
            >
              ＋
            </button>
            {isSnippet && (
              <span className="font-mono text-xs text-faint">
                {snippet.length.toLocaleString()} / {MAX_SNIPPET.toLocaleString()}
              </span>
            )}
          </div>
          <button className="btn-primary px-5" onClick={onAnalyze} disabled={!canAnalyze}>
            {busy ? (
              <>
                <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                Scanning…
              </>
            ) : (
              <>
                Analyze <span aria-hidden>→</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* controls row (target · source · model) */}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 px-1 text-[13px]">
        <div className="flex items-center gap-2">
          <select
            className="rounded-lg border border-transparent bg-transparent py-1 pl-1 pr-2 font-medium text-body hover:border-border focus:border-clay focus:outline-none"
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
          {current?.source && (
            <a
              href={current.source}
              target="_blank"
              rel="noreferrer"
              className="text-claydeep hover:underline"
            >
              source ↗
            </a>
          )}
        </div>
        {info && (
          <span className="font-mono text-xs text-faint">
            {info.model_name} · {info.model_backend}
          </span>
        )}
      </div>

      <input
        ref={fileRef}
        type="file"
        accept=".py,.js,.ts,.java,.go,.rb,.php,.c,.cpp,.cs,.txt,text/*"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) readFile(file);
          e.target.value = "";
        }}
      />
    </div>
  );
}
