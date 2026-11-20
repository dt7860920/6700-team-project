import { useCallback, useRef, useState } from "react";
import type { InfoResponse, SourceCheck, TargetSummary } from "../api/types";
import { Logo } from "./Logo";

interface Props {
  targets: TargetSummary[];
  selected: string | null;
  onSelect: (id: string) => void;
  snippet: string;
  onSnippet: (code: string) => void;
  repoUrl: string;
  onRepoUrl: (value: string) => void;
  repoCheck: SourceCheck | null;
  repoChecking: boolean;
  repoCheckError: string | null;
  onCheckSource: () => void;
  authorizedToScan: boolean;
  onAuthorizedToScan: (value: boolean) => void;
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
  repoUrl,
  onRepoUrl,
  repoCheck,
  repoChecking,
  repoCheckError,
  onCheckSource,
  authorizedToScan,
  onAuthorizedToScan,
  onAnalyze,
  busy,
  info,
}: Props) {
  const [dragging, setDragging] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const current = targets.find((t) => t.target_id === selected) ?? null;
  const isSnippet = current?.target_id === "snippet";
  const isPublicRepo = selected === "public-github";
  const repoScanningAvailable = info?.model_backend === "service";
  const firstDemo = targets.find((t) => t.target_id === "pygoat") ?? targets[0];

  const readFile = useCallback(
    (file: File) => {
      if (!file.name.toLowerCase().endsWith(".py")) {
        setFileError("Only Python source files can be attached as a snippet.");
        return;
      }
      if (file.size > MAX_SNIPPET) {
        setFileError("Python snippet files must be 20 KB or smaller.");
        return;
      }
      setFileError(null);
      const reader = new FileReader();
      reader.onload = () => {
        const text = String(reader.result);
        if (text.length > MAX_SNIPPET) {
          setFileError("Python snippet files must be 20,000 characters or fewer.");
          return;
        }
        onSelect("snippet");
        onSnippet(text);
      };
      reader.onerror = () => setFileError("Could not read that Python file.");
      reader.readAsText(file);
    },
    [onSelect, onSnippet],
  );

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (isPublicRepo) return;
    const file = e.dataTransfer.files?.[0];
    if (file) readFile(file);
  };

  const canAnalyze = !busy && !!selected && (
    isPublicRepo
      ? repoScanningAvailable && !!repoCheck?.scan_ready && authorizedToScan
      : !isSnippet || snippet.trim().length > 0
  );

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
          if (!isPublicRepo) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        {isPublicRepo ? (
          <div className="space-y-3 px-5 py-5">
            <div>
              <label htmlFor="public-repo-url" className="mb-1 block text-sm font-medium text-ink">
                Public GitHub repository URL
              </label>
              <div className="flex flex-wrap gap-2">
                <input
                  id="public-repo-url"
                  type="url"
                  className="min-w-[220px] flex-1 rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink focus:border-clay focus:outline-none"
                  placeholder="https://github.com/owner/repository"
                  value={repoUrl}
                  onChange={(e) => onRepoUrl(e.target.value)}
                  disabled={busy}
                />
                <button
                  type="button"
                  className="btn-ghost px-4"
                  onClick={onCheckSource}
                  disabled={busy || repoChecking || !repoUrl.trim()}
                >
                  {repoChecking ? "Checking…" : "Check source"}
                </button>
              </div>
              <p className="mt-1 text-xs text-muted">
                Public GitHub repositories only. No account connection or private-repo access.
              </p>
            </div>
            {repoCheckError && (
              <p role="alert" className="text-sm text-sev-critical">{repoCheckError}</p>
            )}
            {repoCheck && (
              <div className="rounded-xl border border-border bg-sand/50 p-3 text-sm">
                <p className="font-medium text-ink">
                  {repoCheck.scan_ready ? "Source checked" : "No supported code language detected"}
                  {" · "}{repoCheck.repository}
                </p>
                <p className="mt-1 text-muted">
                  Default branch: <code>{repoCheck.default_branch}</code> · GitHub size: {repoCheck.size_mb} MB
                </p>
                <p className="mt-1 text-muted">
                  Detected languages: {repoCheck.languages.join(", ") || "none"}
                </p>
                <p className="mt-1 text-muted">
                  GitHub language totals are hints; eligibility can vary by file.
                </p>
                {repoCheck.unsupported_languages.length > 0 && (
                  <p className="mt-1 text-amber-800">
                    May not be analyzed: {repoCheck.unsupported_languages.join(", ")}
                  </p>
                )}
                <p className="mt-1 text-muted">{repoCheck.message}</p>
              </div>
            )}
            <label className="flex items-start gap-2 text-sm text-body">
              <input
                type="checkbox"
                className="mt-1 accent-clay"
                checked={authorizedToScan}
                onChange={(e) => onAuthorizedToScan(e.target.checked)}
                disabled={busy || !repoScanningAvailable || !repoCheck?.scan_ready}
              />
              <span>I’m authorized to scan this public repository and understand its source is processed by the configured analysis service.</span>
            </label>
            <p className="border-t border-border pt-2 text-xs text-muted">
              Repository files are cloned with server-side time and size limits. ONO analyzes supported source files; it does not run repository code. With the real service backend, the Docker sandbox is checked before cloning. No file or archive uploads are accepted in this mode.
            </p>
            {!repoScanningAvailable && (
              <p role="status" className="text-sm text-amber-800">
                Repository scanning requires the real service backend. Mock mode only returns demo results.
              </p>
            )}
          </div>
        ) : isSnippet ? (
          <textarea
            className="h-32 w-full resize-none rounded-t-[22px] bg-transparent px-5 pt-4 font-mono text-[13px] text-ink placeholder:text-faint focus:outline-none"
            placeholder="Paste Python code to analyze…"
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

        {isSnippet && (
          <p className="px-5 pb-2 text-xs text-muted">
            Python snippets only · 20,000 characters max · attached files must be .py and 20 KB or smaller.
          </p>
        )}

        {/* footer row */}
        <div className="flex items-center justify-between gap-2 px-3 pb-3 pt-1">
          <div className="flex items-center gap-1">
            {!isPublicRepo && <button
              type="button"
              className="flex h-9 w-9 items-center justify-center rounded-full text-xl text-muted transition hover:bg-sand hover:text-ink"
              onClick={() => fileRef.current?.click()}
              disabled={busy}
              title="Attach a Python snippet file, up to 20 KB"
              aria-label="Attach a Python snippet file, up to 20 KB"
            >
              ＋
            </button>}
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
      {fileError && !isPublicRepo && (
        <p role="alert" className="mt-2 px-2 text-sm text-sev-critical">{fileError}</p>
      )}

      {/* controls row (target · source · model) */}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 px-1 text-[13px]">
        <div className="flex items-center gap-2">
          <button
            type="button"
            className={isPublicRepo ? "btn-ghost" : "btn-soft"}
            aria-pressed={!isPublicRepo}
            onClick={() => onSelect(isPublicRepo ? firstDemo?.target_id ?? "" : selected ?? "")}
            disabled={busy || !firstDemo}
          >
            Demo target
          </button>
          <button
            type="button"
            className={isPublicRepo ? "btn-soft" : "btn-ghost"}
            aria-pressed={isPublicRepo}
            onClick={() => onSelect("public-github")}
            disabled={busy}
          >
            Public GitHub repo
          </button>
          {!isPublicRepo && (
            <select
              className="rounded-lg border border-transparent bg-transparent py-1 pl-1 pr-2 font-medium text-body hover:border-border focus:border-clay focus:outline-none"
              value={selected ?? ""}
              onChange={(e) => onSelect(e.target.value)}
              disabled={busy}
              aria-label="Choose a demo target"
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
          )}
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

      {!isPublicRepo && <input
        ref={fileRef}
        type="file"
        accept=".py,text/x-python"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) readFile(file);
          e.target.value = "";
        }}
      />}
    </div>
  );
}
