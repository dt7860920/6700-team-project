import { useEffect, useRef } from "react";
import type { Scan, StageName } from "../api/types";
import { STAGE_ORDER } from "../lib/labels";

type PhaseState = "pending" | "active" | "ok" | "skipped" | "failed";
type PhaseKey = StageName | "deliver";

interface Phase {
  key: PhaseKey;
  title: string;
  blurb: string; // what this phase does, shown until the backend reports a summary
  state: PhaseState;
  summary?: string;
  durationMs?: number;
}

// Analyst-facing names for the backend stages, plus a final hand-off phase.
const COPY: Record<PhaseKey, { title: string; blurb: string }> = {
  ingest: { title: "Upload code", blurb: "Fetch the target and snapshot its source." },
  sast: { title: "Find bugs", blurb: "Static analysis flags candidate vulnerabilities." },
  plan: { title: "Plan", blurb: "Decide which candidates are worth investigating." },
  analyze: { title: "Determine fixes", blurb: "The agent traces each bug and drafts a patch." },
  verify: { title: "Validate", blurb: "Prove each patch applies and the bug no longer fires." },
  deliver: { title: "Send through", blurb: "Hand the findings and patches to the analyst." },
};

function buildPhases(scan: Scan): Phase[] {
  const reported = new Map(scan.pipeline.map((p) => [p.stage, p]));
  const firstPending = STAGE_ORDER.find((s) => !reported.has(s));
  const live = scan.status === "running" || scan.status === "queued";

  const phases: Phase[] = STAGE_ORDER.map((stage) => {
    const r = reported.get(stage);
    let state: PhaseState = "pending";
    if (r) state = r.status;
    else if (stage === firstPending) {
      if (scan.status === "running") state = "active";
      else if (scan.status === "failed") state = "failed";
    }
    return { key: stage, ...COPY[stage], state, summary: r?.summary, durationMs: r?.duration_ms };
  });

  const n = scan.findings_count;
  phases.push({
    key: "deliver",
    ...COPY.deliver,
    state: scan.status === "done" ? "ok" : live && !firstPending ? "active" : "pending",
    summary:
      scan.status === "done" ? `${n} finding${n === 1 ? "" : "s"} delivered` : undefined,
  });
  return phases;
}

const DOT: Record<PhaseState, string> = {
  pending: "border-border2 bg-card text-faint",
  active: "border-brand bg-brand text-white ring-4 ring-brandsoft",
  ok: "border-ok bg-ok text-white",
  skipped: "border-border2 bg-sand text-faint",
  failed: "border-sev-critical bg-sev-critical text-white",
};
const CARD: Record<PhaseState, string> = {
  pending: "opacity-70",
  active: "",
  ok: "",
  skipped: "opacity-70",
  failed: "",
};
const STATE_TEXT: Record<PhaseState, [string, string]> = {
  pending: ["Up next", "text-faint"],
  active: ["In progress", "text-brand"],
  ok: ["Done", "text-ok"],
  skipped: ["Skipped", "text-faint"],
  failed: ["Failed", "text-sev-critical"],
};

const duration = (ms: number) =>
  ms < 1 ? "<1 ms" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;

export function StageTimeline({ scan }: { scan: Scan }) {
  const phases = buildPhases(scan);
  const track = useRef<HTMLOListElement>(null);

  // The phase the user should be looking at: the live one, else the failure,
  // else the end of the line.
  const focusIdx = Math.max(
    0,
    phases.findIndex((p) => p.state === "active" || p.state === "failed"),
  );
  const current =
    phases.some((p) => p.state === "active" || p.state === "failed") || scan.status !== "done"
      ? focusIdx
      : phases.length - 1;

  const scrollTo = (idx: number) => {
    const el = track.current;
    const item = el?.children[idx] as HTMLElement | undefined;
    if (!el || !item) return;
    el.scrollTo({
      left: item.offsetLeft - el.offsetLeft - (el.clientWidth - item.clientWidth) / 2,
      behavior: "smooth",
    });
  };

  // Follow the scan as it moves from phase to phase. A scan opened after it
  // finished starts at the beginning so it reads left to right.
  const followed = useRef(false);
  const live = scan.status === "running" || scan.status === "queued";
  useEffect(() => {
    if (live || scan.status === "failed") followed.current = true;
    if (followed.current) scrollTo(current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current, scan.scan_id, live]);

  const step = (dir: -1 | 1) => {
    const el = track.current;
    if (el) el.scrollBy({ left: dir * 320, behavior: "smooth" });
  };

  return (
    <section aria-label="Scan timeline" className="font-terminal">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm">
          <span className="mr-2 text-xs uppercase tracking-wide text-faint">Timeline</span>
          <span className="font-medium text-ink">
            Phase {current + 1} of {phases.length} · {phases[current].title}
          </span>
        </div>
        <div className="flex gap-1.5">
          <button type="button" className="btn-ghost px-2.5 py-1" onClick={() => step(-1)} aria-label="Scroll timeline back">
            ←
          </button>
          <button type="button" className="btn-ghost px-2.5 py-1" onClick={() => step(1)} aria-label="Scroll timeline forward">
            →
          </button>
        </div>
      </div>

      <ol
        ref={track}
        tabIndex={0}
        className="flex snap-x snap-mandatory overflow-x-auto scroll-smooth px-1 pb-4 pt-6 focus:outline-none"
      >
        {phases.map((p, i) => {
          const [stateLabel, stateTone] = STATE_TEXT[p.state];
          const lastPhase = i === phases.length - 1;
          const passed = p.state === "ok" || p.state === "skipped";
          return (
            <li
              key={p.key}
              aria-current={i === current ? "step" : undefined}
              className="flex w-[300px] shrink-0 snap-center flex-col"
            >
              {/* rail: numbered marker + connector to the next phase */}
              <div className="flex items-center">
                <span
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 text-xs font-semibold ${DOT[p.state]} ${
                    p.state === "active" ? "animate-pulse" : ""
                  }`}
                >
                  {p.state === "ok" ? "✓" : p.state === "failed" ? "✕" : i + 1}
                </span>
                {!lastPhase && (
                  <span className={`h-0.5 flex-1 ${passed ? "bg-ok" : "bg-border2"}`} />
                )}
              </div>

              <div className={`mr-6 mt-3 ${CARD[p.state]}`}>
                <div className="flex items-baseline justify-between gap-2">
                  <h3 className="font-terminal text-sm font-semibold uppercase tracking-wide text-ink">{p.title}</h3>
                  <span className={`shrink-0 text-[11px] font-medium uppercase tracking-wide ${stateTone}`}>{stateLabel}</span>
                </div>
                <p className="mt-1.5 line-clamp-4 text-[13px] leading-relaxed text-body" title={p.summary}>
                  {p.summary || p.blurb}
                </p>
                {p.state === "active" && scan.progress && (
                  <p className="mt-2 text-xs text-muted">
                    <span className="text-brand">›</span> {scan.progress}
                  </p>
                )}
                {p.durationMs !== undefined && (
                  <p className="mt-2 text-xs text-faint">{duration(p.durationMs)}</p>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
