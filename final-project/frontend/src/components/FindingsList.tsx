import type { Finding, Scan, Severity } from "../api/types";
import { SEVERITY_ORDER } from "../lib/labels";
import { FindingCard } from "./FindingCard";

const SEV_FILL: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

// CodeRabbit-style "posture" strip: one square per finding, worst first.
function PostureStrip({ findings }: { findings: Finding[] }) {
  const ordered = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  return (
    <div className="flex flex-wrap gap-1">
      {ordered.map((f) => (
        <span
          key={f.finding_id}
          title={`${f.severity} · ${f.cwe}`}
          className={`h-3.5 w-3.5 rounded-[4px] ${SEV_FILL[f.severity]} ${
            f.verified ? "ring-1 ring-ok/60 ring-offset-1 ring-offset-card" : "opacity-70"
          }`}
        />
      ))}
    </div>
  );
}

function Summary({ findings }: { findings: Finding[] }) {
  const bySev = SEVERITY_ORDER.map(
    (s) => [s, findings.filter((f) => f.severity === s).length] as const,
  ).filter(([, n]) => n > 0);
  const verified = findings.filter((f) => f.verified).length;

  return (
    <div className="card">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="eyebrow">Repository posture</div>
          <h2 className="mt-1.5 font-sans text-lg font-semibold text-ink">
            {findings.length} finding{findings.length === 1 ? "" : "s"}
            <span className="ml-2 font-mono text-xs font-normal text-muted">
              {bySev.map(([s, n]) => `${n} ${s}`).join(" · ")}
            </span>
          </h2>
        </div>
        <PostureStrip findings={findings} />
      </div>
      <div className="mt-3 flex items-center gap-2 border-t border-border pt-3 font-mono text-xs text-faint">
        <span className={verified > 0 ? "text-ok" : "text-sev-medium"}>●</span>
        {verified > 0
          ? `${verified} of ${findings.length} verified by the deterministic verifier`
          : "none verified yet — these are model-asserted (rung ≤ 2)"}
      </div>
    </div>
  );
}

export function FindingsList({ scan, findings }: { scan: Scan; findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="card animate-fade-up text-center">
        <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full border border-ok/40 text-lg text-ok">
          ✓
        </div>
        <p className="mt-3 font-medium text-ink">No findings</p>
        <p className="mt-1 text-sm text-muted">
          {scan.message ||
            "The scan completed without flagging a vulnerability on this target."}
        </p>
      </div>
    );
  }

  const ordered = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      b.rung - a.rung,
  );

  return (
    <div className="space-y-4">
      <Summary findings={findings} />
      {ordered.map((f, i) => (
        <div key={f.finding_id} className="animate-fade-up" style={{ animationDelay: `${i * 60}ms` }}>
          <FindingCard finding={f} />
        </div>
      ))}
    </div>
  );
}
