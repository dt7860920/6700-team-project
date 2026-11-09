import type { Finding, Scan } from "../api/types";
import { SEVERITY_ORDER } from "../lib/labels";
import { FindingCard } from "./FindingCard";

function Summary({ findings }: { findings: Finding[] }) {
  const bySev = SEVERITY_ORDER.map(
    (s) => [s, findings.filter((f) => f.severity === s).length] as const,
  ).filter(([, n]) => n > 0);
  const verified = findings.filter((f) => f.verified).length;

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
      <span className="font-medium text-ink">
        {findings.length} finding{findings.length === 1 ? "" : "s"}
      </span>
      {bySev.map(([s, n]) => (
        <span key={s} className="capitalize">
          {n} {s}
        </span>
      ))}
      <span>
        {verified > 0
          ? `${verified} of ${findings.length} verified by the deterministic verifier`
          : "none verified yet — these are model-asserted (rung ≤ 2)"}
      </span>
    </div>
  );
}

export function FindingsList({ scan, findings }: { scan: Scan; findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="card text-center">
        <div className="text-2xl">✓</div>
        <p className="mt-2 font-medium text-ink">No findings</p>
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
      {ordered.map((f) => (
        <FindingCard key={f.finding_id} finding={f} />
      ))}
    </div>
  );
}
