import { useState } from "react";
import type { Finding } from "../api/types";
import { locationOf } from "../lib/labels";
import {
  ConfidenceBadge,
  CweBadge,
  RungBadge,
  SeverityBadge,
  VerifiedBadge,
} from "./Badges";
import { DiffView } from "./DiffView";
import { Trace } from "./Trace";

const SEV_ACCENT: Record<Finding["severity"], string> = {
  low: "before:bg-sev-low",
  medium: "before:bg-sev-medium",
  high: "before:bg-sev-high",
  critical: "before:bg-sev-critical",
};

export function FindingCard({ finding }: { finding: Finding }) {
  const [showPatch, setShowPatch] = useState(false);
  const [showRule, setShowRule] = useState(false);

  return (
    <article
      className={`card relative overflow-hidden pl-6 before:absolute before:inset-y-0 before:left-0 before:w-1 ${SEV_ACCENT[finding.severity]}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <CweBadge cwe={finding.cwe} />
        <SeverityBadge severity={finding.severity} />
        <RungBadge rung={finding.rung} />
        <VerifiedBadge verified={finding.verified} />
        <ConfidenceBadge confidence={finding.confidence} />
      </div>

      <h3 className="mt-3 text-lg font-semibold text-ink">{finding.title}</h3>
      <div className="mt-1 font-mono text-sm text-muted">
        {locationOf(finding.file, finding.line_range)}
      </div>

      {finding.description && (
        <p className="mt-3 text-sm leading-relaxed text-ink/80">{finding.description}</p>
      )}

      <Trace steps={finding.trace} />

      {finding.patch_diff && (
        <div className="mt-4">
          <button
            className="btn-ghost text-xs"
            onClick={() => setShowPatch((v) => !v)}
            aria-expanded={showPatch}
          >
            {showPatch ? "▾ Hide patch" : "▸ Proposed patch"}
          </button>
          {showPatch && <DiffView diff={finding.patch_diff} />}
        </div>
      )}

      {finding.detection_rule && (
        <div className="mt-3">
          <button
            className="btn-ghost text-xs"
            onClick={() => setShowRule((v) => !v)}
            aria-expanded={showRule}
          >
            {showRule ? "▾ Hide detection rule" : "▸ Detection rule (rung 5)"}
          </button>
          {showRule && (
            <pre className="mt-2 overflow-x-auto rounded-lg border border-edge bg-ground p-3 font-mono text-xs">
              <code>{finding.detection_rule}</code>
            </pre>
          )}
        </div>
      )}
    </article>
  );
}
