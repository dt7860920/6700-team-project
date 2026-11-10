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

export function FindingCard({ finding }: { finding: Finding }) {
  const [showPatch, setShowPatch] = useState(false);
  const [showRule, setShowRule] = useState(false);

  return (
    <article className="card transition hover:shadow-lift">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <CweBadge cwe={finding.cwe} />
        <RungBadge rung={finding.rung} />
        <VerifiedBadge verified={finding.verified} />
        <ConfidenceBadge confidence={finding.confidence} />
      </div>

      <h3 className="mt-3 max-w-[70ch] text-lg font-semibold leading-snug text-ink">
        {finding.title}
      </h3>
      <div className="mt-1 font-mono text-xs text-faint">
        {locationOf(finding.file, finding.line_range)}
      </div>

      {finding.description && (
        <p className="mt-3 max-w-[58ch] text-pretty text-sm leading-relaxed text-muted">
          {finding.description}
        </p>
      )}

      <Trace steps={finding.trace} />

      {finding.patch_diff && (
        <div className="mt-4">
          <button
            className="btn-ghost px-3 py-1.5 text-xs"
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
            className="btn-ghost px-3 py-1.5 text-xs"
            onClick={() => setShowRule((v) => !v)}
            aria-expanded={showRule}
          >
            {showRule ? "▾ Hide detection rule" : "▸ Detection rule (rung 5)"}
          </button>
          {showRule && (
            <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-sand p-3 font-mono text-xs text-body">
              <code>{finding.detection_rule}</code>
            </pre>
          )}
        </div>
      )}
    </article>
  );
}
