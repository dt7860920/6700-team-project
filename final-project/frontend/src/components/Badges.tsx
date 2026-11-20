import type { Rung, Severity } from "../api/types";
import { RUNG_HELP, RUNG_LABELS, cweUrl } from "../lib/labels";

const SEV_CLASS: Record<Severity, string> = {
  low: "border-sev-low/30 bg-sev-low/5 text-sev-low",
  medium: "border-sev-medium/30 bg-sev-medium/5 text-sev-medium",
  high: "border-sev-high/30 bg-sev-high/5 text-sev-high",
  critical: "border-sev-critical/40 bg-sev-critical/5 text-sev-critical",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge uppercase ${SEV_CLASS[severity]}`} title={`Severity: ${severity}`}>
      {severity}
    </span>
  );
}

export function RungBadge({ rung }: { rung: Rung }) {
  return (
    <span className="badge border-claydeep/30 bg-claysoft/50 text-claydeep" title={RUNG_HELP[rung]}>
      rung {rung}/5 · {RUNG_LABELS[rung]}
    </span>
  );
}

export function VerifiedBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="badge border-ok/30 bg-ok/5 text-ok" title="The deterministic verifier passed.">
      ✔ verified
    </span>
  ) : (
    <span
      className="badge border-sev-medium/30 bg-sev-medium/5 text-sev-medium"
      title="Asserted by the model; the verifier has not confirmed it."
    >
      ⚠ not verified
    </span>
  );
}

export function CweBadge({ cwe }: { cwe: string }) {
  return (
    <a
      href={cweUrl(cwe)}
      target="_blank"
      rel="noreferrer"
      className="badge text-muted hover:border-border2 hover:text-ink"
      title="Open the CWE definition at cwe.mitre.org"
    >
      {cwe} ↗
    </a>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: number }) {
  return (
    <span className="badge text-muted" title="Model confidence in this finding">
      confidence {Math.round(confidence * 100)}%
    </span>
  );
}
