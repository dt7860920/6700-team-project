import type { Rung, Severity } from "../api/types";
import { RUNG_HELP, RUNG_LABELS, cweUrl } from "../lib/labels";

const SEV_CLASS: Record<Severity, string> = {
  low: "border-sev-low/40 text-sev-low",
  medium: "border-sev-medium/40 text-sev-medium",
  high: "border-sev-high/40 text-sev-high",
  critical: "border-sev-critical/50 text-sev-critical",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge capitalize ${SEV_CLASS[severity]}`} title={`Severity: ${severity}`}>
      {severity}
    </span>
  );
}

export function RungBadge({ rung }: { rung: Rung }) {
  return (
    <span
      className="badge border-accent/40 text-indigo-300"
      title={RUNG_HELP[rung]}
    >
      rung {rung}/5 · {RUNG_LABELS[rung]}
    </span>
  );
}

export function VerifiedBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <span
      className="badge border-emerald-500/40 text-emerald-300"
      title="The deterministic verifier passed."
    >
      ✔ verified
    </span>
  ) : (
    <span
      className="badge border-amber-500/40 text-amber-300"
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
      className="badge border-edge text-muted hover:text-ink hover:border-ink/40"
      title="Open the CWE definition at cwe.mitre.org"
    >
      {cwe}
    </a>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: number }) {
  return (
    <span className="badge border-edge text-muted" title="Model confidence in this finding">
      confidence {Math.round(confidence * 100)}%
    </span>
  );
}
