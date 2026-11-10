// Display text matching the API's own vocabulary: the rung wording follows
// Finding.rung in src/ono/models.py and the README's output-strength ladder.

import type { Rung, Severity, StageName } from "../api/types";

export const RUNG_LABELS: Record<Rung, string> = {
  1: "flagged line",
  2: "CWE + evidence",
  3: "reachability proven",
  4: "fix proven",
  5: "detection rule",
};

export const RUNG_HELP: Record<Rung, string> = {
  1: "A line looks vulnerable; the CWE is the suspected weakness class. No multi-step trace or fix yet.",
  2: "Plus evidence: a source-to-sink trace read from the code and/or a proposed patch (patches arrive when the fixer agent is enabled).",
  3: "Plus a read-only proof that attacker input really reaches the sink.",
  4: "Plus proof the fix works: patch applies, the proof no longer fires, tests pass.",
  5: "Plus a detection rule to catch exploitation until the patch ships.",
};

export const STAGE_LABELS: Record<StageName, string> = {
  ingest: "Fetch target",
  sast: "Static analysis",
  plan: "Plan",
  analyze: "Agent analysis",
  verify: "Verify",
};

export const STAGE_ORDER: StageName[] = ["ingest", "sast", "plan", "analyze", "verify"];

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export const cweUrl = (cwe: string): string => {
  const num = cwe.replace(/\D/g, "");
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
};

export const locationOf = (file: string, range: [number, number]): string => {
  const [start, end] = range;
  return start === end ? `${file}:${start}` : `${file}:${start}-${end}`;
};
