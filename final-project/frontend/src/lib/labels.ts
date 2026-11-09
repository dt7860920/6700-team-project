// Display text ported verbatim from src/ono/ui.py so the React UI reads
// identically to the API's own vocabulary.

import type { Rung, Severity, StageName } from "../api/types";

export const RUNG_LABELS: Record<Rung, string> = {
  1: "flagged line",
  2: "CWE + patch",
  3: "reachability proven",
  4: "fix proven",
  5: "detection rule",
};

export const RUNG_HELP: Record<Rung, string> = {
  1: "A line looks vulnerable. No CWE, no fix yet.",
  2: "Plus the weakness class (CWE) and a proposed patch.",
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
