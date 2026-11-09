// Typed mirror of the ONO API schemas (src/ono/models.py). The OpenAPI document
// at /docs is the authoritative contract; keep these in sync with it.

export type Severity = "low" | "medium" | "high" | "critical";
export type ScanStatus = "queued" | "running" | "done" | "failed";
export type StageName = "ingest" | "sast" | "plan" | "analyze" | "verify";
export type StageStatus = "ok" | "skipped" | "failed";
export type Rung = 1 | 2 | 3 | 4 | 5;

export interface TargetSummary {
  target_id: string;
  name: string;
  kind: string;
  languages: string[];
  description: string;
  source: string;
  snapshot: string;
  authorized: boolean;
}

export interface TargetsResponse {
  targets: TargetSummary[];
}

export interface InfoResponse {
  app_name: string;
  version: string;
  environment: string;
  model_backend: string;
  model_name: string;
  targets_registered: number;
}

export interface TraceStep {
  file: string;
  line: number;
  symbol: string;
  note: string;
}

export interface Finding {
  finding_id: string;
  fingerprint: string;
  scan_id: string;
  target_id: string;
  title: string;
  cwe: string; // e.g. "CWE-89"
  severity: Severity;
  file: string;
  line_range: [number, number];
  trace: TraceStep[];
  confidence: number; // 0..1
  rung: Rung;
  verified: boolean;
  description: string;
  patch_diff: string;
  detection_rule: string | null;
}

export interface StageResult {
  stage: StageName;
  status: StageStatus;
  duration_ms: number;
  summary: string;
}

export interface ProgressEvent {
  at: string; // ISO datetime
  message: string;
}

export interface Scan {
  scan_id: string;
  target_id: string;
  status: ScanStatus;
  model_backend: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  pipeline: StageResult[];
  progress: string;
  events: ProgressEvent[];
  message: string;
}

export interface ScanOptions {
  snippet?: string | null;
  max_findings?: number;
  min_rung?: Rung;
}

export interface ScanRequest {
  target_id: string;
  options?: ScanOptions;
}

export interface ApiError {
  detail: string;
}

export const isTerminal = (s: ScanStatus): boolean => s === "done" || s === "failed";
