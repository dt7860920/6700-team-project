// Drives one scan: POST /scans, then poll GET /scans/{id} until terminal, then
// fetch findings. Exposes the live Scan record so the UI can show pipeline
// progress exactly as the backend reports it.

import { useCallback, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import { isTerminal, type Finding, type Scan, type ScanRequest } from "../api/types";

const POLL_MS = 1000;

export type ScanPhase = "idle" | "starting" | "running" | "done" | "failed" | "error";

export interface ScanState {
  phase: ScanPhase;
  scan: Scan | null;
  findings: Finding[];
  error: string | null;
}

const INITIAL: ScanState = { phase: "idle", scan: null, findings: [], error: null };

export function useScan() {
  const [state, setState] = useState<ScanState>(INITIAL);
  const timer = useRef<number | null>(null);
  const cancelled = useRef(false);

  const clearTimer = () => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  };

  const reset = useCallback(() => {
    cancelled.current = true;
    clearTimer();
    setState(INITIAL);
  }, []);

  const poll = useCallback((scanId: string) => {
    const tick = async () => {
      if (cancelled.current) return;
      try {
        const scan = await api.getScan(scanId);
        if (cancelled.current) return;
        if (!isTerminal(scan.status)) {
          setState((s) => ({ ...s, phase: "running", scan }));
          timer.current = window.setTimeout(tick, POLL_MS);
          return;
        }
        // Terminal: pull findings (empty on failure is fine).
        const findings = scan.status === "done" ? await api.getFindings(scanId) : [];
        if (cancelled.current) return;
        setState({
          phase: scan.status === "done" ? "done" : "failed",
          scan,
          findings,
          error: scan.status === "failed" ? scan.message || "Scan failed." : null,
        });
      } catch (err) {
        if (cancelled.current) return;
        const detail = err instanceof ApiError ? err.detail : "Unexpected error while polling.";
        setState((s) => ({ ...s, phase: "error", error: detail }));
      }
    };
    void tick();
  }, []);

  const start = useCallback(
    async (req: ScanRequest) => {
      cancelled.current = false;
      clearTimer();
      setState({ phase: "starting", scan: null, findings: [], error: null });
      try {
        const scan = await api.startScan(req);
        if (cancelled.current) return;
        setState({ phase: "running", scan, findings: [], error: null });
        poll(scan.scan_id);
      } catch (err) {
        const detail =
          err instanceof ApiError
            ? err.status === 429
              ? "The scanner is busy (max concurrent scans reached). Try again in a moment."
              : err.detail
            : "Could not start the scan.";
        setState({ phase: "error", scan: null, findings: [], error: detail });
      }
    },
    [poll],
  );

  const load = useCallback(
    async (scanId: string) => {
      cancelled.current = false;
      clearTimer();
      setState({ phase: "running", scan: null, findings: [], error: null });
      try {
        const scan = await api.getScan(scanId);
        if (cancelled.current) return;
        if (isTerminal(scan.status)) {
          const findings = scan.status === "done" ? await api.getFindings(scanId) : [];
          if (cancelled.current) return;
          setState({
            phase: scan.status === "done" ? "done" : "failed",
            scan,
            findings,
            error: scan.status === "failed" ? scan.message || "Scan failed." : null,
          });
        } else {
          setState({ phase: "running", scan, findings: [], error: null });
          poll(scanId);
        }
      } catch (err) {
        const detail = err instanceof ApiError ? err.detail : "Could not load that scan.";
        setState({ phase: "error", scan: null, findings: [], error: detail });
      }
    },
    [poll],
  );

  return { ...state, start, load, reset };
}
