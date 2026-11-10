// Thin typed fetch client. All paths are absolute from the origin root so the
// same code works in dev (Vite proxies them to the API) and in production
// (served same-origin from /ui).

import type {
  Finding,
  InfoResponse,
  Scan,
  ScanRequest,
  TargetsResponse,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch (cause) {
    throw new ApiError(0, "Could not reach the ONO API. Is the server running?");
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body?.detail) detail = body.detail;
    } catch {
      /* non-JSON error body — keep the status line */
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export const api = {
  info: () => request<InfoResponse>("/info"),
  targets: () => request<TargetsResponse>("/targets"),
  startScan: (body: ScanRequest) =>
    request<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
  getScan: (scanId: string) => request<Scan>(`/scans/${scanId}`),
  getFindings: (scanId: string) => request<Finding[]>(`/scans/${scanId}/findings`),
};
