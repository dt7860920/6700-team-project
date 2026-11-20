// Thin typed fetch client. All paths are absolute from the origin root so the
// same code works in dev (Vite proxies them to the API) and in production
// (served same-origin from /ui).

import type {
  Finding,
  InfoResponse,
  Me,
  Scan,
  ScanRequest,
  SourceCheck,
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

/** Send the browser to GitHub sign-in, returning here afterwards. */
export function redirectToLogin(): void {
  const next = location.pathname + location.search + location.hash;
  location.assign(`/auth/github/login?next=${encodeURIComponent(next)}`);
}

interface RequestOpts {
  /** On a 401, bounce to GitHub sign-in (default true). `/auth/me` opts out. */
  redirectOn401?: boolean;
}

async function request<T>(path: string, init?: RequestInit, opts?: RequestOpts): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch {
    throw new ApiError(0, "Could not reach the ONO API. Is the server running?");
  }
  if (res.status === 401 && opts?.redirectOn401 !== false) {
    // A gated endpoint rejected us: the session is missing or expired.
    redirectToLogin();
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
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  info: () => request<InfoResponse>("/info"),
  targets: () => request<TargetsResponse>("/targets"),
  checkSource: (repoUrl: string) =>
    request<SourceCheck>("/sources/check", {
      method: "POST",
      body: JSON.stringify({ repo_url: repoUrl }),
    }),
  startScan: (body: ScanRequest) =>
    request<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
  getScan: (scanId: string) => request<Scan>(`/scans/${scanId}`),
  getFindings: (scanId: string) => request<Finding[]>(`/scans/${scanId}/findings`),

  /** Current signed-in GitHub login, or null when signed out / auth disabled. */
  me: async (): Promise<Me | null> => {
    try {
      return await request<Me>("/auth/me", undefined, { redirectOn401: false });
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 404)) return null;
      throw err;
    }
  },
  logout: () => request<void>("/auth/logout", { method: "POST" }, { redirectOn401: false }),
};
