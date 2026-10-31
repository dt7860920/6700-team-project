"""Golden-path heartbeat: scan PyGoat -> scan is `done` -> >=1 finding with file:line + patch.

If this is green, the whole pipeline is alive (plan §8.5). Two modes:

    uv run scripts/golden_path.py                        # against a live server (default :8080)
    uv run scripts/golden_path.py --base-url http://<jetstream-ip>:8080
    uv run scripts/golden_path.py --in-process           # no server needed (used in CI)

Also runs the blocking allowlist security check: an unknown target_id must be a 403.
Exit code 0 on success, 1 on any failed assertion.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time

import httpx


async def run(
    client: httpx.AsyncClient, *, poll_interval: float = 0.5, poll_timeout: float = 600.0
) -> None:
    def check(cond: bool, msg: str) -> None:
        status = "PASS" if cond else "FAIL"
        print(f"[{status}] {msg}")
        if not cond:
            raise SystemExit(1)

    r = await client.get("/health")
    check(r.status_code == 200 and r.json() == {"status": "ok"}, "GET /health -> ok")

    r = await client.get("/targets")
    ids = {t["target_id"] for t in r.json().get("targets", [])}
    check(r.status_code == 200 and "pygoat" in ids, f"GET /targets includes pygoat ({len(ids)})")

    r = await client.post("/scans", json={"target_id": "pygoat"})
    check(r.status_code == 202, f"POST /scans pygoat -> {r.status_code} (accepted)")
    scan = r.json()
    check(scan["status"] in ("queued", "running"), f"scan {scan['scan_id']} is {scan['status']}")

    # The scan runs in the background: poll the live record until it ends.
    deadline = time.monotonic() + poll_timeout
    while scan["status"] not in ("done", "failed"):
        check(time.monotonic() < deadline, f"scan finished within {poll_timeout:.0f}s")
        await asyncio.sleep(poll_interval)
        r = await client.get(f"/scans/{scan['scan_id']}")
        check(r.status_code == 200, f"GET /scans/{scan['scan_id']} -> {r.status_code}")
        scan = r.json()
        print(f"       ... {scan['status']}: {scan['progress'] or scan['message']}")
    check(scan["status"] == "done", f"scan {scan['scan_id']} status == done ({scan['message']})")
    check(
        [s["stage"] for s in scan["pipeline"]] == ["ingest", "sast", "plan", "analyze", "verify"],
        "all five pipeline stages recorded",
    )

    r = await client.get(f"/scans/{scan['scan_id']}/findings")
    check(r.status_code == 200, "GET /scans/{id}/findings -> 200")
    findings = r.json()
    check(len(findings) >= 1, f">= 1 finding ({len(findings)})")
    f = findings[0]
    check(
        bool(f["file"]) and f["line_range"][0] >= 1,
        f"real file:line -> {f['file']}:{f['line_range'][0]}",
    )
    check(bool(f["patch_diff"].strip()), "non-empty patch_diff")
    check(f["verified"] is True, f"finding is verified (rung {f['rung']}, {f['cwe']})")
    check(scan["findings_count"] == len(findings), "findings_count matches the findings list")

    r = await client.post("/scans", json={"target_id": "not-in-allowlist"})
    check(r.status_code == 403, "SECURITY: unknown target_id -> 403, no scan started")

    print("\nGolden path: GREEN")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument(
        "--in-process", action="store_true", help="run against the ASGI app directly"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=600.0,
        help="seconds to wait for the scan to finish (a real service-backend scan takes minutes)",
    )
    args = parser.parse_args()

    if args.in_process:
        from ono.api import create_app
        from ono.config import Settings

        app = create_app(Settings(_env_file=None, model_backend="mock"), mount_ui=False)
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://ono") as client:
                await run(client, poll_interval=0.05, poll_timeout=args.timeout)
        finally:
            app.state.service.close()  # no lifespan under ASGITransport: stop the workers
    else:
        print(f"target: {args.base_url}")
        async with httpx.AsyncClient(base_url=args.base_url, timeout=30) as client:
            await run(client, poll_timeout=args.timeout)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except httpx.ConnectError as exc:
        print(f"[FAIL] cannot reach server: {exc}")
        sys.exit(1)
