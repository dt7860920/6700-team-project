# Operation: Negative One (ONO)

**An agentic system that finds software vulnerabilities in authorized code targets, proves they are real, and proposes verified fixes.**

DSAN 6700 — Deploying Machine Learning Applications to Customers · Georgetown University
Team: Sazan Khalid · Kenedy Ducheine · Junyi Tang · Jeffrey Pinarchick

| | |
|---|---|
| Live prototype (Jetstream2) | `http://<INSTANCE-FLOATING-IP>:8080` ← fill in after deploy |
| API docs (OpenAPI) | `http://<INSTANCE-FLOATING-IP>:8080/docs` |
| Repository | `https://github.com/<org>/operation-negative-one` ← fill in |

> **Deliverable 2 status.** This is the midpoint *skeleton*. The API, configuration, container, CI, and analyst UI are real and deployable. The **analyzer is mocked** (`MODEL_BACKEND=mock`): it is shaped exactly like the production pipeline — `ingest → SAST shortlist → plan → analyze → verify` — but returns deterministic, representative findings instead of calling a model. See [Where the real pipeline slots in](#where-the-real-pipeline-slots-in).

---

## What it does

ONO never scans "a website". Every request names a **`target_id`** from an exact allowlist of targets we host ourselves — intentionally-vulnerable practice apps (OWASP PyGoat, OWASP Juice Shop), ingested open-source repository snapshots, or a pasted code snippet. Anything else is rejected with **HTTP 403 before any analysis starts**.

Each **finding** is shaped by the *output-strength ladder*:

| Rung | Output |
|---|---|
| 1 | bare flag ("line X looks vulnerable") |
| 2 | + CWE + suggested patch |
| 3 | + proof the flaw is reachable (read-only PoC in the sandbox) |
| 4 | + proof the fix works (patch applies, PoC no longer fires, tests pass) — **our floor** |
| 5 | + a detection rule to catch exploitation until the patch ships — stretch |

```json
{
  "finding_id": "fnd_…", "cwe": "CWE-89", "severity": "critical",
  "file": "introduction/views.py", "line_range": [210, 211],
  "trace": [{"file": "…", "line": 208, "symbol": "request.POST.get(\"name\")", "note": "attacker-controlled source"}, "…"],
  "confidence": 0.94, "rung": 4, "verified": true,
  "patch_diff": "--- a/introduction/views.py\n+++ b/introduction/views.py\n@@ …",
  "detection_rule": null
}
```

---

## Run locally (uv)

Requires Python 3.13 and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone <REPO-URL> && cd operation-negative-one
uv sync --extra dev
cp .env.example.local .env
uv run ono                      # http://localhost:8080  (UI at /ui, docs at /docs)
```

Quality gates (the same ones CI runs):

```bash
uv run ruff check && uv run ruff format --check
uv run mypy src/
uv run pytest
uv run scripts/golden_path.py --in-process     # golden-path heartbeat, no server needed
# or simply:  make check smoke-ci
```

## Run with Docker

```bash
docker build -t ono:prototype .
docker run --rm -p 8080:8080 --env-file .env.example.production ono:prototype
curl http://localhost:8080/health             # {"status":"ok"}
```

The image is based on `ghcr.io/astral-sh/uv:python3.13-bookworm-slim`, installs dependencies from the lockfile in a cached layer *before* copying source, runs as a non-root user, and carries a `HEALTHCHECK` against `/health`. Only port **8080** is exposed.

## Run with Compose on Jetstream2

On the instance (Docker + Compose plugin installed; security group allows inbound 8080 only):

```bash
git clone <REPO-URL> && cd operation-negative-one
cp .env.example.production .env
echo "EXECUTOR_TOKEN=$(openssl rand -hex 32)" >> .env   # the Executor refuses to start without one
docker compose up -d --build
docker compose ps                              # wait for both services to be "healthy"
curl http://localhost:8080/health
```

From your laptop: `uv run scripts/golden_path.py --base-url http://<FLOATING-IP>:8080`.

`compose.yml` defines **two services** and publishes **one port** (8080): the app, and the sandbox **Executor** (see [The sandbox Executor](#the-sandbox-executor-step-3a)) on an `internal: true` network with no `ports:` block. There is deliberately no database in the skeleton — scan state is in-memory. When the findings DB, threat-intel cache, and vLLM join the stack they are added the same way, as internal services *without* `ports:`, so the published surface stays exactly `:8080`.

---

## API

Interactive documentation is generated from the code at **`/docs`** (Swagger UI) and **`/redoc`**; the raw schema is at `/openapi.json`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness → `{"status":"ok"}` |
| `GET` | `/info` | App name, version, environment, model backend (no secrets) |
| `GET` | `/targets` | The authorized-target allowlist |
| `POST` | `/scans` | Start a scan. **403** if `target_id` is not allowlisted. Returns the scan **with findings** (201). |
| `GET` | `/scans/{scan_id}` | Scan metadata (status, pipeline stage timings, findings count) |
| `GET` | `/scans/{scan_id}/findings` | Findings for a scan |
| `GET` | `/findings/{finding_id}` | One finding |
| `GET` | `/ui` | Gradio analyst UI (`/` redirects here) |

```bash
BASE=http://localhost:8080

curl -s $BASE/health
# {"status":"ok"}

curl -s $BASE/targets | python -m json.tool
# {"targets": [{"target_id": "pygoat", "name": "OWASP PyGoat", "kind": "practice-app", ...}, ...]}

# Scan an authorized target (synchronous in the prototype: findings come back inline)
curl -s -X POST $BASE/scans -H 'content-type: application/json' \
     -d '{"target_id": "pygoat"}' | python -m json.tool

# Scan a pasted snippet (the mock SAST reacts to the actual code)
curl -s -X POST $BASE/scans -H 'content-type: application/json' \
     -d '{"target_id": "snippet", "options": {"snippet": "cur.execute(f\"SELECT * FROM t WHERE id={uid}\")"}}'

# Unauthorized target -> 403, nothing runs
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/scans \
     -H 'content-type: application/json' -d '{"target_id": "example.com"}'
# 403

curl -s $BASE/scans/<scan_id>/findings
curl -s $BASE/findings/<finding_id>
```

The scan is synchronous today. `ScanService.start_scan` is already split into *authorize → create → execute → persist*, so moving execution onto a worker (202 Accepted, `status="queued"`, poll `GET /scans/{id}`) is a local change that does not alter the resource model.

---

## Configuration

All configuration is read by `ono.config.Settings` (pydantic-settings) from environment variables or a `.env` file. Three profiles ship: `.env.example.local`, `.env.example.production`, and `.env.example.service` (real model via Ollama, see below). Invalid values fail fast at startup.

| Variable | Default | Values / notes |
|---|---|---|
| `APP_NAME` | `Operation: Negative One` | Display name |
| `ENVIRONMENT` | `local` | `local` · `staging` · `production` (validated) |
| `LOG_LEVEL` | `INFO` | Any Python logging level name (validated) |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | Bind address; 8080 is the one published port |
| `MODEL_BACKEND` | `mock` | `mock` · `local` · `service` (validated). **Deliverable 2 runs `mock`**; `service` calls a real model; `local` is not implemented yet. |
| `MODEL_NAME` | `Qwen/Qwen2.5-Coder-7B-Instruct` | Informational for `mock`; sent as the `model` field by `service` (e.g. `qwen2.5-coder:7b` for Ollama) |
| `MODEL_SERVICE_URL` | — | **Required when `MODEL_BACKEND=service`** (startup fails otherwise). OpenAI-compatible base URL, e.g. `http://localhost:11434/v1` |
| `MODEL_SERVICE_API_KEY` | — | `SecretStr`: never logged, never returned by `/info` |
| `MAX_VERIFIER_RETRIES` | `3` | 1–5. Hard cap on the verifier self-correction loop |
| `WORKSPACE_DIR` | `.ono-workspace` | Per-scan clone workspaces (`<dir>/<scan_id>/`), removed when each scan ends. Must be writable; the image sets `/tmp/ono-workspace` |
| `SAST_RULESET` | `p/owasp-top-ten` | Comma-separated Semgrep `--config` values (registry packs or local rule files). A language pack (`p/python`, `p/javascript`, …) is appended per target language. Empty = skip Semgrep, regex scanner only |
| `MAX_CANDIDATES` | `20` | 1–200. Cap on SAST candidates kept per scan — and therefore on model calls |
| `CONTEXT_LINES` | `25` | 5–200. Lines of code shown to the model on each side of a candidate sink |
| `CLONE_TIMEOUT_S` | `120` | 5–1800. Hard timeout for the shallow `git clone` |
| `MAX_CLONE_MB` | `200` | 1–5000. Snapshots larger than this (after `.git` is stripped) abort the scan; also the cap on a workspace archive uploaded to the Executor |
| `EXECUTOR_URL` | `http://127.0.0.1:8081` | Where the app reaches the Executor (`http://executor:8081` under Compose) |
| `EXECUTOR_TOKEN` | — | `SecretStr`, ≥16 chars. **Required by the Executor** (it refuses to start without it); sent as `Authorization: Bearer` |
| `EXECUTOR_HOST` / `EXECUTOR_PORT` | `127.0.0.1` / `8081` | Executor bind address. Loopback by default; `0.0.0.0` only inside the Compose internal network. Never published |
| `SANDBOX_IMAGE` | `python:3.13-slim` | Base image of the jailed target containers (pulled if missing) |
| `SANDBOX_MEM_MB` | `1024` | 64–65536. Memory limit per jail, swap disabled; the tmpfs workspace counts against it |
| `SANDBOX_CPUS` | `1.0` | 0.1–64. CPU quota per jail |
| `SANDBOX_PIDS_LIMIT` | `256` | 16–8192. PID limit per jail (fork bombs) |
| `SANDBOX_CMD_TIMEOUT_S` | `300` | 1–3600. Hard cap on any single `run()` / `run_tests()` |
| `SANDBOX_TTL_S` | `1800` | 30–86400. Max jail age; the sweeper force-removes older containers, orphans included |
| `SANDBOX_OUTPUT_CAP_BYTES` | `1000000` | 1 KB–50 MB. Per-stream cap on captured stdout/stderr and on file reads |
| `SANDBOX_WORKSPACE_MB` | `512` | 16–16384. Size of the writable tmpfs holding the workspace (`/tmp` gets half) |
| `SANDBOX_MAX_ACTIVE` | `8` | 1–64. Max concurrently live jails per Executor |

The ingest/SAST settings apply to the `service` backend (`mock` never clones or runs Semgrep). The `EXECUTOR_*` / `SANDBOX_*` settings configure the Executor service (step 3a); the analyzer pipeline does not call it yet (that is step 3b).

The **target allowlist** lives in [`src/ono/targets.yaml`](src/ono/targets.yaml) and is loaded into an exact mapping (`TargetRegistry`). Adding a target means adding an entry there — nothing is accepted that is not in the file. Three real, cloneable targets ship: `pygoat` and `juice-shop` (practice apps) and `vulpy` (a small intentionally vulnerable Flask repo, the "ingested OSS repo" kind).

---

## Project layout

```
operation-negative-one/
├── src/ono/
│   ├── api.py          FastAPI app: documented endpoints + mounted Gradio UI
│   ├── ui.py           Gradio analyst UI (target picker / snippet -> Analyze -> finding cards)
│   ├── service.py      ScanService: allowlist gate -> run pipeline -> persist
│   ├── analyzer.py     Pipeline skeleton (ingest/sast/plan/analyze/verify) + MockAnalyzer + ServiceAnalyzer
│   ├── ingest.py       Stage 1 for real backends: shallow clone / snippet file into a per-scan workspace
│   ├── sast.py         Stage 2 for real backends: Semgrep JSON -> Candidate queue, regex fallback
│   ├── models.py       Pydantic schemas: ScanRequest, Finding, Scan, ScanResponse, ...
│   ├── targets.py      TargetRegistry (exact allowlist) + targets.yaml
│   ├── store.py        ScanStore protocol + in-memory implementation
│   ├── config.py       Settings (pydantic-settings)
│   ├── __main__.py     `ono` / `python -m ono` entrypoint (uvicorn)
│   └── executor/       step 3a: the sandboxed "hands" (separate, internal-only service)
│       ├── sandbox.py      SandboxManager / Sandbox: jailed per-scan containers, exec protocol, TTL sweeper
│       ├── _guest.py       stdlib helper that runs INSIDE the jail: confined read/tree/grep, diff applier
│       ├── archive.py      workspace <-> gzipped tar (ship in, validate, snapshot for reset)
│       ├── app.py          the Executor FastAPI service (bearer-token auth on everything but /health)
│       ├── client.py       ExecutorClient: typed HTTP client the orchestrator (3b) will use
│       ├── models.py       request/response schemas shared by service and client
│       └── __main__.py     `ono-executor` / `python -m ono.executor`
├── tests/              pytest: config, API (incl. 403 allowlist test), analyzers, ingest, SAST, executor
│   ├── fixtures/       tiny vulnerable sample repo + a real Semgrep JSON document (tests stay offline)
│   ├── fakedocker.py   fake docker-py client (extracts the tar, runs the real guest helper) for CI
│   └── test_executor_docker.py   REAL-container stress tests (`-m docker`; auto-skipped in CI / without a daemon)
├── scripts/golden_path.py   smoke heartbeat (live server or --in-process)
├── Dockerfile · compose.yml · .dockerignore
├── .env.example.local · .env.example.production
├── .github/workflows/ci.yml   ruff + mypy + pytest + docker build/health on push & PR
└── Makefile · .pre-commit-config.yaml
```

---

## Where the real pipeline slots in

`ono/analyzer.py` defines `BaseAnalyzer` with five stage methods. `MockAnalyzer` implements them with canned data; the Deliverable-3 backends implement the same five methods for real (every stage carries a `TODO(D3)` marker):

| Stage | Mock today | Real (Deliverable 3) |
|---|---|---|
| `ingest` | returns the pinned snapshot ref | **done (step 2):** shallow clone into a per-scan workspace, `.git` stripped, size/time bounded (`ono/ingest.py`). Still to come: the egress-blocked sandbox container around it, CVE-string stripping, tree-sitter + call graph |
| `sast_shortlist` | canned candidates (regex SAST for snippets) | **done (step 2):** Semgrep JSON → normalized, ranked, deduplicated `Candidate` queue with a regex fallback (`ono/sast.py`). Still to come: CodeQL → SARIF |
| `plan` | fixed step list | **frozen Qwen2.5-Coder, planner role** emits the per-target scaffold (Fugu-inspired, no training) |
| `analyze` | canned findings | **Qwen analyst role** in a bounded LangGraph ReAct loop (read_file / callers / grep / retrieve_cwe), served by vLLM |
| `verify` | passes `verified=True` | **deterministic verifier** (plain code): line exists, PoC reaches sink, patch applies, PoC no longer fires, tests pass; failure reasons feed a bounded self-correction loop (`MAX_VERIFIER_RETRIES`) |

Switching is a config change: `MODEL_BACKEND=local` (vLLM on the same box, never published) or `MODEL_BACKEND=service` (remote OpenAI-compatible endpoint). `build_analyzer()` is the only place that needs to know. The in-memory `ScanStore` is likewise the seam for the internal findings database.

### Service backend today: real ingest + Semgrep shortlist (step 2)

`ServiceAnalyzer` (`MODEL_BACKEND=service`) analyzes **real repository files**:

1. **ingest** — `repo` / `practice-app` targets are shallow-cloned (`git clone --depth 1 --no-tags --single-branch`, timeout `CLONE_TIMEOUT_S`, cap `MAX_CLONE_MB`) into `WORKSPACE_DIR/<scan_id>/`; `.git` is deleted immediately, so the origin is contacted exactly once and nothing cloned is ever executed. A `snippet` is written to `snippet.py` in the same workspace. The workspace is removed when the scan ends, success or failure.
2. **sast_shortlist** — Semgrep (`semgrep scan --json --metrics=off --config <SAST_RULESET> …`) over the workspace; results are normalized to `Candidate{file, line, cwe_hint, rule, excerpt}` (file relative to the clone root, CWE from the rule's metadata), ranked by severity, deduplicated and capped at `MAX_CANDIDATES`. If Semgrep is missing, fails or times out, a built-in regex scanner takes over so the stage never fails a scan (the log says which engine ran).
3. **analyze** — one model call **per candidate** (so a large repo fans out to at most `MAX_CANDIDATES` calls) over the real code `CONTEXT_LINES` around the sink. The model confirms or dismisses; each `Finding` is anchored to the candidate's real `file:line` and carries a one-hop trace naming the SAST rule.
4. **plan** is still a fixed step list and **verify** is still a pass-through, so findings remain `verified=False` and at most rung 2. The deterministic verifier + self-correction loop is the next step.

With Ollama serving `qwen2.5-coder:7b` on the instance (`git` is on `PATH`; Semgrep arrives with `uv sync`):

```bash
cp .env.example.service .env        # MODEL_BACKEND=service, MODEL_SERVICE_URL=http://localhost:11434/v1, MODEL_NAME=qwen2.5-coder:7b
uv run ono

# A real repository, end to end. The first run clones PyGoat and lets Semgrep fetch its
# rule packs, then makes up to MAX_CANDIDATES model calls - expect a minute or two.
curl -s -X POST localhost:8080/scans -H 'content-type: application/json' \
  -d '{"target_id":"pygoat"}' | jq '.pipeline, .findings[] | {cwe, file, line_range, rung, verified, title}'

# The pasted-snippet path works the same way (snippet -> SAST -> model).
curl -s -X POST localhost:8080/scans -H 'content-type: application/json' \
  -d '{"target_id":"snippet","options":{"snippet":"import os\nos.system(\"ping \" + host)\n"}}' | jq .
```

The `.pipeline` array in the response shows each stage's status and timing (`ingest` reports the workspace path, `sast` the candidate count). Clone or Semgrep problems surface as `status: "failed"` with the reason in the server log — never as a silent empty result.

---

## The sandbox Executor (step 3a)

Rung 3/4 output ("the PoC reaches the sink", "the patch applies and the tests still pass") means **running untrusted target code**. That happens only inside the **Executor**: a separate, internal-only, token-authenticated FastAPI service (`ono.executor.app`, container C in `compose.yml`) that spins up **one ephemeral, jailed Docker container per scan**, runs operations against it over `docker exec`, and destroys it afterwards (on `DELETE`, on Executor shutdown, or when the TTL sweeper finds it).

**Trust boundary.** The Executor is *privileged* — it mounts the host Docker socket, which is equivalent to root on the host — so it is kept tiny and audited, never published (Compose puts it on an `internal: true` network with no `ports:`), and runs nothing untrusted itself. The **target containers it spawns are the untrusted, jailed ones**:

| Jail flag | Why |
|---|---|
| `network_mode=none` | no egress at all: only `lo`; cannot reach the internet, the Executor, the app, the model, or another sandbox |
| non-root, two uids | PID 1 (`docker-init` + `sleep`) runs as uid 10002, every exec as uid 10001 — so a `kill -9 -1` *as the sandbox user* reaps every stray process (including `setsid` escapes) without touching PID 1, and the inmate cannot kill its own container |
| `cap_drop=ALL`, `no-new-privileges`, `nosuid,nodev` mounts | zero capabilities, no privilege-escalation path |
| `read_only=True` rootfs + bounded `tmpfs` for `/workspace` (owned by uid 10001) and `/tmp` | the image is immutable; writable space is sized |
| `mem_limit` (= `memswap_limit`), `nano_cpus`, `pids_limit`, `init=True`, `oom_score_adj=1000` | memory hogs are OOM-killed inside the jail, fork bombs hit the PID wall, zombies are reaped, and under host memory pressure sandbox processes die first |
| no volumes at all | the Docker socket is never mounted into a target |
| labels `ono.sandbox` / `ono.scan_id` / `ono.created_at` | the TTL sweeper force-removes orphans (e.g. after an Executor crash) |

**Operations** — all executed *inside* the jail, all with a hard deadline and a byte cap: `read_file` / `read_lines` / `tree` / `grep` (path-confined: no absolute paths, no `..`, every component opened with `O_NOFOLLOW` so a planted symlink is never followed), `apply_patch` (strict all-or-nothing unified-diff applier), `run(cmd, timeout_s)` (`timeout -s KILL` plus a host-side socket deadline; strays reaped afterwards; `timed_out` / `oom_killed` / `truncated` reported), `run_tests()` (pytest / npm detection, best-effort), and `reset()` (destroy + recreate from the snapshot kept on the trusted side — about 100 ms — which also revives a jail that died).

```bash
# Run the Executor locally (Docker required; it pulls python:3.13-slim on first use)
echo "EXECUTOR_TOKEN=$(openssl rand -hex 32)" >> .env
make executor                        # == uv run ono-executor  -> http://127.0.0.1:8081/docs

# Drive it from Python (this is what the orchestrator in step 3b will do)
uv run python -c '
from pathlib import Path
from ono.executor.client import ExecutorClient
client = ExecutorClient("http://127.0.0.1:8081", "<EXECUTOR_TOKEN>")
with client.sandbox("scn_demo", Path("tests/fixtures/vuln_repo")) as sbx:
    print(sbx.grep(r"os\.system", path="app").matches)
    print(sbx.run("python3 -c \"import urllib.request as u; u.urlopen(\"http://example.com\")\"", timeout_s=5).exit_code)  # != 0: no egress
    print(sbx.run("sleep 999", timeout_s=2).timed_out)      # True
'

# The real-container stress suite: egress, timeouts, OOM, fork bombs, disk fill, path
# escapes, teardown-on-error, orphan sweeper, concurrency, patch/reset, service auth.
make test-docker
```

The stress tests live in `tests/test_executor_docker.py` and run automatically with plain `pytest` whenever a Docker daemon is reachable (they are skipped in CI, where the unit tests exercise the same code paths against `tests/fakedocker.py`).

---

## Course concepts demonstrated

- **Configuration through settings** — one `Settings` class (pydantic-settings) drives the app, the container, Compose, and CI; environment and backend values are validated; secrets are `SecretStr`. Two `.env.example.*` profiles.
- **Containerized deployment** — multi-step `Dockerfile` (lockfile-first cached dependency layer, non-root user, `HEALTHCHECK`), `.dockerignore`, and a `compose.yml` where `docker compose up -d` is the whole start procedure.
- **Documented API** — FastAPI with typed pydantic request/response models, generated OpenAPI at `/docs` and `/redoc`, explicit error schemas (403 / 404 / 422).
- **Publish only the app port** — the single service publishes `8080` and nothing else; future DB / vLLM / sandbox services stay internal by construction.
- **Testing and CI** — pytest (including the blocking allowlist security test), ruff, strict mypy, a golden-path smoke script, and a GitHub Actions workflow that also builds the image and probes `/health`.

## Guardrails

ONO is defensive tooling that uses offensive techniques, so the boundary is enforced in code, not policy: scans are addressed by `target_id` only (never a URL), the registry is an exact allowlist, proofs-of-concept are read-only and run only inside an egress-blocked sandbox, and the model, sandbox, and data stores are never published. The full ethics and dual-use discussion is in the project plan.
