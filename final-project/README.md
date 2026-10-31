# Operation: Negative One (ONO)

**An agentic system that finds software vulnerabilities in authorized code targets, proves they are real, and proposes verified fixes.**

DSAN 6700 — Deploying Machine Learning Applications to Customers · Georgetown University
Team: Sazan Khalid · Kenedy Ducheine · Junyi Tang · Jeffrey Pinarchick

| | |
|---|---|
| Live app (Jetstream2) | [http://149.165.154.219:8080/ui/](http://149.165.154.219:8080/ui/), running the `service` backend with `qwen2.5-coder:7b` |
| API docs (OpenAPI) | [http://149.165.154.219:8080/docs](http://149.165.154.219:8080/docs) |
| Repository | [`dt7860920/6700-team-project`](https://github.com/dt7860920/6700-team-project), in `final-project/` |
| Design docs | [Project plan](docs/plan.md) · [Deliverable 2 write-up](docs/deliverable2.md) |

> **Status.** The API, configuration, container, and analyst UI are real and deployable. The default **analyzer is mocked** (`MODEL_BACKEND=mock`): it is shaped exactly like the production pipeline — `ingest → SAST shortlist → plan → analyze → verify` — but returns deterministic, representative findings instead of calling a model, so its `rung`, `verified`, and line-number values are illustrative. `MODEL_BACKEND=service` runs the real pipeline up to and including **detection** (Deliverable 3, step 3b-1): real ingest, Semgrep shortlist, and a planner + analyst agent loop that reads the target only through the jailed sandbox Executor. The verifier and fixer agent are not built yet, so real findings come back `verified=false` at rung 1 or 2 with no patch. `MODEL_BACKEND=local` is not implemented yet. See [Where the real pipeline slots in](#where-the-real-pipeline-slots-in).

---

## What it does

ONO never scans "a website". Every request names a **`target_id`** from an exact allowlist of targets we host ourselves — intentionally-vulnerable practice apps (OWASP PyGoat, OWASP Juice Shop), ingested open-source repository snapshots, or a pasted code snippet. An unknown id is rejected with **HTTP 403 before any analysis starts**, and a malformed one (such as a full URL) fails request validation with **HTTP 422**.

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

Requires Python 3.13 or newer and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/dt7860920/6700-team-project.git
cd 6700-team-project/final-project
uv sync --extra dev
cp .env.example.local .env
uv run ono                      # http://localhost:8080  (UI at /ui, docs at /docs)
```

Quality gates (the same ones defined in the CI workflow):

```bash
uv run ruff check && uv run ruff format --check
uv run mypy src/
uv run pytest
uv run scripts/golden_path.py --in-process     # golden-path heartbeat, no server needed
# or simply:  make check smoke-ci
```

Run these by hand for now. The workflow is at `final-project/.github/workflows/ci.yml`, but GitHub only runs workflows from `.github/workflows/` at the repository root, and the root CI does not cover `final-project/`.

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
git clone https://github.com/dt7860920/6700-team-project.git
cd 6700-team-project/final-project
cp .env.example.production .env
echo "EXECUTOR_TOKEN=$(openssl rand -hex 32)" >> .env   # the Executor refuses to start without one
docker compose up -d --build
docker compose ps                              # wait for both services to be "healthy"
curl http://localhost:8080/health
```

From your laptop: `curl http://<FLOATING-IP>:8080/health`. For a deployment running `MODEL_BACKEND=mock`, you can also run `uv run scripts/golden_path.py --base-url http://<FLOATING-IP>:8080`. Don't use it against the `service` backend: it starts a real scan and requires a verified finding with a patch, which that backend can't produce until the verifier and fixer exist.

`compose.yml` defines **two services** and publishes **one port** (8080): the app, and the sandbox **Executor** (see [The sandbox Executor](#the-sandbox-executor-step-3a)) on an `internal: true` network with no `ports:` block. There is deliberately no database in the skeleton — scan state is in-memory. When the findings DB, threat-intel cache, and vLLM join the stack they are added the same way, as internal services *without* `ports:`, so the published surface stays exactly `:8080`.

---

## API

Interactive documentation is generated from the code at **`/docs`** (Swagger UI) and **`/redoc`**; the raw schema is at `/openapi.json`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness → `{"status":"ok"}` |
| `GET` | `/info` | App name, version, environment, model backend (no secrets) |
| `GET` | `/targets` | The authorized-target allowlist |
| `POST` | `/scans` | Start a scan **in the background**. **202** with the scan record (`status: "queued"`, `scan_id`). **403** if `target_id` is not allowlisted; **429** if the worker pool and queue are full. |
| `GET` | `/scans/{scan_id}` | The **live** scan record: `status` (`queued → running → done \| failed`), `progress` (what it is doing now), `events` (activity log), `pipeline` (stage results so far), `findings_count`, `message` |
| `GET` | `/scans/{scan_id}/findings` | Findings for a scan (empty until it is `done`) |
| `GET` | `/findings/{finding_id}` | One finding |
| `GET` | `/ui` | Gradio analyst UI (`/` redirects here) — see [The analyst UI](#the-analyst-ui-handoff-surface) |

```bash
BASE=http://localhost:8080

curl -s $BASE/health
# {"status":"ok"}

curl -s $BASE/targets | python -m json.tool
# {"targets": [{"target_id": "pygoat", "name": "OWASP PyGoat", "kind": "practice-app", ...}, ...]}

# Start a scan of an authorized target: 202 Accepted, the scan runs in the background
curl -s -X POST $BASE/scans -H 'content-type: application/json' \
     -d '{"target_id": "pygoat"}' | python -m json.tool
# {"scan_id": "scn_…", "status": "queued", "progress": "Waiting for a free scan worker", ...}

# Poll the live record until status is "done" or "failed"
curl -s $BASE/scans/<scan_id> | jq '{status, progress, findings_count, pipeline: [.pipeline[].stage]}'
# {"status": "running", "progress": "Analyzing candidate 2 of 3 - app/views.py:16 (CWE-89)", ...}

# Then read the findings
curl -s $BASE/scans/<scan_id>/findings
curl -s $BASE/findings/<finding_id>

# Scan a pasted snippet (the mock SAST reacts to the actual code)
curl -s -X POST $BASE/scans -H 'content-type: application/json' \
     -d '{"target_id": "snippet", "options": {"snippet": "cur.execute(f\"SELECT * FROM t WHERE id={uid}\")"}}'

# Unauthorized target -> 403, nothing runs
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/scans \
     -H 'content-type: application/json' -d '{"target_id": "example.com"}'
# 403
```

**How a scan runs.** `POST /scans` only checks the allowlist and creates the record; the pipeline runs on a small **background worker pool** (`MAX_ACTIVE_SCANS` threads — a scan does blocking work: `git clone`, Semgrep, Docker, model HTTP calls — so it never touches the event loop). The worker writes into the record as it goes: `status`, a one-line `progress` (`Fetching the target snapshot` → `Static analysis` → `Analyzing candidate 2 of 3 - app/views.py:16` → `Candidate 2 of 3 dismissed: …`), the `events` log, and each `pipeline` stage result as it completes. On failure `status` is `failed` and `message` carries the reason (`analysis pipeline failed: executor unreachable at …`). Up to `MAX_QUEUED_SCANS` scans wait for a worker (`status: "queued"`); beyond that `POST /scans` answers **429** with a `Retry-After` header instead of growing an unbounded backlog of model sessions. `scripts/golden_path.py` shows the submit-then-poll loop in ten lines.

---

## The analyst UI (handoff surface)

`http://<host>:8080/ui` is the only surface a reviewer needs; it is mounted inside the same FastAPI process (no extra port) and calls the same `ScanService` the API uses, so the allowlist check cannot be bypassed from the browser.

1. **Pick a target** from the dropdown (name + kind: *practice app*, *repository*, or *paste code*). Choosing *Pasted code snippet* reveals a code box with an example.
2. **Click Analyze.** The scan is submitted in the background and the page **polls** it every `UI_POLL_INTERVAL_S` seconds, so the browser never waits on a long request. The progress card shows a status pill (Queued / Running / Done / Failed), the elapsed time, the current step (`Cloning … → Static analysis → Analyzing candidate 2 of 3 - app/views.py:16 → Verifying`), a five-stage checklist with timings, and an expandable activity log (every candidate the agents confirmed or dismissed, and why).
3. **Read the findings.** Each finding is a card: title; **CWE** linked to MITRE; **severity**; the **rung** badge (1–5, hover for what it means); **✔ verified** (the deterministic verifier passed) or **⚠ not verified** (model-asserted); **confidence**; `file:line`; the readable **source → sink trace**; the description; and the **proposed patch** as a collapsible colored diff (plus the detection rule on rung 5). Cards are ordered by severity. "How to read a finding" explains the ladder; "Raw JSON" shows exactly what the API returned.
4. **No findings** is a clear green state ("No vulnerabilities found", with how many candidates were reviewed and dismissed). **A failed scan** shows the reason in plain language ("Scan failed: executor unreachable at …") with a hint to check the model endpoint and the Executor — never a stack trace. If ONO is at capacity you see "Busy … retry in a moment".
5. **Long scans.** A real `service`-backend scan takes minutes. You can leave the page: the scan keeps running, and **Look up a scan by id** re-attaches to it (the id is in the status card and in the API response).

The UI works unchanged on both backends: `mock` finishes in milliseconds (good for a first click), `service` streams real progress for the whole run.

---

## Configuration

All configuration is read by `ono.config.Settings` (pydantic-settings) from environment variables or a `.env` file. Three profiles ship: `.env.example.local`, `.env.example.production`, and `.env.example.service` (real model via Ollama, see below). Invalid values fail fast at startup.

| Variable | Default | Values / notes |
|---|---|---|
| `APP_NAME` | `Operation: Negative One` | Display name |
| `ENVIRONMENT` | `local` | `local` · `staging` · `production` (validated) |
| `LOG_LEVEL` | `INFO` | Any Python logging level name (validated) |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | Bind address for `uv run ono`. The Docker image always binds `0.0.0.0:8080`, the one published port |
| `MODEL_BACKEND` | `mock` | `mock` · `local` · `service` (validated). **Deliverable 2 runs `mock`**; `service` calls a real model; `local` is not implemented yet. |
| `MODEL_NAME` | `Qwen/Qwen2.5-Coder-7B-Instruct` | Informational for `mock`; sent as the `model` field by `service` (e.g. `qwen2.5-coder:7b` for Ollama) |
| `MODEL_SERVICE_URL` | — | **Required when `MODEL_BACKEND=service`** (startup fails otherwise). OpenAI-compatible base URL, e.g. `http://localhost:11434/v1` |
| `MODEL_SERVICE_API_KEY` | — | `SecretStr`: never logged, never returned by `/info` |
| `MAX_VERIFIER_RETRIES` | `3` | 1–5. Reserved cap for the verifier self-correction loop, which is not built yet (3b-2) |
| `MAX_ACTIVE_SCANS` | `2` | 1–16. Scans that run at the same time (background worker threads). Each holds a model session and, on `service`, one sandbox |
| `MAX_QUEUED_SCANS` | `8` | 0–100. Scans allowed to wait for a worker; beyond this `POST /scans` answers 429 (busy) |
| `UI_POLL_INTERVAL_S` | `1.0` | 0.2–10. How often the UI refreshes a running scan's status card |
| `UI_POLL_TIMEOUT_S` | `3600` | 30–86400. How long the UI keeps watching one scan (the scan itself continues; "Look up a scan by id" picks it up again) |
| `WORKSPACE_DIR` | `.ono-workspace` | Per-scan clone workspaces (`<dir>/<scan_id>/`), removed when each scan ends. Must be writable; the image sets `/tmp/ono-workspace` |
| `SAST_RULESET` | `p/owasp-top-ten` | Comma-separated Semgrep `--config` values (registry packs or local rule files). A language pack (`p/python`, `p/javascript`, …) is appended per target language. Empty = skip Semgrep, regex scanner only |
| `MAX_CANDIDATES` | `20` | 1–200. Cap on SAST candidates kept per scan — and therefore on model calls |
| `CONTEXT_LINES` | `25` | 5–200. Lines of code shown to the model on each side of a candidate sink |
| `CLONE_TIMEOUT_S` | `120` | 5–1800. Hard timeout for the shallow `git clone` |
| `MAX_CLONE_MB` | `200` | 1–5000. Snapshots larger than this (after `.git` is stripped) abort the scan; also the cap on a workspace archive uploaded to the Executor |
| `PLANNER_ENABLED` | `true` | Run the planner agent (one model call per candidate) before the analyst. `false` = fixed default plan, no planner call |
| `ANALYST_MAX_STEPS` | `8` | 1–32. Hard cap on model calls in the analyst's ReAct loop per candidate (tool calls, retries after malformed replies and the final verdict all count) |
| `AGENT_TEMPERATURE` | `0.0` | 0–2. Sampling temperature for every agent call |
| `AGENT_TOOL_PROTOCOL` | `auto` | `native` (OpenAI function calling) · `text` (one JSON action per reply) · `auto` (native first; falls back to text for the rest of the process if the endpoint rejects `tools`) |
| `AGENT_TOOL_OUTPUT_CHARS` | `6000` | 500–100000. Max characters of any single tool result fed back to the model (truncated on whole lines) |
| `AGENT_CANDIDATE_TIMEOUT_S` | `300` | 10–3600. Wall-clock budget per candidate (planner + analyst), checked between steps |
| `AGENT_TRAJECTORY_DIR` | — | If set, every agent trajectory (each model call, tool call, result, verdict) is appended as JSON lines to `<dir>/<scan_id>.jsonl` |
| `EXECUTOR_URL` | `http://127.0.0.1:8081` | Where the app reaches the Executor (`http://executor:8081` under Compose) |
| `EXECUTOR_TOKEN` | — | `SecretStr`, ≥16 chars. **Required by the Executor** (it refuses to start without it) **and by `MODEL_BACKEND=service`** (the agents read code only through the sandbox); sent as `Authorization: Bearer` |
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

The ingest/SAST/agent settings apply to the `service` backend (`mock` never clones, runs Semgrep, calls a model or opens a sandbox). The `EXECUTOR_URL` / `EXECUTOR_TOKEN` pair is how the app reaches the Executor service; the `SANDBOX_*` settings configure the jails the Executor spawns. Upper bound on model calls per scan: `MAX_CANDIDATES × (ANALYST_MAX_STEPS + 1 if PLANNER_ENABLED)` — 180 with the defaults — and the orchestrator enforces it as a hard counter.

The **target allowlist** lives in [`src/ono/targets.yaml`](src/ono/targets.yaml) and is loaded into an exact mapping (`TargetRegistry`). Adding a target means adding an entry there — nothing is accepted that is not in the file. Three real, cloneable targets ship: `pygoat` and `juice-shop` (practice apps) and `vulpy` (a small intentionally vulnerable Flask repo, the "ingested OSS repo" kind).

---

## Project layout

```
final-project/
├── src/ono/
│   ├── api.py          FastAPI app: documented endpoints + mounted Gradio UI
│   ├── ui.py           Gradio analyst UI (target picker -> Analyze -> live progress -> finding cards)
│   ├── service.py      ScanService: allowlist gate -> background worker pool -> live scan record
│   ├── progress.py     ProgressSink: how the pipeline reports "what I am doing now"
│   ├── analyzer.py     Pipeline skeleton (ingest/sast/plan/analyze/verify) + MockAnalyzer + ServiceAnalyzer
│   ├── ingest.py       Stage 1 for real backends: shallow clone / snippet file into a per-scan workspace
│   ├── sast.py         Stage 2 for real backends: Semgrep JSON -> Candidate queue, regex fallback
│   ├── orchestrator.py step 3b-1: the deterministic detection state machine (one sandbox per scan,
│   │                   planner -> analyst per candidate, every budget enforced here)
│   ├── agents/         step 3b-1: agent *definitions* on the one pinned model
│   │   ├── definitions.py  PLANNER / ANALYST = role prompt + allowed tools + step budget + temperature
│   │   ├── model.py        shared OpenAI-compatible client: native tool calling, text fallback, call budget
│   │   ├── tools.py        read_lines / read_file / grep / tree dispatched to the jail; truncation; read ledger
│   │   ├── protocol.py     tolerant parsing of model replies into tool calls / verdicts
│   │   ├── planner.py      one call -> InvestigationPlan (degrades to a default plan)
│   │   ├── analyst.py      the bounded ReAct loop -> anchored Finding or dismissal
│   │   └── trajectory.py   per-run step log (JSONL sink) - observability / learning data
│   ├── errors.py       PipelineError: scan failures whose message is safe to show
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
│       ├── client.py       ExecutorClient: typed HTTP client the orchestrator uses
│       ├── models.py       request/response schemas shared by service and client
│       └── __main__.py     `ono-executor` / `python -m ono.executor`
├── tests/              pytest: config, API (incl. 403 allowlist test), analyzers, ingest, SAST, executor, agents
│   ├── fixtures/       tiny vulnerable sample repo + a real Semgrep JSON document (tests stay offline)
│   ├── fakedocker.py   fake docker-py client (extracts the tar, runs the real guest helper) for CI
│   ├── agentfakes.py   scripted model + local sandbox + fake Executor for the agent / orchestrator tests
│   ├── test_agents.py  protocol parsing, tools + ledger, ReAct loop, planner, model wire format, orchestrator
│   ├── test_executor_docker.py      REAL-container stress tests (`-m docker`; auto-skipped in CI / without a daemon)
│   └── test_orchestrator_docker.py  REAL-jail end-to-end run of the detection core, model scripted (`-m docker`)
├── scripts/golden_path.py   smoke heartbeat (live server or --in-process)
├── docs/               project plan and Deliverable 2 write-up
├── Dockerfile · compose.yml · .dockerignore
├── .env.example.local · .env.example.production · .env.example.service
├── .github/workflows/ci.yml   ruff + mypy + pytest + docker build/health (not active from this subfolder)
└── Makefile · .pre-commit-config.yaml
```

---

## Where the real pipeline slots in

`ono/analyzer.py` defines `BaseAnalyzer` with five stage methods. `MockAnalyzer` implements them with canned data; `ServiceAnalyzer` implements the same five methods for real, with `verify` still a pass-through:

| Stage | Mock today | Real (Deliverable 3) |
|---|---|---|
| `ingest` | returns the pinned snapshot ref | **done (step 2):** shallow clone into a per-scan workspace, `.git` stripped, size/time bounded (`ono/ingest.py`). Still to come: the egress-blocked sandbox container around it, CVE-string stripping, tree-sitter + call graph |
| `sast_shortlist` | canned candidates (regex SAST for snippets) | **done (step 2):** Semgrep JSON → normalized, ranked, deduplicated `Candidate` queue with a regex fallback (`ono/sast.py`). Still to come: CodeQL → SARIF |
| `plan` | fixed step list | **done (step 3b-1):** the frozen Qwen **planner role** emits a compact per-candidate investigation plan (what to read, which taint to check, how to decide) that feeds the analyst (`ono/agents/planner.py`) |
| `analyze` | canned findings | **done (step 3b-1):** the Qwen **analyst role** in a bounded ReAct loop over read-only sandbox tools (`read_lines` / `read_file` / `grep` / `tree`), driven by a deterministic orchestrator; findings are anchored to lines actually read through the jail (`ono/orchestrator.py`, `ono/agents/analyst.py`). Still to come (3b-2): the fixer agent and the execution tools |
| `verify` | passes `verified=True` | **not built yet (3b-2):** a deterministic verifier (plain code): line exists, PoC reaches sink, patch applies, PoC no longer fires, tests pass; failure reasons feed a bounded self-correction loop (`MAX_VERIFIER_RETRIES`) |

Switching is a config change: `MODEL_BACKEND=service` calls an OpenAI-compatible endpoint today. `MODEL_BACKEND=local` (vLLM on the same box, never published) is planned and raises `NotImplementedError` at startup until then. `build_analyzer()` is the only place that needs to know. The in-memory `ScanStore` is likewise the seam for the internal findings database.

### Service backend today: the agentic detection core (step 3b-1)

`ServiceAnalyzer` (`MODEL_BACKEND=service`) analyzes **real repository files** with two agents on one pinned model, orchestrated by deterministic code:

1. **preflight** — the Executor must answer `/health` (and see Docker), otherwise the scan fails *before* anything is cloned with `status: "failed"` and a message such as `executor unreachable at http://127.0.0.1:8081 (...); start it with \`make executor\``. There is no silent fallback to reading code on the host.
2. **ingest** — `repo` / `practice-app` targets are shallow-cloned (`git clone --depth 1 --no-tags --single-branch`, timeout `CLONE_TIMEOUT_S`, cap `MAX_CLONE_MB`) into `WORKSPACE_DIR/<scan_id>/`; `.git` is deleted immediately. A `snippet` is written to `snippet.py` in the same workspace. The workspace is removed when the scan ends, success or failure.
3. **sast_shortlist** — Semgrep over the workspace (regex fallback if Semgrep is unavailable), normalized to `Candidate{file, line, cwe_hint, rule, excerpt}`, ranked, deduplicated and capped at `MAX_CANDIDATES`.
4. **plan** — deterministic: the candidate queue the orchestrator will walk (no model call).
5. **analyze** — `DetectionOrchestrator.detect` (`ono/orchestrator.py`), a state machine, not an LLM:
   * opens **one jailed sandbox for the scan** (`ExecutorClient.sandbox(scan_id, workspace)`), only if there is at least one candidate; it is destroyed by the context manager on success, error or budget exhaustion;
   * per candidate — **WINDOW**: the orchestrator reads `CONTEXT_LINES` around the sink *through the jail* (this seeds the analyst's read ledger); **PLAN**: the **planner** agent makes one bounded call and returns a compact JSON investigation plan (hypothesis, source, sink, greps, reads, steps, decision rule), degrading to a default plan on unusable output; **ANALYZE**: the **analyst** agent runs a ReAct loop — reason → call one of `read_lines` / `read_file` / `grep` / `tree` (each dispatched to the sandbox, each result truncated to `AGENT_TOOL_OUTPUT_CHARS`) → see the result → repeat, at most `ANALYST_MAX_STEPS` model calls, ending with `confirm(...)` or `dismiss(reason)`; **COLLECT**: a confirmed verdict becomes a `Finding`, a dismissal becomes nothing;
   * **anchoring**: the finding's file and line range, and every hop of its source→sink trace, are honoured only if the analyst actually read those lines through the sandbox (a `ReadLedger` of `file → lines seen`); anything else snaps to the SAST sink, and unread trace hops are dropped. The model cannot invent a location;
   * **robustness**: a malformed reply, an unknown tool, bad arguments or a path the jail refuses are fed back as text and the loop continues (every retry counts against the step budget); the last step is announced and may only end with a verdict — a non-verdict there is `exhausted` (no finding). A dead model endpoint fails the scan; it never produces an empty "clean" result;
   * **budgets**: `MAX_CANDIDATES` on the queue, `ANALYST_MAX_STEPS` per candidate, `AGENT_CANDIDATE_TIMEOUT_S` wall-clock per candidate, at most 3 tool executions per model turn, and one scan-wide model-call counter (`MAX_CANDIDATES × (ANALYST_MAX_STEPS + planner)`) that no agent can exceed. A large repo cannot fan out past these;
   * **tool calling**: `AGENT_TOOL_PROTOCOL=auto` sends OpenAI-style `tools` first and falls back to a strict text protocol (`{"tool": "...", "args": {...}}`, one JSON object per reply) for the rest of the process if the endpoint rejects them; replies in either style are parsed by the same tolerant parser (fenced JSON, prose around JSON, `{"name","arguments"}` spellings, the step-2 `{"vulnerable": ...}` verdict shape, ...);
   * **trajectories**: every model call, tool call, result and verdict is logged (`trajectory[...]` lines) and, with `AGENT_TRAJECTORY_DIR`, appended as JSON lines per scan — observability now, learning data later.
6. **verify** is still a pass-through (`TODO(3b-2)`), so findings remain `verified=False`: rung 2 when the CWE comes with an evidence-anchored multi-hop trace, rung 1 otherwise. The `patch_diff` slot stays empty until the fixer agent (3b-2); `apply_patch` / `run` / `run_tests` are deliberately not exposed to the analyst in this step.

**End to end on the instance** (Ollama serving `qwen2.5-coder:7b` on `localhost:11434`, Docker installed, `git` on `PATH`; Semgrep arrives with `uv sync`):

```bash
cp .env.example.service .env
echo "EXECUTOR_TOKEN=$(openssl rand -hex 32)" >> .env   # shared by the app and the Executor

# terminal 1: the sandbox Executor (owns the Docker socket; pulls python:3.13-slim once)
make executor                                           # http://127.0.0.1:8081/health -> {"docker": true}

# terminal 2: the app
uv run ono                                              # http://localhost:8080

# terminal 3: scan the ingested OSS repo target. Expect: clone -> Semgrep -> one jail ->
# up to MAX_CANDIDATES x (planner + analyst loop) model calls. Minutes, not seconds.
# (Or open http://localhost:8080/ui, pick "vulpy", click Analyze and watch the progress card.)
SCAN=$(curl -s -X POST localhost:8080/scans -H 'content-type: application/json' -d '{"target_id":"vulpy"}' | jq -r .scan_id)
watch -n 2 "curl -s localhost:8080/scans/$SCAN | jq '{status, progress, pipeline: [.pipeline[] | {stage, status, summary}]}'"
curl -s localhost:8080/scans/$SCAN/findings | jq '.[] | {cwe, file, line_range, rung, verified, title, trace}'

# watch the agents work
tail -f .ono-trajectories/scn_*.jsonl                   # if AGENT_TRAJECTORY_DIR=.ono-trajectories
```

The `.pipeline` array shows each stage's status and timing; the `analyze` summary reads like `2 raw finding(s) from 9 candidate(s) (2 confirmed, 6 dismissed, 1 exhausted); 31/81 model call(s)`, and the `events` log lists every candidate the agents confirmed or dismissed, with the reason. If the Executor is down the record ends with `status: "failed"` and the reason in `.message`. Under Compose the same flow runs with `EXECUTOR_URL=http://executor:8081` (already set in `compose.yml`) and `MODEL_SERVICE_URL` pointing at the host's Ollama (`http://host.docker.internal:11434/v1` or the instance's internal address).

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

# Drive it from Python (this is what the orchestrator's tools do in step 3b-1)
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

- **Configuration through settings** — one `Settings` class (pydantic-settings) drives the app, the container, Compose, and CI; environment and backend values are validated; secrets are `SecretStr`. Three `.env.example.*` profiles.
- **Containerized deployment** — multi-step `Dockerfile` (lockfile-first cached dependency layer, non-root user, `HEALTHCHECK`), `.dockerignore`, and a `compose.yml` where `docker compose up -d` is the whole start procedure once `.env` sets `EXECUTOR_TOKEN`.
- **Documented API** — FastAPI with typed pydantic request/response models, generated OpenAPI at `/docs` and `/redoc`, explicit error schemas (403 / 404 / 422 / 429).
- **Publish only the app port** — of the two Compose services, only the app publishes a port (`8080`). The Executor has no `ports:` block, and future DB / vLLM services stay internal the same way.
- **Testing and CI** — pytest (including the blocking allowlist security test), ruff, strict mypy, a golden-path smoke script, and a GitHub Actions workflow definition that also builds the image and probes `/health` (not active from this subfolder; see [Run locally](#run-locally-uv)).

## Guardrails

ONO is defensive tooling that uses offensive techniques, so the boundary is enforced in code, not policy: scans are addressed by `target_id` only (never a URL), the registry is an exact allowlist, the agents read target code only through a jailed container with no network, and the Executor is never published. Ingest and Semgrep still run outside the jail for now. Read-only proofs-of-concept are planned for step 3b-2 and will run only inside that sandbox. The full ethics and dual-use discussion is in [§10 of the project plan](docs/plan.md#10-ethics--dual-use-guardrails).
