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
docker compose up -d --build
docker compose ps                              # wait for "healthy"
curl http://localhost:8080/health
```

From your laptop: `uv run scripts/golden_path.py --base-url http://<FLOATING-IP>:8080`.

`compose.yml` defines **one service** and publishes **one port** (8080). There is deliberately no database in the skeleton — scan state is in-memory. When the findings DB, threat-intel cache, and vLLM join the stack in Deliverable 3 they are added as internal services *without* a `ports:` block, so the published surface stays exactly `:8080`.

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
| `MAX_CLONE_MB` | `200` | 1–5000. Snapshots larger than this (after `.git` is stripped) abort the scan |

The ingest/SAST settings apply to the `service` backend (`mock` never clones or runs Semgrep).

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
│   └── __main__.py     `ono` / `python -m ono` entrypoint (uvicorn)
├── tests/              pytest: config, API (incl. 403 allowlist test), analyzers, ingest, SAST
│   └── fixtures/       tiny vulnerable sample repo + a real Semgrep JSON document (tests stay offline)
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

## Course concepts demonstrated

- **Configuration through settings** — one `Settings` class (pydantic-settings) drives the app, the container, Compose, and CI; environment and backend values are validated; secrets are `SecretStr`. Two `.env.example.*` profiles.
- **Containerized deployment** — multi-step `Dockerfile` (lockfile-first cached dependency layer, non-root user, `HEALTHCHECK`), `.dockerignore`, and a `compose.yml` where `docker compose up -d` is the whole start procedure.
- **Documented API** — FastAPI with typed pydantic request/response models, generated OpenAPI at `/docs` and `/redoc`, explicit error schemas (403 / 404 / 422).
- **Publish only the app port** — the single service publishes `8080` and nothing else; future DB / vLLM / sandbox services stay internal by construction.
- **Testing and CI** — pytest (including the blocking allowlist security test), ruff, strict mypy, a golden-path smoke script, and a GitHub Actions workflow that also builds the image and probes `/health`.

## Guardrails

ONO is defensive tooling that uses offensive techniques, so the boundary is enforced in code, not policy: scans are addressed by `target_id` only (never a URL), the registry is an exact allowlist, proofs-of-concept are read-only and run only inside an egress-blocked sandbox, and the model, sandbox, and data stores are never published. The full ethics and dual-use discussion is in the project plan.
