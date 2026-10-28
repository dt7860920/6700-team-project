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

All configuration is read by `ono.config.Settings` (pydantic-settings) from environment variables or a `.env` file. Two profiles ship: `.env.example.local` and `.env.example.production`. Invalid values fail fast at startup.

| Variable | Default | Values / notes |
|---|---|---|
| `APP_NAME` | `Operation: Negative One` | Display name |
| `ENVIRONMENT` | `local` | `local` · `staging` · `production` (validated) |
| `LOG_LEVEL` | `INFO` | Any Python logging level name (validated) |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | Bind address; 8080 is the one published port |
| `MODEL_BACKEND` | `mock` | `mock` · `local` · `service` (validated). **Deliverable 2 runs `mock`.** |
| `MODEL_NAME` | `Qwen/Qwen2.5-Coder-7B-Instruct` | Informational for `mock`; used by `local`/`service` |
| `MODEL_SERVICE_URL` | — | **Required when `MODEL_BACKEND=service`** (startup fails otherwise) |
| `MODEL_SERVICE_API_KEY` | — | `SecretStr`: never logged, never returned by `/info` |
| `MAX_VERIFIER_RETRIES` | `3` | 1–5. Hard cap on the verifier self-correction loop |

The **target allowlist** lives in [`src/ono/targets.yaml`](src/ono/targets.yaml) and is loaded into an exact mapping (`TargetRegistry`). Adding a target means adding an entry there — nothing is accepted that is not in the file.

---

## Project layout

```
operation-negative-one/
├── src/ono/
│   ├── api.py          FastAPI app: documented endpoints + mounted Gradio UI
│   ├── ui.py           Gradio analyst UI (target picker / snippet -> Analyze -> finding cards)
│   ├── service.py      ScanService: allowlist gate -> run pipeline -> persist
│   ├── analyzer.py     Pipeline skeleton (ingest/sast/plan/analyze/verify) + MockAnalyzer
│   ├── models.py       Pydantic schemas: ScanRequest, Finding, Scan, ScanResponse, ...
│   ├── targets.py      TargetRegistry (exact allowlist) + targets.yaml
│   ├── store.py        ScanStore protocol + in-memory implementation
│   ├── config.py       Settings (pydantic-settings)
│   └── __main__.py     `ono` / `python -m ono` entrypoint (uvicorn)
├── tests/              pytest: config validation, API (incl. 403 allowlist test), analyzer
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
| `ingest` | returns the pinned snapshot ref | clone into the egress-blocked sandbox, strip `.git`/CVE strings, tree-sitter + call graph |
| `sast_shortlist` | canned candidates (regex SAST for snippets) | Semgrep + CodeQL → SARIF → normalized `Candidate` queue |
| `plan` | fixed step list | **frozen Qwen2.5-Coder, planner role** emits the per-target scaffold (Fugu-inspired, no training) |
| `analyze` | canned findings | **Qwen analyst role** in a bounded LangGraph ReAct loop (read_file / callers / grep / retrieve_cwe), served by vLLM |
| `verify` | passes `verified=True` | **deterministic verifier** (plain code): line exists, PoC reaches sink, patch applies, PoC no longer fires, tests pass; failure reasons feed a bounded self-correction loop (`MAX_VERIFIER_RETRIES`) |

Switching is a config change: `MODEL_BACKEND=local` (vLLM on the same box, never published) or `MODEL_BACKEND=service` (remote OpenAI-compatible endpoint). `build_analyzer()` is the only place that needs to know. The in-memory `ScanStore` is likewise the seam for the internal findings database.

---

## Course concepts demonstrated

- **Configuration through settings** — one `Settings` class (pydantic-settings) drives the app, the container, Compose, and CI; environment and backend values are validated; secrets are `SecretStr`. Two `.env.example.*` profiles.
- **Containerized deployment** — multi-step `Dockerfile` (lockfile-first cached dependency layer, non-root user, `HEALTHCHECK`), `.dockerignore`, and a `compose.yml` where `docker compose up -d` is the whole start procedure.
- **Documented API** — FastAPI with typed pydantic request/response models, generated OpenAPI at `/docs` and `/redoc`, explicit error schemas (403 / 404 / 422).
- **Publish only the app port** — the single service publishes `8080` and nothing else; future DB / vLLM / sandbox services stay internal by construction.
- **Testing and CI** — pytest (including the blocking allowlist security test), ruff, strict mypy, a golden-path smoke script, and a GitHub Actions workflow that also builds the image and probes `/health`.

## Guardrails

ONO is defensive tooling that uses offensive techniques, so the boundary is enforced in code, not policy: scans are addressed by `target_id` only (never a URL), the registry is an exact allowlist, proofs-of-concept are read-only and run only inside an egress-blocked sandbox, and the model, sandbox, and data stores are never published. The full ethics and dual-use discussion is in the project plan.
