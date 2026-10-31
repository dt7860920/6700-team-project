# Operation: Negative One (ONO)

**An agentic system that finds software vulnerabilities in authorized code targets,
with the goal of proving they are real and proposing verified fixes.**

DSAN 6700: Deploying Machine Learning Applications to Customers · Georgetown University

Team: Sazan Khalid · Kenedy Ducheine · Junyi Tang · Jeffrey Pinarchick

| | |
|---|---|
| Live app (Jetstream2) | http://149.165.154.219:8080/ui/ |
| API docs | http://149.165.154.219:8080/docs |
| Full documentation | [`final-project/README.md`](final-project/README.md) |
| Design docs | [Project plan](final-project/docs/plan.md) · [Deliverable 2 write-up](final-project/docs/deliverable2.md) |

All ONO code lives in [`final-project/`](final-project/), so run the commands below
from that directory. The `Dockerfile`, `compose.yml`, `src/`, and `tests/` at the repo
root belong to earlier coursework, not ONO.

## What it does

Every scan names a `target_id` from an exact allowlist of targets, never a URL. An
unknown ID is rejected with HTTP 403 before any analysis starts.

| `target_id` | Target |
|---|---|
| `pygoat` | OWASP PyGoat, an intentionally vulnerable Django app |
| `juice-shop` | OWASP Juice Shop, an intentionally vulnerable Node.js app |
| `vulpy` | A small, intentionally vulnerable Flask repo |
| `snippet` | Code pasted into the UI or sent through the API |

A scan runs five stages: `ingest → SAST shortlist → plan → analyze → verify`. Each
finding is rated on an output-strength ladder:

| Rung | Output |
|---|---|
| 1 | Bare flag |
| 2 | Adds a CWE and suggested patch |
| 3 | Adds proof the flaw is reachable, using a read-only proof of concept in the sandbox |
| 4 | Adds proof the fix works: the patch applies, the proof of concept stops firing, and tests pass (the project's target) |
| 5 | Adds a detection rule (stretch goal) |

## Status

| Backend | Setting | What it does today |
|---|---|---|
| Mock | `MODEL_BACKEND=mock` (default) | Returns representative findings without calling a model. Their rung, verified, and line-number values are illustrative |
| Service | `MODEL_BACKEND=service` | Runs real ingest, Semgrep, and planner and analyst agents against an OpenAI-compatible model endpoint. The agents read target code only through a jailed container with no network |
| Local | `MODEL_BACKEND=local` | Not implemented yet; fails at startup |

The live app runs the service backend with `qwen2.5-coder:7b`. The verifier and fixer
agent are not built yet, so real findings come back `verified=false` at rung 1 or 2
with no patch.

## Quick start

Requires Python 3.13 or newer and [`uv`](https://docs.astral.sh/uv/). This runs the
mock backend, with no model or Docker needed.

```bash
git clone https://github.com/dt7860920/6700-team-project.git
cd 6700-team-project/final-project
uv sync --extra dev
cp .env.example.local .env
uv run ono
```

Open the UI at http://localhost:8080/ui and the API docs at http://localhost:8080/docs.

To run real scans or deploy with Compose, see
[the service backend steps](final-project/README.md#service-backend-today-the-agentic-detection-core-step-3b-1)
and [the Compose steps](final-project/README.md#run-with-compose-on-jetstream2).

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `GET` | `/info` | App name, version, environment, and model backend |
| `GET` | `/targets` | The target allowlist |
| `POST` | `/scans` | Start a background scan. Returns 202 with a `scan_id`, 403 for an unknown target, or 429 when busy |
| `GET` | `/scans/{scan_id}` | Live scan status, progress, and pipeline stages |
| `GET` | `/scans/{scan_id}/findings` | Findings for a scan |
| `GET` | `/findings/{finding_id}` | One finding |
| `GET` | `/ui` | Analyst UI |

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": "pygoat"}'
```

## Project layout

```
final-project/
├── src/ono/
│   ├── api.py            FastAPI app and mounted Gradio UI
│   ├── ui.py             Analyst UI
│   ├── service.py        Allowlist check and background scan workers
│   ├── analyzer.py       Five-stage pipeline: mock and service backends
│   ├── ingest.py         Shallow clone into a per-scan workspace
│   ├── sast.py           Semgrep shortlist with a regex fallback
│   ├── orchestrator.py   Detection state machine and budgets
│   ├── agents/           Planner and analyst agents
│   ├── executor/         Sandbox service: one jailed container per scan
│   └── targets.yaml      The target allowlist
├── tests/
├── scripts/golden_path.py   Smoke test
├── docs/                 Project plan and Deliverable 2 write-up
├── Dockerfile · compose.yml · Makefile
└── .env.example.local · .env.example.production · .env.example.service
```

## Testing

```bash
make check      # ruff, mypy, and pytest
make smoke-ci   # golden-path smoke test on the mock backend
```

Run these by hand before opening a pull request. The repo's CI doesn't cover
`final-project/` yet, because GitHub only runs workflows from `.github/workflows/` at
the repo root. Sandbox stress tests are skipped when no Docker daemon is reachable.

## Guardrails

ONO is defensive tooling that uses offensive techniques. Scans use allowlisted target
IDs only, and the sandbox Executor is never published. Ingest and Semgrep still run
outside the jail, and read-only proofs of concept are planned but not built. The full
ethics and dual-use discussion is in
[§10 of the project plan](final-project/docs/plan.md#10-ethics--dual-use-guardrails).
