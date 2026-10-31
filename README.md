# 6700 Team Project

Team repository for DSAN 6700 (Deploying Machine Learning Applications to
Customers) at Georgetown University.

Team: Jeffrey Pinarchick · Kenedy Ducheine · Sazan Khalid · Junyi Tang

The repo holds two independent `uv` projects, each with its own `pyproject.toml`,
lockfile, `Dockerfile`, and `compose.yml`. Run each project's commands from its
own directory.

| Path | Project | Status |
|---|---|---|
| [`/`](#recommendation-service-homework-2) | Recommendation Service (Homework 2) | FastAPI service with a stub model |
| [`final-project/`](final-project/README.md) | Operation: Negative One (ONO), agentic vulnerability analysis of authorized code targets | In progress: mock analyzer by default; `MODEL_BACKEND=service` runs real ingest, Semgrep, and agent-based detection. The verifier and fixer are not built yet |

The rest of this README covers the Recommendation Service. For the final project,
see [`final-project/README.md`](final-project/README.md). The live app is at
http://149.165.154.219:8080/ui/. To try it locally with the mock analyzer:

```bash
cd final-project
uv sync --extra dev
cp .env.example.local .env
uv run ono   # UI at http://localhost:8080/ui, API docs at /docs
```

---

# Recommendation Service (Homework 2)

A FastAPI service that returns interest-based recommendations. Built as a `uv`
Python package with an `src/` layout. This project covers git collaboration, async
responsiveness, containerization, configurable model placement, and quality gates.

The model is a stub. `FakeModel` sleeps for 1.5 s to simulate inference and then
echoes its input, so each recommendation is a placeholder (`Sample <category>`, a
fixed `distance_miles` of `0.5`). The request's `location` is accepted but not used
yet.

## Project layout
```
├── src/team_project/
│   ├── api.py            FastAPI app: /health and /predict
│   ├── models.py         Request/response schemas and interest aliases
│   ├── model_client.py   ModelClient: selects the local or remote backend
│   ├── fakemodel.py      Stub model (1.5 s sleep, echoes its input)
│   ├── config.py         Settings (pydantic-settings)
│   └── app.py            Empty placeholder
├── tests/                pytest suite
├── scripts/measure_concurrency.py   Sends 10 concurrent /predict requests
├── discussion.md         Async responsiveness: before/after measurements
├── Dockerfile · compose.yml · .dockerignore
├── .env.example.local · .env.example.production
├── .github/workflows/ci.yml
└── final-project/        Operation: Negative One (separate project)
```

## Dependencies
Installed automatically by `uv sync` (see below):
`fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `httpx`, plus the dev tools:
`pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy`, `pre-commit`.

## Running locally
1. Install uv: `pip install uv` (or `pipx install uv`). See https://docs.astral.sh/uv/
2. Clone and enter the repo:
   ```bash
   git clone https://github.com/dt7860920/6700-team-project.git
   cd 6700-team-project
   ```
3. Install dependencies from the lockfile (uv installs Python 3.13 if needed):
   ```bash
   uv sync --extra dev --frozen
   ```
4. Create your settings file:
   ```bash
   cp .env.example.local .env
   ```
5. (Optional) install the pre-commit hooks (ruff lint and format, plus file checks):
   ```bash
   uv run pre-commit install
   ```
6. Run the service:
   ```bash
   uv run uvicorn team_project.api:app --reload
   ```
   API at http://127.0.0.1:8000, interactive docs at http://127.0.0.1:8000/docs.

## Running with Docker
```bash
docker build -t team_project:latest .
docker run -p 8000:8000 --env-file .env team_project:latest
```

## Running the full stack with Compose (e.g. on Jetstream2)
```bash
git clone https://github.com/dt7860920/6700-team-project.git
cd 6700-team-project
cp .env.example.production .env   # fill in real values
docker compose up -d
```
`docker compose up -d` is the entire start procedure on a fresh clone. This
project has no external service dependency (no database), so `compose.yml`
defines only the app service.

## Deployment

For Homework 2, the service was deployed on Jetstream2 using `docker compose up -d`,
with only the application port (8000) published to the internet. That instance,
`http://149.165.168.237:8000`, was not reachable as of 2026-10-31. To run the service
again, follow the Compose steps above on a new instance.

## Endpoints
| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/predict` | Recommendations for a user's interests |

```bash
curl http://localhost:8000/health
# {"status":"ok"}

curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"user_id": "grad_student_1", "interests": ["reading", "running", "exploring"]}'
# {"user_id":"grad_student_1","recommendations":[
#   {"name":"Sample reading","category":"reading","distance_miles":0.5},
#   {"name":"Sample exercise","category":"exercise","distance_miles":0.5},
#   {"name":"Sample exploring","category":"exploring","distance_miles":0.5}]}
```

`POST /predict` body:

| Field | Type | Default | Notes |
|---|---|---|---|
| `user_id` | string | required | Echoed in the response |
| `interests` | list of strings | required | At least one; see the table below |
| `location` | string | `Pentagon City, VA` | Accepted but not used yet |
| `max_results` | integer | `5` | 1 to 20 |

Interests are case-insensitive and may be a category or one of its aliases. An
unrecognized interest, an empty list, or an out-of-range `max_results` returns
`422`.

| Category | Aliases |
|---|---|
| `reading` | `bookstores`, `libraries` |
| `exercise` | `running`, `gym`, `lifting weights` |
| `exploring` | `sightseeing`, `travelling` |
| `food` | `restaurants`, `dining` |
| `drinking` | `bar`, `beer`, `drinks` |
| `sports` | `sports_bar`, `football`, `soccer`, `baseball`, `basketball` |

## Configuration
Settings come from environment variables or a `.env` file. See
`.env.example.local` and `.env.example.production`.

| Variable | Default | Notes |
|---|---|---|
| `APP_NAME` | `ApartmentTest1` | Shown in the API docs |
| `ENVIRONMENT` | `local` | Must be `local`, `staging`, or `production` |
| `MAX_RESULTS_CAP` | `20` | Not used yet; the limit is hard-coded in `models.py` |
| `LOG_LEVEL` | `INFO` | Not used yet |
| `MODEL_BACKEND` | `local` | `local` (in-process) or `service` (remote HTTP) |
| `MODEL_PATH` | `./artifacts/model` | Passed to the local backend; the stub ignores it |
| `MODEL_DEVICE` | `cpu` | Passed to the local backend; the stub ignores it |
| `MODEL_SERVICE_URL` | none | Required when `MODEL_BACKEND=service` |
| `MODEL_SERVICE_API_KEY` | none | Sent as a bearer token; never commit it |

Swapping the model backend is a `.env` change plus a restart, with no code change.

## Architecture note: model placement
The model currently runs in-process (`MODEL_BACKEND=local`) as a lightweight
stub, reached through `team_project.model_client.ModelClient`. The `/predict`
handler calls it via `asyncio.to_thread`, so the blocking inference call never
ties up the event loop (see `discussion.md` for the before/after measurements).
If a future model needs independent scaling or special hardware, set
`MODEL_BACKEND=service` and `MODEL_SERVICE_URL` to route calls to a separate
model service after a restart. See the comment at the top of the `Dockerfile`.

A remote model service must accept `POST {MODEL_SERVICE_URL}/predict` with
`{"inputs": [...]}` and return `{"predictions": [...]}`, both lists of strings.

To reproduce the concurrency measurement, start the service and run:
```bash
uv run python scripts/measure_concurrency.py
```

## Docker build metrics
Recorded during Homework 2, before `final-project/` was added to the repo
(`docker build` / `docker system df`):

| Metric | Value |
|---|---|
| Image size | ~67.6 MB (70,976,775 bytes) |
| Rebuild, source-only change (cached deps layer) | ~0.45 s |
| Rebuild, `--no-cache` (full rebuild) | ~2.53 s |

The Dockerfile copies `pyproject.toml` + `uv.lock` and installs dependencies
**before** copying the source, so a source-only change reuses the cached dependency
layer. That explains the gap between the cached (~0.45 s) and uncached (~2.53 s)
rebuilds. `docker system df` reports overall Docker disk usage (images, containers,
volumes, build cache) on the host.

## Testing & quality gates
```bash
uv run ruff check src/ tests/           # lint
uv run ruff format --check src/ tests/  # formatting
uv run mypy src/                        # type-check
uv run pytest                           # tests
```
Tests cover: the health endpoint, the `/predict` endpoint (relevant categories
and `max_results`), config validation, the model-client backend selection
(`test_model_client.py`), and that `/health` stays responsive while a slow
`/predict` is in flight (`test_responsiveness.py`). CI runs all of the above on
Python 3.13 and 3.14 for every push and pull request.

These commands and the root CI workflow cover this project only. `final-project/`
is excluded from the root ruff config and pytest paths, so run its checks from its
own directory.
