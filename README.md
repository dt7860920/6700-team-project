# 6700 Team Project — Recommendation Service

A FastAPI service that returns interest-based recommendations. Built as a `uv`
Python package with an `src/` layout. This README covers Homework 2: git
collaboration, async responsiveness, containerization, configurable model
placement, and quality gates.

## Dependencies
Installed automatically by `uv sync` (see below):
`fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `httpx` — plus the dev
group: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy`, `pre-commit`.

## Running locally
1. Install uv: `pip install uv` (or `pipx install uv`) — see https://docs.astral.sh/uv/
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
5. (Optional) install the pre-commit hook so ruff runs before each commit:
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

## Endpoints
```bash
curl http://localhost:8000/health
# {"status":"ok"}

curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"user_id": "grad_student_1", "interests": ["reading", "running", "exploring"]}'
```

## Configuration
Settings come from environment variables or a `.env` file. See
`.env.example.local` and `.env.example.production`.

| Variable | Default | Notes |
|---|---|---|
| `APP_NAME` | `ApartmentTest1` | Shown in the API docs |
| `ENVIRONMENT` | `local` | Must be `local`, `staging`, or `production` |
| `MAX_RESULTS_CAP` | `20` | |
| `LOG_LEVEL` | `INFO` | |
| `MODEL_BACKEND` | `local` | `local` (in-process) or `service` (remote HTTP) |
| `MODEL_PATH` | `./artifacts/model` | used when `MODEL_BACKEND=local` |
| `MODEL_SERVICE_URL` | — | required when `MODEL_BACKEND=service` |
| `MODEL_SERVICE_API_KEY` | — | never logged or committed |

Swapping the model backend is a `.env` change plus a restart — no code change.

## Architecture note: model placement
The model currently runs in-process (`MODEL_BACKEND=local`) as a lightweight
stub, reached through `team_project.model_client.ModelClient`. The `/predict`
handler calls it via `asyncio.to_thread`, so the blocking inference call never
ties up the event loop (see `discussion.md` for the before/after measurements).
If a future model needs independent scaling or special hardware, set
`MODEL_BACKEND=service` and `MODEL_SERVICE_URL` to route calls to a separate
model service after a restart. See the comment at the top of the `Dockerfile`.

## Docker build metrics
Measured on the build machine (`docker build` / `docker system df`):

| Metric | Value |
|---|---|
| Image size | ~67.6 MB (70,976,775 bytes) |
| Rebuild, source-only change (cached deps layer) | ~0.45 s |
| Rebuild, `--no-cache` (full rebuild) | ~2.53 s |

The Dockerfile copies `pyproject.toml` + `uv.lock` and installs dependencies
**before** copying `src/`, so a source-only change reuses the cached dependency
layer — hence the large gap between the cached (~0.45 s) and uncached (~2.53 s)
rebuilds. `docker system df` reports overall Docker disk usage (images,
containers, volumes, build cache) on the host.

## Testing & quality gates
```bash
uv run ruff check src/ tests/        # lint
uv run ruff format --check src/ tests/  # formatting
uv run mypy src/                     # type-check
uv run pytest                        # tests
```
Tests cover: the health endpoint, the `/predict` endpoint (relevant categories
and `max_results`), config validation, the model-client backend selection
(`test_model_client.py`), and that `/health` stays responsive while a slow
`/predict` is in flight (`test_responsiveness.py`). CI runs all of the above on
Python 3.13 and 3.14 for every push and pull request.
