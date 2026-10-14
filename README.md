### Homework 1
For this assignment, we were tasked with building a Python package. Specifically using uv as a package manager for the benefits of the toml file and src file structure.

#### Dependencies
These will be installed automatically in step 4.
- fastapi
- httpx
- mypy
- pre-commit
- pydantic
- pytest
- ruff
- uvicorn

#### Running the code
1. In terminal, install ```uv``` using ```pip install uv``` or ```pipx install uv```
2. Clone the repo using ```git clone <repo link>```
3. ```cd 6700-team-project```
4. Then use ```uv sync --extra dev --frozen``` to install dependencies
5. Use ```uv run pytest``` to run tests on our dependencies
6. use ```uv run uvicorn --app-dir src team_project.api:app --reload``` to 'open' the app


#### Key functions
test_api.py:
```
def test_health_returns_ok(client):
  Verifies the health status code is 200

    Args:
    client - Test client used for this assignment

    Returns:
    {"status" : "ok"}

def test_predict_returns_relevant_categories(client, grad_student_request):
    Sending the test grad student's sample categories to the prediction endpoint. Asserts that health endpoint returns 200 and '
    the categories are either reading, exercies, or exploring.

    Args:
    client - Test client used for this assignment
    grad_student_requests - grad student's user_id and interests.

def test_predict_respects_max_results(client, pentagon_worker_request):
    Sending the test pentagon employee's sample categories to the prediction endpoint. Asserts that health endpoint returns 200 and
    the length of the recommendatons is no longer than a specific value (3).

    Args:
    client - Test client used for this assignment
    pentagon_worker_requests - pentagon employee's user_id and interests.
```

conftest.py
```
def grad_student_request():
    Building a user. A grad student with interest in reading, running, and exploring.


def pentagon_worker_request():
    Building a user. A pentagon worker with interest in food and sports bars.
```

test_config.py
```
def test_invalid_env_raises():
    Checks if the code throws an error as expected.
```

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

`docker compose up -d` is the entire start procedure on a fresh clone.

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
`.env.example.local` and `.env.example.production`. Key settings:

| Variable | Default | Notes |
|---|---|---|
| `MODEL_BACKEND` | `local` | `local` (in-process) or `service` (remote HTTP) |
| `MODEL_PATH` | `./artifacts/model` | used when `MODEL_BACKEND=local` |
| `MODEL_SERVICE_URL` | — | required when `MODEL_BACKEND=service` |
| `MODEL_SERVICE_API_KEY` | — | never logged or committed |

Swapping the model backend is a `.env` change plus a restart — no code change.

## Architecture note: model placement

The model currently runs in-process (`MODEL_BACKEND=local`) as a lightweight
stub. If a future model needs independent scaling or special hardware, set
`MODEL_BACKEND=service` and `MODEL_SERVICE_URL` to route calls to a separate
model service after a restart. See the comment at the top of the `Dockerfile`.
