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
#### Installation
1. Install uv: `pip install uv` (or see https://docs.astral.sh/uv/)
2. Clone the repo and enter it:
```bash
   git clone https://github.com/dt7860920/6700-team-project.git
   cd 6700-team-project
```
3. Install dependencies from the lockfile (uv installs Python 3.13 if you don't have it):
```bash
   uv sync --extra dev --frozen
```
4. Create your settings file from the local example:
```bash
   cp .env.example.local .env
```
5. Install the git hook so ruff runs before every commit:
```bash
   uv run pre-commit install
```

#### Running the service
```bash
uv run uvicorn team_project.api:app --reload
```
The API is now at http://127.0.0.1:8000. Interactive docs are at http://127.0.0.1:8000/docs.

Check that it's healthy (in a second terminal):
```bash
curl http://127.0.0.1:8000/health
# {"status":"ok","environment":"local"}
```

Try the placeholder recommendation endpoint:
```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"user_id": "demo", "interests": ["reading", "gym"], "max_results": 2}'
```

#### Configuration
Settings are read from environment variables or a `.env` file. See `.env.example.local` and `.env.example.production`.

| Variable | Default | Notes |
|---|---|---|
| `APP_NAME` | `ApartmentTest1` | Shown in the API docs |
| `ENVIRONMENT` | `local` | Must be `local`, `staging` or `production`; anything else stops the app at startup |
| `MAX_RESULTS_CAP` | `20` | |
| `LOG_LEVEL` | `INFO` | |

#### Running the checks
```bash
uv run ruff check
uv run ruff format --check
uv run mypy src/
uv run pytest
```

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
