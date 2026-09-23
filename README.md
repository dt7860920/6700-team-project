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
2. Then use ```uv sync --extra dev --frozen``` to install dependencies
3. Use ```uv pytest``` to run


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
