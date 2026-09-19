### Homework 1
For this assignment, we were tasked with building a Python package. Specifically using uv as a package manager for the toml and src benefits. 

#### Dependencies 
These will be installed automatically below. 
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
