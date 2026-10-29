.PHONY: install dev lint format typecheck test check smoke-ci smoke-live docker-build docker-run compose-up compose-down

install:          ## Install runtime + dev dependencies
	uv sync --extra dev

dev:              ## Run locally with auto-reload (reads .env)
	uv run ono

lint:
	uv run ruff check

format:
	uv run ruff format

typecheck:
	uv run mypy src/

test:
	uv run pytest

check: lint typecheck test   ## Everything CI runs
	uv run ruff format --check

smoke-ci:         ## Golden path against the in-process app (mock backend, no server)
	uv run scripts/golden_path.py --in-process

BASE_URL ?= http://localhost:8080
smoke-live:       ## Golden path against a running deployment
	uv run scripts/golden_path.py --base-url $(BASE_URL)

docker-build:
	docker build -t ono:prototype .

docker-run: docker-build
	docker run --rm -p 8080:8080 --env-file .env.example.production ono:prototype

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down
