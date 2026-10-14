
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim 

RUN useradd -m app
WORKDIR /app

COPY --chown=app pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY --chown=app . . 
RUN uv sync --frozen --no-dev 

USER app
EXPOSE 8000

HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uv", "run", "--no-sync", "uvicorn", "team_project.api:app", "--host", "0.0.0.0", "--port", "8000"]

