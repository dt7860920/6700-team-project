# --- Architecture decision ---
# The model currently runs as an in-process library in this container with
# MODEL_BACKEND=local. The current stub is lightweight, so a network hop to a
# separate service would add complexity and latency without a practical gain.
# If a future model needs independent scaling or specialized hardware, changing
# MODEL_BACKEND to service will route calls to MODEL_SERVICE_URL after a restart.
# Model weights will live in a mounted cache rather than in the image so model
# updates do not require rebuilding the application image.
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
