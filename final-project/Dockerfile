# syntax=docker/dockerfile:1.7
#
# Operation: Negative One - application image.
#
# Architecture decision: the model runs IN-PROCESS behind the `model_backend`
# setting. For the Deliverable-2 prototype that backend is `mock` (deterministic,
# GPU-free). On the Jetstream2 g3.large the same image runs with
# `MODEL_BACKEND=local`, talking to a vLLM process on the same box that is
# never published outside the host. Only port 8080 is ever exposed.

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS base

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 0. git for the ingest stage (shallow clone of allowlisted targets). Semgrep itself
#    ships as a Python wheel and arrives with the dependencies below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 1. Install dependencies first (cached layer; invalidated only by lockfile changes).
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

# 2. Then copy the source and install the project itself.
COPY README.md ./
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# 3. Run as a non-root user.
RUN groupadd --system ono && useradd --system --gid ono --home-dir /app --shell /usr/sbin/nologin ono \
    && chown -R ono:ono /app
USER ono

# The root filesystem is read-only under Compose; per-scan clones and Semgrep's own
# state go to /tmp (a tmpfs). Semgrep never phones home or checks for updates.
ENV PATH="/app/.venv/bin:$PATH" \
    HOST=0.0.0.0 \
    PORT=8080 \
    GRADIO_ANALYTICS_ENABLED=False \
    WORKSPACE_DIR=/tmp/ono-workspace \
    SEMGREP_SETTINGS_FILE=/tmp/semgrep-settings.yml \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "ono.api:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
