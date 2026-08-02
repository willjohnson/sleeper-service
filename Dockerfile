FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

FROM python:3.13-slim-bookworm
RUN groupadd -r sleeper && useradd -r -g sleeper sleeper
WORKDIR /app
COPY --from=builder --chown=sleeper:sleeper /app /app
ENV PATH="/app/.venv/bin:$PATH"
USER sleeper
EXPOSE 8000
CMD ["uvicorn", "sleeper_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
