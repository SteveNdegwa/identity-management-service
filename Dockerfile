# ---- builder -----------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/usr/src/app/.venv

WORKDIR /usr/src/app

# build-essential supplies cc/gcc/make for any wheels that fall back to a
# source build under cp314 (e.g. bcrypt's Rust extension needs a linker).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY . .

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev


# ---- runtime -----------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/src/app/.venv/bin:${PATH}"

WORKDIR /usr/src/app

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app /usr/src/app

RUN mkdir -p /var/www/idms

EXPOSE 8000
