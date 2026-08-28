# ==============================================================================
# Enterprise Multi-Stage Dockerfile for LangGraph Adversarial Red Teamer
# ==============================================================================

# Build Stage
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --prefix=/install .

# Production Stage
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="langgraph-adversarial-red-teamer" \
      org.opencontainers.image.description="LangGraph-powered adversarial red teaming framework for OWASP LLM Top 10" \
      org.opencontainers.image.authors="cibi-dev" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/src"

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Create non-root user for DevSecOps compliance
RUN groupadd -r redteamer && useradd -r -g redteamer -u 1001 -m -d /app redteam_user

# Copy application code
COPY --chown=redteam_user:redteamer src/ ./src/
COPY --chown=redteam_user:redteamer pyproject.toml README.md ./

USER redteam_user

ENTRYPOINT ["red-teamer"]
CMD ["enterprise-guardrail-v1", "20"]
