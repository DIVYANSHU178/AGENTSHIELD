# =============================================================================
# AgentShield Backend Production Dockerfile (Phase 18 Containerization)
# Multi-stage build: minimal, non-root, zero-secret, production-hardened.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Dependency Builder
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

# Set build-time environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Copy production requirements manifest (excluding pytest and dev tooling)
COPY requirements-prod.txt .

# Install dependencies into isolated installation prefix
RUN pip install --prefix=/install --no-compile -r requirements-prod.txt

# -----------------------------------------------------------------------------
# Stage 2: Minimal Production Runtime
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

# Security: prevent bytecode writing and buffer output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/usr/local/bin:$PATH"

# Create non-root system group and user
RUN groupadd -g 10001 agentshield \
    && useradd -u 10001 -g agentshield -s /bin/false -M -d /app agentshield

# Copy installed production packages from builder stage
COPY --from=builder /install /usr/local

# Establish working directory and persistent data volume directory
WORKDIR /app
RUN mkdir -p /app/data /app/app \
    && chown -R agentshield:agentshield /app \
    && chmod 700 /app/data

# Copy application source code with non-root ownership
COPY --chown=agentshield:agentshield app /app/app

# Drop all privileges to non-root user
USER 10001:10001

# Expose standard internal API service port
EXPOSE 8000

# Container liveness probe using native Python HTTP client (zero curl/wget dependency)
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=4)"]

# Deterministic production server startup
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
