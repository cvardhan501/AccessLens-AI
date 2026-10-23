# AccessLens AI — Production Playwright Chromium Container
# Designed for AWS App Runner, Amazon ECS (Fargate), and Docker hosting

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PORT=8000 \
    HOST=0.0.0.0 \
    ACCESSLENS_DB_PATH=/app/data/accesslens.db

WORKDIR /app

# Install curl for container health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for caching
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install Chromium browser binary and all required Linux OS shared libraries
RUN playwright install --with-deps chromium

# Create non-root application user for secure container execution
RUN groupadd -r accesslens && useradd -r -g accesslens -d /home/accesslens -m accesslens && \
    mkdir -p /app/data /ms-playwright && \
    chown -R accesslens:accesslens /app /ms-playwright /home/accesslens

# Copy application package, static assets, fixtures, and documentation
COPY --chown=accesslens:accesslens accesslens/ ./accesslens/
COPY --chown=accesslens:accesslens tests/fixtures/ ./tests/fixtures/
COPY --chown=accesslens:accesslens README.md LICENSE ./

USER accesslens

EXPOSE 8000

# Health check verifies the live FastAPI server status
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Launch FastAPI dashboard with production Uvicorn ASGI server
CMD ["uvicorn", "accesslens.server:app", "--host", "0.0.0.0", "--port", "8000"]
