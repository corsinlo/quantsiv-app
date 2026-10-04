# Two targets (A09): `docker build --target web .` and `docker build --target worker .`
# TODO: pin both base images by digest once CI is green.

FROM python:3.12-slim-bookworm AS web
# Pango/HarfBuzz for WeasyPrint (PDF reports)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY quantsiv_scanner/ ./quantsiv_scanner/
# Migrations run from this image before each deploy (railway.toml preDeployCommand)
COPY alembic.ini ./
COPY migrations/ ./migrations/
RUN adduser --disabled-password --gecos '' appuser
USER appuser
ENV PORT=8000
# Trust X-Forwarded-* only from the platform proxy; '*' is acceptable only when the
# container is reachable solely through that proxy (Railway private networking)
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --forwarded-allow-ips=\"${FORWARDED_ALLOW_IPS:-*}\""]

FROM python:3.12-slim-bookworm AS worker
# git for cloning; Java only here, for the scan engine (decision D2)
RUN apt-get update && apt-get install -y --no-install-recommends git openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements-worker.txt .
RUN pip install --no-cache-dir -r requirements-worker.txt
COPY app/ ./app/
# The worker runs the scan engine as a separate process (ScanPipeline.scan_source)
COPY quantsiv_scanner/ ./quantsiv_scanner/
RUN adduser --disabled-password --gecos '' appuser
USER appuser
CMD ["python", "-m", "arq", "app.worker.WorkerSettings"]

# The customer-side scanner (D1): runs in the customer's CI, offline by default.
#   docker build --target scanner -t quantsiv-scanner .
#   docker run --rm -v "$PWD:/src" quantsiv-scanner scan /src --out /src/quantsiv-out
FROM python:3.12-slim-bookworm AS scanner
WORKDIR /app
COPY requirements-scanner.txt .
RUN pip install --no-cache-dir -r requirements-scanner.txt
# Only the shared, dependency-light modules the scanner imports; no web app, no secrets
COPY app/__init__.py ./app/
COPY app/services/__init__.py app/services/cbom.py app/services/errors.py \
     app/services/ingest.py app/services/lifetimes.py app/services/scoring.py ./app/services/
COPY quantsiv_scanner/ ./quantsiv_scanner/
RUN adduser --disabled-password --gecos '' scanner
USER scanner
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "-m", "quantsiv_scanner"]
CMD ["--help"]
