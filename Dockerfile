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
RUN adduser --disabled-password --gecos '' appuser
USER appuser
CMD ["python", "-m", "arq", "app.worker.WorkerSettings"]
