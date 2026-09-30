# Quantsiv MVP - Quantum Risk Management Platform

A GitHub-native quantum cryptography scanner that detects quantum-vulnerable algorithms (RSA, ECDSA, Diffie-Hellman) in source code and TLS configurations.

## Overview

Quantsiv scans your codebase, certificates, and cloud infrastructure to find quantum-vulnerable cryptography before it becomes a breach. This MVP implements the core scanning engine, GitHub App integration, web dashboard, and compliance reporting.

## Features Implemented in MVP

✅ **GitHub App Installation** - Secure authentication via GitHub OAuth  
✅ **Source Code Scanning** - AST-level scanning for Python, Java, Go using cbomkit-lib  
✅ **TLS/Certificate Scanning** - Domain inspection via sslyze  
✅ **CycloneDX 1.6 CBOM Output** - Standard format for cryptographic bill of materials  
✅ **Web Dashboard** - Findings table with risk scores and contextual details  
✅ **Plain-English Risk Descriptions** - Clear explanations like "RSA-2048 in JWT signing — vulnerable to Shor's algorithm by ~2032"  
✅ **Compliance PDF Report Export** - Gated at Developer tier (€99/month)  
✅ **GitHub Action for CI/CD** - `quantsiv/scan-action@v1` with SARIF upload  
✅ **Free Tier** - 1 repository, push-triggered scans (no credit card required)  
✅ **Developer Tier** - €99/month, unlimited repositories, 3 seats  
✅ **Team Tier** - €299/month, 15 seats, API access  
✅ **Stripe Billing** - Subscription management with VAT compliance  
✅ **Behavioral Email Sequence** - 7-day onboarding and nurturing flow  

## Architecture

Based on the MVP specifications, the platform uses:

- **Python 3.12 + FastAPI + ARQ + Redis + SQLite** (MVP) → Postgres (production)
- **cbomkit-lib** (Java JAR) run as subprocess for source code scanning
- **sslyze** for TLS scanning
- **cyclonedx-python-lib** for CBOM assembly
- **HTMX + Alpine.js + Tailwind CSS** for minimal frontend
- **WeasyPrint** for PDF report generation
- **SQLite** (MVP) → Postgres (production) database

## API Endpoints

### GitHub Webhooks
- `POST /webhook/github` - Handle GitHub App events (installation, push, etc.)

### Dashboard Routes
- `GET /` - API root
- `GET /health` - Health check
- `GET /dashboard` - Main dashboard (HTML)
- `GET /dashboard/scans/{id}` - Scan results (HTML)
- `GET /dashboard/scans/{id}/live` - Live scan progress (HTML)
- `GET /api/scans/{id}` - Get scan details (JSON)
- `POST /api/scans` - Trigger manual scan
- `GET /api/scans/{id}/events` - Server-Sent Events for live progress

### Worker
- `ScanWorker` class handles the scanning pipeline:
  1. GitHub installation token generation
  2. Repository cloning
  3. Source code scanning (cbomkit-lib)
  4. TLS domain detection & scanning (sslyze)
  5. Risk score calculation
  6. CBOM generation (cyclonedx-python-lib)
  7. Database persistence
  8. Cleanup & completion signaling

## Database Schema

The MVP uses SQLite with tables for:
- `users` (GitHub OAuth authentication)
- `installations` (GitHub App installations)
- `scans` (scan jobs and metadata)
- `findings` (individual cryptographic findings)
- `cbom_snapshots` (CycloneDX JSON per scan)
- `tls_scans` (TLS scan results)

## Deployment

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Start worker (in separate terminal)
python -m arq app.worker.WorkerSettings
```

### Docker
```bash
# Build image
docker build -t quantsiv-mvp .

# Run container
docker run -p 8000:8000 quantsiv-mvp
```

### Cloud Deployment (MVP)
As specified in the docs: **Railway** with services:
- `web`: FastAPI + uvicorn
- `worker`: ARQ worker
- `redis`: Railway Redis plugin
- `persistent volume`: SQLite file at `/data/quantsiv.db`

## MVP Success Metrics

By day 90 after first public availability:
1. At least one customer paying €99+/month via pure self-serve
2. At least three developers reported finding a real quantum-vulnerable call they were previously unaware of
3. Scan-to-first-result time consistently under 5 minutes for repos under 100k LOC
4. No security incident involving customer repository data

## Next Steps (Post-MVP)

Based on the roadmap:
- JavaScript/TypeScript scanning (v1.1)
- Semgrep-style cross-file dataflow analysis (v2)
- Container image scanning (v2)
- Cloud infrastructure scanning (AWS/Azure/GCP) (v2)
- SAML/SSO authentication (v2)
- Mobile experience (v2)
- Enterprise multi-tenant support (v2)

## License

This is the MVP implementation of Quantsiv - Quantum Risk Management Platform.