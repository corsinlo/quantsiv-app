# Quantsiv (app)

Quantsiv is a post-quantum cryptography (PQC) readiness product. It inventories the
quantum-vulnerable cryptography in your code and TLS endpoints, ranks it by how long your data
must stay secret, and produces CycloneDX 1.6 CBOM evidence.

**Status: pre-launch. This repository is a skeleton under active remediation; most of it does
not run yet.**

## What is built (single source of truth)

Only move a row to **Built** when the code is merged and covered by tests.

| Capability | Status | Where |
| --- | --- | --- |
| FastAPI app serving `/` and `/health` | Prototype: boots under uvicorn; smoke tests and a Docker build in CI | `app/main.py`, WP1 |
| Dashboard and scan pages (Jinja2 + htmx) | Prototype: no placeholder data; empty states until scans are stored (WP4). Checked against WCAG 2.1 A/AA with axe-core in CI | WP2 |
| GitHub webhook handler | Built: signature check, size limit, deduplicated queueing; the worker stores installations and filters pushes | WP3, WP4 |
| Sign-in (GitHub OAuth), sessions, CSRF, security headers | Built; scans are scoped to the signed-in user in SQL | WP3, WP4 |
| Data model (Postgres, Alembic) and ARQ worker | Built: installations are stored from webhooks, pushes create scan records. Every scan fails with "not available yet" until repository access (WP5) and the engine (D2) exist | WP4 |
| Hosted scan pipeline for public repos (down-scoped token, hardened clone, size limit, limited engine process) | Built; runs the scanner below | WP5 |
| Source scanning: Quantsiv rules for Python, JS/TS, Go, Java/Kotlin, C#, Rust, Ruby, PHP and shell/CI scripts, plus CBOMkit's CBOM merged when its action runs first | Built (pattern-based, limits in `docs/scanner.md`) | WP5, WP7 |
| TLS scanning (sslyze, verified domains only) | Planned; the SSRF guard it must use is built | later |
| CycloneDX 1.6 CBOM output, per-scan download | Built and validated against the 1.6 schema; no scan produces findings until the engine (D2) exists | WP6 |
| HNDL scoring from declared data lifetimes (`quantsiv.yml`), plus a separate signature-deadline track | Built; same caveat (D2) | WP6 |
| CBOM import (any CycloneDX 1.6) with provenance, delta gate, estate export, org API tokens | Built | WP7 |
| Agent foundations: read-only policy MCP server for AI coding assistants (`quantsiv mcp`), gate explainer (PR comment, check-run, SARIF), approved exceptions, audit export | Built. Deterministic: no model is called anywhere. The eval harness exists but has no results yet | WP10 |
| Local runner `python -m quantsiv_scanner scan` (offline: CBOM, SARIF, report; optional upload with gate) and CI templates for GitHub Actions, GitLab, Jenkins and Azure DevOps | Built; the container image is built from this repo until the stealth exit | WP7 |
| Legal pages | Routes and placeholders built, hidden in production until decision D4 and counsel review; erasure runbook and automatic purge on uninstall built | WP8 |
| Evidence reports (PDF), billing, emails | Planned; requirements are in WP8, pricing needs decision D5 | WP8 |

## Start here

- [`CLAUDE.md`](CLAUDE.md): conventions, rules and the session protocol.
- [`docs/audit/2026-10-03-app-audit.md`](docs/audit/2026-10-03-app-audit.md): audit findings
  A01-A53.
- [`docs/audit/REMEDIATION_PLAN.md`](docs/audit/REMEDIATION_PLAN.md): ordered work packages and
  open decisions.
- [`quantsiv.md`](quantsiv.md): narrative, regulatory context, delivery model and pricing
  proposal.
- [`quantsiv_mvp_spec.md`](quantsiv_mvp_spec.md): the build spec. Read the revision 1.1 block
  first.

## Target architecture

- **Scanner (data plane, customer side).** A `quantsiv scan` container that runs in the
  customer's CI after their build. It wraps CBOMkit and sslyze plus Quantsiv rules, and writes a
  CBOM, SARIF and an HNDL report. Source code never leaves the customer.
- **Control plane (this app).** FastAPI with Jinja2/htmx, ARQ on Redis, and Postgres, hosted in
  the EU. It handles CBOM ingest, history and diffs, HNDL prioritisation, and evidence packs. It
  stores metadata only.
- **Hosted scanning.** Limited to public repositories and the demo, using the hardened clone and
  SSRF guard described in the audit.

## Development

Python 3.12. Dependencies are locked with hashes; edit `requirements*.in` and re-lock with the
command in each file's header.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
npm ci && npm run build                    # only after changing templates, JS or Tailwind
cp .env.example .env                       # then fill the values
alembic upgrade head                       # DATABASE_URL: Postgres, or sqlite:///./quantsiv.db
uvicorn app.main:app --reload
python -m arq app.worker.WorkerSettings    # needs REDIS_URL
python -m quantsiv_scanner scan .          # the customer-side scanner, offline
pytest
```

## Licence

This is a private repository and no licence is granted. Do not publish it.
