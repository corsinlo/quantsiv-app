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
| FastAPI app serving `/` and `/health` | Prototype: runs locally under uvicorn; no tests, and the Docker build fails (A09) | `app/main.py`, WP1 |
| Dashboard and scan pages (Jinja2 + htmx) | Prototype templates with placeholder data | WP1, WP2 |
| GitHub webhook handler | Prototype: not mounted, insecure placeholders | WP3 |
| Data model (Postgres) and ARQ worker | Not built | WP4 |
| Source scanning (Java and Python via CBOMkit, plus our own rules) | Planned; engine choice is decision D2 | WP5 |
| TLS scanning (sslyze, verified domains only) | Planned | WP5 |
| CycloneDX 1.6 CBOM output | Reference generator validated against the schema; not yet in the app | WP6 |
| HNDL scoring from declared data lifetimes | Planned | WP6 |
| Local runner `quantsiv scan` and CI templates (GitHub Actions, GitLab, Jenkins, Azure DevOps) | Planned; delivery model is decision D1 | WP7 |
| Legal pages | Planned; content needs decision D4 | WP8 |
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

Once WP1 has landed:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env                       # then fill the values
uvicorn app.main:app --reload
python -m arq app.worker.WorkerSettings    # needs REDIS_URL
pytest
```

## Licence

This is a private repository and no licence is granted. Do not publish it.
