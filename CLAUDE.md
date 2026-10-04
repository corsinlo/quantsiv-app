# quantsiv-app

Quantsiv is a B2B post-quantum-cryptography (PQC) readiness product. It is pre-launch and in
stealth. This repository is the product app (FastAPI + ARQ + Jinja2/htmx) and it is **private**.
The marketing site is the separate, **public** repo `quantsiv-landing`. The strategy docs
(roadmap, pitch, whitepaper) live outside both repos. This repo carries what code work needs:
`quantsiv.md` (narrative, delivery model, pricing proposal) and `quantsiv_mvp_spec.md` (build
spec, revision 1.1).

## Current state (2026-10-04)

WP0 (hygiene) and WP1 (build, boot, smoke tests, CI) are implemented and awaiting review. With
them the app **boots but does nothing real yet**:
- `uvicorn app.main:app` serves `/health` and the dashboard pages, which still show placeholder
  data (WP2 makes them honest);
- `python -m arq app.worker.WorkerSettings` starts, with no-op jobs (WP4 implements them);
- there are no real models, no authentication (WP3) and no scan engine (D2);
- the Docker build is checked by the CI `docker` job only (the cloud VM's network policy blocks
  `deb.debian.org`).

The full audit is in [`docs/audit/2026-10-03-app-audit.md`](docs/audit/2026-10-03-app-audit.md)
(findings A01-A53). The work plan is
[`docs/audit/REMEDIATION_PLAN.md`](docs/audit/REMEDIATION_PLAN.md) (work packages WP0-WP10 and
decisions D1-D9).

## Session protocol (cloud or local)

1. Open `docs/audit/REMEDIATION_PLAN.md` and take the first work package with status `todo`.
   Skip `blocked` ones.
2. Create a branch `fix/wpN-short-name` and implement only that WP, including the tests listed
   under its **Acceptance**. Reference finding IDs in commit messages (e.g. `WP1: close api.py
   docstring (A01)`).
3. Before opening the PR, run all of these:
   `ruff check . && ruff format --check . && pytest && pip-audit -r requirements.txt`
4. In the same PR, tick the checkboxes and update the WP's row in the status table.
5. When you reach a decision D1-D9 or anything marked **BLOCKED**, stop and ask. Never invent
   legal entity details, prices, dates, statistics, regulatory requirements or customer names.

## Commands (once WP1 has landed)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env                       # then fill the values
uvicorn app.main:app --reload              # web
python -m arq app.worker.WorkerSettings    # worker; needs REDIS_URL
pytest
```

**In Claude Code cloud sessions,** the SessionStart hook (`.claude/settings.json` running
`scripts/install_pkgs.sh`) creates `.venv` (Python 3.12 when available, matching CI) and
installs `requirements.txt` and `requirements-dev.txt` automatically.
- Use `.venv/bin/python -m pytest`, or `source .venv/bin/activate`.
- Docker may be unavailable in the cloud VM, and its default network policy blocks the Debian
  mirrors the Dockerfile's `apt-get` needs. Rely on the CI `docker` job.
- Dependencies: edit the `requirements*.in` files, then re-lock with the `uv pip compile` command
  in each file's header (hashes, Python 3.12). Never hand-edit the `.txt` locks.

## Narrative: keep it identical everywhere, and cite the authority each time

1. **Harvest now, decrypt later (HNDL).**
   - Adversaries record encrypted data today and decrypt it once a cryptographically relevant
     quantum computer exists. The binding constraint is how long the data must stay
     confidential.
   - HNDL threatens key establishment and encryption. For signatures the risk is future forgery,
     not retroactive decryption.
2. **The deadlines are set:**
   - **NIST FIPS 203/204/205:** published 13 Aug 2024.
   - **NIST IR 8547** (initial public draft, Nov 2024):
     - 112-bit-strength RSA/ECC/DH, e.g. RSA-2048, is deprecated after 2030;
     - all quantum-vulnerable public-key algorithms, *including P-256*, are disallowed after
       2035.
   - **EO 14412** (22 Jun 2026):
     - PQC key establishment on high-value assets and high-impact systems by 31 Dec 2030, and
       signatures by 31 Dec 2031;
     - a proposed FAR rule for covered contractors;
     - CISA, in coordination with NIST, publishes guidance on CBOM minimum elements within 270
       days (about Mar 2027).
   - **OMB M-26-15** (24 Jun 2026):
     - five phases from 2026 to 2035;
     - agency plans due 22 Oct 2026;
     - an automated inventory whose data "should populate a central Cryptographic Bill of
       Materials".
   - **EU NIS Cooperation Group roadmap** (23 Jun 2025, a recommendation):
     - national strategies by end-2026;
     - high-risk use cases by end-2030;
     - as many systems as feasible by 2035.
   - **NSA CNSA 2.0:** exclusive-use dates of 2030-2033 depending on the category. Verify
     against the current NSA advisory before quoting a single year.
3. **The CBOM is the wedge.** Quantsiv is *built to* emit CycloneDX 1.6 CBOMs (the reference
   generator is in audit section 7). Do not write "already emits" until WP6 ships.

## Delivery model (proposed; founder decision D1)

- **Scanning happens in the customer's environment.** A local-first scanner (`quantsiv scan`
  CLI plus a signed container) runs in the customer's CI (GitHub Actions, GitLab, Jenkins via a
  container step, Azure DevOps) after their build. Source code never leaves the customer.
- **Quantsiv hosts only metadata.** An EU-hosted control plane receives only the CBOM and
  finding metadata, and can later be self-hosted or air-gapped.
- **Server-side cloning is for public repos and demos only.** The spec's GitHub App flow is
  kept for those and nothing else.
- **B2B only.** See `quantsiv.md`, "Delivery model".
- **Positioning (decision D6).** Quantsiv is *cryptographic change control and CBOM evidence*,
  complementary to posture platforms (QIZ Security, Wiz for PQC Readiness):
  - Export and ingest plain CycloneDX.
  - Build no runtime or cloud inventory before Phase 3.
  - Scoring is dual-track: HNDL by data lifetime, plus a separate signature-deadline track.
  - Never call the product "cryptographic posture management".

## Rules

- **Claims.** Every capability stated in the UI or README must be backed by code merged here.
  Cite the authority for every regulatory claim. Never invent dates, statistics or competitor
  facts.
- **No fabricated data.** Never show made-up data in the UI. Label any demo data as a demo.
- **Cryptography.**
  - Use standardised primitives only: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).
  - Hybrid by default during the transition (e.g. X25519MLKEM768).
  - Never invent algorithms.
  - Never ship our own cryptographic implementations to customers without CMVP (FIPS 140-3)
    validation.
- **Agents (D7, D8).**
  - Agents propose, deterministic tools decide, and a human approves.
  - Never add auto-merge or auto-deploy.
  - The MCP server has no write tools.
  - Never send source code to a hosted model.
  - Never claim an agent capability in the UI or README before its code is merged.
  - Never write "first or only MCP server for crypto", "auto-fix", "autonomous", or "agentless"
    as a differentiator.
- **Security.**
  - Secrets come only through `app/config.py` Settings.
  - Tokens never appear in URLs, argv, logs, the database or user-visible errors.
  - TLS-scan only verified domains, and always through the SSRF guard.
  - Treat cloned repositories as hostile: no network, limits, sandbox.
  - Don't store raw code snippets by default.
- **Stealth.**
  - Keep this repo private.
  - Never copy code, strategy, pricing or audit material into `quantsiv-landing`. That repo is
    public, and GitHub Pages publishes everything in it.
  - Don't publish legal pages until D4 (legal identity) is answered.
- **Scope.** Landing-page work happens in `quantsiv-landing`, not here.
- **Encoding.** Use UTF-8 with no BOM. Windows tooling previously wrote UTF-16 files into this
  repo, and that breaks Python. The repository stores LF; only Windows checkouts show CRLF,
  through `core.autocrlf`. WP0's `.gitattributes` makes LF explicit. Shell scripts must stay LF.
- **Local-only files.** `app/templates/privacy_policy.html` is an inaccurate draft, and
  `write_privacy.py` is junk; both are untracked and must not be committed.

## Keep this file current

When a work package lands or a decision is made, update "Current state" above and the decision
table in `docs/audit/REMEDIATION_PLAN.md`.
