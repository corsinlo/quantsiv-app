# Quantsiv — MVP Spec

**Version 1.0 | September 2026 | Solo Founder Document**
**Revision 1.1 | 3 October 2026**: corrections from the code and compliance audit. Read this
block first. Where it conflicts with the text below, this block wins.

---

## Revision 1.1: what changed and why

Each item names the audit finding it comes from (`docs/audit/2026-10-03-app-audit.md`). Work is
sequenced in `docs/audit/REMEDIATION_PLAN.md`.

1. **Delivery model (decision D1, proposed).**
   - Primary delivery is a **local-first scanner**: a CLI plus a container that runs in the
     customer's CI after their build (GitHub Actions, GitLab, Jenkins via a container step,
     Azure DevOps).
   - Only the CBOM and metadata go to an EU-hosted control plane.
   - The GitHub App that clones repos into our infrastructure (§1, §3, §7) is kept only for
     public repositories and the demo scan.
   - See `quantsiv.md`, "Delivery model".
2. **Scan engine (A27).** There is no `java -jar cbomkit-lib.jar` CLI.
   - `cbomkit-lib` is a Java library (github.com/cbomkit/cbomkit-lib) supporting **Java and
     Python only**.
   - Its Python detection covers pyca/cryptography only.
   - Its Java accuracy depends on build artifacts.
   - Remove Go from v1.0 claims, add Quantsiv rules for PyCryptodome, and pick the integration
     under decision D2.
3. **Classification (A30, A53).**
   - AES-128 is **not** quantum-vulnerable: NIST IR 8547 (draft) treats ≥128-bit symmetric
     primitives as meeting Category 1.
   - Severity is ranked by CycloneDX primitive and declared data lifetime. Key establishment and
     encryption protecting long-lived data rank highest (HNDL); signatures rank by their
     deadline and artifact lifetime.
   - This replaces the path heuristics that ranked signing above key exchange.
4. **Cloning (A15, A16, A52).**
   - Never put the token in the URL.
   - Use down-scoped installation tokens that are revoked after use.
   - Pass the token via `GIT_CONFIG_*` environment variables, with hardened clone flags, a size
     pre-check, a sandboxed scanner, and a fixed user-facing error.
5. **TLS scanning (A17).**
   - Resolve, then check the IP: public addresses only, port 443 only, internal names blocked.
   - Scan only verified domains (DNS TXT record).
6. **Database (A51).** Use Postgres from day one. A SQLite file cannot be shared between Railway's
   web and worker services.
7. **Data minimisation (A39).** `findings.raw_match` is opt-in per tenant; store a snippet hash
   by default.
8. **Truthful UI and copy (A28, A29, A31).**
   - No fabricated counters or demo data shown as real.
   - The "live counter" in §4 shows only real aggregate numbers.
   - The "HNDL score" label is used only when data lifetimes are declared.
   - No time claims ("90 seconds") until they are measured.
9. **Emails (A36).**
   - Days 1, 3, 5 and 7 are marketing emails. They need consent or the existing-customer soft
     opt-in, an unsubscribe link, `List-Unsubscribe` headers, and a postal address in the
     footer.
   - Content errors are fixed inline below.
10. **Billing (A22, A37; decision D5).**
    - The client sends a plan name, never a price ID.
    - Stripe webhooks are verified with `construct_event`.
    - The subscribe button shows the price, the billing period, VAT treatment, auto-renewal and
      how to cancel.
    - Pricing itself is on hold: see `quantsiv.md`, "Pricing".
11. **Share links (A23).** Use random tokens, stored hashed in a `share_links` table, so they are
    revocable and scoped to one scan, and keep them out of access logs.
12. **Third parties (A19, A38).**
    - Intercom sets cookies, so load it only after consent and list it as a subprocessor.
    - Self-host htmx and the Tailwind build instead of using CDNs.
13. **Build timeline (§8).** Superseded by `docs/audit/REMEDIATION_PLAN.md`; it is kept below for
    history.
14. **Sessions (A14, A24).** After GitHub OAuth, don't issue a long-lived JWT through
    python-jose. Instead, use one of:
    - an opaque session ID in an `HttpOnly; Secure; SameSite=Lax` cookie, mapped to a
      `sessions` table;
    - Starlette's `SessionMiddleware`.

    Add CSRF tokens to every state-changing request, and scope every query through the
    user's installations.
15. **Go-to-market (§9, §10).** Superseded by `quantsiv.md`, "Go-to-Market Motion": NDA design
    partners first, then the stealth exit around Q2 2027. §9 and §10 are kept below for
    history.

---

## 1. What the MVP Is

Quantsiv v1.0 is a GitHub-native quantum cryptography scanner that detects quantum-vulnerable algorithms (RSA, ECDSA, Diffie-Hellman) in source code and TLS configurations, presents findings in a web dashboard, and exports a compliance-ready PDF report. A developer adds the Quantsiv scanner to their CI (or, for public repositories, installs the GitHub App), and after the next build sees a prioritized list of quantum-vulnerable cryptographic calls with exact file locations and plain-English risk descriptions. (Revised 1.1: the 1.0 text promised "within 90 seconds", which is unmeasured.) The MVP proves three things: the scanner finds real findings in real codebases, the results are legible to a developer without a security background, and at least one regulated design partner will pay for a fixed-fee readiness assessment and convert to an annual subscription. (Revised 1.1; pricing is on hold under D5. The 1.0 text said "will pay €99/month to scan more than one repository".)

**Primary delivery mechanism** (revised in 1.1, decision D1): the local scanner, a CLI plus a container, running in the customer's CI through thin templates for GitHub Actions, GitLab, Jenkins and Azure DevOps. It uploads only the CBOM and metadata. The GitHub App becomes a later onboarding and check-run surface; its server-side clone serves public repos and the demo only. *(The 1.0 text said: "The GitHub App, installed from GitHub Marketplace. Everything else ... is secondary.")*

**Explicitly not in v1.0:**

- Cloud infrastructure scanning (AWS/Azure/GCP API integration)
- Container image scanning
- SAML/SSO authentication
- Self-hosted control plane (designed for, targeted H2 2027 per rev 1.1; local scanning itself IS in v1.0)
- Subdomain enumeration
- Compliance policy engine (custom rule definitions)
- Multi-region data residency
- API access for external integrations
- Slack or Jira notifications
- Any mobile experience

---

## 2. MVP Feature Set

| Feature | In v1.0 | Deferred | Notes |
|---|---|---|---|
| GitHub App installation | Yes | — | Public repos + demo scan; later an onboarding/check-run surface (rev 1.1, D1) |
| Source code scanning (Java, Python; Go later) | Yes | Go | Via CBOMkit (a Java library, no CLI; decision D2) plus Quantsiv rules (PyCryptodome) |
| TLS/certificate scanning by domain | Yes | — | Via sslyze Python library |
| CycloneDX 1.6 CBOM output | Yes | — | Standard format, no invention |
| Web dashboard: findings table | Yes | — | Severity, file, line, algorithm |
| Web dashboard: risk score | Yes | — | 0–100, derived from finding count and severity weights |
| Plain-English risk descriptions | Yes | — | "RSA-2048 in JWT signing: quantum-vulnerable (Shor's algorithm); migrate to ML-DSA (FIPS 204)". No invented dates (rev 1.1) |
| Compliance PDF report export | Yes (paid) | — | Gated at Developer tier (€99/mo). v1.0 pricing, on hold under D5 |
| GitHub Action for CI/CD | Yes | — | `quantsiv/scan-action@v1`, week 6 |
| SARIF upload to GitHub Code Scanning | Yes | — | Ships with GitHub Action |
| Free tier (1 repo, push-triggered scans) | Yes | — | No credit card required. v1.0 pricing, on hold under D5 |
| Developer tier (€99/mo, unlimited repos, 3 seats) | Yes | — | Stripe Checkout. v1.0 pricing, on hold under D5 |
| Team tier (€299/mo, 15 seats) | Yes | — | Stripe Checkout. v1.0 pricing, on hold under D5; API access is not in v1.0 (see §1) |
| Enterprise tier (€1k–5k/mo) | Partial | Full | Manual quote + Stripe invoice; metered billing deferred. v1.0 pricing, on hold under D5 |
| Annual pricing (20% discount) | Yes | — | Default UI toggle. v1.0 pricing, on hold under D5 |
| Stripe Customer Portal (invoice, cancel, upgrade) | Yes | — | Single SDK call |
| EU VAT / OSS scheme compliance | Yes | — | Stripe Tax enabled day 1 |
| 7-day behavioral email sequence | Yes | — | Behavioral branching on scan completion |
| Intercom support widget | Yes | — | Dashboard only; loaded only after cookie consent and listed as a subprocessor (rev 1.1, A38) |
| Demo scan on empty dashboard | Yes | — | Public repo example shown before user's scan completes |
| CLI scanner (`quantsiv scan .`) | Yes (core) | — | Full local mode is the primary delivery; upload to the control plane is optional (rev 1.1, D1) |
| Snyk Broker equivalent (scan locally, report centrally) | — | — | Not needed: scanning is local by design (rev 1.1) |
| Cloud infra scanning (AWS/Azure/GCP) | No | v2 | Different auth model entirely |
| Container image scanning | No | v2 | Docker-in-Docker complexity |
| SAML/SSO | No | v2 | GitHub OAuth only in v1 |
| Slack community | No | Week 8 | Post-launch, not pre-launch |
| PQL scoring and CRM | No | Month 3 | Manual Slack alerts to founder in v1 |
| Semgrep-style cross-file dataflow analysis | No | v2 | cbomkit handles this partially |
| JavaScript/TypeScript scanning | No | Later | Quantsiv rules; CBOMkit covers Java and Python only. Add after Java/Python are validated (rev 1.1) |

---

## 3. Technical Architecture

### Recommended Tech Stack

**Python 3.12 + FastAPI + ARQ + Redis + Postgres** (revised 1.1, A51: Postgres from day one; SQLite only for local tests. The 1.0 text said "SQLite (MVP) → Postgres (production)".)

The entire scanning toolchain — sslyze, cyclonedx-python-lib, PyGithub, gitpython — is Python. Choosing a different language for the API layer would mean reimplementing TLS scanning and CBOM serialization from scratch. FastAPI is async-native, which is mandatory when you have concurrent long-running scan jobs. ARQ (async Redis queue, same author as Pydantic) has no Celery impedance mismatch and is the right choice for a solo founder who cannot afford operational complexity.

(Revised 1.1, A27/D2.) `cbomkit-lib` is a Java **library** with no CLI. There are two ways to use it:
- wrap it in a pinned fat jar that runs in the worker image only, with a JRE there and not in the web image; or
- ingest CBOMs from CBOMkit's CI tooling run in the customer's pipeline after their build.

Either way, do not rewrite the detection engine. (The 1.0 text said: "cbomkit-lib is a Java JAR. Run it as a subprocess.")

The frontend is deliberately minimal: HTMX + Alpine.js + Tailwind CSS rendered server-side via Jinja2 templates. This is not a React SPA. The reason: a solo founder cannot maintain a separate frontend build pipeline, a FastAPI backend, and a scanning engine simultaneously. HTMX gives interactive behavior (polling for scan status, progressive result loading) without a JavaScript framework. Switch to React if and when you hire a frontend engineer.

### Component Overview

```
[GitHub] ←→ [GitHub App Webhook Handler]
                        ↓
              [FastAPI Web + API Layer]
                        ↓
              [ARQ Job Queue via Redis]
                        ↓
          [Scan Worker Process]
            ├── git clone (gitpython + installation token)
            ├── cbomkit-lib.jar (subprocess, Java 17)
            ├── sslyze (TLS scanning, Python)
            ├── cyclonedx-python-lib (CBOM assembly)
            └── findings → DB → scan complete event
                        ↓
              [SQLite (MVP) / Postgres (v1.1)]
                        ↓
              [Dashboard: HTMX/Jinja2 templates]
                        ↓
              [PDF Report generator: WeasyPrint]
```

**GitHub App Webhook Handler**: Receives `installation`, `installation_repositories`, and `push` events. On `push` to default branch: enqueues a scan job for that repo. On `installation`: creates the installation record, triggers an initial scan of all connected repos (up to the plan limit).

**FastAPI Web + API Layer**: Serves the dashboard (HTML via Jinja2), handles GitHub OAuth login, exposes REST endpoints for the GitHub Action (`POST /api/v1/scans`, `GET /api/v1/scans/{id}`), and proxies upgrade flows to Stripe Checkout.

**ARQ Job Queue**: Redis-backed async task queue. Each scan job is independent. Workers are horizontally scalable — add a second worker container when scan queue depth exceeds 10 jobs.

**Scan Worker**: The only process with file system access. It downloads public or demo repos to `/tmp/{scan_id}/` using the hardened clone, runs the engine, and parses the output. It runs sslyze only for domains the customer has verified (DNS TXT), through `resolve_scan_target()`. It assembles the CBOM and cleans up temp files in a `finally` block. (Rev 1.1: A15, A16, A17, D1.)

**PDF Report Generator**: WeasyPrint converts a Jinja2 HTML template into PDF. The compliance report includes: executive summary, finding table by severity, NIST PQC migration checklist, remediation priority order, CBOM JSON appendix. This is a synchronous operation triggered on demand; it does not go through the job queue.

### Database Schema

Start with SQLite. The schema is designed for a Postgres migration — no SQLite-specific types, foreign keys enforced, no triggers.

```sql
-- Users (authenticated via GitHub OAuth)
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    github_user_id INTEGER UNIQUE NOT NULL,
    github_login  TEXT NOT NULL,
    email         TEXT,
    plan          TEXT NOT NULL DEFAULT 'free',  -- 'free'|'developer'|'team'|'enterprise'
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- GitHub App installations
CREATE TABLE installations (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    github_installation_id INTEGER UNIQUE NOT NULL,
    account_name           TEXT NOT NULL,
    account_type           TEXT NOT NULL,  -- 'user'|'organization'
    user_id                INTEGER REFERENCES users(id),
    created_at             DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Scan jobs
CREATE TABLE scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id INTEGER REFERENCES installations(id),
    repo_full_name  TEXT NOT NULL,   -- 'org/repo'
    scan_type       TEXT NOT NULL,   -- 'source'|'tls'|'both'
    status          TEXT NOT NULL DEFAULT 'queued',  -- 'queued'|'running'|'done'|'failed'
    triggered_by    TEXT NOT NULL,   -- 'push'|'manual'|'scheduled'|'action'
    error_message   TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at    DATETIME
);

-- Individual findings
CREATE TABLE findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER REFERENCES scans(id),
    file_path        TEXT,           -- NULL for TLS findings
    line_number      INTEGER,
    algorithm        TEXT NOT NULL,  -- 'RSA'|'ECDSA'|'DH'|'DSA'
    algorithm_family TEXT NOT NULL,  -- 'asymmetric'|'kex'|'signature'
    key_size         INTEGER,        -- 2048, 256, etc.
    quantum_safe     BOOLEAN NOT NULL DEFAULT FALSE,
    severity         TEXT NOT NULL,  -- 'critical'|'high'|'medium'|'low'
    confidence       REAL,           -- 0.0–1.0 from cbomkit
    context_label    TEXT,           -- 'JWT signing'|'TLS handshake'|'Key generation'
    raw_match        TEXT,           -- opt-in per tenant only (rev 1.1, A39)
    snippet_hash     TEXT            -- stored by default instead of the snippet
);

-- CBOM snapshots (full CycloneDX JSON per scan)
CREATE TABLE cbom_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER UNIQUE REFERENCES scans(id),
    cbom_json   TEXT NOT NULL,  -- JSON blob; change to JSONB on Postgres
    risk_score  INTEGER,        -- 0–100
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- TLS scan results
CREATE TABLE tls_scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER REFERENCES scans(id),
    domain           TEXT NOT NULL,
    ip_address       TEXT,
    port             INTEGER DEFAULT 443,
    cert_subject     TEXT,
    cert_expiry      DATETIME,
    cert_algorithm   TEXT,
    cert_key_bits    INTEGER,
    cipher_suites    TEXT,   -- JSON array
    tls_version      TEXT,
    quantum_safe     BOOLEAN NOT NULL DEFAULT FALSE,
    scanned_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

When migrating to Postgres: change `cbom_json TEXT` to `cbom_json JSONB`, add a GIN index, and switch `aiosqlite` to `asyncpg`. Everything else stays identical.

### Cloud Deployment Plan

**MVP: Railway. Cost: ~$20–30/month.**

Railway services:
- `web`: FastAPI + uvicorn (`uvicorn app.main:app --host 0.0.0.0 --port $PORT`)
- `worker`: ARQ worker (`python -m arq app.worker.WorkerSettings`)
- `redis`: Railway Redis plugin (built-in)
- ~~Persistent volume mounted at `/data/quantsiv.db` (SQLite file)~~. Revised 1.1 (A51): a Railway volume attaches to one service only, so web and worker cannot share a SQLite file. Use Railway Postgres (`DATABASE_URL`) from day one, in an EU region.

Dockerfile base: `python:3.12-slim` with `openjdk-17-jre-headless` added via `apt-get`. The cbomkit-lib JAR ships inside the image at `/app/bin/cbomkit-lib.jar`. Total image size target: under 800MB.

Environment variables stored in Railway's secret manager: `GITHUB_APP_PRIVATE_KEY` (PEM), `GITHUB_APP_ID`, `GITHUB_WEBHOOK_SECRET`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `DATABASE_URL`, `REDIS_URL`.

**Migration trigger: move to Render when any of these happen:**
- Monthly Railway bill exceeds $80 (scale-up signal)
- First enterprise prospect asks for SOC 2 compliance documentation (verify the hosting provider's current certifications and EU region before citing them)
- You need managed Postgres with point-in-time recovery

Do not touch AWS until you have two engineers and an operations budget. The operational overhead is not justified for a solo founder below $10k MRR.

### How the Scanning Engine Works Step-by-Step

```
1. Trigger arrives (GitHub push webhook or manual scan request)

2. Worker receives job from ARQ queue with: installation_id, repo_full_name, scan_type

3. Request fresh GitHub installation access token:
   - Sign a JWT with the GitHub App private key (RS256, 10-minute expiry)
   - POST https://api.github.com/app/installations/{id}/access_tokens
   - Receive token (1-hour TTL) — never written to DB

4. Clone repository to /tmp/{scan_id}/  (REVISED 1.1, A15/A16; hosted path = public repos only)
   NEVER put the token in the URL. Pass it via env, never argv:
     GIT_CONFIG_COUNT=1
     GIT_CONFIG_KEY_0=http.https://github.com/.extraheader
     GIT_CONFIG_VALUE_0="Authorization: Basic base64(x-access-token:{token})"
   git -c core.symlinks=false -c core.hooksPath=/dev/null \
       -c protocol.allow=never -c protocol.https.allow=always \
       clone --depth=1 --single-branch --no-tags --no-recurse-submodules \
       -- https://github.com/{repo}.git /tmp/{scan_id}/
   Before cloning, check `size` (KB) via GET /repos/{owner}/{repo}. Timeout 120 s.
   Delete .git before scanning. Show users only a generic error message.

5. Run the source-code engine  (REVISED 1.1, A27, decision D2)
   cbomkit-lib is a Java LIBRARY (Java + Python only), not a CLI. Either wrap it in a small
   pinned Java main (a fat jar), or ingest the CBOM from CBOMkit's CI tooling run in the
   customer's pipeline after their build. Run it with a timeout, memory limits and no network.

6. Parse CycloneDX CBOM JSON output:
   - For each component where type = 'cryptographic-asset':
     - Extract: algorithm name, key size, primitive type, file location, line number
     - Classify as quantum-safe or not  (REVISED 1.1, A30):
       Quantum-safe: ML-KEM, ML-DSA, SLH-DSA, and symmetric primitives with >=128-bit security
         (AES-128/192/256, ChaCha20); NIST IR 8547 ipd: these meet Category 1
       Quantum-vulnerable: RSA (any size), ECDSA, EdDSA, ECDH/X25519, DH, DSA
     - Assign severity by CycloneDX primitive and declared data lifetime  (REVISED 1.1, A53):
       critical: key-agree / kem / pke protecting data whose confidentiality lifetime
                 outlasts the threat horizon (HNDL)
       high:     key-agree / kem / pke otherwise; long-lived signing roots
                 (code/firmware signing, CA keys)
       medium:   short-lived signatures (e.g. session tokens); weak TLS configuration
       low:      informational
     - Add context_label from file path heuristics:
       */auth/* or */jwt/* → 'Authentication signing'
       */tls/* or */ssl/* → 'Transport encryption'
       */payment/* or */crypto/* → 'Data encryption'

7. Detect domains from config files  (REVISED 1.1, A17)
   Scan for hostnames in .env, config.yaml, application.properties, .env.example.
   Detected hostnames are only SUGGESTIONS for the user. A full TLS scan runs only for domains
   the customer has verified (DNS TXT record). Every target goes through resolve_scan_target():
   internal names blocked, public IPs only, port 443, connect to the vetted IP with SNI.

8. Run TLS scan via sslyze (if domains detected or scan_type includes 'tls'):
   scanner = Scanner()
   scanner.queue_scans([ServerScanRequest(target) for target in domains])
   results = list(scanner.get_results())
   Extract: cert algorithm, key bits, cipher suites, TLS version, expiry

9. Compute risk score (0–100):
   base = 0
   base += critical_count * 25   (cap at 50)
   base += high_count * 10        (cap at 30)
   base += medium_count * 5       (cap at 20)
   risk_score = min(100, base)

10. Assemble CycloneDX 1.6 CBOM via cyclonedx-python-lib:
    Include all components (quantum-safe and not), metadata, evidence

11. Write to database:
    - INSERT INTO scans: set status='done', completed_at=now()
    - INSERT INTO findings: one row per cryptographic-asset
    - INSERT INTO cbom_snapshots: full CBOM JSON + risk_score
    - INSERT INTO tls_scans: one row per domain

12. Clean up temp files:
    shutil.rmtree('/tmp/{scan_id}/', ignore_errors=True)
    (This is in a finally block — runs even on failure)

13. Emit scan_complete event via Redis pub/sub:
    Dashboard SSE endpoint picks this up and pushes update to open browser connections
```

---

## 4. User Journey: Signup to First Value

Target: **under 5 minutes** from landing page to first scan result displayed.

### Step 1 — Landing Page (0:00)

The landing page has one CTA above the fold: **"Scan your codebase for quantum-vulnerable cryptography — free, no credit card."**

Below the CTA: a live counter showing **real** aggregate numbers only, and only once they exist (revised 1.1, A29; the example figures "3,842 repos scanned, 41,203 vulnerabilities found" were illustrative), plus a screenshot of the findings dashboard labelled as a demo of a public repository. No feature list, no pricing table, no testimonials on the first scroll.

Headline: **"Find quantum-vulnerable cryptography before your adversaries do."**
Sub-headline: "NIST finalized PQC standards in August 2024. Adversaries can record encrypted traffic today and decrypt it later. Quantsiv inventories the cryptography in your codebase, inside your own pipeline." (Revised 1.1: no time claim until it is measured.)

### Step 2 — GitHub OAuth (0:30)

Click "Start free scan" → GitHub OAuth. Requests only: read user profile + email addresses. No repository access at this step — requesting repo access on the OAuth screen triggers fear. Repository access comes at the GitHub App installation step, which follows immediately.

On OAuth callback: create user record, set `plan='free'`, and start a server-side session: an opaque session ID in an `HttpOnly; Secure; SameSite=Lax` cookie, or Starlette's SessionMiddleware (rev 1.1, A14; no long-lived JWT). Redirect to `/onboarding/connect`.

### Step 3 — Connect a Repository (1:00)

(Revised 1.1, D1: the hosted-clone flow below applies to public repositories and the demo only. The primary onboarding is "Add one step to your CI" with the local scanner; see §1.)

The `/onboarding/connect` page shows the GitHub App installation CTA:

```
Connect your first repository

Quantsiv needs read-only access to your code to detect
quantum-vulnerable cryptography. We clone your repo temporarily,
scan it, then delete the copy.

[Install on GitHub →]   [Learn what access we request]
```

Click "Install on GitHub" → GitHub App installation page. Default selection: "Only select repositories" with the user's most recently pushed repo pre-filled. This is deliberate — reduce the number of repos authorized to reduce anxiety.

On install: GitHub redirects back to your callback, backend records the installation, enqueues a scan job, redirects to `/dashboard/scans/{scan_id}/live`.

### Step 4 — Scan in Progress (1:30)

Real-time progress UI powered by Server-Sent Events (SSE):

```
Scanning your-org/your-repo

[=====>         ] 35%

Cloning repository...         ✓
Analyzing Python files...     ✓  (1,247 files)
Analyzing Java files...       ↻  (scanning now)
Checking TLS configuration...
Generating risk report...

Findings so far: 7 critical, 12 high
```

The "Findings so far" counter updates in real time. This is the most important UX element — it proves the scan is finding real things before it completes.

### Step 5 — Results Dashboard (3:00–4:30)

**Top bar:**
```
your-org/your-repo    Risk Score: 73/100 (HIGH)    7 critical  |  12 high  |  4 medium
[Export Compliance Report ↓]   [Add to CI/CD]   [Scan another repo]
```

**Findings table:**

| Severity | Algorithm | Location | Key Size | Context | Fix |
|---|---|---|---|---|---|
| MEDIUM | RSA | auth/jwt.py:47 | 2048-bit | Token signing (short-lived signature; rev 1.1, A53) | View fix |
| CRITICAL | RSA | payment/encrypt.py:23 | 2048-bit | Data encryption | View fix |
| HIGH | ECDSA | api/auth.py:91 | P-256 | Request signing | View fix |

Clicking a row expands to show: exact code snippet (3 lines of context), plain-English risk explanation, migration guide link.

**Right sidebar:**
```
NIST PQC Compliance
0 of 19 findings use PQC algorithms    (demo data, labelled as such; rev 1.1 removed the "% migrated" bar)

[Generate Compliance Report]
(Requires Developer plan — €99/mo)
```

### Step 6 — Upgrade Prompt (First Natural Trigger)

The upgrade prompt fires at the first natural limit hit, not immediately on results. Appears when:

- User clicks "Export Compliance Report" → modal with findings count personalization
- User clicks "Scan another repo" → modal referencing their current repo count
- User clicks "Add to CI/CD" → modal

**Hypothesis to measure: findings-personalized upgrade prompts convert better than generic ones.** (Rev 1.1 removed the unsourced 2-3% and 8-12% figures.)

---

## 5. Onboarding Flow Detail

### Engineering the Aha Moment

The aha moment is: **a developer sees their own file path and their own function name labeled as quantum-vulnerable, with a timeline for when it becomes a real threat.**

Not: "you have crypto issues."
Yes: "auth/jwt.py:47 uses RSA-2048 for token signing. A cryptographically relevant quantum computer could forge these signatures; migrate to ML-DSA (FIPS 204) before EO 14412's 31 Dec 2031 signature deadline." For a key-exchange finding, add: "Traffic recorded today could be decrypted later (harvest now, decrypt later)." (Rev 1.1: no invented dates, and no HNDL claims on signatures.)

Three design decisions that engineer this moment:

1. **The first finding shown is always the most critical, most contextual one.** If there is an RSA key in a file path containing `auth`, `jwt`, `login`, or `payment` — that is shown first. Ranking (rev 1.1, A53): by CycloneDX primitive and declared data lifetime. Path keywords (`auth`, `jwt`, `login`, `payment`, `crypto`, `sign`) only break ties.

2. **The real-time counter during scanning** sets anticipation. By the time the results page loads, the user already expects to see a real report.

3. **The demo scan on the empty dashboard** prevents the zero-state problem. Show a completed scan of `pallets/flask` with a banner: "This is a demo scan of a public repo — your scan of `your-repo` is running." Proves the tool works before their results arrive.

### First 7-Day Email Sequence

All emails sent from `ludo@quantsiv.io` (founder's personal address), plain-text, no HTML. Deliverability is higher, developer response rate is higher.

**Compliance (revision 1.1, A36):**
- **Classification.** Day 0 and Day 2 are service emails. Days 1, 3, 5 and 7 are marketing.
- **Who may receive marketing emails.** Send them only with consent, or under the
  existing-customer soft opt-in (ePrivacy Directive Art. 13(2); NL Telecommunicatiewet
  art. 11.7). Offer an opt-out at signup and in every message.
- **Footer on every marketing email:**
  - an unsubscribe link;
  - the legal entity's name and postal address (CAN-SPAM, 15 U.S.C. 7704(a)(5), for US
    recipients).
- **Headers on every marketing email:**
  - `List-Unsubscribe`;
  - `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058).
- **Content.** Every factual claim needs a source. Never imply data about other customers.

**Day 0 — "Your scan is running" (send immediately on signup)**
```
Subject: Your quantum risk scan is running

Hi {first_name},

Your scan of {repo_name} is running now. We'll email you when the results are ready.

View your results here: https://quantsiv.io/dashboard/scans/{scan_id}

Quantsiv scans for RSA, ECDSA, and Diffie-Hellman — the algorithms
that a quantum computer running Shor's algorithm will break.

NIST finalized post-quantum standards in August 2024. The clock is running.

— Ludo
```

**Day 1 — Activation nudge (only if `first_scan_completed = FALSE` at 24h)**
```
Subject: Run your first Quantsiv scan

Hi {first_name},

You signed up for Quantsiv yesterday but haven't run a scan yet.

Add one step to your CI (copy-paste snippet) and your next build
produces a cryptographic inventory:

https://quantsiv.io/onboarding/connect

What scans commonly flag:
- RSA-2048 keys in authentication flows
- ECDSA signing in payment APIs
- DHE key exchange in TLS configs

Each of these would be broken by Shor's algorithm on a future
cryptographically relevant quantum computer.

— Ludo
```

**Day 2 — First findings context (send within 1 hour of scan completion)**
```
Subject: You have {critical_count} critical quantum vulnerabilities in {repo_name}

Hi {first_name},

Your Quantsiv scan found {total_findings} quantum-vulnerable endpoints
in {repo_name}. Here are the three most critical:

1. {top_finding_1_location} — {top_finding_1_algorithm}, {top_finding_1_context}
2. {top_finding_2_location} — {top_finding_2_algorithm}, {top_finding_2_context}
3. {top_finding_3_location} — {top_finding_3_algorithm}, {top_finding_3_context}

These algorithms would be broken by Shor's algorithm on a future
quantum computer. For the key-exchange and encryption findings,
"harvest now, decrypt later" applies: traffic captured today could be
decrypted later. Signature findings face future forgery instead.

View your full report: https://quantsiv.io/dashboard/scans/{scan_id}

— Ludo
```

**Day 3 — Education + urgency (send to all users)**
```
Subject: EO 14412 set federal PQC deadlines in June 2026

Hi {first_name},

Three things happened recently that affect your codebase:

1. NIST finalized ML-KEM, ML-DSA, and SLH-DSA as the official post-quantum
   cryptography standards in August 2024 (FIPS 203/204/205).

2. Executive Order 14412 (22 June 2026) requires federal high-value and
   high-impact systems to use PQC key establishment by 31 Dec 2030 and PQC
   signatures by 31 Dec 2031, and directs a FAR rule bringing covered
   contractors to FIPS compliance by 31 Dec 2030.

3. The EU's coordinated PQC roadmap (June 2025) asks for high-risk use
   cases to be migrated by end-2030, starting with an inventory.

If your product handles financial data, health records, or government
contracts — your security team will need a quantum risk assessment before
your next audit cycle. Quantsiv generates that report automatically.

https://quantsiv.io/dashboard

— Ludo
```

**Day 5 — Compliance report + team expansion (activated users only)**
```
Subject: Share your Quantsiv results with your security team

Hi {first_name},

The Quantsiv findings for {repo_name} can be exported as a
PQC migration readiness report (Developer plan).

The report includes:
- Algorithm inventory
- Quantum vulnerability assessment per finding
- Migration checklist mapped to NIST IR 8547 (draft) and OMB M-26-15
  (NB: NIST SP 800-208 covers LMS/XMSS signatures; it is not a migration checklist)
- CycloneDX CBOM
- Remediation priority order

Exporting the report requires the Developer plan (€99/month).

https://quantsiv.io/upgrade

If you want to share findings with your security lead before upgrading,
forward them this read-only link:
https://quantsiv.io/dashboard/scans/{scan_id}/share/{share_token}

— Ludo
```

**Day 7 — Divergence**

For non-activated users:
```
Subject: 15 minutes — I'll scan your repo live on a call

Hi {first_name},

I'm offering 15-minute setup calls (only say "for the first 50 users" if that cap is real and enforced). I'll share
my screen, walk you through connecting your repo, and show you what
Quantsiv finds. No sales pitch.

Book here: https://cal.com/ludo-quantsiv/15min

— Ludo
```

For activated users not yet converted:
```
Subject: Scan the rest of your repositories with Quantsiv
(rev 1.1: pricing on hold under D5; the plan list below is v1.0 history)

Hi {first_name},

You've scanned {repo_name} with Quantsiv. Found {total_findings} findings.

The Developer plan (€99/month) unlocks:
- Unlimited repositories
- Compliance PDF export
- Scheduled weekly scans
(rev 1.1: the CI step is free for everyone, so it is not a paid unlock)

https://quantsiv.io/upgrade

— Ludo
```

---

## 6. Payment Model

> **On hold (rev 1.1, decision D5).** The tiers and prices below are the v1.0 draft, kept for history. The proposed packaging is in `quantsiv.md`, "Pricing": free scanner, fixed-fee assessment, Supplier tier, annual Organisation subscription, and Enterprise self-hosted. Do not implement these prices. The engineering requirements here still apply: plan allow-list, `construct_event`, renewal disclosure, and EU VAT.

### Exact Tier Structure

| | Free | Developer | Team | Enterprise |
|---|---|---|---|---|
| **Price (monthly)** | €0 | €99/mo | €299/mo | €1,000–5,000/mo |
| **Price (annual)** | €0 | €79/mo (€948/yr) | €239/mo (€2,868/yr) | Custom |
| **Repositories** | 1 | Unlimited | Unlimited | Unlimited |
| **Seats** | 1 | 3 | 15 | Custom |
| **Scan trigger** | Push only | Push + scheduled | Push + scheduled | Push + scheduled + API |
| **Compliance PDF export** | No | Yes | Yes | Yes + custom branding |
| **CI/CD GitHub Action** | Yes (rev 1.1: the scanner and CI templates are free, D1) | Yes | Yes | Yes |
| **SARIF upload** | No | Yes | Yes | Yes |
| **API access** | No | No | Yes | Yes |
| **SSO/SAML** | No | No | No | Yes |
| **Audit logs** | No | No | Yes | Yes |
| **SLA** | None | None | 99.5% uptime | 99.9% + support SLA |
| **Support** | Intercom (community) | Email, 48h | Email, 24h | Private Slack + dedicated |
| **Onboarding** | Self-serve | Self-serve | Self-serve | Founder-led session |

### What Gates the Free-to-Paid Upgrade

Four triggers, in order of conversion probability:

1. **Compliance report export** (highest intent): user has already decided they need the artifact; they just hit a paywall.
2. **Second repo**: user clicks "Scan another repo" → natural expansion trigger.
3. **CI/CD integration**: user ready to operationalize, not just evaluate.
4. **Second seat**: colleague with same email domain tries to sign up → prompt to merge accounts under a shared plan.

No time-gated trial. No "your trial expires in 14 days" countdown. Developers are allergic to artificial urgency. The free tier is permanent and functional for one repo.

### Stripe Implementation Plan

**Products and Prices:**
```
Products:
  quantsiv-developer     (name: "Quantsiv Developer")
  quantsiv-team          (name: "Quantsiv Team")

Prices:
  developer-monthly:    €99.00 EUR, recurring monthly
  developer-annual:     €948.00 EUR, recurring yearly  (= €79/mo)
  team-monthly:         €299.00 EUR, recurring monthly
  team-annual:          €2,868.00 EUR, recurring yearly (= €239/mo)
```

**Checkout Session Endpoint** (revised 1.1, A22: the client sends a plan name and the server maps it to a price; a client-supplied price ID would let a user pick any active price):
```python
class CheckoutRequest(BaseModel):
    plan: Literal["developer-monthly", "developer-annual", "team-monthly", "team-annual"]

@router.post("/api/billing/checkout")
async def create_checkout_session(
    body: CheckoutRequest,
    user: User = Depends(current_user)
):
    price_id = settings.stripe_prices[body.plan]   # server-side allow-list
    session = stripe.checkout.Session.create(
        customer=user.stripe_customer_id or None,
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url="https://quantsiv.io/billing/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://quantsiv.io/upgrade",
        client_reference_id=str(user.id),
        tax_id_collection={"enabled": True},
        automatic_tax={"enabled": True},
        allow_promotion_codes=True,
    )
    return {"checkout_url": session.url}
```

**Webhook Handler — handle these events in order of importance:**
```python
# checkout.session.completed → update user.plan, store stripe_customer_id + stripe_subscription_id
# customer.subscription.updated → update user.plan when user upgrades/downgrades
# customer.subscription.deleted → downgrade user.plan to 'free'
# invoice.payment_failed → send payment failure email, show banner in dashboard
```

Verify every webhook with `stripe.Webhook.construct_event` (signature plus timestamp tolerance), and reject any that fails. Derive `user.plan` from the subscription's price ID, never from client data.

**Customer Portal:**
```python
session = stripe.billing_portal.Session.create(
    customer=user.stripe_customer_id,
    return_url="https://quantsiv.io/dashboard"
)
return redirect(session.url)
```

**Annual vs Monthly UI**: Default pricing page toggle to "Annual." Show savings in euros, not percentage: "Save €240/year" not "Save 20%." (Revised 1.1, A37: next to the subscribe button, show:
- the amount charged today (e.g. "€948 billed today");
- whether VAT is included;
- "renews automatically every 12 months";
- how to cancel.

Pricing itself is on hold under decision D5; see `quantsiv.md`, "Pricing".)

**Enterprise tier**: No Stripe Checkout. Manual Stripe invoices or wire transfer. Implement metered billing only when you have three enterprise customers with different repo counts.

### EU VAT Handling

**Day 1 setup — do not defer:**

1. Enable Stripe Tax: Settings → Tax → Add Netherlands origin address.
2. Enable `tax_id_collection: {"enabled": True}` in Checkout (already in code above). EU B2B customers enter their VAT number — Stripe validates via VIES and zero-rates automatically.
3. EU OSS (One Stop Shop) registration at belastingdienst.nl is needed only for B2C sales. Quantsiv sells B2B only (rev 1.1), so this applies only if that changes. If it does, register within 30 days of the first EU B2C sale; returns are quarterly (Jan/Apr/Jul/Oct).
4. US customers: Stripe Tax handles state sales tax automatically. Economic nexus thresholds don't trigger until $100k+ revenue in most states.

**Common mistake to avoid**: Not collecting VAT numbers at checkout means you charge VAT to EU B2B customers entitled to zero-rating. They will dispute the charge.

---

## 7. How It Ships to Customers

### GitHub App Install Flow

1. User clicks "Start free scan" on landing page
2. GitHub OAuth → account creation → redirect to `/onboarding/connect`
3. Click "Install on GitHub" → `github.com/apps/quantsiv/installations/new`
4. GitHub shows: "Quantsiv requests: Repository contents (Read), Repository metadata (Read)"
5. User selects repos (default: one pre-filled), clicks "Install"
6. GitHub redirects to `quantsiv.io/callback/github?installation_id={id}`
7. Quantsiv records installation, enqueues first scan, redirects to live scan page

**Marketplace listing**: Publish to `github.com/marketplace` as a free listing with paid plans. Gives organic discovery from GitHub's developer audience.

### CI/CD GitHub Action

Published as `quantsiv/scan-action` on GitHub Marketplace:

```yaml
name: Quantsiv PQC Scan
on:
  pull_request: {}
  push:
    branches: [main, master]

jobs:
  quantum-risk-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for quantum-vulnerable cryptography
        uses: quantsiv/scan-action@v1
        with:
          token: ${{ secrets.QUANTSIV_TOKEN }}
          fail_on: critical          # block PRs with critical findings (optional)
          report_format: sarif       # uploads to GitHub Security tab
```

The Action: runs scanner as Docker container, posts findings to API, emits SARIF for GitHub Code Scanning, exits with code 1 if critical findings exist and `fail_on: critical` is set.

Setup in 3 steps: create API token in dashboard → add as GitHub secret → add YAML to `.github/workflows/quantsiv.yml`.

### Read-Only Share Links

Generate a share token for any scan result: `https://quantsiv.io/dashboard/scans/{id}/share/{token}`. It expires after 7 days. Lets developers share results with a CISO or auditor without giving them a Quantsiv account. High-value for enterprise sales motion. (Revised 1.1, A23:
- the token is a random 32-byte value, stored hashed in `share_links` (`scan_id`, `expires_at`, `revoked_at`), so it is revocable and scoped to one scan;
- `/share/` paths are masked in access logs;
- share pages send `Referrer-Policy: no-referrer`.)

### Support Model at MVP Stage

**Phase 1 (0–50 customers, weeks 1–12):**
- Intercom chat widget on the dashboard only, loaded after cookie consent and listed as a subprocessor (rev 1.1, A38; the landing page stays free of third-party scripts)
- Founder responds personally within 4 hours during NL business hours
- Every support conversation tagged by theme — this is product research

**Phase 2 (50–200 customers, months 3–6):**
- `quantsiv-community` Slack workspace
- Invite all users via welcome email
- Seed with 3–4 posts per week: NIST updates, CVE advisories, migration examples

**Phase 3 (first enterprise customer, month 4+):**
- Dedicated `#quantsiv-{company}` private Slack channel per enterprise customer
- Use for urgent advisories: "New ECDSA lattice attack paper published — Quantsiv detection updated today"

Do not use Discord. Security professionals work in Slack.

---

## 8. Build Timeline (Solo Founder)

### Week 1 — GitHub App Foundation
**Goal**: GitHub App exists, installs without errors, basic auth works.
- Register GitHub App: Contents Read, Metadata Read, Pull Requests Read/Write, Checks Write
- Set up Railway: web + worker + Redis + persistent volume
- Scaffold FastAPI: `app/main.py`, `app/worker.py`, `app/models.py`
- GitHub OAuth login flow (account creation, session JWT)
- GitHub App installation webhook handler
- SQLite schema: `users`, `installations` tables
- Deploy to Railway. Smoke test: install App on test repo, verify installation recorded.

**Ships**: GitHub App installable. No scanning yet.

### Week 2 — Scanning Engine Core
**Goal**: Source code scanner runs end-to-end on a test repo.
- Add `scans` and `findings` tables to schema
- Integrate cbomkit-lib as subprocess call (Java 17 in Docker base image)
- Implement ARQ worker: `clone → cbomkit-lib → parse CBOM → write findings → cleanup`
- Implement GitHub installation access token generation
- Enqueue first scan on installation webhook
- Manual test: `POST /api/v1/scans` → verify findings written to DB

**Ships**: Scanner runs end-to-end on Python repos. No dashboard yet.

### Week 3 — TLS Scanner + CBOM Output
**Goal**: sslyze integrated, CycloneDX CBOM generated, risk score computed.
- Add `tls_scans` and `cbom_snapshots` tables
- Integrate sslyze: detect domains from config files, run async TLS scan
- Integrate cyclonedx-python-lib: assemble CycloneDX 1.6 CBOM
- Implement risk score computation
- Implement plain-English context labels (file path heuristics)
- Add Java and Go scanning

**Ships**: Full scan pipeline produces CBOM JSON + risk score across Java and Python. (Revision 1.1: CBOMkit has no Go support, so Go is deferred.)

### Week 4 — Dashboard: Findings Table
**Goal**: A developer can see their scan results in a browser.
- Scaffold HTMX + Jinja2 + Tailwind CSS dashboard
- Implement `/dashboard/scans/{id}` (findings table, severity filter, expanding row detail)
- Implement `/dashboard/scans/{id}/live` (SSE-based real-time scan progress)
- Implement demo scan on empty dashboard
- Implement read-only share link generation
- Wire plain-English risk descriptions

**Ships**: Complete flow from GitHub App install → scan → results dashboard. Invite first 5 beta users.

### Week 5 — Landing Page + Onboarding Flow
**Goal**: Cold visitor can sign up and reach first scan result without guidance.
- Build landing page: headline, sub-headline, CTA, proof counter
- Build `/onboarding/connect` page
- Implement repo pre-selection (fetch user's most recent repo)
- Wire 7-day behavioral email sequence in Postmark/Resend
- Add Intercom widget

**Ships**: End-to-end user flow complete. Invite first 10 beta users.

### Week 6 — GitHub Action
**Goal**: `quantsiv/scan-action@v1` published and installable.
- Build Docker scanner image
- Build GitHub Action wrapper (`action.yml`, `entrypoint.sh`)
- Implement SARIF output
- Wire SARIF upload to `github/codeql-action/upload-sarif`
- Implement API token generation in dashboard
- Publish to GitHub Marketplace

**Ships**: CI/CD GitHub Action live.

### Week 7 — PDF Compliance Report
**Goal**: Compliance PDF export production-ready (the primary upgrade trigger).
- Design compliance report template (Jinja2 HTML/CSS)
- Implement WeasyPrint PDF generation endpoint
- Gate behind plan check (free users get 402 with upgrade modal)
- Style PDF to look like a professional audit document

**Ships**: PDF compliance report generates for Developer+ users.

### Week 8 — Stripe Billing
**Goal**: First paid customer can upgrade through self-serve checkout.
- Create Stripe account, enable Stripe Tax (Netherlands origin)
- Create Products × Prices (developer/team × monthly/annual)
- Implement checkout session endpoint
- Implement Stripe webhook handler
- Implement plan feature gating throughout the app
- Enable Stripe Customer Portal
- Annual/monthly toggle on pricing page (default: annual)
- Enable tax ID collection
- Register for EU OSS at Belastingdienst

**🎯 First milestone: first paying customer. Target: end of week 8.**

### Week 9 — PQL Alerts + Founder Sales
**Goal**: High-intent signals routed to founder automatically.
- Implement signal detection:
  - `compliance_export_attempted` (free user clicks export)
  - `multi_seat_attempt` (second user from same email domain signs up)
  - `repo_limit_hit` (second repo attempted on free)
- Route signals to founder Slack via incoming webhook within 60 seconds
- Implement Calendly link in Day 7 non-activated email
- Instrument Clearbit enrichment on signup: flag companies >200 employees in fintech/healthtech/govtech

### Week 10 — Security Hardening
**Goal**: No security vulnerabilities in the product that scans other people's security.
- Verify row-level access control on all DB queries
- Verify webhook HMAC validation is not bypassable
- Verify temp file cleanup in `finally` blocks
- Verify GitHub installation access tokens never written to DB or logs
- Run `bandit` (Python security linter) over entire codebase
- Rate limiting: 100 scans/hour per installation, 1000 requests/hour per API token

### Week 11 — JavaScript/TypeScript Scanning (Beta)
**Goal**: Expand language coverage to JavaScript/TypeScript.
- Evaluate cbomkit-lib JS/TS coverage. If insufficient: implement AST-based scanner using `tree-sitter` Python bindings
- Patterns: `new RSAKey()`, `RS256`, `createSign('RSA-SHA256')`, `crypto.createDiffieHellman()`
- Mark JS/TS findings as `confidence = 0.8`, labeled "(Beta)" in dashboard
- Test against 10 real-world JS repos

### Week 12 — Go-To-Market Push
**Goal**: €1,000 MRR. Public launch.
- Product Hunt (schedule Tuesday 00:01 PST)
- Hacker News "Show HN" — lead with data, not product
- Publish on dev.to / Medium: "How to find quantum-vulnerable cryptography in your Python codebase"
- Submit to TLDR Newsletter (security edition)
- Email all beta users asking for GitHub star on the scan-action repo
- Personal outreach to 10 fintech/healthtech CTOs via LinkedIn

---

## 9. MVP Success Metrics

*(Historical; see revision 1.1 item 15. The metrics stay useful once self-serve exists.)*

### Definition of "MVP Succeeded"

By day 90 after first public availability:

1. At least one customer paying €99+/month via pure self-serve (no manual intervention)
2. At least three developers reported finding a real quantum-vulnerable call they were previously unaware of
3. Scan-to-first-result time consistently under 5 minutes for repos under 100k LOC
4. No security incident involving customer repository data

### 5 Key Metrics Tracked from Day 1

**Metric 1 — Time to First Scan Result (TTFSR)**
- Definition: GitHub App installation complete → first finding on dashboard
- Target: median under 3 minutes, 95th percentile under 10 minutes
- Alert: if median exceeds 5 minutes for 3 consecutive days, stop all other work

**Metric 2 — Activation Rate**
- Definition: Signups who complete at least one scan and see results
- Target: 60% within 48 hours of signup
- Benchmark: Snyk ~55%. Alert: below 40% for a weekly cohort

**Metric 3 — Free-to-Paid Conversion Rate**
- Definition: Activated users who upgrade within 30 days
- Target: 4% in months 1–2, 6% by month 3
- Benchmark: developer tools freemium is 2–4%; compliance urgency justifies upper bound

**Metric 4 — Scan Reliability Rate**
- Definition: Scan jobs completing with `status='done'` (not `'failed'`)
- Target: 95% success rate
- Alert: below 90% for any 24-hour period → critical, scanner is broken

**Metric 5 — MRR Growth Rate**
- Definition: Month-over-month MRR growth
- Target: €1,000 MRR by day 90, 30%+ MoM through month 6
- Secondary: net revenue retention — are paying customers expanding to higher tiers?

---

## 10. First 90 Days Go-To-Market

*(Historical; see revision 1.1 item 15. The public-launch steps below come after the stealth exit.)*

### Week 1 — Waitlist Landing Page

- Launch `quantsiv.io` with single-page waitlist: headline + email capture
- Headline: "EO-14412 mandated PQC migration. NIST finalized the standards. Does your codebase use RSA?"
- Set up Postmark/Resend, send welcome email with a 2-minute explanation of harvest-now-decrypt-later
- Post landing page to: Hacker News (Ask HN), relevant LinkedIn groups, personal network
- **Target: 100 waitlist signups before launch**

### Week 4 — First 10 Beta Users

- Send "beta access" email to waitlist: offer early access to first 10 people who reply
- Personally onboard each beta user, ask 3 specific questions after first scan:
  1. Was the finding accurate?
  2. Did you understand the risk description without help?
  3. Would you pay €99/month to scan 5 more repos?
- Fix top 3 friction points before public launch
- Target ICP for beta: fintech/healthtech engineers, Python or Java codebase, NL or DACH region

### Week 8 — First Paying Customer

- Open public access (remove waitlist gate)
- Submit GitHub Action to GitHub Marketplace
- Write: "We found RSA-2048 in the authentication layer of 7 open-source Python projects — here's the scan" (use public repos, not customer data)
- Submit to Product Hunt in Developer Tools + Security categories
- Submit to tl;dr sec, Unsupervised Learning, SANS NewsBites
- Direct outreach to 20 ICP targets on LinkedIn

The first paying customer likely comes from: (a) beta user who hit repo limit, (b) developer who needs compliance report for audit, (c) direct outreach response from fintech engineer.

### Week 12 — €1,000 MRR

- Product Hunt launch (coordinate beta users for upvotes)
- "Show HN" post: lead with the data, not the product (e.g. "found RSA in X% of repos tested", where X is measured on real public repositories, never an illustrative figure)
- Publish gated PDF: "NIST PQC Migration Checklist for Fintech Startups" — generates leads organically for 6–12 months
- Begin enterprise outreach to 5 companies: >500 employees + GitHub org with Java/Python + fintech/healthtech/defense contracting

**€1,000 MRR decomposition**: 10 Developer (€990) + 1 Team (€299) = €1,289. Or 3 Team (€897) + 1 small enterprise manual invoice (€200) = €1,097. Either path achievable with 50–100 free signups and 4–6% conversion.

**The real validation milestone**: a customer renews automatically. Their second monthly payment processes without any action from the founder. That is the proof the business model works.
