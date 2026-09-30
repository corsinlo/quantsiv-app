# Quantsiv — MVP Spec

**Version 1.0 | September 2026 | Solo Founder Document**

---

## 1. What the MVP Is

Quantsiv v1.0 is a GitHub-native quantum cryptography scanner that detects quantum-vulnerable algorithms (RSA, ECDSA, Diffie-Hellman) in source code and TLS configurations, presents findings in a web dashboard, and exports a compliance-ready PDF report. A developer installs the Quantsiv GitHub App, selects a repository, and within 90 seconds sees a prioritized list of quantum-vulnerable cryptographic calls with exact file locations and plain-English risk descriptions. The MVP proves three things: the scanner finds real findings in real codebases, the results are legible to a developer without a security background, and at least one regulated-industry team will pay €99/month to scan more than one repository.

**Primary delivery mechanism**: The GitHub App, installed from GitHub Marketplace. Everything else — the CI/CD action, the CLI, the TLS domain scanner — is secondary and ships after the GitHub App produces its first paid customer.

**Explicitly not in v1.0:**

- Cloud infrastructure scanning (AWS/Azure/GCP API integration)
- Container image scanning
- SAML/SSO authentication
- Self-hosted deployment option
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
| GitHub App installation | Yes | — | Primary acquisition path |
| Source code scanning (Python, Java, Go) | Yes | — | Via cbomkit-lib subprocess |
| TLS/certificate scanning by domain | Yes | — | Via sslyze Python library |
| CycloneDX 1.6 CBOM output | Yes | — | Standard format, no invention |
| Web dashboard: findings table | Yes | — | Severity, file, line, algorithm |
| Web dashboard: risk score | Yes | — | 0–100, derived from finding count and severity weights |
| Plain-English risk descriptions | Yes | — | "RSA-2048 in JWT signing — vulnerable to Shor's algorithm by ~2032" |
| Compliance PDF report export | Yes (paid) | — | Gated at Developer tier (€99/mo) |
| GitHub Action for CI/CD | Yes | — | `quantsiv/scan-action@v1`, week 6 |
| SARIF upload to GitHub Code Scanning | Yes | — | Ships with GitHub Action |
| Free tier (1 repo, push-triggered scans) | Yes | — | No credit card required |
| Developer tier (€99/mo, unlimited repos, 3 seats) | Yes | — | Stripe Checkout |
| Team tier (€299/mo, 15 seats, API access) | Yes | — | Stripe Checkout |
| Enterprise tier (€1k–5k/mo) | Partial | Full | Manual quote + Stripe invoice; metered billing deferred |
| Annual pricing (20% discount) | Yes | — | Default UI toggle |
| Stripe Customer Portal (invoice, cancel, upgrade) | Yes | — | Single SDK call |
| EU VAT / OSS scheme compliance | Yes | — | Stripe Tax enabled day 1 |
| 7-day behavioral email sequence | Yes | — | Behavioral branching on scan completion |
| Intercom support widget | Yes | — | Dashboard only |
| Demo scan on empty dashboard | Yes | — | Public repo example shown before user's scan completes |
| CLI scanner (`quantsiv scan .`) | Partial | Full | Wrapper that POSTs to API; full local mode deferred |
| Snyk Broker equivalent (scan locally, report centrally) | No | v1.1 | Critical for enterprise but complex |
| Cloud infra scanning (AWS/Azure/GCP) | No | v2 | Different auth model entirely |
| Container image scanning | No | v2 | Docker-in-Docker complexity |
| SAML/SSO | No | v2 | GitHub OAuth only in v1 |
| Slack community | No | Week 8 | Post-launch, not pre-launch |
| PQL scoring and CRM | No | Month 3 | Manual Slack alerts to founder in v1 |
| Semgrep-style cross-file dataflow analysis | No | v2 | cbomkit handles this partially |
| JavaScript/TypeScript scanning | No | v1.1 | cbomkit coverage; add after Python/Java/Go validated |

---

## 3. Technical Architecture

### Recommended Tech Stack

**Python 3.12 + FastAPI + ARQ + Redis + SQLite (MVP) → Postgres (production)**

The entire scanning toolchain — sslyze, cyclonedx-python-lib, PyGithub, gitpython — is Python. Choosing a different language for the API layer would mean reimplementing TLS scanning and CBOM serialization from scratch. FastAPI is async-native, which is mandatory when you have concurrent long-running scan jobs. ARQ (async Redis queue, same author as Pydantic) has no Celery impedance mismatch and is the right choice for a solo founder who cannot afford operational complexity.

cbomkit-lib is a Java JAR. Accept this. Run it as a subprocess. The Docker base image includes JRE 17 alongside Python 3.12. This is the correct approach — do not rewrite cbomkit-lib.

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

**Scan Worker**: The only process with file system access. Downloads repos to `/tmp/{scan_id}/`, runs cbomkit-lib, parses output, runs sslyze if domains are detected in config files, assembles CBOM, cleans up temp files in a `finally` block.

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
    raw_match        TEXT            -- the matched code snippet (never logged externally)
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
- Persistent volume mounted at `/data/quantsiv.db` (SQLite file)

Dockerfile base: `python:3.12-slim` with `openjdk-17-jre-headless` added via `apt-get`. The cbomkit-lib JAR ships inside the image at `/app/bin/cbomkit-lib.jar`. Total image size target: under 800MB.

Environment variables stored in Railway's secret manager: `GITHUB_APP_PRIVATE_KEY` (PEM), `GITHUB_APP_ID`, `GITHUB_WEBHOOK_SECRET`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `DATABASE_URL`, `REDIS_URL`.

**Migration trigger: move to Render when any of these happen:**
- Monthly Railway bill exceeds $80 (scale-up signal)
- First enterprise prospect asks for SOC 2 compliance documentation (Render has ISO 27001)
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

4. Clone repository to /tmp/{scan_id}/:
   git clone https://x-access-token:{token}@github.com/{repo}.git /tmp/{scan_id}/
   Timeout: 60 seconds. Repos over 500MB: clone with --depth 1

5. Run cbomkit-lib source code scan:
   java -jar /app/bin/cbomkit-lib.jar scan \
     --input /tmp/{scan_id}/ \
     --output /tmp/{scan_id}/cbom.json \
     --format cyclonedx-json
   Timeout: 120 seconds. Parse exit code; on non-zero, mark scan failed with error_message.

6. Parse CycloneDX CBOM JSON output:
   - For each component where type = 'cryptographic-asset':
     - Extract: algorithm name, key size, primitive type, file location, line number
     - Classify as quantum-safe or not:
       Quantum-safe: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), AES-256, ChaCha20
       Quantum-vulnerable: RSA (any key size), ECDSA, ECDH, DH, DSA, AES-128 (borderline)
     - Assign severity:
       critical: RSA/ECDSA in auth/signing/token paths
       high: RSA/ECDSA/DH in key exchange or encryption paths
       medium: weak TLS cipher suite, deprecated curve
       low: hash-only usage, informational
     - Add context_label from file path heuristics:
       */auth/* or */jwt/* → 'Authentication signing'
       */tls/* or */ssl/* → 'Transport encryption'
       */payment/* or */crypto/* → 'Data encryption'

7. Detect domains from config files:
   Scan for hostnames in .env, config.yaml, application.properties, .env.example
   Queue TLS scan for each detected domain

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

Below the CTA: a live counter ("3,842 repos scanned, 41,203 vulnerabilities found") and a static screenshot of the findings dashboard showing RSA-2048 findings with file paths. No feature list, no pricing table, no testimonials on the first scroll.

Headline: **"Find quantum-vulnerable cryptography before your adversaries do."**
Sub-headline: "NIST finalized PQC standards in August 2024. Harvest-now-decrypt-later attacks are active today. Quantsiv scans your codebase in 90 seconds."

### Step 2 — GitHub OAuth (0:30)

Click "Start free scan" → GitHub OAuth. Requests only: read user profile + email addresses. No repository access at this step — requesting repo access on the OAuth screen triggers fear. Repository access comes at the GitHub App installation step, which follows immediately.

On OAuth callback: create user record, set `plan='free'`, issue session JWT. Redirect to `/onboarding/connect`.

### Step 3 — Connect a Repository (1:00)

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
| CRITICAL | RSA | auth/jwt.py:47 | 2048-bit | Token signing | View fix |
| CRITICAL | RSA | payment/encrypt.py:23 | 2048-bit | Data encryption | View fix |
| HIGH | ECDSA | api/auth.py:91 | P-256 | Request signing | View fix |

Clicking a row expands to show: exact code snippet (3 lines of context), plain-English risk explanation, migration guide link.

**Right sidebar:**
```
NIST PQC Compliance
[====          ] 12% migrated

0 of 19 findings use PQC algorithms

[Generate Compliance Report]
(Requires Developer plan — €99/mo)
```

### Step 6 — Upgrade Prompt (First Natural Trigger)

The upgrade prompt fires at the first natural limit hit, not immediately on results. Appears when:

- User clicks "Export Compliance Report" → modal with findings count personalization
- User clicks "Scan another repo" → modal referencing their current repo count
- User clicks "Add to CI/CD" → modal

**Generic upgrade prompts convert at 2–3%. Findings-personalized prompts convert at 8–12%.**

---

## 5. Onboarding Flow Detail

### Engineering the Aha Moment

The aha moment is: **a developer sees their own file path and their own function name labeled as quantum-vulnerable, with a timeline for when it becomes a real threat.**

Not: "you have crypto issues."
Yes: "auth/jwt.py:47 uses RSA-2048 for token signing — exploitable by Shor's algorithm on a fault-tolerant quantum computer, estimated 2030–2035. Harvest-now-decrypt-later attacks can target this today."

Three design decisions that engineer this moment:

1. **The first finding shown is always the most critical, most contextual one.** If there is an RSA key in a file path containing `auth`, `jwt`, `login`, or `payment` — that is shown first. Ranking algorithm: `file_path ILIKE ANY ('%auth%', '%jwt%', '%login%', '%payment%', '%crypto%', '%sign%')`.

2. **The real-time counter during scanning** sets anticipation. By the time the results page loads, the user already expects to see a real report.

3. **The demo scan on the empty dashboard** prevents the zero-state problem. Show a completed scan of `pallets/flask` with a banner: "This is a demo scan of a public repo — your scan of `your-repo` is running." Proves the tool works before their results arrive.

### First 7-Day Email Sequence

All emails sent from `ludo@quantsiv.io` (founder's personal address), plain-text, no HTML. Deliverability is higher, developer response rate is higher.

**Day 0 — "Your scan is running" (send immediately on signup)**
```
Subject: Your quantum risk scan is running

Hi {first_name},

Your scan of {repo_name} is running now. It takes about 90 seconds.

View your results here: https://quantsiv.io/dashboard/scans/{scan_id}

Quantsiv scans for RSA, ECDSA, and Diffie-Hellman — the algorithms
that a quantum computer running Shor's algorithm will break.

NIST finalized post-quantum standards in August 2024. The clock is running.

— Ludo
```

**Day 1 — Activation nudge (only if `first_scan_completed = FALSE` at 24h)**
```
Subject: It takes 90 seconds — here's what others found

Hi {first_name},

You signed up for Quantsiv yesterday but haven't connected a repo yet.

Click here, authorize GitHub, and Quantsiv scans your most recently
pushed repo automatically.

https://quantsiv.io/onboarding/connect

What developers typically find:
- RSA-2048 keys in authentication flows
- ECDSA signing in payment APIs
- DHE key exchange in TLS configs

All of these are broken by Shor's algorithm. All in production today.

Takes 90 seconds. No config required.

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

These algorithms are broken by Shor's algorithm. Timeline: 2030–2035.

"Harvest now, decrypt later" means adversaries are collecting your
encrypted traffic today.

View your full report: https://quantsiv.io/dashboard/scans/{scan_id}

— Ludo
```

**Day 3 — Education + urgency (send to all users)**
```
Subject: EO-14412 mandated US government PQC migration in June 2026

Hi {first_name},

Three things happened recently that affect your codebase:

1. NIST finalized ML-KEM, ML-DSA, and SLH-DSA as the official post-quantum
   cryptography standards in August 2024.

2. Executive Order 14412 (June 2026) mandated that US government agencies
   and their contractors migrate to PQC algorithms.

3. Only ~5% of enterprises have assessed their quantum cryptography risk.

If your product handles financial data, health records, or government
contracts — your security team will need a quantum risk assessment before
your next audit cycle. Quantsiv generates that report automatically.

https://quantsiv.io/dashboard

— Ludo
```

**Day 5 — Compliance report + team expansion (activated users only)**
```
Subject: Your compliance report is ready to share with your security team

Hi {first_name},

The Quantsiv findings for {repo_name} are formatted as a
NIST PQC Migration Readiness Report.

The report includes:
- Algorithm inventory
- Quantum vulnerability assessment per finding
- NIST SP 800-208 migration checklist
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

I'm offering 15-minute setup calls for the first 50 users. I'll share
my screen, walk you through connecting your repo, and show you what
Quantsiv finds. No sales pitch.

Book here: https://cal.com/ludo-quantsiv/15min

— Ludo
```

For activated users not yet converted:
```
Subject: Scanning {total_repos_scanned} repo — your next 4 are free with Developer

Hi {first_name},

You've scanned {repo_name} with Quantsiv. Found {total_findings} findings.

The Developer plan (€99/month) unlocks:
- Unlimited repositories
- Compliance PDF export
- CI/CD GitHub Action
- Scheduled weekly scans

https://quantsiv.io/upgrade

— Ludo
```

---

## 6. Payment Model

### Exact Tier Structure

| | Free | Developer | Team | Enterprise |
|---|---|---|---|---|
| **Price (monthly)** | €0 | €99/mo | €299/mo | €1,000–5,000/mo |
| **Price (annual)** | €0 | €79/mo (€948/yr) | €239/mo (€2,868/yr) | Custom |
| **Repositories** | 1 | Unlimited | Unlimited | Unlimited |
| **Seats** | 1 | 3 | 15 | Custom |
| **Scan trigger** | Push only | Push + scheduled | Push + scheduled | Push + scheduled + API |
| **Compliance PDF export** | No | Yes | Yes | Yes + custom branding |
| **CI/CD GitHub Action** | No | Yes | Yes | Yes |
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

**Checkout Session Endpoint:**
```python
@router.post("/api/billing/checkout")
async def create_checkout_session(
    price_id: str,
    user: User = Depends(current_user)
):
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

Verify every webhook with HMAC-SHA256. Reject any webhook that fails verification.

**Customer Portal:**
```python
session = stripe.billing_portal.Session.create(
    customer=user.stripe_customer_id,
    return_url="https://quantsiv.io/dashboard"
)
return redirect(session.url)
```

**Annual vs Monthly UI**: Default pricing page toggle to "Annual." Show savings in euros, not percentage: "Save €240/year" not "Save 20%."

**Enterprise tier**: No Stripe Checkout. Manual Stripe invoices or wire transfer. Implement metered billing only when you have three enterprise customers with different repo counts.

### EU VAT Handling

**Day 1 setup — do not defer:**

1. Enable Stripe Tax: Settings → Tax → Add Netherlands origin address.
2. Enable `tax_id_collection: {"enabled": True}` in Checkout (already in code above). EU B2B customers enter their VAT number — Stripe validates via VIES and zero-rates automatically.
3. Register for EU OSS (One Stop Shop) at belastingdienst.nl within 30 days of first EU B2C sale. Quarterly returns: Jan/Apr/Jul/Oct.
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

Generate signed share token for any scan result: `https://quantsiv.io/dashboard/scans/{id}/share/{token}`. HMAC-signed with 7-day expiry. Lets developers share results with a CISO or auditor without giving them a Quantsiv account. High-value for enterprise sales motion.

### Support Model at MVP Stage

**Phase 1 (0–50 customers, weeks 1–12):**
- Intercom chat widget on dashboard and landing page (Starter: $39/month)
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

**Ships**: Full scan pipeline produces CBOM JSON + risk score across Python, Java, Go.

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
- "Show HN" post: lead with the data ("found RSA in 60% of repos tested"), not the product
- Publish gated PDF: "NIST PQC Migration Checklist for Fintech Startups" — generates leads organically for 6–12 months
- Begin enterprise outreach to 5 companies: >500 employees + GitHub org with Java/Python + fintech/healthtech/defense contracting

**€1,000 MRR decomposition**: 10 Developer (€990) + 1 Team (€299) = €1,289. Or 3 Team (€897) + 1 small enterprise manual invoice (€200) = €1,097. Either path achievable with 50–100 free signups and 4–6% conversion.

**The real validation milestone**: a customer renews automatically. Their second monthly payment processes without any action from the founder. That is the proof the business model works.
