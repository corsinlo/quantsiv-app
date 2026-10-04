# Remediation plan - quantsiv-app

This is the living work plan derived from [`2026-10-03-app-audit.md`](2026-10-03-app-audit.md).
Finding IDs (`A01`...) refer to that file, which is the immutable record; this file is the one
that changes.

## How to work through this plan
- Work packages run **in order**. Each one is a separate branch (`fix/wpN-short-name`) and a
  separate PR titled `WPN: ...`. Reference the finding IDs in commit messages.
- A WP is **done** only when every acceptance check passes in CI. Update the status table in the
  same PR.
- **Agent rule (D7).** No WP may add auto-merge, auto-deploy, a write-capable MCP tool, or any
  code path that sends source code to a hosted model.
- **BLOCKED** items need a founder decision (D1-D9 below). Do not invent legal entity details,
  prices, dates, statistics or regulatory claims. Leave a clearly marked TODO and move on.
- Never add UI or README copy that claims a capability the code doesn't have. The README's
  status table is the single source of truth for what is built.

## Status

| WP | Title | Status | PR | Notes |
| --- | --- | --- | --- | --- |
| WP0 | Repository hygiene | done | #2 | The empty directories did not exist in the clone |
| WP1 | Build, boot, smoke tests, CI | done | #2 | CI green (test, docker web, docker worker). Docker can't build in the cloud VM (Debian mirrors blocked); rely on CI |
| WP2 | Honest, accessible UI | done | #3 | axe-core check: `pytest -m a11y` (own CI job). Export link waits for an export route |
| WP3 | Security foundation | done | #4 | Share links wait for WP4 (`share_links` table) |
| WP4 | Data layer and worker | done | #5 | Scans run end to end but fail with "not available yet" until WP5 (access, clone) and D2 (engine): no invented findings |
| WP5 | Scan pipeline safety | done | #6 | Engine part blocked by D2. Also: manual scans from the dashboard, public repos only (D1) |
| WP6 | CBOM and HNDL scoring | done | #7 | Severity thresholds are our own documented rule (services/scoring.py). Also: per-scan CBOM download. Runs on real findings once the D2 engine exists |
| WP7 | Local runner and CBOM ingest | in progress | #9 (ingest) | Ingest, tokens, delta gate and export merged; scanner half unblocked by D2 |
| WP8 | Legal and privacy surfaces | blocked | | Content needs D4/D5; routes can be built |
| WP9 | Performance | done | #8 | About 96 KB of static assets per page; `tests/test_performance.py` enforces the 100 KB budget |
| WP10 | Agent foundations: policy MCP server and gate explainer | blocked | | Needs WP7 landed (D7 confirmed 2026-10-04). No LLM in this WP |

## Founder decisions

Confirmed decisions say so in their row; the rest are still open.

**Market scope (founder, 2026-10-04): Quantsiv will operate in both the US and the EU markets.**
Consequences recorded here, none of them yet built: the control plane stays EU-hosted (D3), with a
US-region option to be decided if a US customer requires data residency; the legal pages (WP8)
must cover both GDPR and the applicable US state privacy laws, which is a question for counsel
when D4 is answered; the narrative already cites US (EO 14412, OMB M-26-15, NIST) and EU (NIS
Cooperation Group) authorities, and must keep both.

| ID | Decision | Recommended default | Blocks |
| --- | --- | --- | --- |
| D1 | Delivery model | **Confirmed 2026-10-04.** Local-first scanner (CLI plus container) runs in the customer's CI, so code never leaves. Only the CBOM goes to an EU-hosted, metadata-only control plane (self-hosted later). Server-side cloning stays only for public repos and demos. See `quantsiv.md`, "Delivery model". Local-first is the default, not a permanent limit: hosted scanning of private repos may be offered later as an opt-in, once a network-less sandbox (A16) and the compliance work (security certification, DPA, EU processing) are funded. | WP7 (unblocked); shapes WP5 |
| D2 | Scan engine | **Confirmed 2026-10-04, as recommended, with the faster route:** no Java wrapping at all. (1) Quantsiv's own rules engine (`quantsiv_scanner`, pure Python, pattern-based) is the first engine; it covers the gaps named here (PyCryptodome, Go, JS/TS) and more, runs in the CLI and, through the sandbox, in the hosted worker. (2) CBOMkit comes in as *data*: the CI template runs CBOMkit-action (Apache-2.0, Java/Python/Go) before `quantsiv scan`, which merges its `cbom/cbom.json`, and the upload path already accepts any CycloneDX 1.6 CBOM. The original text: Ingest CBOMs from CBOMkit's published CI tooling run after the customer's build, plus your own rules for gaps (PyCryptodome, Go, JS/TS). Wrap `cbomkit-lib` (Java library, Java and Python only) in a pinned fat jar only if hosted scanning stays. | WP5 engine step (done), WP7 scanner half |
| D3 | Hosting and region | Railway (or Render), EU region, Postgres (not a shared SQLite file, A51) | WP4 deploy |
| D4 | Legal identity | Entity name, registered address, KvK and VAT numbers, privacy contact email **Needed from the founder:** legal entity name and form; country of incorporation (the plan assumed a Dutch entity: confirm, since the US is also a target market); registered address; company registration number (KvK or equivalent) and VAT number; privacy contact email and whether a DPO is appointed; the hosting provider and region (for the privacy policy's recipients list); which e-mail and payment providers will be used. | WP8 content, footer |
| D5 | Packaging and pricing | To be validated with design partners. The proposals live in `quantsiv.md`, "Pricing". **Needed from the founder:** the tier names and what each includes (repositories, seats, retention, support); the price per tier, its currency and billing period (monthly/annual); the free tier's limits and any trial; whether prices are shown ex- or including VAT, and for which countries; the refund and cancellation terms; the renewal terms. | WP8 pricing display; billing |
| D6 | Competitive positioning | Complementary to posture platforms (QIZ Security, Wiz for PQC Readiness): export and ingest CycloneDX, build no runtime or cloud inventory before Phase 3, and never use the label "cryptographic posture management". See `quantsiv.md`, "Posture platforms". | Nothing blocked; shapes the WP7 interoperability scope and the copy |
| D7 | Agent principles | **Confirmed 2026-10-04.** Agents propose, the pipeline verifies, a human approves. Deterministic tools decide every verdict; never auto-merge or auto-deploy. Agents are off by default per organisation, with a kill switch. The read-only policy MCP server ships free with the scanner; agents that use control-plane data go to design partners first. See `quantsiv.md`, "Agent layer". | WP10 (still needs WP7) |
| D8 | Model hosting for LLM features | No LLM in Phase 1.0. Agents that touch code run in the customer's pipeline, on a model endpoint the customer chooses (bring your own model). Control-plane drafting (metadata only) uses an EU-region endpoint whose terms exclude training on customer data; choose the provider after reading its current terms. | Phase 1.1 lifetime assistant and evidence drafter; Phase 2 migration proposer |
| D9 | Migration-corpus data rights | An opt-in clause in the design-partner agreement keeps code-free outcome records: rule ID, from/to primitive, library versions, fix class, verifier results, human verdict and reason. Diffs only with a separate written opt-in; deletion on request. Needs legal review. | Corpus collection; the first design-partner NDA |

## Target layout (reached gradually; don't refactor ahead of the WPs)

```text
app/
  __init__.py
  main.py          # app setup: middleware, static, routers
  config.py        # pydantic-settings Settings (A10)
  templating.py    # the single Jinja2Templates instance (A46)
  security.py      # headers middleware, CSRF (A20, A14)
  db.py            # SQLAlchemy engine and session (A03, A51)
  models.py        # declarative models for the six spec tables
  routers/
    web.py         # dashboard pages
    api.py         # JSON API; later POST /api/v1/cbom (WP7)
    webhooks.py    # GitHub (Stripe later)
    legal.py       # /legal/* (A33)
  services/
    github.py      # app JWT; installation tokens, down-scoped and revoked (A52)
    clone.py       # secure clone (A15, A16)
    ssrf.py        # resolve_scan_target (A17)
    cbom.py        # build_cbom (A26)
    scoring.py     # HNDL scoring and migration guidance (A28, A30, A53)
  worker.py        # ARQ jobs + WorkerSettings (A50)
  static/  templates/
tests/
```

---

## WP0 - Repository hygiene (A49, A21, part of A03)
- [x] Delete `app/test.txt`, `app/test2.txt`, `app/test3.txt`, `app/test5.txt`, `app/test7.txt`,
      `app/simple.txt` and `app/models2.py`.
- [x] Delete the empty directories `app/api/`, `app/models/` and `app/worker/` if they exist.
- [x] Add an empty `app/__init__.py`.
- [x] Re-save `app/models.py` as UTF-8 without a BOM. WP4 rewrites it; for now it holds
      placeholder model classes so imports work.
- [x] Add `.editorconfig`: `root = true`, then under `[*]` set `charset = utf-8`,
      `end_of_line = lf` and `insert_final_newline = true`.
- [x] Add `.gitattributes` containing `* text=auto eol=lf` (plus `*.png binary`).
      Then run `git add --renormalize .`. The stored blobs are already LF (Windows checkouts
      convert them through `core.autocrlf`), so expect no content changes. The file only pins
      LF for every contributor.
- [x] `.gitignore`:
  - replace `*key*` with `*.key`, `*.pem` and `github-app-*.pem`;
  - stop ignoring `.env.example`;
  - remove the duplicate `.env`;
  - change `cython_debug.sqlite` to `cython_debug/`.
- [x] Add `.env.example`, listing every Settings field with an empty value.
- [x] Add `.dockerignore`: `.git`, `.env*`, `tests/`, `docs/`, `*.md`.

**Acceptance:**
- `git ls-files app | grep -E 'test[0-9]*\.txt|simple\.txt|models2'` prints nothing.
- `python -c "import ast;ast.parse(open('app/models.py','rb').read())"` succeeds.

## WP1 - Build, boot, smoke tests, CI (P0: A01-A09, A50)
- [x] `app/api.py:37`: close the docstring (A01).
- [x] `app/worker.py:133-137`: re-indent to 8 spaces (A02).
- [x] Split dependencies into `requirements.txt` (web), `requirements-worker.txt` and
      `requirements-dev.txt`, using the pins in audit section 7 (A07, A18, A24).
      Lock them with `pip-compile --generate-hashes`. (Done with `uv pip compile --universal
      --generate-hashes` for Python 3.12; the `.in` sources sit next to each lock.)
- [x] Convert every `TemplateResponse` call to `TemplateResponse(request, name, ctx)` (A08).
- [x] Mount the router in `main.py`; keep `/` and `/health` in one place; disable docs when
      `env == "production"` (A04).
- [x] Add `app/config.py`, the Settings class from audit section 7 (A10). Read the secrets that
      `api.py:21-24` hard-codes from Settings instead.
- [x] Fix `scan_details.html`: `:64` becomes `</h2>`; delete the `{% endif %}` on `:97` (A05).
- [x] Fix `base.html`: remove the backtick-n on `:4`; add `id="main-content"` to `<main>` (A06).
      Hide or disable buttons whose routes don't exist.
- [x] Add a minimal `WorkerSettings` (no-op jobs are fine for now) so
      `python -m arq app.worker.WorkerSettings` starts (A50).
- [x] Rewrite the Dockerfile as the two-stage file from audit section 7 (A09). Pin the base to
      `-bookworm`; Java goes in the worker stage only. Add `railway.toml` with
      `healthcheckPath = "/health"`.
- [x] Add these tests (code in audit section 7): `tests/conftest.py`, `tests/test_imports.py`,
      `tests/test_templates.py`, and `tests/test_routes.py` (`/health` returns 200; every page
      renders).
- [x] Add `.github/workflows/ci.yml` (audit section 7): ruff, pytest with coverage, pip-audit,
      and docker build for both targets.

**Acceptance:**
- CI is green.
- `pip install -r requirements.txt -r requirements-dev.txt` resolves.
- `pytest` passes.
- `pip-audit -r requirements.txt` reports no known vulnerabilities.
- `docker build --target web .` and `--target worker .` both succeed.
- `uvicorn app.main:app` serves `/health`.

## WP2 - Honest, accessible UI (A28-A32, A41-A45, clean-scan text)
- [x] Delete the `Math.random()` counter at `scan_details.html:294-309` (A29).
- [x] `scan_details.html:167`: show `—` when `confidence is none` (A29).
- [x] `dashboard.html`: replace the hard-coded row with data from the route and an empty state.
      If a demo is shown, label it "Demo scan of a public repository" (A29).
      (Routes read from `app/scans.py`'s `ScanStore`, empty until WP4 plugs in the database. No
      demo is shown.)
- [x] Remove "Compliance Rate" (A29).
- [x] API stubs return 404 or 501 instead of fake scans. `POST /api/scans` returns 501 until
      WP4 (A29).
- [x] Rewrite `dashboard.html:99-102` so it claims only what exists (A31).
- [x] README: replace "Features Implemented" with a built/planned status table, and remove
      "by ~2032" (A31).
- [x] Add a `ScanStatus` StrEnum (`queued`/`running`/`done`/`failed`), used by the worker, API
      and templates (A32).
- [x] Risk text: show the HNDL paragraph only for `key-agree`/`kem`/`pke` findings, and drop the
      unsourced timeline (A30).
- [x] Contrast swaps: `orange-500` → `orange-700`, `yellow-400` → `yellow-700`,
      `green-500` → `green-700`, `indigo-500` → `indigo-600` (A41).
- [x] Underline in-text links in every template, including the legal templates WP8 creates
      (A41). Do not edit or commit the untracked local draft `privacy_policy.html`.
- [x] `scan_live.html` (A42):
  - [x] `role="progressbar"` with `aria-*`, and `aria-live` on the counters;
  - [x] read the scan ID from a `data-scan-id` attribute;
  - [x] replace the custom confirm with `hx-confirm`; (the custom confirm is gone; Cancel stays
        disabled until the cancel route exists, and WP4 adds `hx-post` with `hx-confirm` then)
  - [x] delete the `alert()`;
  - [x] make Back a link;
  - [x] pass `repo_name`.
- [x] `scan_details.html` (A43):
  - [x] accessible disclosure rows (`aria-expanded`/`aria-controls`, toggling `hidden`), with
        unique IDs;
  - [ ] Export becomes a link; (still a disabled "coming soon" button: there is no export
        route yet)
  - [x] `scope="col"` on headers, plus a caption;
  - [x] honest clean-scan text.
- [x] `dashboard.html` (A44): `aria-hidden` on decorative SVGs (the decorative SVGs were removed), `sr-only` repo names on "View"
      links, and delete the `setInterval`.
- [x] `base.html` (A45, P3): skip link, logo link with `alt="Quantsiv home"`, and reduced-motion
      handling for spinners.

**Acceptance:**
- `grep -rn "Math.random\|7 critical\|or 0.8" app/templates` prints nothing.
- Template tests pass for every status.
- An axe-core run (Playwright, or `pa11y-ci`) on the rendered pages reports no WCAG 2.1 A/AA
  violations.

## WP3 - Security foundation (A10-A14, A19, A20, A24, A25)
- [x] Webhook handler as in audit section 7 (A11-A13):
  - [x] compare signatures as bytes;
  - [x] enforce the 25 MB limit;
  - [x] return 400 for non-JSON bodies;
  - [x] enqueue with `_job_id=f"gh-{delivery}"`;
  - [x] read the account from `installation.account`;
  - [x] apply the default-branch filter and skip deletions.
- [x] Authentication (A14):
  - [x] GitHub OAuth login;
  - [x] sessions (pick one design deliberately: opaque ID plus a `sessions` table, or
        `SessionMiddleware`); (chosen: `SessionMiddleware`, because there is no database
        before WP4. Revocation is by the 8-hour expiry or by rotating `SESSION_SECRET`; see
        `app/auth.py`)
  - [x] a `current_user` dependency;
  - [x] every scan query scoped through installations (404 when the scan isn't the user's);
        (the `ScanStore` interface takes the user id; WP4's database store must join through
        installations as in audit section 7)
  - [x] CSRF on POSTs (htmx `hx-headers`);
  - [x] `POST /api/scans` validates the repo against the installation's repository list.
        (through the `RepoAccess` interface; its real implementation needs installation
        tokens, so it answers 501 until WP5)
- [x] Self-host assets (A19):
  - [x] Tailwind standalone CLI build to `app/static/app.css`; (the `tailwindcss` npm CLI,
        pinned in `package.json`; CI fails if the committed output drifts)
  - [x] vendor htmx into `app/static/js/` with `defer`;
  - [x] delete Alpine;
  - [x] add `app/static/vendor/LICENSES.md` (MIT notices).
- [x] Move every inline script and `onclick` into `app/static/js/*.js`, and remove inline
      `style` attributes (A20).
- [x] Add the security headers middleware (audit section 7, plus `object-src 'none'`) and the
      htmx-config meta (A20).
- [x] Replace `print()` with `logging`; no personal data at INFO (A25).
- [ ] Share links (A23): hashed tokens from the WP4 `share_links` table, `/share/` paths masked
      in access logs, and `Referrer-Policy: no-referrer` on share pages. Build this when the
      share feature is built; it depends on WP4.

**Acceptance:**
- `tests/test_webhook.py` (7 cases from audit section 7) passes.
- `tests/test_auth.py` passes: anonymous → 401 or redirect; another tenant's scan → 404.
- `tests/test_headers.py` passes: CSP, HSTS, `nosniff`, `Referrer-Policy`.
- `grep -rn "cdn.tailwindcss\|unpkg.com\|onclick=" app/` prints nothing.

## WP4 - Data layer and worker (A03, A46, A50, A51)
- [x] SQLAlchemy 2.0 models for users, installations, scans, findings, cbom_snapshots and
      tls_scans (spec §3). Also add:
  - `share_links` (A23): a random 32-byte token stored hashed, plus `expires_at` and
    `revoked_at`;
  - `sessions`, if WP3 chose opaque sessions (A14). (Not needed: WP3 chose `SessionMiddleware`.)
  - [x] `findings.raw_match` is opt-in per tenant; store a snippet hash by default.
        (`installations.store_code_snippets`, default false, plus `findings.snippet_hash`; the
        scanner that writes findings arrives with D2/WP6)
- [x] Alembic migrations. Postgres in deployment; SQLite only for local tests (A51).
- [x] ARQ jobs `scan_repository`, `handle_github_event` and `delete_account` (stub), plus
      `WorkerSettings` (audit section 7) (A50).
- [x] The API enqueues jobs through an `ArqRedis` pool created at startup. Remove the
      import-time `ScanWorker()` (A50). (Created on first use and closed at shutdown, in
      `app/queue.py` since WP3, so the web app starts without Redis.)
- [x] Replace blocking I/O in async code with `asyncio.to_thread` or
      `asyncio.create_subprocess_exec`, with timeouts (A46).
- [x] Error handling: store only `ScanError` messages in `scans.error_message`; everything else
      becomes "Internal error" and goes to the logs (A15).

**Acceptance:**
- `alembic upgrade head` runs against a Postgres service in CI.
- Worker jobs pass unit tests (call the job functions directly with a fake `ctx`).
- No `print(` remains in `app/`.

## WP5 - Scan pipeline safety (A15-A17, A27, A52)
- [x] `services/clone.py`: the secure clone from audit section 7 (token passed via `GIT_CONFIG_*`
      env, the listed flags, a fixed user-facing error), plus a repo-size pre-check and deleting
      `.git` before scanning (A15, A16).
- [x] `services/github.py`: down-scoped installation tokens, revoked in `finally` (A52).
- [x] `services/ssrf.py`: `resolve_scan_target` with the internal-suffix block-list. TLS scans
      only for DNS-TXT-verified domains; at most one handshake for unverified ones (A17).
      (The guard is built and tested. TLS scanning itself and domain verification are not
      built yet; the rule is recorded in `docs/hosted-scanning.md`.)
- [x] Sandbox: the scanner runs as a separate process with a timeout and memory limit. Document
      that hosted scanning of private repos stays off until it can run with no network (A16).
      (`services/sandbox.py`; `docs/hosted-scanning.md`. The pipeline refuses private repos.)
- [ ] **BLOCKED by D2:** integrate the chosen engine. Until then, the "scan" step is clearly
      labelled as a stub in the UI and logs. (Done for the label: scans fail with "The scan
      engine is not available yet.")

**Acceptance:**
- `tests/test_clone.py` passes: mock `create_subprocess_exec` and assert the token appears in no
  argv element, no URL and no error message.
- `tests/test_ssrf_guard.py` passes (the address list in audit section 7, plus
  `redis.railway.internal`).

## WP6 - CBOM and HNDL scoring (A26, A28, A30, A53)
- [x] `services/cbom.py`: `build_cbom` from audit section 7. Delete `_generate_cbom` and the fake
      vulnerabilities, CVSS scores and CVE (A26). (`_generate_cbom` went in WP4.)
- [x] `services/scoring.py`:
  - [x] map each finding to a CycloneDX primitive;
  - [x] `PQC_GUIDANCE` and `HNDL_EXPOSED` (A30);
  - [x] a severity model by primitive and data lifetime (A53).
- [x] Data-lifetime input: a `quantsiv.yml` (or settings UI) that maps repos or services to data
      classes and confidentiality lifetimes. The HNDL score uses it; without it, label the score
      "severity score", not "HNDL" (A28). (`services/lifetimes.py`; read from the scanned
      repository's root. No settings UI yet.)
- [x] Remove AES-128 from any "quantum-vulnerable" list (A30). (Symmetric primitives and hashes
      are never classed as quantum-vulnerable; tested.)
- [x] Make the score dual-track (D6):
  - **Confidentiality findings** (`key-agree`, `kem`, `pke`) are ranked by declared data
    lifetime and labelled "HNDL".
  - **Signature findings** are ranked by deadline (EO 14412's 31 Dec 2031 by default,
    configurable) and by the trust lifetime of what they sign, and labelled "signature deadline".
- [x] Write declared lifetimes into the CBOM as a namespaced property, e.g.
      `quantsiv:confidentiality-lifetime-years`.

**Acceptance:**
- `tests/test_cbom.py` passes CycloneDX 1.6 strict validation and contains a
  `cryptographic-asset` component.
- `tests/test_scoring.py` passes: a `key-agree` finding protecting 25-year data outranks a
  short-lived token signature.
- A code-signing finding is never labelled HNDL.
- The lifetime property survives a CBOM round-trip through strict 1.6 validation.

## WP7 - Local runner and CBOM ingest (D1)
D1 was confirmed on 2026-10-04 (local-first by default; see the decision table).
**The scanner half (CLI, CI templates, offline run, time-to-value) is BLOCKED by D2**, because
the CLI's core is the engine. The ingest/export half is built.
- [ ] Extract the engine glue into a `quantsiv_scanner` package with a CLI, `quantsiv scan`. It
      runs CBOMkit tooling and your own rules on a local checkout, then writes the CBOM
      (`build_cbom`), SARIF and an HNDL report, offline.
- [ ] CI templates (each one runs the same container):
  - [ ] GitHub Action: free; the token is optional and only used for upload;
  - [ ] GitLab CI component;
  - [ ] Jenkinsfile snippet (`docker.image(...).inside { sh 'quantsiv scan' }`);
  - [ ] Azure DevOps YAML.
- [x] `POST /api/v1/cbom`: org-token authenticated, CBOM JSON only (no source). It is
      validated against the 1.6 schema, stored per scan, and diffed against the previous scan.
      (`app/routers/v1.py`; tokens are created and revoked at `/dashboard/tokens`.)
- [x] Gate PRs on the CBOM **delta** (new vulnerable crypto), not the absolute count.
      (The upload response carries `gate: pass|fail` from the delta; posting it as a PR check
      is the CI templates' job.)
- [ ] **Offline by default** (D6): no network call and no token are needed to write the CBOM,
      SARIF and report. Upload happens only with an organisation token.
- [ ] **Measure time-to-value:** record in the scanner output the time from the CI step starting
      to the first CBOM, so it can be reported per design partner.
- [x] **Import any CBOM** (D6): `POST /api/v1/cbom` accepts any schema-valid CycloneDX 1.6
      CBOM, not only Quantsiv's, and stores the producing tool (`metadata.tools`) as provenance.
- [x] **Export endpoint:** returns the stored estate CBOM as plain CycloneDX 1.6 JSON.
      (`GET /api/v1/cbom`, token-authenticated.)

**Acceptance (WP7):**
- A CBOM produced by CBOMkit's GitHub Action ingests and diffs cleanly.
- The scanner runs to completion with networking disabled.
- The export validates against the CycloneDX 1.6 schema.

## WP8 - Legal and privacy surfaces (A33-A40)
- [ ] `routers/legal.py` (audit section 7) with templates under `templates/legal/`. Until D4 is
      answered, these pages return 404 in production (`settings.legal_ready = False`).
- [ ] Rewrite the privacy policy from the A34 table. Do **not** reuse the untracked draft's
      entity, address, DPO or security claims.
- [ ] Terms, including:
  - [ ] eligibility (18+ and authorised to bind the organisation; replaces an age gate);
  - [ ] B2B-only clause (part of the proposed D1; confirm it when D1 is confirmed);
  - [ ] acceptable use (scan only what you own or are authorised for);
  - [ ] the DSA single point of contact.
- [ ] Refund policy and cookie policy. Today: only strictly necessary cookies; list them.
- [ ] Footer: entity details and legal links (A40).
- [ ] Erasure runbook in `docs/runbooks/erasure.md`, plus the `installation.deleted` purge
      (A35, P1). Self-serve `POST /account/delete` is P2.
- [ ] Email (when email is built): footer and `List-Unsubscribe` headers (audit section 7);
      classify each email; fix the spec §5 content errors (A36).
- [ ] Pricing display (when billing is built): price, period, VAT treatment, auto-renewal and
      cancellation next to the button; the Stripe plan allow-list; webhooks via
      `construct_event` (A37, A22).
- [ ] Third-party disclosures and data minimisation (A38, A39).

## WP9 - Performance (A47)
- [x] Generate `logo-64.png`, `logo-128.png`, `favicon-32.png`, `favicon-16.png` and
      `apple-touch-icon.png` (180 px) from the source PNG. The logo kit, which is kept outside
      this repo, asks for a simplified favicon at 16 and 32 px to be drawn eventually.
      (`scripts/make_icons.py`; the source moved to `assets/logo-symbol.png`, out of the served
      directory. The simplified 16/32 px favicon is still to be drawn.)
- [x] Delete the unreferenced `logo-horizontal.png`.
- [x] Add `defer` to every script.

**Acceptance:** total static weight per page is under 100 KB, excluding fonts (there are none).

## WP10 - Agent foundations: policy MCP server and gate explainer (D7)
**BLOCKED until WP7 has landed.** D7 was confirmed on 2026-10-04. Nothing in this WP calls an LLM. Never add
UI or README copy claiming agents until this WP is merged.
- [ ] `quantsiv_scanner/policy.py`. It loads the `policy:` section of `quantsiv.yml`: allowed and
      blocked primitives per data class, declared lifetimes, and the signature deadline (default
      2031-12-31 per EO 14412 §4(b), configurable). It exposes `evaluate(cbom_delta) -> Verdict`.
      **The WP7 CI gate and the MCP server call this same function.**
- [ ] `quantsiv mcp` subcommand: an MCP server over stdio, in the same package and container.
  - It is offline by default and **read-only**.
  - Tools: `get_policy`, `check_change`, `get_cbom_summary`, `explain_finding`.
  - No tool writes files, runs git or a shell, or opens a network connection. The one exception:
    with an org token, `get_cbom_summary` may read the estate CBOM through `GET /api/v1/cbom`
    with a read-only scope.
  - Use the official MCP Python SDK, pinned. Verify the current version and schema first.
- [ ] Tool names, descriptions and schemas are static strings. A snapshot test fails if they
      change without a version bump. Tool outputs are plain data; never put repository text into
      tool descriptions.
- [ ] Gate explainer. It renders the check-run, the PR comment and the SARIF from a Jinja
      template, using the CBOM delta and the dual-track scores. Each new asset shows:
  - its track ("HNDL" or "signature deadline");
  - its declared lifetime;
  - the cited authority;
  - the approved alternatives.
- [ ] Exceptions. Each one needs a named approver and an expiry. It is recorded in the CBOM as a
      namespaced property and in the audit log.
- [ ] Audit log of every MCP tool call and every gate verdict, exportable to the evidence pack.
- [ ] Eval harness in `evals/agent/`: a few coding tasks on public demo repos, run with and
      without the MCP server across the assistants available. It records gate verdicts only.
      Its results feed the stealth-exit data report; never quote a benefit before it is
      measured.

**Acceptance:**
- The CI gate and `check_change` return identical verdicts on the same delta (a property test).
- The MCP server runs with networking disabled, and exposes no write-capable tool (a test).
- The tool-description snapshot test passes.
- A code-signing finding is explained on the signature-deadline track, never as HNDL.
