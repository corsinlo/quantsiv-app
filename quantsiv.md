# Quantsiv — Quantum Risk Management Platform

## The Name

**Quant** — quantum.  
**Siv** — sieve.

Quantsiv combines these concepts to represent our mission: using quantum-resistant approaches to sieve through and protect your digital infrastructure from emerging threats.

The **General Number Field Sieve** is the most powerful classical algorithm for factoring large integers, forming the cryptographic foundation of RSA encryption. Shor's algorithm on quantum computers can break this sieve exponentially faster than classical methods, rendering current public-key cryptography vulnerable.

Our name reflects this duality:
- We **sieve through** your codebase, certificates, and systems to identify quantum-vulnerable cryptography
- We prepare you for when the **sieve breaks** — when quantum computers render current encryption obsolete

When asked about our name, we explain:  
*"Quant — quantum. Siv — sieve. We find where your encryption is vulnerable to quantum attacks before cryptographically relevant quantum computers arrive."*

---

## The One-Liner

> *Quantsiv inventories the quantum-vulnerable cryptography in your code and TLS endpoints, ranks it by how long your data must stay secret, and turns it into regulator-ready CBOM evidence. The scanning runs in your pipeline, so your code never leaves.*

**Category:** DevSecOps / Cryptographic Agility / PQC Compliance  
**Business type:** B2B (proposed, decision D1). An open-core local scanner, plus an EU-hosted, metadata-only CBOM evidence control plane that can be self-hosted later. See "Delivery model".  
**Status (2026-10-03):** pre-launch and in stealth. The app is a skeleton; see `docs/audit/` in this repo.  
**Primary domain:** quantsiv.io (+ .com, .net, .xyz, .store, .info, .online as redirects)

---

## The Threat — Why This Market Exists

Almost everything secure on the internet today — bank logins, HTTPS connections, API authentication, encrypted emails, VPN tunnels, digital signatures — is protected by three algorithms: **RSA, ECDSA, and Diffie-Hellman**. They work because factoring very large numbers is computationally impossible for classical computers.

A sufficiently powerful quantum computer running **Shor's algorithm** would break RSA, ECC and Diffie-Hellman. No such machine exists today. Arrival estimates vary (NIST, Aug 2024: "some experts predict ... within a decade"), so quote a forecast only with its source.

Current quantum computers can't do this yet. But the active threat is happening now:

> **"Harvest now, decrypt later."** State actors and sophisticated adversaries are capturing and storing encrypted internet traffic today. They can't read it yet. When quantum computers mature, they decrypt everything they stored. Your 2026 financial records, medical data, or trade secrets could become readable once a cryptographically relevant quantum computer exists (NIST, Aug 2024: "some experts predict ... within a decade").

Data that must stay confidential for 10+ years is already at risk if it is captured today and a cryptographically relevant quantum computer arrives within that window.

Harvest-now-decrypt-later threatens **confidentiality**, which means key establishment and encryption. Signatures face a different risk, future forgery, which is why EO 14412 sets the signature deadline a year after the key-establishment one.

This is not a fringe reading of the threat. US Executive Order 14412 (22 June 2026) states it as federal policy, describing adversaries "collecting United States information now, and decrypting it later once large-scale quantum computers are operational." CISA points to the G7 Cyber Expert Group roadmap for suggested timelines to reduce HNDL risk.

The practical consequence: **the deadline that matters is not the arrival of the quantum computer, it is the length of time your data must stay secret.** That is why the migration cannot wait for the machine to appear.

---

## Regulatory Context

The regulatory picture is now dated and specific. Every claim below is traceable to a
primary source.

**Standards — the algorithms exist.**

- **NIST FIPS 203 / 204 / 205, approved 13 August 2024:**
  - ML-KEM (FIPS 203, from CRYSTALS-Kyber) — key establishment, replaces Diffie-Hellman and RSA key transport
  - ML-DSA (FIPS 204, from CRYSTALS-Dilithium) — digital signatures, replaces ECDSA and RSA signatures
  - SLH-DSA (FIPS 205, from SPHINCS+) — stateless hash-based signatures, the conservative fallback
- **NIST IR 8547 (Initial Public Draft, 12 November 2024; not yet final):** quantum-vulnerable
  signature and key-establishment schemes at **112 bits** of security strength (e.g. RSA-2048)
  become *deprecated after 2030*. **All** quantum-vulnerable ones, including ≥128-bit ones such
  as P-256 and RSA-3072, become *disallowed after 2035* (Tables 2 and 4). P-256 is **not**
  deprecated in 2030. The same draft states that symmetric primitives with at least 128 bits of
  security, such as AES-128, meet NIST's Category 1, so they are not "quantum-vulnerable".

**US federal mandates — the deadlines are binding.**

- **Executive Order 14412** ("Securing the Nation Against Advanced Cryptographic Attacks"),
  signed **22 June 2026**, published at 91 FR 38483. Names harvest-now-decrypt-later
  explicitly. Section 4(b) requires PQC key establishment on high-value assets and high-impact
  systems by **31 December 2030**, and PQC digital signatures on those systems by
  **31 December 2031**. Section 6(c) directs the FAR Council to propose a rule, within 180
  days, requiring covered contractors to comply with NIST FIPS, including the PQC FIPS, by
  31 December 2030. (Some secondary sources mis-number this order as EO 14409; cite the Federal
  Register. The "EO 14413 companion order" reference is unverified, so verify it before external
  use.)
- **OMB M-26-15** ("Execution of the Migration to Post-Quantum Cryptography"), **24 June 2026**.
  - Sets a five-phase federal migration: 2026-27 strategy, planning and discovery; 2027-28
    pilots; 2028-30 prioritized migration; 2031 signatures; 2035 full migration.
  - §6 calls for automated inventory (SCA, SAST/DAST, network scanners) whose data "should
    populate a central Cryptographic Bill of Materials (CBOM)". That is "should", not "must".
  - Agency migration plans are due within 120 days of the memo: **22 October 2026**.
- **EO 14412 sec. 5(d):** CISA (DHS), in coordination with NIST, has 270 days, roughly to
  **March 2027**, to publish guidance on the minimum elements for a CBOM.
- **EO 14306** (also in M-26-15): TLS 1.3 or a successor required by **2 January 2030**.
- **OMB M-23-02** (November 2022): the original federal cryptographic-inventory mandate.
- **NSA CNSA 2.0:** governs National Security Systems, which EO 14412 explicitly excludes from
  its scope. Its exclusive-use dates run **2030-2033 depending on the category** (software and
  firmware signing and networking equipment by 2030; browsers, servers, cloud services and
  operating systems by 2033), within NSM-10's 2035 goal. NSA blocks automated fetches, so
  verify against the current NSA advisory before quoting a single year.

**Guidance and allied posture.**

- **CISA Post-Quantum Cryptography Initiative:** "Preparing for the Post-Quantum Era: A Call to
  Action" (issued jointly in the G7 context), "Product Categories for Technologies That Use PQC
  Standards", "PQC for Operational Technology", and "Strategy for Migrating to Automated PQC
  Discovery and Inventory Tools" (September 2024).
- **G7 Cyber Expert Group:** roadmap with suggested timelines to reduce harvest-now-decrypt-later
  risk.
- **EU:** "A Coordinated Implementation Roadmap for the Transition to Post-Quantum
  Cryptography" (EU Member States with the NIS Cooperation Group, **23 June 2025**). It is a
  recommendation, not law. It recommends:
  - national PQC strategies by **end-2026**;
  - high-risk use cases transitioned **no later than end-2030**;
  - as many systems as practically feasible by **2035**.

  NIS2 and DORA obligations are converging on the same cryptographic-inventory expectations.
- **Netherlands:** the AIVD/TNO/CWI *PQC Migration Handbook* makes a cryptographic inventory its
  first step. Map Quantsiv's output to that step, and verify the current edition before citing
  it.
- **Other national guidance to track:** BSI (DE), ANSSI (FR), NCSC (UK) and ETSI.

**Industry signals.** These are company migration targets, not regulation or Q-Day forecasts:
- Google set 2029 as its own PQC migration target (25 Mar 2026).
- Cloudflare targets 2029 for full post-quantum security, including authentication
  (7 Apr 2026).

The industry is moving faster than the federal 2030/2031 dates, especially on signatures.

**The wedge for Quantsiv:** EO 14412 makes CBOM minimum elements a federal deliverable due around
March 2027, and M-26-15 says agencies' automated inventories should populate a central CBOM.
Quantsiv is **built to** emit CycloneDX 1.6 CBOMs. A reference generator passes CycloneDX 1.6
strict-schema validation, and it ships in remediation work package WP6. Until then, never say
"already emits". Once it ships, alignment with the minimum elements is a mapping exercise, not a
rebuild.

**Stats to verify before external use.** The following figures appear in earlier drafts and
are not yet sourced; confirm or drop them before they go in a deck: "only 5% of enterprises
have migrated", "$15 billion PQC migration market", and "cyber insurance providers ask about
PQC at renewal (Lloyd's 2026)". The mandate-versus-reality gap is the market either way, but
it should be argued with a citable number.

---

## The Problem Enterprises Have

Companies don't know where their quantum-vulnerable cryptography lives. It's hidden everywhere:

- TLS certificates on every subdomain
- Code libraries importing OpenSSL, BouncyCastle, Java Cryptography
- JWT tokens signed with ECDSA
- SSH keys on every server
- VPN configurations
- S3 bucket encryption settings
- API authentication tokens
- Hardcoded keys buried in config files
- Code signing certificates
- Docker image signing

A mid-size company might have 400 certificates across 80 subdomains, 12 backend services using RSA, and JWT tokens signed with ECDSA across their entire auth layer — and their security team has no inventory of any of it.

**The first obstacle in every migration guide is the same: you cannot migrate what you have not inventoried** (OMB M-26-15; the EU coordinated roadmap; the AIVD/TNO/CWI PQC Migration Handbook).

---

## What Quantsiv Does — Product Modules

> Status: every module below is **planned**. None of them is built yet; the README in this repo
> holds the built/planned table, which is the single source of truth.

### 1. Code Scanner
Finds uses of quantum-vulnerable algorithms in source code. The first engine is IBM's CBOMkit
library (`cbomkit-lib`, now under the Linux Foundation's PQCA), which supports **Java and
Python**: on Python, pyca/cryptography only; on Java, best results come from scanning after the
build. Quantsiv's own rules fill the gaps, starting with PyCryptodome. Go, JavaScript/TypeScript
and C/C++ come later, added as design partners need them. Examples:
- `RSA.generate(2048)` in Python
- `new RSAKeyPairGenerator()` in Java
- `crypto.createSign('SHA256withRSA')` in Node
- Config files specifying `algorithm: RSA`

### 2. Certificate Scanner
Inspects the TLS handshake and certificates of endpoints the customer declares and has verified
it owns. Internal endpoints are scanned from inside the customer network by the same scanner, and
there is no subdomain enumeration of third-party assets. Flags:
- RSA-2048 and ECDSA P-256 certificates (both quantum-vulnerable)
- Certificate expiry dates (combined migration planning)
- Public-facing vs. internal classification

### 3. Cloud Infrastructure Scanner (Phase 3)
**Ingest first, build second.** Before writing any cloud connectors, import the cloud
cryptographic inventory customers already have:
- Wiz's inventory export, for Wiz customers;
- Google Cloud KMS "PQC insights";
- CycloneDX CBOMs from other tools.

Wiz and QIZ already cover runtime cloud inventory, so build Quantsiv's own read-only connectors
only where no import exists. They run in the customer's own cloud account under their IAM role,
and Quantsiv never holds cloud credentials. Checks:
- S3 bucket encryption algorithms
- RDS database encryption keys
- Lambda function signing certificates
- Load balancer SSL policies

### 4. Risk Scorer (HNDL-first)
Prioritises findings by:
- **Primitive:** key establishment and encryption (`key-agree`, `kem`, `pke`) carry
  harvest-now-decrypt-later risk; signatures carry future-forgery risk.
- **Data lifetime:** the customer declares, in `quantsiv.yml`, how long each data class must
  stay confidential. Findings are ranked by that lifetime against the threat horizon
  (Mosca-style), not by algorithm name. Without a declaration the score is labelled "severity",
  never "HNDL".
- **Exposure:** a public-facing API versus an internal service.
- **Signature deadline (a second, separate track).** Signature findings (code signing, JWT, PKI)
  are ranked by obligation date and by how long what they sign must stay trusted.
  - EO 14412 requires PQC signatures on high-value and high-impact systems by 31 Dec 2031.
  - Google set 2029 as its own PQC migration target (25 Mar 2026).
  - Cloudflare targets 2029 for full post-quantum security "including, crucially, post-quantum
    authentication" (7 Apr 2026).
  - These are company targets, not Q-Day forecasts.

  Only the confidentiality track is labelled HNDL. Wiz, for comparison, ranks signatures
  "long-term".
- **Portability.** Declared lifetimes are written into the CBOM as a namespaced property (e.g.
  `quantsiv:confidentiality-lifetime-years`), so the ranking travels with the artifact into any
  platform that imports it.

Output: an ordered migration backlog, not a flat list. The default view is a short top-N list,
with the full CBOM behind it.

### 5. CI/CD Integration
The same scanner container runs in GitHub Actions, GitLab CI, Jenkins (as a container step) and
Azure DevOps. It writes a CBOM on every merge and diffs it against the last one. If a change
introduces new quantum-vulnerable cryptography protecting long-lived data, the build fails with a
clear explanation. Gating on the **delta**, not the backlog, stops the problem growing while
existing debt is worked through. It is the same pattern Snyk uses for dependency
vulnerabilities.

### 6. Evidence Packs (control plane)
Exportable evidence (PDF and the signed CBOM) that maps each finding to named obligations:
- the CISA/NIST CBOM minimum elements, once published;
- the OMB M-26-15 inventory;
- the EU roadmap milestones;
- DORA/NIS2;
- the AIVD handbook's inventory step.

Each obligation shows its source and its status. The pack also includes:
- an HNDL-ordered migration backlog with effort estimates;
- a board-ready summary;
- later, a pre-fill for cyber-insurance questionnaires, once a design partner asks for it.

---

## Competitive Landscape

### Open-source detection (free, increasingly capable)

| Tool | Who | What it does | Notes |
|---|---|---|---|
| CBOMkit (`cbomkit-lib`, sonar-cryptography, CBOMkit GitHub Action) | IBM, donated to the Linux Foundation's PQCA; Apache-2.0 | Generates CBOMs from Java and Python code; ships a GitHub Action and a SonarQube plugin | Quantsiv's first engine. Detection is commoditising: do not compete on it |
| CodeQL PQC/CBOM work | GitHub | Queries that locate cryptography for PQC migration | Free on GitHub; the same commoditisation pressure |
| pqcscan, pqc-scan, cryptoscan | Various | Endpoint or repo scanners, some emitting CBOM/SARIF | Unverified details; verify before citing externally |

These validate the technical approach, and they also mean "we emit a CBOM" is not a moat.

### Enterprise players (real products, enterprise sales)

| Player | Status (sourced) | Why it is not our segment |
|---|---|---|
| SandboxAQ AQtive Guard | On-prem and cloud; partnership with the US DoW CIO on cryptography modernisation (Dec 2025). SandboxAQ acquired Cryptosense (Sept 2022). Valuation figures are unverified, so don't cite them | Fortune 500 / government top end |
| Keyfactor + IBM Consulting | Joint quantum-safe transformation offering (Jan 2026) | Consulting-led enterprise programmes |
| AppViewX AVX ONE, TYCHON | PKI-focused / government-focused | Enterprise pricing, long cycles |

Platform vendors added PQC inventory in 2026 as well. Palo Alto Networks' Quantum-Safe Security
(GA Jan 2026) offers a CBOM and a cipher-translation proxy. IBM Guardium Quantum Safe ingests
CBOMs, Entrust added CBOM import/export (Sep 2026), and CrowdStrike lists PQC readiness as a use
case.

### Posture platforms (funded, closest comparables; reviewed 2026-10-03)

The full brief is local and confidential (`docs/COMPETITORS.md`, outside this repo).

| Player | What it is (sourced) | Where it stops in public material |
|---|---|---|
| **QIZ Security** | "Cryptographic Posture Management": API-first and agentless, selling to large regulated enterprises and federal buyers. $17M seed on 9 Jul 2026, co-led by Bessemer and Merlin Ventures. Founded 2025 by Ben Volkow and Lenny Ridel (Traffix, acquired by F5 for $133.7M in 2012) and Dr. Itan Barmes (ran Deloitte's global quantum cyber-readiness practice). Remediation through SafeLogic's FIPS 140-3 libraries; listed on Google Cloud Marketplace | No CycloneDX CBOM, no CI/merge gate, no data-lifetime scoring, no self-hosted or zero-egress option, no published pricing, no supplier CBOM exchange. Its investors name DORA, NIS2 and the CRA, but its site has no EU content |
| **Wiz for PQC Readiness** | GA 18 May 2026, "for all Wiz customers" (including FedRAMP High). Covers cloud KMS, load balancers and API gateways, public TLS/SSH endpoints, certificates and SSH keys, and libraries in container images. Adds CLI/CI configuration guardrails and an IDE extension. Wiz has been part of Google Cloud since 11 Mar 2026 ($32B) | Only for Wiz customers. No CycloneDX CBOM named, no PQC remediation or PRs, no data-lifetime model, and signature migration ranked "long-term" |

**How they won** (lessons we apply in Go-to-Market):
- **QIZ:** repeat founders plus a Deloitte practice turned into product; ecosystem proof before the
  round; a category named with an Axonius/Wiz analogy; one dated regulation (EO 14412) as the
  anchor.
- **Wiz:** agentless time-to-value; prioritisation instead of alert lists; a research-led brand.

### The gap

The open layer sits between the free detectors, the enterprise platforms and the new posture
platforms. It is CI-native, zero-source-egress **cryptographic change control** with
HNDL-prioritised, standards-conformant CBOM evidence, built for EU regulated mid-market
organisations and their software suppliers, and self-hostable. As of 2026-10-03, neither QIZ nor
Wiz publicly documents any of these:
- a CycloneDX CBOM;
- scoring by how long data must stay confidential;
- a merge gate on new vulnerable cryptography;
- supplier CBOM exchange.

Wiz serves only Wiz customers, and QIZ sells demo-led to large enterprises. Export CBOMs into
those platforms, and ingest theirs, rather than fighting them.

Security scanning in 2015 had the same structure: open-source tools existed, enterprise players
existed, and nothing in between served the developer who wanted a CI step and a dashboard. Snyk
built a multi-billion-dollar business in that gap. (It was not sold to Broadcom; avoid that
claim.)

**Quantsiv is not inventing the scanner, and it does not compete for runtime inventory. It wraps
open detectors and sells what detectors and posture platforms lack: data-lifetime and
signature-deadline prioritisation, change control on cryptography, regulator-mapped CBOM evidence,
and supplier CBOM exchange.**

### The broader "wrapper" ecosystem — not competitors, upstream customers

A second category of players exists: companies that implement quantum-safe wrappers over existing infrastructure (QuSecure, ExeQuantum, PQShield, CryptoNext Security, 01 Quantum). These are not competitors.

| These "wrapper" companies | Quantsiv |
|---|---|
| **Wrap** existing systems with quantum-safe layers | **Scans** to find where wrapping is needed |
| Answer: "How do we become quantum-safe?" | Answers: "Where are we quantum-vulnerable?" |
| Step 3 of the migration journey | Step 1 of the migration journey |

From Phase 2 onward, Quantsiv's own migration features overlap with these companies. Treat them as partners: Quantsiv's CBOM export tells them what to wrap.

Every company that uses QuSecure or PQShield to implement quantum-safe wrappers **needs an inventory first** to know what to wrap. The implementation ecosystem growing (Palo Alto, Cisco, IBM, AWS all adding PQC layers) means the migration wave is real — and every migration starts with discovery. Quantsiv owns step 1.

---

## Who Pays and How Much

Willingness-to-pay hypotheses by segment, to validate with design partners. The packaging itself
is in "Pricing" below.

| Customer | Why they buy | Price |
|---|---|---|
| VC-backed fintech / healthtech startups | Cyber insurance requirement, investor due diligence | €99–299/month |
| Mid-size companies in regulated industries | CISO needs compliance evidence for auditors | €500–2,000/month |
| Enterprise (banks, hospitals, government contractors) | Full migration orchestration, compliance mandates | €5,000–20,000/month |
| Quantum / deep tech companies | They understand the threat better than anyone | Any tier |

### Pricing

Pricing is under revision (decision D5). Every doc points here; validate it with design
partners before publishing anything.

**Proposed packaging (follows the delivery model):**
- **Scanner and CI templates:** free and ungated. They are the distribution surface.
- **Readiness assessment:** a fixed fee per application portfolio, delivered by the founder with
  the tool. This is the first revenue; the price is still to be validated.
- **Supplier tier:** self-serve, billed annually (indicatively in the €99-299/month range). It
  lets a software vendor share attested CBOMs with its regulated customers.
- **Organisation (control plane):** an annual subscription priced by the number of repositories
  or endpoints under inventory.
- **Enterprise:** self-hosted or air-gapped control plane, SSO and audit logs. Custom pricing.

The v1.0 monthly table in `quantsiv_mvp_spec.md` §6 (Free 1 repo, Developer €99, Team €299,
Enterprise €1-5k) is on hold. An earlier draft here said "Free 3 repos / Team 5 seats"; that
line is retired, so don't reuse it.

Sales are **B2B only**. State that in the Terms and at checkout, which avoids the consumer-law
14-day withdrawal regime.

---

## Delivery model

Proposed 2026-10-03; confirmed by the founder on 2026-10-04 (decision D1). Two independent
reviews reached this answer separately. Local-first is the default, not a permanent limit:
hosted scanning of private repos may be offered later as an opt-in, once a network-less sandbox
and the compliance work are funded.

**Who it is for:** B2B only. Developers and AppSec engineers are the users and the adoption
channel; organisations pay. There is no B2C product, because consumers have no cryptographic
estate to inventory and no deadline that forces a purchase.

**How it is delivered:** one engine, many thin adapters, with zero source-code egress.

- **Scanner (the data plane, on the customer's side; free).**
  - `quantsiv scan` is a CLI plus a signed container.
  - It runs in the customer's CI after their build: GitHub Actions, GitLab CI, Jenkins via a
    container step, or Azure DevOps. It can also run on a host inside their network to reach
    internal TLS endpoints.
  - It wraps CBOMkit and sslyze, plus Quantsiv's own rules.
  - It writes a CycloneDX 1.6 CBOM, SARIF and an HNDL report, all locally. **Source code never
    leaves the customer.**
- **Control plane (Quantsiv's side; paid).**
  - EU-hosted, and it receives only CBOMs and finding metadata. Code snippets are off by
    default.
  - It provides an estate-wide CBOM, diffs between scans, policy gates on the delta, and HNDL
    prioritisation driven by declared data lifetimes.
  - It produces evidence packs mapped to named obligations: the CISA/NIST CBOM minimum elements
    once published, OMB M-26-15, the EU roadmap, DORA/NIS2 and the AIVD handbook.
  - It also offers signed share links and supplier CBOM exchange.
  - A self-hosted and air-gapped edition follows when the first enterprise needs it.
- **Remediation (Phase 2 onward).**
  - Pull requests are opened inside the customer's pipeline, using the customer's own token.
  - Deterministic codemods come first. An LLM may only propose a diff.
  - Validation suites run on every change, a human approves it, and nothing is ever
    auto-merged.
  - Any LLM step runs in the customer's pipeline, on a model endpoint the customer chooses
    (decision D8), so source code never reaches Quantsiv. See "Agent layer".

- **Interoperability (neutral by design).**
  - **Export.** Every CBOM is plain CycloneDX 1.6 JSON plus SARIF, so any platform that imports
    CycloneDX can consume it. Name a specific consumer only after a tested round-trip.
  - **Import.** The control plane accepts any schema-valid CycloneDX 1.6 CBOM, not only
    Quantsiv's, and records the producing tool. CBOMkit, supplier and third-party CBOMs then land
    in one estate graph.
  - **Posture platforms (QIZ, Wiz).** Neither publishes a CBOM ingest interface (checked
    2026-10-03). Revisit when one does or a design partner asks.
- **Offline by default.** The scanner writes a CBOM, SARIF and a report with no account and no
  network call. Upload happens only with an organisation token. Time from adding the CI step to
  the first CBOM is measured and reported.
- **Category name.** "Cryptographic change control and CBOM evidence", the "Snyk for
  cryptography" layer that feeds posture platforms. Never "cryptographic posture management":
  that is QIZ's category phrase.

**Not doing:**
- Cloning customers' private repos into our infrastructure. That stays for public repos and
  demos only.
- Runtime or cloud posture inventory that competes with Wiz or QIZ. Ingest it instead (Phase 3).
- A native Jenkins plugin before a paying customer needs one. The container step covers Jenkins.
- An IDE extension before the CI signal has proven precise.
- A hosted service that holds customer keys.
- A hosted model that sees customer source code.
- Auto-merge or auto-deploy of any cryptographic change, by any agent.
- FedRAMP before revenue.
- B2C.

**Why:**
- Detection is commoditising: CBOMkit is free under the Linux Foundation, and GitHub has
  published CodeQL work on CBOMs.
- Regulated buyers will not let a young vendor clone their source code.
- `cbomkit-lib` scans Java best with build artifacts, which exist in CI and not in a fresh
  server-side clone.
- One container covers every CI system, on-prem and air-gapped.

**What makes it category-defining:**
1. *Cryptography as change-controlled code.* A CBOM on every merge, diffed, with policy gates on
   the delta.
2. *Dual-track scoring carried inside the CBOM.* Confidentiality findings are scored by declared
   data lifetime (HNDL), and signatures by deadline. The lifetimes travel in the CBOM, with
   history and, under opt-in, pooled priors.
   - The Mosca-style formula itself is not unique: the open-source tool cryptosweep implements
     it. The edge is estate-level, declared lifetimes inside the CBOM workflow.
   - CycloneDX has discussed a protection-period field for CBOM (issue #1126, 2026); be its
     reference user.
3. *Zero source egress.* One engine serves SaaS, self-hosted and air-gapped customers.
4. *Supplier CBOM exchange.* Vendors share attested CBOMs with regulated customers, the way SBOM
   sharing works.
5. *Closed-loop, human-approved remediation,* inside the customer's pipeline.
6. *Agents that read the organisation's ground truth,* and a gate that checks them (see "Agent
   layer").

"All-in-one plug-in" therefore means one engine, one policy model and one CBOM graph across code,
TLS and (later) cloud KMS/PKI and runtime. It is delivered as SaaS, self-hosted or air-gapped, not
as a hosted monolith.

## Agent layer (decision D7, confirmed 2026-10-04)

> Status: planned. Nothing in this section is built. The README status table is the single
> source of truth.

**Rule: agents propose, the pipeline verifies, a human approves.**
- Deterministic tools decide every verdict: the scanner, the CBOM diff, the dual-track scorer
  and the policy engine.
- An LLM may draft text or a diff. It never decides pass or fail, never merges and never
  deploys.
- Agents that touch code run in the customer's pipeline, on a model the customer chooses (D8).
  Source code never reaches Quantsiv.

**Why agents.**
- **Customers' AI coding assistants now write cryptographic code.** They need the organisation's
  crypto policy and declared data lifetimes at the moment they write it, and an independent
  check afterwards. In "Can Coding Agents Migrate to Post-Quantum Cryptography?" (Alquwayfili,
  arXiv 2512.12989, v3 Sep 2026):
  - four exploratory trials with frontier agents passed all 40 checks;
  - but across 160 attempts in four local-agent configurations, twelve final patches passed
    local verification and failed external requirements.

  Local tests are not enough; a verifier is.
- **Migration (Phases 2-3) is labour.** Agents that draft and verify let a small team serve many
  repositories.

**What is not new, so never claim it** (market check, 2026-10-03):
- Wiz says its AI agents analyse PQC findings, and its Green Agent opens fix PRs.
- Snyk, Semgrep, Socket and Endor Labs ship MCP servers or guardrails for coding agents. None of
  them is crypto-specific.
- IBM publishes an MCP server for its cryptography manager.
- Keyfactor's MCP server (in preview) covers PKI operations.
- Open-source PQC MCP servers exist, e.g. qrp-mcp, and cryptosweep, which also implements Mosca
  scoring.

**Where the market is open or crowded:**
| Idea | Status |
| --- | --- |
| An MCP server that gives coding agents an organisation's *crypto policy and CBOM* | Open |
| An agent that infers data lifetimes | Open |
| Supplier CBOM intake | Open |
| PQC pull-request agents | Some players (e.g. QuantumGenie; Moderne's PQC recipes are detection-only) |
| Regulator-evidence agents | Crowded (Vanta, Drata) |

**The agents.** Each one depends on the data and the gate beneath it.

| Agent | Job | Autonomy | Phase |
| --- | --- | --- | --- |
| A1 Policy context server (`quantsiv mcp`) | Gives a customer's AI coding assistant the organisation's crypto policy, declared lifetimes and CBOM. Its `check_change` tool runs the same function as the merge gate | Read-only; no LLM of ours | 1.0 tail (WP10) |
| A2 Gate explainer | Turns a failed CBOM delta into a cited PR comment, and records approved exceptions with an approver and an expiry | Posts comments only; no LLM | 1.0 tail (WP10) |
| A3 Lifetime declaration assistant | Drafts `quantsiv.yml` data classes and lifetimes from the customer's own data inventory and retention policy | Draft for approval | 1.1, design partners first |
| A4 Evidence drafter | Drafts the evidence pack. Every sentence is bound to a CBOM element or a cited obligation, and a deterministic citation checker verifies it | Draft for approval | 1.1 |
| A5 Supplier CBOM intake | Validates supplier CBOMs (schema, attestation, diff, policy) and drafts follow-up questions that a human sends | Draft for approval | 1.2 |
| A6 Migration proposer | Tries a codemod first and an LLM diff second. A verifier (re-scan, build and tests, known-answer and interoperability tests, performance budget) must pass. The output is a draft PR or a blocker report | Draft for approval; never auto-merge | Phase 2 |
| A7 Inventory reconciler | Merges imported runtime inventories (Wiz export, Google Cloud KMS PQC insights, CycloneDX) into the estate graph | Read-only; ambiguous matches need a human | Phase 3 |
| A8 Agility planner | Recommends an algorithm per use case from constraint tables, and plans staged rollouts with rollback | A named person approves each stage | Phase 3 |

**Moat.** None of it exists yet; each part starts with the first design partner.
- **CBOM history.** A CBOM on every merge, per organisation, which creates switching cost.
- **Migration-pattern corpus.** Code-free records of human-approved outcomes, kept under opt-in
  (D9). It cannot be scraped from GitHub.
- **The gate's position.** The merge gate verifies every change, human or AI.
- **Priors and obligations.** Declared-lifetime priors, plus the EU obligation library.
- **The supplier network.**

MCP servers and "agents" by themselves are table stakes.

**Exclusivity, honestly.**
- **Design partners first.** Agents that use control-plane data go to the 5-10 NDA design
  partners first, because they are co-built on those pipelines and one founder can support only
  that many.
- **Founding-partner terms.** Early access, roadmap influence and a price lock, in exchange for an
  opt-in, code-free corpus contribution (D9) and a reference if the partner is satisfied.
- **Open where it spreads, paid where it compounds.** The scanner, the CI templates and the
  read-only MCP server are free at the stealth exit. Agents that read the CBOM history, the
  corpus or supplier data are paid.
- **No fake scarcity.** No "invite-only" claims, and no waitlist counts beyond the real partner
  cap.

**Stealth-exit demo** (~Q2 2027, after WP7 and WP10):
- Run the same coding task in a public demo repo twice, with and without `quantsiv mcp`
  connected. The merge gate decides both times.
- Show the exception log and the audit trail.
- Publish the eval harness and its measured results, whatever they are.
- No auto-fix, no auto-merge, and no hosted model that sees code.

**Investor lines (honest):**
- "Agents propose, the pipeline verifies, a human approves."
- "Before an AI coding assistant writes cryptography, it should ask: what does this organisation
  allow here, and how long must this data stay secret? Quantsiv is designed to answer from the
  customer's own policy and CBOM, and to check the answer at the merge gate."
- "The model is a commodity. The verifier and the history are not."
- "Agents and MCP are table stakes. We sell the ground truth that agents read, and the gate that
  checks them."

**Do not claim:**
- that anything here is built;
- "first" or "only" MCP server for cryptography;
- "only tool that scores by data lifetime";
- "auto-fix", "self-healing" or "autonomous migration";
- "agentless" as a differentiator;
- any corpus size, accuracy or time-saved figure before it is measured.

## Go-to-Market Motion

**Founder-led design partners first, then product-led.**
- **Now to Q1 2027 (in stealth, under NDA):**
  - 5-10 Dutch/EU regulated organisations (DORA financial entities, NIS2 essential entities) and
    1-2 security consultancies run the scanner in their own CI.
  - The first revenue is fixed-fee readiness assessments delivered with the tool.
- **H1 2027, around the CBOM minimum elements (~Mar 2027):**
  - Ship the control plane, and convert the assessments into annual organisation subscriptions.
- **About Q2 2027, exiting stealth:**
  - Open-source the scanner, then make the public launch (Show HN and the rest).
- **Channels:**
  - EU consultancies and auditors (a "consultant edition").
  - Software suppliers of regulated buyers (the Supplier tier).
  - Never direct US federal sales before revenue; that path requires FedRAMP.

### Competitive guardrails (2026-10-03)

- **Qualify on the incumbent.**
  - Ask every prospect whether they run Wiz or are working with QIZ or Deloitte. Deloitte and EY
    are named QIZ partners.
  - With Wiz, position Quantsiv as the CI and evidence layer on top of Wiz's inventory, never as
    a replacement inventory.
  - With QIZ or Deloitte, qualify out or position as complementary.
- **Sell below them.** QIZ sells demo-led to large enterprises and federal buyers, and Wiz PQC is
  for Wiz customers. Lead with mid-market DORA/NIS2 entities and software suppliers.
- **Channel.** Recruit independent NL/EU boutiques and auditors for the consultant edition, not
  the Big Four.
- **Supplier hook.** Software suppliers will owe SBOMs under the EU Cyber Resilience Act
  (Regulation (EU) 2024/2847, main obligations from 11 Dec 2027; verify on EUR-Lex). Pitch the
  Supplier tier as "add cryptography to the CycloneDX SBOM you already produce", not as a new
  obligation.
- **Before raising, borrow the playbook that got QIZ its round:**
  - add one credible advisor (an EU PKI or crypto practitioner, or an ex-DORA/NIS2 supervisor or
    auditor);
  - get an upstream contribution merged into CBOMkit/PQCA;
  - document a tested CBOM round-trip into a third-party consumer;
  - turn a design-partner CISO into a reference.
- **At the stealth exit, borrow from Wiz.** Publish a small data report from scans of public
  repositories, together with Quantsiv's CBOM profile.

### Distribution channels
- **Hacker News** (Show HN) — security engineers are the audience
- **ProductHunt** — launch day spike + upcoming page for pre-launch followers
- **Betalist** — free, reaches early adopters
- **GitHub** — open-source the scanning engine, sell the platform
- **LinkedIn** — thought leadership on quantum threats (see content plan below)
- **Reddit** r/netsec, r/cryptography — when a rough demo exists
- **AWS / Azure Marketplace** — listing for enterprise inbound

### Keyword split (intentional)
- **Website hero / enterprise:** "Quantum Risk Management Platform" (CISOs landing from LinkedIn/ads)
- **Docs / GitHub / ProductHunt:** "PQC scanner for your codebase" (engineers Googling)
- **Sales deck:** Platform framing throughout

---

## How to Build It

The early build plan that used to be here (a Python AST and regex scanner) is superseded. The
current sources are:
- `quantsiv_mvp_spec.md`: the build spec, at revision 1.1.
- `docs/audit/REMEDIATION_PLAN.md`: the ordered work packages WP0-WP10, which turn today's
  skeleton into a working, secure app and then into the local runner (WP7).

Open-source building blocks:
- CBOMkit (`cbomkit-lib`, the CBOMkit GitHub Action, sonar-cryptography), for detection.
- `cyclonedx-python-lib` ≥ 7 (currently 11.x), for CBOM output.
- sslyze, for TLS.
- Open Quantum Safe `liboqs` and the OpenSSL 3 providers, as reference PQC implementations for
  test fixtures. Never ship them as our own cryptography.

---

## Four-Phase Product Roadmap

The build plan above gets us to a shipped MVP. The product roadmap that follows is what the
landing page and pitch deck present, and it is sequenced against the regulatory calendar
rather than against engineering convenience. (The full roadmap is a local-only strategy document kept outside this repo; this section is the in-repo summary.)

**Phase 1 — Audit (now → 2027).** A local scanner runs in customer CI and maps the
cryptographic footprint of every application. It prioritises HNDL exposure from declared data
lifetimes, and emits a CBOM aligned to the CISA/NIST minimum-element guidance expected around
March 2027. Milestones:
- 1.0 (Q4 2026 to Q1 2027): local scanner plus design partners. Then agent foundations (WP10):
  the read-only policy MCP server (A1) and the gate explainer (A2), neither using an LLM.
- 1.1 (H1 2027): control plane and evidence packs. Plus a design-partner preview of the lifetime
  assistant (A3) and the evidence drafter (A4), both draft-for-approval.
- 1.2 (H2 2027): self-hosted control plane, the GitHub App as a check-run surface, GitLab and
  Azure DevOps marketplace entries, supplier CBOM exchange with the intake agent (A5),
  container-image coverage, and SOC 2 readiness work.

*Regulatory anchor: EO 14412 / M-26-15 discovery phase; CBOM minimum elements; the EU roadmap's
end-2026 national strategies.*

**Phase 2 — Migrate (2027 → 2028).** Close the loop from finding to fix: automated migration of
vulnerable cryptographic dependencies, hybrid ciphers running classical and post-quantum
algorithms in parallel for backward compatibility, generated pull requests with diffs and
cited rationale, and rapid validation suites proving nothing broke. Every PR runs in the
customer's pipeline with the customer's token, and a human merges it. The migration proposer
(A6) tries a codemod first and an LLM diff second, on the customer's model. A deterministic
verifier must pass before it produces either a draft PR or a blocker report. Code-free outcome
records build the migration corpus, under opt-in (D9). *Regulatory anchor:
M-26-15 pilot phase; under NIST IR 8547 (draft), 112-bit RSA/ECC is deprecated after 2030.*

**Phase 3 — Agentic crypto-agility (2028 → 2030).** Scale from per-repository scanning to a
crypto-agile architecture spanning clouds, PKI, KMS and service meshes. Agents recommend the PQC
algorithm for each use case, with size, performance and protocol constraints made explicit. They
draft and validate migrations, which run in the pipeline after human approval, with staged
rollout, rollback, a full audit trail and a crypto-agility scorecard. *Regulatory anchor: PQC key
establishment on high-value systems by 31 December 2030; TLS 1.3 by 2 January 2030; EU high-risk
use cases by end-2030.*

**Phase 4 — Platform consolidation (2030 → 2035).**
- A dedicated cryptographic research team.
- High-performance, constant-time implementations of the *standardized* primitives (ML-KEM,
  ML-DSA, SLH-DSA). Shipped to customers only once validated under CMVP (FIPS 140-3).
- One engine and one control plane, deployable as SaaS, self-hosted or air-gapped.
- Optionally, a customer-deployed agility layer that delegates to validated modules.
- Multi-region deployment, plus SOC 2 / ISO 27001.

A hosted service that holds customer keys is not planned. *Regulatory anchor: signatures by
31 December 2031; full migration by 2035.*

> Note on Phase 4: this is deliberately about proprietary *implementations* of
> NIST-standardized algorithms, not about inventing new ones. Unvetted cryptography is a
> liability, and claiming novel algorithms costs credibility with the buyers we are selling to.

---

## First Revenue Scenario

These are hypotheses to validate, not a forecast.

1. Build the local scanner (WP0-WP7), and run it with 5-10 NDA design partners in their own CI.
2. Sell fixed-fee PQC readiness assessments to 3 of them; the deliverable is a CBOM plus an HNDL
   backlog plus an evidence pack.
3. Convert the assessments into annual control-plane subscriptions when the CBOM minimum
   elements land (~Mar 2027).
4. Exit stealth (~Q2 2027): open-source the scanner and run the Show HN with data from public
   repos.
5. Self-serve Supplier tier for vendors whose regulated customers ask them for CBOMs.

The earlier "Show HN → 300-500 engineers → €99/month" path sits after the stealth exit, not
before it.

---

## Tagline Options

- *"Know your quantum risk."*
- *"Your encryption has an expiry date."*
- *"Find every quantum-vulnerable algorithm before they find you."*

---

## Buzz Strategy — Stealth Mode

**The play:** make noise about the threat, not the solution. Become the person who understands quantum cryptography risk. Quantsiv reveals itself later as the answer being built the whole time.

### LinkedIn content sequence (one post per week)

**Post 1 — The hook:**
> *"The US government now states it as policy: adversaries are 'collecting United States information now, and decrypting it later once large-scale quantum computers are operational' (EO 14412, June 2026). If your data has to stay secret for 10+ years, the clock started when it was captured. This is 'harvest now, decrypt later'."*

**Post 2 — The regulation angle:**
> *"NIST finalized the post-quantum standards in August 2024. EO 14412 now requires federal high-value systems to move key establishment to PQC by 31 Dec 2030, and the EU roadmap asks for high-risk use cases by end-2030. Step one everywhere is the same: a cryptographic inventory."* (Do not use the unsourced "only 5%" statistic.)

**Post 3 — The teaser:**
> *"Been heads-down building something in the quantum security space. More soon."*

**Post 4 — The waitlist drop:**
> *"Quantsiv is coming. If you're responsible for security at your company and you've been thinking about post-quantum migration — you want to be on this list."* [link]

### Other channels
- Submit to **Betalist** for early traction
- Register **ProductHunt upcoming page** — collect followers before launch day
- Post in **r/netsec** when a rough demo exists: *"Built a free PQC scanner this weekend, curious what the community thinks"*

---

## Immediate Next Steps

- [ ] Point all secondary domains (.store, .info, .xyz, .net, .online) to forward to quantsiv.io
- [x] Landing page live on GitHub Pages (corsinlo.github.io/quantsiv-landing)
- [ ] Connect the landing waitlist form to a real email list with double opt-in. Today it shows a success message but records nothing; see `quantsiv-landing/CLAUDE.md`.
- [ ] Get professional email: hello@quantsiv.io or ludo@quantsiv.io (Google Workspace $6/month or Proton Business $4/month)
- [ ] Write and post LinkedIn Post 1
- [ ] Register ProductHunt upcoming page
- [ ] Submit to Betalist

---

## Strategic Position

Quantsiv sits at the intersection of three converging forces:

1. **Regulatory pressure** — binding deadlines and compliance requirements (EO 14412, OMB M-26-15, the EU roadmap)
2. **Technical urgency** — harvest now decrypt later is an active threat, not a future one
3. **Market gap** — free detectors and enterprise platforms exist. CI-native, zero-egress,
   HNDL-prioritised evidence for the regulated mid-market and its suppliers does not.

The scanner is the entry point (and free). The control plane, meaning evidence, change control
and supplier exchange, is the moat. The same security and engineering teams that use Quantsiv for PQC scanning become the pipeline for expanded quantum services as the ecosystem matures.

**Quantsiv is not a bet on quantum computers existing. It is a bet on companies being afraid they will — which is already true.**
