# Feature claims and landing-page sync

Purpose: one list of what Quantsiv may say about itself, each line backed by merged code, and a
line-by-line comparison with the public landing page (`quantsiv-landing`, `index.html`, checked
2026-10-05). This file is for the **private** repo. Landing edits happen in `quantsiv-landing`;
carry the wording across by hand, never the file. Do not copy code, pricing, audit material or
this table's "evidence" column into the public repo.

Rules that apply to every line (CLAUDE.md): cite the authority for every regulatory claim, never
invent dates, statistics or competitor facts, say what the scanner does not cover, never claim
type-resolved analysis, and never claim an agent capability beyond merged code.

## 1. Approved capability statements

| Statement | Evidence (merged) |
| --- | --- |
| Scans source for quantum-vulnerable public-key cryptography with pattern rules for Python, JavaScript/TypeScript, Go, Java/Kotlin, C#, Rust, Ruby, PHP, C/C++/Objective-C, Swift and Dart, plus `openssl`, `ssh-keygen` and `keytool` commands in shell, Dockerfiles, Makefiles and CI YAML | `quantsiv_scanner/rules.py`, `docs/scanner.md` coverage table (WP11) |
| Reads PEM keys, certificates and OpenSSH public keys for algorithm and key size. Only the header line is kept, never key material | `quantsiv_scanner/keyfiles.py` (WP11) |
| Probes a TLS endpoint with one handshake: protocol version, cipher suite, key-exchange group where the runtime exposes it, certificate key, expiry. Hosted scans cover only domains you verify with a DNS TXT record | `app/services/tls.py`, `domains.py`, `worker.scan_tls` (WP11). A probe, not a cipher-suite scan |
| Emits a CycloneDX 1.6 CBOM, validated against the 1.6 schema, plus SARIF 2.1.0 and a ranked report | `app/services/cbom.py`, `quantsiv_scanner/outputs.py` (WP6, WP7) |
| Scores on two tracks: harvest-now-decrypt-later (HNDL) exposure by the confidentiality lifetime you declare in `quantsiv.yml`, and a separate signature-deadline track | `app/services/scoring.py` (WP6). Thresholds are Quantsiv's own documented rule, not a regulatory requirement |
| Runs in your CI by default; only the CBOM and finding metadata reach Quantsiv | Decision D1; CLI, container and CI templates (WP7) |
| Accepts any schema-valid CycloneDX 1.6 CBOM from any CI (for example CBOMkit's), records its producer, and exports the estate CBOM | `POST/GET /api/v1/cbom` (WP7) |
| Gates a change on newly added quantum-vulnerable crypto, with a per-repository policy. Exceptions need a named approver and an expiry. The same verdict comes from the CI gate, the upload endpoint and the MCP tool | `quantsiv_scanner/policy.py`, `gate.py` (WP10) |
| Posts the verdict as a pull request comment, a check run and SARIF | `explainer.py`, `ci/github-actions/quantsiv.yml` (WP10) |
| A read-only MCP server lets coding assistants ask the policy before they write crypto. It has no write tools and no model inside | `quantsiv mcp` (WP10); snapshot-tested tool contract |
| Guidance per finding: ML-KEM (FIPS 203) as a hybrid with X25519, ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) | `PQC_GUIDANCE` in `scoring.py`. Findings whose use is unclassified say so instead |
| Test code is reported but flagged | `quantsiv:test-code` property (PR #14) |
| Measured scan time: 2 to 4 seconds on two public repositories (PyJWT, golang-jwt) | `docs/scanner.md` status table. Quote only with that scope |

## 2. Not yet true. Do not say it

| Claim | Status |
| --- | --- |
| "Complete inventory", "every quantum-vulnerable key" | Pattern matching misses aliased imports, dynamic calls, vendored primitives and config outside code. Say "finds" and link the limits |
| Dependency scanning | Not built. Dependencies are not scanned (`docs/scanner.md`) |
| Container, cloud, KMS, PKI or runtime inventory | Not built. Decision D6: nothing before Phase 3 |
| One-click or audit-ready compliance reports, PDF evidence packs | Planned (WP8 requirements). Today: CBOM, SARIF, `report.md`, `report.json` |
| "AST-level" or type-resolved analysis | False. The rules are line patterns |
| cbomkit-lib scanning, sslyze analysis | Not used. CBOMkit output is merged as data; TLS is Quantsiv's own probe |
| Marketplace GitHub Action | Not published (stealth). CI templates exist for GitHub Actions, GitLab, Jenkins and Azure DevOps |
| Automated migration, generated pull requests, hybrid cipher deployment | Phase 2, not built. Agent decision D8 open |
| SOC 2, ISO 27001, penetration tests, constant-time PQC implementations | None exist. Own cryptographic implementations also need CMVP (FIPS 140-3) validation before shipping |
| Any claim about a customer, price, legal entity or availability date | Needs D4/D5 or the founder |

## 3. Forbidden words (CLAUDE.md)

"auto-fix", "autonomous", "agentless", "first or only MCP server for crypto", "cryptographic
posture management", and any absolute "your code never leaves". Use "scanning runs in your CI by
default".

## 4. Landing page comparison

Checked against `index.html` in `quantsiv-landing`. "Fix" is suggested wording, to be edited in
that repo.

| Landing text | Problem | Fix |
| --- | --- | --- |
| "maps every quantum-vulnerable key in your codebase" | Overclaim | "finds quantum-vulnerable cryptography in your code and tells you which to fix first" |
| "From code scanning to an audit-ready CBOM in 90 seconds" | The 90 s figure has no measurement behind it | Drop it, or "a first CBOM in seconds on typical repositories (2 to 4 s measured on two public repos)" |
| "source code, dependencies, configuration files, certificates and live TLS endpoints ... a complete inventory" | Dependencies not scanned; "complete" overclaims; TLS is one probe on domains you verify | "source code, key and certificate files, CI scripts and TLS endpoints you name or verify" |
| "Agentless, installed through a GitHub App or Action" | Forbidden word; also stale delivery model | "Scanning runs in your CI by default. Only the CBOM and finding metadata reach Quantsiv" |
| "scored on two axes: cryptographic severity, and HNDL exposure" | Not the model | "Two tracks: HNDL exposure by how long the data must stay confidential, and a separate signature-deadline track. HNDL threatens encryption and key establishment; for signatures the risk is future forgery" |
| "Every finding carries a plain-English explanation and its recommended replacement" | Unclassified findings carry none | "Each finding carries the reason for its rank and, where the use is clear, the standard to migrate to" |
| "Export a CycloneDX 1.6 CBOM and an audit-ready compliance report citing the authority" | Report not built | "Export a CycloneDX 1.6 CBOM, SARIF and a ranked report" |
| "Continuous monitoring flags new quantum-vulnerable code the moment it is introduced" | Gate runs per CI run and upload | "A CI gate fails a change that adds quantum-vulnerable cryptography, with exceptions that need a named approver and an expiry" |
| Capability "Source and TLS Detection": "AST-level scanning of Python, Java and Go via cbomkit-lib ... sslyze" | Wrong on engine, depth and languages | "Pattern-based detection across Python, JavaScript/TypeScript, Go, Java/Kotlin, C#, Rust, Ruby, PHP, C/C++, Swift, Dart and CI scripts, plus key and certificate files and a TLS endpoint probe. Limits are published" |
| Capability "CI/CD Enforcement": "A GitHub Action" | Not published | "CI templates for GitHub Actions, GitLab, Jenkins and Azure DevOps, with SARIF for Code Scanning" |
| Capability "Migration Guidance": "Concrete replacements for every finding" | Overclaim | "Guidance per finding: ML-KEM, ML-DSA or SLH-DSA, hybrid with X25519 during the transition" |
| Capability "Audit-Ready Reporting" "One-click" | Not built | Remove until WP8 evidence packs exist, or label "planned" |
| Timeline, NIST IR 8547: "RSA-2048 and P-256 are deprecated ... by 2030" | Wrong for P-256, and the document is an initial public draft | "NIST IR 8547 (initial public draft, Nov 2024): 112-bit-strength RSA and ECC such as RSA-2048 are deprecated after 2030; all quantum-vulnerable public-key algorithms, including P-256, are disallowed after 2035" |
| Timeline, OMB M-26-15 and EO 14412 | Dates match CLAUDE.md. Check the EO quotation against the source text before keeping it | Keep dates; verify the quoted sentence |
| "Quantsiv already emits CycloneDX 1.6 CBOMs, so alignment is a mapping exercise rather than a rebuild" | A forecast about guidance that is not published yet | "Quantsiv emits CycloneDX 1.6 CBOMs; CISA and NIST publish the minimum elements within 270 days of EO 14412 (about Mar 2027)" |
| "NSA CNSA 2.0 to a 2033 deadline" | One year hides the range | "exclusive-use dates between 2030 and 2033 depending on the category (verify against the current NSA advisory)" |
| "contractors are pulled in through federal acquisition rules" | The FAR rule is proposed | "a proposed FAR rule for covered contractors" |
| Standards ticker: "CISA PQC Guidance", "G7 Quantum Roadmap" | Not in the cited set | Keep only authorities you can cite; add the EU NIS Cooperation Group roadmap (23 Jun 2025, a recommendation: national strategies by end-2026, high-risk use cases by end-2030, as many systems as feasible by 2035) |
| Threat copy: AI assistants "pick RSA-2048, default JWT signing algorithms, MD5" | Unsourced assertion; MD5 is not something the rules report | Cite a source or soften to "assistants can reproduce quantum-vulnerable defaults" |
| Threat copy: "Everything protected by RSA or ECC becomes readable" | True for encrypted data and key exchange; signatures are forged, not read | "Anything encrypted with, or keyed through, RSA or ECC becomes readable; signatures become forgeable" |
| Roadmap Phase 1: "JavaScript/TypeScript, container and cloud coverage" | JS/TS built; container and cloud are not | "JavaScript/TypeScript, C/C++, Swift and Dart (built); container and cloud inventory later" |
| Roadmap Phase 1: "Pipeline integration for push, PR and scheduled scans" | Push, PR and CI runs work; scheduled hosted scans are not built | Remove "scheduled" or label planned |
| Roadmap Phase 3: "Autonomous execution ... of approved migrations", "AI agents that select the optimal PQC algorithm" | Forbidden word; contradicts D7 (agents propose, deterministic tools decide, a human approves) | "Agents propose; deterministic checks verify; a person approves. Nothing merges or deploys on its own" |
| Roadmap Phase 2: "Automated migration of vulnerable dependencies" | "Auto-fix" wording; D8 open | "Suggested changes as draft pull requests with the diff, rationale and cited authority, for a person to review" |
| Roadmap Phase 4: "constant-time implementations of standardized PQC primitives", "SOC 2 / ISO 27001" | CMVP rule; no certification exists | Remove, or "use validated libraries; certifications are a goal, not a status" |
| Footer: "GitHub: lcorsini" | A personal handle on a public page | Founder's call |

## 5. Worth adding to the landing page (all merged)

- The delivery model in one sentence: scanning runs in your CI by default; metadata only reaches
  an EU-hosted control plane (hosting provider decision D3 is still open, so confirm before
  naming a region).
- The change gate with approver-and-expiry exceptions. It is the centre of the product
  (decision D6: cryptographic change control and CBOM evidence, complementary to posture
  platforms; it exports and ingests plain CycloneDX).
- The read-only MCP server for coding assistants. Describe what it does; do not rank it against
  others.
- Published limits: a link or short list of what the scanner does not cover builds trust with the
  buyers this page is for.
- US and EU framing: add the EU NIS Cooperation Group roadmap next to the US timeline.

## 6. Keeping this in sync

When a work package lands or a claim changes, update section 1 and 2 here first, then the landing
page. Before any landing change ships, check it against sections 2 and 3.
