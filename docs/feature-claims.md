# Feature claims and landing-page sync

Purpose: one list of what Quantsiv may say about itself, each line backed by merged code, and a
line-by-line comparison with the public landing page (`quantsiv-landing`, `index.html`, checked
2026-10-05 and again 2026-10-06; the landing repository's last commit is from 1 Oct). This file is for the **private** repo. Landing edits happen in `quantsiv-landing`;
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
| Emits a CycloneDX 1.6 CBOM that passes the 1.6 schema's strict validation in tests, plus SARIF 2.1.0 and a ranked report. Uploaded CBOMs are validated on receipt | `app/services/cbom.py`, `quantsiv_scanner/outputs.py` (WP6, WP7) |
| Scores on two tracks: harvest-now-decrypt-later (HNDL) exposure by the confidentiality lifetime you declare in `quantsiv.yml`, and a separate signature-deadline track | `app/services/scoring.py` (WP6). Thresholds are Quantsiv's own documented rule, not a regulatory requirement |
| Runs in your CI by default; only the CBOM and finding metadata reach Quantsiv | Decision D1; CLI, container and CI templates (WP7) |
| Accepts any schema-valid CycloneDX 1.6 CBOM from any CI records its producer, and exports the estate CBOM | `POST/GET /api/v1/cbom` (WP7) |
| Compares a change with the latest default-branch upload of the repository and flags cryptography the change adds. The baseline's policy decides, so a change cannot excuse itself or switch the gate off; edits to the policy are listed in the verdict. Exceptions record a named approver and an expiry. The CI gate, the upload endpoint and the MCP tool give the same verdict | `quantsiv_scanner/policy.py`, `gate.py`, `ci.py` (WP10, WP12). Limits in section 2 |
| Writes the verdict as a pull request comment, check-run text and SARIF. The GitHub Actions template posts the comment and uploads SARIF to Code Scanning; the other templates keep the files as artifacts. Posting a GitHub check run needs the GitHub App (roadmap 1.2) | `explainer.py`, `ci/` templates (WP10) |
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
| Naming CBOMkit as a tested import | The merge is tested against a CBOMkit-shaped fixture only (`docs/scanner.md`). Run the action on a real repository before naming the integration. Say "any schema-valid CycloneDX 1.6 CBOM" |
| "We publish our limits", or a link to them | The limits live in private documentation. State them on the page instead |
| Marketplace GitHub Action | Not published (stealth). CI templates exist for GitHub Actions, GitLab, Jenkins and Azure DevOps |
| Automated migration, generated pull requests, hybrid cipher deployment | Phase 2, not built. Agent decision D8 open |
| SOC 2, ISO 27001, penetration tests, constant-time PQC implementations | None exist. Own cryptographic implementations also need CMVP (FIPS 140-3) validation before shipping |
| Any claim about a customer, price, legal entity or availability date | Needs D4/D5 or the founder |
| "Enforces", "blocks", "tamper-proof" or "audit-grade" change control | Since WP12 a failing pull request fails again on re-run, a change cannot excuse itself, and a second use in a file counts. What remains: a pull request can edit the workflow file that runs the scan, so only a required check posted by the GitHub App (roadmap 1.2) is enforcement; approver names are records, not identity checks; a moved file reads as removed and added. Say "flags" or "gates", not "enforces" |
| "Deep" Java or .NET analysis | Java has five JCA rules and C# three. No BouncyCastle, JWT-library, KeyFactory or SSLContext rules. CBOMkit, when merged, supplies more depth for Java |
| Configuration-file coverage (nginx, Envoy, Terraform, Kubernetes, sshd) | Not built. Only crypto commands in CI scripts and PEM and SSH key files are read |
| Supplier CBOM exchange, migration-progress views, evidence packs | Planned (roadmap 1.1 and 1.2) |

## 3. Forbidden words (CLAUDE.md)

"auto-fix", "autonomous", "agentless", "first or only MCP server for crypto", "cryptographic
posture management", and any absolute "your code never leaves". Use "scanning runs in your CI by
default".

**Differentiation wording.** Never "unique", "first" or "only". Free tools already scan wide
language sets, emit CBOM 1.6 and SARIF, comment on pull requests, fail builds on thresholds or
baselines, and ship MCP servers (see the landscape table in `quantsiv.md`, checked 2026-10-06).
Say what Quantsiv combines: lifetime-aware ranking, policy per data class, recorded exceptions,
an estate view that ingests any CBOM, and scanning that runs in your CI. Waivers exist elsewhere
(the .NET tool in the landscape table), so exceptions alone are not a difference.

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
| "Continuous monitoring flags new quantum-vulnerable code the moment it is introduced" | The check runs per CI run, and enforcement needs the GitHub App's required check (1.2) | "A CI check flags cryptography that a change adds, and records exceptions with a named approver and an expiry". Do not write "enforces" or "blocks" until the GitHub App posts the check |
| Capability "Source and TLS Detection": "AST-level scanning of Python, Java and Go via cbomkit-lib ... sslyze" | Wrong on engine, depth and languages | "Pattern-based detection across Python, JavaScript/TypeScript, Go, Java/Kotlin, C#, Rust, Ruby, PHP, C/C++, Swift, Dart and CI scripts, plus key and certificate files and a TLS endpoint probe. Limits are stated on the page" |
| Capability "CI/CD Enforcement": "A GitHub Action" | Not published | "CI templates for GitHub Actions, GitLab, Jenkins and Azure DevOps, with SARIF for Code Scanning" |
| Capability "Migration Guidance": "Concrete replacements for every finding" | Overclaim | "Guidance per finding: ML-KEM, ML-DSA or SLH-DSA, hybrid with X25519 during the transition" |
| Capability "Audit-Ready Reporting" "One-click" | Not built | Remove until WP8 evidence packs exist, or label "planned" |
| Timeline, NIST IR 8547: "RSA-2048 and P-256 are deprecated ... by 2030" | Wrong for P-256, and the document is an initial public draft | "NIST IR 8547 (initial public draft, Nov 2024): 112-bit-strength RSA and ECC such as RSA-2048 are deprecated after 2030; all quantum-vulnerable public-key algorithms, including P-256, are disallowed after 2035" |
| Timeline, OMB M-26-15 and EO 14412 | Dates match CLAUDE.md. Check the EO quotation against the source text before keeping it | Keep dates; verify the quoted sentence |
| "Quantsiv already emits CycloneDX 1.6 CBOMs, so alignment is a mapping exercise rather than a rebuild" | A forecast about guidance that is not published yet | "Quantsiv emits CycloneDX 1.6 CBOMs; CISA, in coordination with NIST, publishes guidance on CBOM minimum elements within 270 days of EO 14412 (about Mar 2027)" |
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
| Waitlist form: "Thank you! We've recorded your interest: [address]" | `script.js` shows the message and sends nothing, so nothing is recorded. The statement is false, and collecting emails needs a privacy notice, which waits for D4 | Connect the form to a real store, or say the waitlist is not open yet and disable the button. Founder's call |
| Hero, meta description and capability card say the CBOM is what regulators or the deadlines "require" | EO 14412 sets minimum-element guidance for CBOMs, and OMB M-26-15 says agency inventory data "should populate a central Cryptographic Bill of Materials". Neither obliges a private company, and "should" is not "require". The timeline heading "OMB M-26-15 mandates a central CBOM" has the same problem. Missed in the first pass | "the Cryptographic Bill of Materials that US federal guidance (EO 14412, OMB M-26-15) is built around" |
| Title and hero: "Quantum Security Platform" | Not the category the strategy sets: "cryptographic change control and CBOM evidence" (`quantsiv.md`, which also names "Quantum Risk Management Platform" for the enterprise hero) | Founder's call. If the page says "platform", say what it controls: changes to cryptography |
| Intro: "continuously scanning your code so you know exactly what is exposed" | "Continuously" and "exactly" overclaim: scans run on each build and patterns miss things | "scanning your code on every build so you see what is exposed, how long it stays exposed and what to move to" |
| Nothing on languages, key files, the gate, exceptions, CBOM import, the MCP server or local-first scanning | The page shows none of the work added since the copy was written, and its engine text describes IBM's tool | Sections 5 to 7 |

## 5. Worth adding to the landing page (all merged)

- The delivery model in one sentence: scanning runs in your CI by default; metadata only reaches
  an EU-hosted control plane (hosting provider decision D3 is still open, so confirm before
  naming a region).
- The change check with recorded exceptions. It is the centre of the product (decision D6:
  cryptographic change control and CBOM evidence, complementary to posture platforms; it exports
  and ingests plain CycloneDX). Word it as "flags", not "enforces", until the GitHub App posts it as a required check.
- Lifetime-aware ranking and the separate signature track. It is the clearest difference from
  tools that rank by algorithm name.
- The read-only MCP server for coding assistants. Describe what it does; do not rank it against
  others. Free tools ship MCP servers too; ours answers the organisation's policy and declared
  lifetimes and runs the same function as the gate.
- Plain CycloneDX 1.6 in and out: import a CBOM from any tool, export the estate.
- Key and certificate files, and a TLS probe of domains you prove you own.
- Stated limits: a short list on the page of what the scanner does not cover builds trust with the
  buyers this page is for. The detailed limits are private, so do not write "we publish" or link
  to them.
- US and EU framing: add the EU NIS Cooperation Group roadmap next to the US timeline.

## 6. Language coverage: what to say

Rule counts, from `quantsiv_scanner/rules.py` on 2026-10-06. Do not print counts on the page;
they invite comparison and change often. Say "common cryptographic APIs in".

| Depth | Languages | Rules | Covered |
| --- | --- | --- | --- |
| Broad | C, C++, Objective-C | 37 | OpenSSL, mbedTLS, libsodium, wolfSSL, Windows CNG |
| Broad | Python | 21 | PyCryptodome, pyca/cryptography, JWT libraries |
| Broad | JavaScript, TypeScript | 15 | Node crypto, WebCrypto, jose, jsonwebtoken, node-forge |
| Broad | Dart | 14 | pointycastle, package:cryptography, fast_rsa |
| Broad | Swift | 10 | CryptoKit, swift-crypto, Security framework |
| Broad | Go | 9 | `crypto/*` |
| Basic | Rust | 6 | openssl, rsa, ring, dalek crates |
| Basic | Java, Kotlin | 5 | JCA only: KeyPairGenerator, Cipher, Signature, KeyAgreement |
| Basic | C# | 3 | RSA, ECDsa, ECDiffieHellman |
| Basic | Ruby, PHP | 3 | OpenSSL key generation |
| Scripts | Shell, Dockerfile, Makefile, CI YAML | 6 | openssl, ssh-keygen, keytool commands |
| Files | PEM, SSH public keys | n/a | Certificates, public and private keys: algorithm and size only |

Java and C# are the stacks of the regulated buyers in the target market, and they are the
thinnest. Until they are deepened, do not list "Java" or ".NET" as headline coverage; use the
sentence in section 7.

## 7. Draft copy blocks (public-safe, true today)

Drafts for the founder to edit in `quantsiv-landing`. Each sentence maps to merged code. They
avoid the words in section 3.

**Hero.** "Quantsiv finds quantum-vulnerable cryptography in your code, ranks it by how long your
data must stay secret, and flags the changes that add more. Scanning runs in your CI by default
and produces a CycloneDX 1.6 Cryptographic Bill of Materials."

**Language line.** "Detects common cryptographic APIs in Python, JavaScript and TypeScript, Go,
Java and Kotlin, C#, Rust, Ruby, PHP, C and C++, Objective-C, Swift and Dart, openssl, ssh-keygen
and keytool commands in CI and shell scripts, and keys and certificates in PEM and SSH formats.
Pattern-based, so depth varies by language and some calls are missed."

**Capability cards.**
1. *Cryptographic Bill of Materials.* "CycloneDX 1.6 that passes the schema's strict validation.
   Import a CBOM from any producer and export the whole estate as one."
2. *Lifetime-aware ranking.* "Declare how long each kind of data must stay confidential.
   Encryption and key exchange are ranked by that lifetime. Signatures are tracked separately
   against the signature deadline, because their risk is forgery, not retroactive decryption."
3. *Change check.* "Compare each build with the latest default-branch build and flag the
   cryptography a change adds. Set policy per data class and record exceptions with a named
   approver and an expiry. Results go to Code Scanning as SARIF and, with the GitHub Actions
   template, to the pull request as a comment."
4. *Runs in your CI.* "A container with templates for GitHub Actions, GitLab, Jenkins and Azure DevOps.
   Scanning works offline. Only the CBOM and finding metadata reach Quantsiv, and only if you
   upload."
5. *Keys, certificates and TLS.* "Reads key and certificate files for algorithm and size. Probes
   the TLS endpoints you name; the hosted service probes only domains you prove you own with a
   DNS record."
6. *For coding assistants.* "A read-only MCP server lets an AI coding assistant ask your policy
   and declared lifetimes before it writes cryptography. The same check runs at the gate. It has
   no write tools and no model of ours in it."
7. *Migration guidance.* "Where the use is clear, each finding names the standard to move to:
   ML-KEM (FIPS 203), ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), with hybrid key exchange during the
   transition."
8. *Honest limits.* "Pattern matching misses aliased and dynamic calls, vendored code and
   dependencies. We state the limits up front."

Leave out "Audit-Ready Reporting" until evidence packs exist, or label it planned.

## 8. Keeping this in sync

The public-safe version of these rules, with no strategy and no competitor names, is the
landing repository's CLAUDE.md. Keep the two in step: this sheet is the master.

When a work package lands or a claim changes, update sections 1 and 2 here first, then the landing
page. Before any landing change ships, check it against sections 2 and 3.
