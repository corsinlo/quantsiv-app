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

> *Quantsiv scans your codebase, certificates, and cloud infrastructure to find quantum-vulnerable cryptography before it becomes a breach.*

**Category:** DevSecOps / Cryptographic Agility / PQC Compliance  
**Business type:** B2B SaaS  
**Primary domain:** quantsiv.io (+ .com, .net, .xyz, .store, .info, .online as redirects)

---

## The Threat — Why This Market Exists

Almost everything secure on the internet today — bank logins, HTTPS connections, API authentication, encrypted emails, VPN tunnels, digital signatures — is protected by three algorithms: **RSA, ECDSA, and Diffie-Hellman**. They work because factoring very large numbers is computationally impossible for classical computers.

A sufficiently powerful quantum computer running **Shor's algorithm** makes factoring trivial. RSA-2048 falls in hours.

Current quantum computers can't do this yet. But the active threat is happening now:

> **"Harvest now, decrypt later."** State actors and sophisticated adversaries are capturing and storing encrypted internet traffic today. They can't read it yet. When quantum computers mature (est. 2029–2035), they decrypt everything they stored. Your 2026 financial records, medical data, or trade secrets become readable in 2031.

Data that needs to stay confidential for 10+ years is already compromised if it's been captured in transit.

---

## Regulatory Context

- **NIST** finalized three quantum-resistant algorithm standards in August 2024:
  - CRYSTALS-Kyber (ML-KEM, FIPS 203) — replaces Diffie-Hellman
  - CRYSTALS-Dilithium (ML-DSA, FIPS 204) — replaces ECDSA
  - SPHINCS+ (SLH-DSA, FIPS 205) — alternative signatures
- **EO-14412 (June 2026):** US Executive Order mandating government-wide PQC migration with binding deadlines
- **EU NIS2 Directive:** implicitly requires PQC preparedness for critical infrastructure
- **Cyber insurance providers** now ask about PQC compliance at renewal (Lloyd's 2026)
- **Only 5% of enterprises** have actually migrated as of mid-2026
- **$15 billion** estimated PQC migration market

The gap between mandate and reality is the market.

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

**The #1 complaint from CISOs attempting migration: "We don't know what we have."**

---

## What Quantsiv Does — Product Modules

### 1. Code Scanner
Parses source code (Python, Java, Go, JavaScript, C++) at AST level to find every use of quantum-vulnerable algorithms:
- `RSA.generate(2048)` in Python
- `new RSAKeyPairGenerator()` in Java
- `crypto.createSign('SHA256withRSA')` in Node
- Config files specifying `algorithm: RSA`

### 2. Certificate Scanner
Scans every subdomain and endpoint via TLS handshake inspection. Flags:
- RSA-2048 and ECDSA P-256 certificates (both quantum-vulnerable)
- Certificate expiry dates (combined migration planning)
- Public-facing vs. internal classification

### 3. Cloud Infrastructure Scanner
Connects via AWS / Azure / GCP SDK. Checks:
- S3 bucket encryption algorithms
- RDS database encryption keys
- Lambda function signing certificates
- Load balancer SSL policies

### 4. Risk Scorer
Prioritises findings by two axes:
- **Exposure:** public-facing API vs. internal service
- **Sensitivity:** financial data, health records, authentication = higher risk

Output: ordered migration backlog, not a flat list.

### 5. CI/CD Integration (GitHub Action)
Scans every pull request. If new RSA or ECDSA usage is introduced, the build fails with a clear explanation. Prevents the problem from getting worse while the team works through existing debt. Same pattern as how Snyk works for dependency vulnerabilities.

### 6. Compliance Reporter
One-click PDF showing:
- NIST PQC compliance percentage
- CNSA 2.0 readiness score
- Migration roadmap with effort estimates
- Board-ready summary
- Cyber insurance questionnaire pre-fill

---

## Competitive Landscape

### Open-source CLI tools (free, narrow, no product wrapper)

| Tool | Who | What it does | What's missing |
|---|---|---|---|
| pqcscan (Anvil Secure) | Anvil Secure CTO | Scans SSH/TLS endpoints for PQC support | Can't scan codebases, no cloud, no compliance |
| pqc-scan (wakaken) | Independent, Rust CLI | Scans repos, generates CBOM, SARIF output | No dashboard, no SaaS, no cloud scanning |
| cryptoscan (CSNP/QRAMM) | CSNP community | Codebase scanner, CBOM, GitHub integration | No SaaS wrapper, no compliance reports, no UI |

These validate the technical approach. The engine works. But they're CLI tools, not products.

### Enterprise players (real products, inaccessible pricing)

| Player | Status | Why not a threat |
|---|---|---|
| SandboxAQ | $5.75B valuation, $950M raised, AQtive Guard product | Custom enterprise contracts, Fortune 500 / government only |
| AppViewX AVX ONE | Enterprise SaaS, PKI-focused | Enterprise pricing, long sales cycles |
| TYCHON Quantum Command | Government-focused | Not developer-first |
| Cryptosense | Acquired by Veracode 2022 | Buried in enterprise platform |

### The gap

The PQC middle layer — developer-first SaaS, self-serve, €99/month entry, compliance reporting, cloud scanning — is genuinely empty.

The market structure is identical to security scanning in 2015: open-source tools existed, enterprise players existed, nothing in the middle for the developer who wants `npm install pqc-check` and a dashboard. Snyk built in that gap and sold to Broadcom for $7B.

**Quantsiv is not inventing the scanner. Quantsiv is building the product nobody has wrapped around the scanner yet.**

### The broader "wrapper" ecosystem — not competitors, upstream customers

A second category of players exists: companies that implement quantum-safe wrappers over existing infrastructure (QuSecure, ExeQuantum, PQShield, CryptoNext Security, 01 Quantum). These are not competitors.

| These "wrapper" companies | Quantsiv |
|---|---|
| **Wrap** existing systems with quantum-safe layers | **Scans** to find where wrapping is needed |
| Answer: "How do we become quantum-safe?" | Answers: "Where are we quantum-vulnerable?" |
| Step 3 of the migration journey | Step 1 of the migration journey |

Every company that uses QuSecure or PQShield to implement quantum-safe wrappers **needed Quantsiv first** to know what to wrap. The implementation ecosystem growing (Palo Alto, Cisco, IBM, AWS all adding PQC layers) means the migration wave is real — and every migration starts with discovery. Quantsiv owns step 1.

---

## Who Pays and How Much

| Customer | Why they buy | Price |
|---|---|---|
| VC-backed fintech / healthtech startups | Cyber insurance requirement, investor due diligence | €99–299/month |
| Mid-size companies in regulated industries | CISO needs compliance evidence for auditors | €500–2,000/month |
| Enterprise (banks, hospitals, government contractors) | Full migration orchestration, compliance mandates | €5,000–20,000/month |
| Quantum / deep tech companies | They understand the threat better than anyone | Any tier |

### Pricing tiers

- **Free:** Scan up to 3 repos or 10 certificates (customer acquisition / viral)
- **Developer:** €99/month — unlimited scanning, GitHub integration
- **Team:** €299/month — CI/CD integration, dashboard, 5 seats
- **Enterprise:** €1,000–5,000+/month — cloud scanning, compliance reports, custom integration

---

## Go-to-Market Motion

**Developer-led, bottom-up.** A security engineer installs it, scans their repo in 5 minutes, gets a result, brings it to their manager. Manager buys the team plan. CISO sees the compliance report and buys the enterprise contract.

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

### Phase 1 — MVP (4–6 weeks, one developer, ~€0 infrastructure)
- Python code scanner using AST parsing + regex
- TLS certificate inspector using Python `ssl` and `socket`
- JSON report output with risk scores
- Simple web dashboard showing findings

Open-source building blocks to use:
- `cbomkit` (IBM's Cryptography Bill of Materials scanner)
- `cryptography` (Python) — algorithm detection
- Open Quantum Safe `liboqs` — reference NIST algorithm implementations

### Phase 2 (months 2–3)
- GitHub Action for CI/CD integration
- Cloud scanning (AWS SDK)
- Dashboard with trend tracking over time

### Phase 3 (months 4–6)
- Compliance PDF reports (NIST, CNSA 2.0, EU NIS2)
- Enterprise multi-tenant support
- Migration roadmap generator with effort estimates

---

## First Revenue Scenario

1. Build free scanner, open-source the engine on GitHub
2. Post on Hacker News: *"Show HN: Free PQC scanner for your codebase — tells you what breaks when quantum arrives"*
3. 300–500 security engineers use it in week 1
4. 10–20 want CI/CD integration and dashboard → €99/month = €1,000–2,000 MRR
5. One company needs a compliance report for their board → €500–1,500 one-time
6. First enterprise pilot at €2,000/month by month 4–5

**Realistic by month 6:** €3,000–8,000 MRR from developer subscriptions + early enterprise pilots.

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
> *"Your encryption will be worthless within 10 years. State actors know this. They're collecting your encrypted data right now. This is called 'harvest now, decrypt later' — and almost no company has a plan for it."*

**Post 2 — The regulation angle:**
> *"NIST finalized quantum-resistant encryption standards in 2024. A US Executive Order mandated migration in 2026. Only 5% of enterprises have acted. What happens to the other 95%?"*

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
- [ ] Set up landing page with waitlist (Carrd / Framer / Webflow — live in 30 minutes)
- [ ] Get professional email: hello@quantsiv.io or ludo@quantsiv.io (Google Workspace $6/month or Proton Business $4/month)
- [ ] Write and post LinkedIn Post 1
- [ ] Register ProductHunt upcoming page
- [ ] Submit to Betalist

---

## Strategic Position

Quantsiv sits at the intersection of three converging forces:

1. **Regulatory pressure** — binding deadlines, compliance requirements, cyber insurance mandates
2. **Technical urgency** — harvest now decrypt later is an active threat, not a future one
3. **Market gap** — enterprise tools exist, CLI tools exist, developer-friendly SaaS does not

The scanner is the entry point. The platform is the moat. The same security and engineering teams that use Quantsiv for PQC scanning become the pipeline for expanded quantum services as the ecosystem matures.

**Quantsiv is not a bet on quantum computers existing. It is a bet on companies being afraid they will — which is already true.**
