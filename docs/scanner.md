# The scanner: `quantsiv scan`

The customer-side scanner (decisions D1 and D2). It runs on a local checkout, offline, and writes:

| File | What it is |
| --- | --- |
| `cbom.json` | A CycloneDX 1.6 CBOM: one `cryptographic-asset` component per finding, with `quantsiv:track`, `quantsiv:confidentiality-lifetime-years` and `quantsiv:source` properties. `metadata.properties` carry the repository, files scanned and seconds to the first CBOM. |
| `findings.sarif` | SARIF 2.1.0 for GitHub Code Scanning, GitLab SAST and similar. |
| `report.json`, `report.md` | The ranked findings with the reason for each ranking, counts by track and severity, and the time-to-value measurement. |

```text
python -m quantsiv_scanner scan [PATH] [--out DIR] [--repository owner/name]
                                 [--cbomkit FILE] [--upload] [--api-url URL] [--no-gate] [--json]
```

- `--repository` defaults to `GITHUB_REPOSITORY`, `CI_PROJECT_PATH` or `BUILD_REPOSITORY_NAME`.
- `--cbomkit` defaults to `cbom/cbom.json`, where CBOMkit-action writes its CBOM. If it exists, its
  assets are merged (a rule finding on the same file, line and algorithm family wins) and the
  CBOM records `quantsiv:merged-from`.
- `--upload` sends the CBOM to `POST /api/v1/cbom` with the token from **`QUANTSIV_TOKEN`**. There
  is no `--token` flag: tokens never go on a command line. The exit code is 1 when the control
  plane's gate fails (newly added quantum-vulnerable cryptography since the previous upload of
  the same repository), 0 otherwise; `--no-gate` keeps it at 0.
- `--json` prints the raw engine output and writes nothing. The hosted worker uses it.
- Exit code 2 means a usage or input error; the message says which.

## `quantsiv gate` and `quantsiv mcp` (WP10)

```text
python -m quantsiv_scanner gate --cbom quantsiv-out/cbom.json [--baseline previous.json]
                                [--policy quantsiv.yml] [--out quantsiv-out/gate]
python -m quantsiv_scanner mcp [--repo .] [--cbom quantsiv-out/cbom.json]
                               [--audit quantsiv-out/mcp-audit.jsonl | --no-audit]
                               [--allow-estate --api-url URL]
```

`gate` evaluates the delta between two CBOMs under the policy and writes `verdict.json`,
`pr_comment.md`, `check_run.json` and `gate.sarif`; exit 1 means blocked. The upload endpoint and
the MCP server's `check_change` run the same `policy.evaluate`, so all three agree.

`mcp` serves four read-only tools over stdio to a coding assistant: `get_policy`,
`check_change`, `get_cbom_summary` and `explain_finding`. No tool writes files, runs a shell or
opens a connection; the single exception, `get_cbom_summary(scope="estate")`, is off unless the
server is started with `--allow-estate` and `QUANTSIV_TOKEN` is set. Each call is appended to a
local JSONL audit log (argument hashes, never repository text). The tool contract is a static
snapshot (`tests/scanner/mcp_tools_snapshot.json`, `TOOLS_VERSION`).

The `policy:` section of `quantsiv.yml`:

```yaml
policy:
  block_new_quantum_vulnerable: true          # default: newly added vulnerable assets fail the gate
  blocked_primitives: [key-agree, kem, pke, signature, unknown]
  data_classes:
    public: {blocked_primitives: [signature]} # per data class
  allowed_algorithms: [Ed25519]               # never blocked, e.g. during a planned transition
  exceptions:
    - asset: RSA-2048                         # or just RSA
      path: "legacy/*"                        # optional glob
      approver: Jane Doe                      # required
      expires: 2027-06-30                     # required; expired exceptions do not apply
      reason: vendor SDK; replacement scheduled
```

## How it ranks (`app/services/scoring.py`)

A `quantsiv.yml` in the repository root declares data lifetimes:

```yaml
data_classes:
  customer-records:
    confidentiality_lifetime_years: 25
repositories:
  acme/payments: customer-records
signatures:
  deadline: 2031-12-31        # default: EO 14412's signature date
  trust_lifetime_years: 10    # optional
```

- Key establishment and encryption (`key-agree`, `kem`, `pke`) with a declared lifetime are ranked
  on the **HNDL** track by that lifetime. Without one they are a plain severity, and the report
  says so.
- Signatures are ranked on the **signature deadline** track, never HNDL.
- A public-key algorithm whose use the rule cannot tell (an RSA key pair, for example) is ranked
  as a high severity with the reason "whether it signs or encrypts is not classified".
- ML-KEM, ML-DSA and SLH-DSA are recorded as quantum-safe assets. AES and other symmetric
  primitives and hashes are not quantum-vulnerable (NIST IR 8547 ipd) and the rules do not
  report them; CBOMkit's symmetric assets are kept as merged, quantum-safe assets.

## Coverage of Quantsiv's rules (`quantsiv_scanner/rules.py`)

| Language | Libraries and APIs |
| --- | --- |
| Python | PyCryptodome (`Crypto.PublicKey`, `Crypto.Cipher.PKCS1_OAEP`, `Crypto.Signature`), pyca/cryptography (`rsa`, `ec`, `x25519`, `ed25519`, `dh`, `dsa`, `padding`), JWT libraries (`algorithm="RS256"`) |
| JavaScript, TypeScript | Node `crypto` (`generateKeyPair`, `createECDH`, `createDiffieHellman`, `publicEncrypt`, `createSign`), WebCrypto (`RSA-OAEP`, `RSASSA-PKCS1-v1_5`, `RSA-PSS`, `ECDSA`, `ECDH`, `X25519`, `Ed25519`), jose/jsonwebtoken (`alg`), node-forge |
| Go | `crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/ed25519`, `crypto/dsa`, `crypto/mlkem` |
| Java, Kotlin | JCA `KeyPairGenerator`, `Cipher` (RSA), `Signature`, `KeyAgreement`, `initialize(bits)` |
| C# | `RSA.Create`, `RSACryptoServiceProvider`, `ECDsa.Create`, `ECDiffieHellman.Create` |
| Rust | `openssl::rsa`, the `rsa` crate, `ring::signature`, `x25519_dalek`, `ed25519_dalek` |
| Ruby, PHP | `OpenSSL::PKey::RSA`, `OpenSSL::PKey::EC`, `openssl_pkey_new` |
| C, C++, Objective-C | OpenSSL 1.1 and 3.x (`RSA_generate_key_ex`, `EVP_PKEY_CTX_new_id`, `EVP_PKEY_Q_keygen`, `EVP_RSA_gen`, `EVP_EC_gen`, `EC_KEY_new_by_curve_name`, `RSA_public_encrypt`, `RSA_sign`, `ECDSA_sign`, `ECDH_compute_key`, `DH_*`), mbedTLS (`mbedtls_rsa_gen_key`, `MBEDTLS_PK_RSA`, `MBEDTLS_ECP_DP_*`, `mbedtls_ecdsa_*`, `mbedtls_ecdh_*`, `mbedtls_dhm_*`), libsodium (`crypto_box`, `crypto_kx`, `crypto_scalarmult`, `crypto_sign`), wolfCrypt (`wc_MakeRsaKey`, `wc_ecc_make_key`, `wc_ecc_sign_hash`, `wc_ecc_shared_secret`, `wc_curve25519_*`, `wc_ed25519_*`), Windows CNG (`BCRYPT_*_ALGORITHM`) |
| Swift, Objective-C | CryptoKit (`P256/P384/P521/Curve25519.Signing`, `.KeyAgreement`), swift-crypto (`_RSA.Signing`, `_RSA.Encryption`), Security framework (`kSecAttrKeyTypeRSA`, `kSecAttrKeyTypeECSECPrimeRandom`, `SecKeyAlgorithm` constants) |
| Dart, Flutter | pointycastle (`RSAKeyGenerator`, `ECKeyGenerator`, `ECCurve_*`, `RSAEngine`, `RSASigner`, `ECDSASigner`), package:cryptography (`X25519`, `Ed25519`, `Ecdsa.p256`, `Ecdh.p256`, `RsaPss`), fast_rsa (`RSA.generate`) |
| Shell, Dockerfile, Makefile, CI YAML | `openssl genrsa`, `openssl genpkey`, `openssl ecparam`, `ssh-keygen -t`, `keytool -keyalg` |
| Any of the above | Post-quantum names: ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+ |

Plus, when CBOMkit-action runs first: Java (JCA, BouncyCastle), Python (pyca/cryptography) and Go
(`crypto/*`) with CBOMkit's own detection.

## Status (2026-10-05): what is proven and what is not

| Claim | Evidence |
| --- | --- |
| Scans a real checkout offline and writes CBOM, SARIF and report | Run on public repositories (`jpadilla/pyjwt`, `golang-jwt/jwt`): 2-4 s each; CI runs it under `unshare -n` and in the image with `--network none` |
| Hosted scan end to end | Tested with a faked clone and the real engine in the sandbox; not yet run against a registered GitHub App on a deployed instance |
| CBOMkit merge | Tested against a CBOMkit-shaped fixture; the action publishes no sample, so run it once on a real repository before quoting the integration |
| Scoring thresholds | Quantsiv's own documented rule (`app/services/scoring.py`), not a regulatory requirement; review them |
| Scanner image, Marketplace action | Built from this repo; not published (stealth) |
| Eval harness | Exists; no results |

## Limits, stated plainly

- The rules are pattern matching on source lines, without type resolution. They miss aliased
  imports, dynamic dispatch, and configuration kept outside code (for example a TLS cipher list in
  a load balancer), and they can report comments. Import and type-only lines are skipped; a rule
  needs a call, a constructor or a command. Each finding carries a confidence between 0.6 and 0.9
  for that reason.
- Test code is reported but flagged (`quantsiv:test-code` in the CBOM, "(test)" in the report),
  because test keys do get copied into production; the gate treats it like any other code.
- **Languages not covered by the rules:** Elixir/Erlang, Perl, Scala beyond JCA calls, and
  infrastructure configuration (Terraform, Kubernetes TLS settings). In C and C++ the rules name
  the five libraries above; a vendored or in-house primitive (for example a bare `bn_*` or
  `mpi_*` implementation in firmware) does not match. Key and certificate files (`.pem`, `.p12`,
  `.jks`) are not parsed.
- Dependencies are not scanned: a vulnerable algorithm inside a library you call through a
  wrapper is invisible unless the call itself matches a rule.
- Directories named `node_modules`, `vendor`, `dist`, `build`, `target` and dot-directories are
  skipped, as are symlinks, binary files, files over 2 MB and lines over 4,000 characters.
- TLS endpoints are not scanned by this tool.

## Hosted scans

The same engine runs in the control plane's worker for **public repositories only**, as a
separate limited process (`app/services/sandbox.py`). See `docs/hosted-scanning.md`.
