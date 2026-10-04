"""Migration guidance by CycloneDX primitive (A30).

WP6 adds the finding-to-primitive mapping and the dual-track severity model here.
"""

PQC_GUIDANCE = {
    "signature": "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). Prioritise long-lived "
    "signing keys: code/firmware signing, CA and token-issuer keys.",
    "key-agree": "Migrate key establishment to ML-KEM (FIPS 203), deployed as a hybrid with "
    "X25519 (e.g. X25519MLKEM768 in TLS) during the transition.",
    "kem": "Use ML-KEM (FIPS 203).",
    "pke": "Replace RSA encryption/key transport with ML-KEM (FIPS 203) plus an AEAD.",
}

# Harvest-now-decrypt-later threatens confidentiality only: show the HNDL text for these
HNDL_EXPOSED = frozenset({"key-agree", "kem", "pke"})
