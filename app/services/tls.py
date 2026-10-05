"""TLS endpoint probe: one handshake, metadata only (A17).

What one handshake can tell: the negotiated protocol version and cipher suite, the server
certificate's public key (algorithm and size, the signature algorithm, the expiry) and, where the
runtime exposes it, the key-exchange group. The group is what decides harvest-now-decrypt-later
exposure (X25519 or P-256 versus a hybrid such as X25519MLKEM768), and Python exposes it only
from 3.14 (`SSLSocket.group()`) on OpenSSL 3.2 or newer; on older runtimes the probe records
that the group was not observable instead of guessing, and classifies the exchange from the
cipher suite (ECDHE, DHE, or static RSA key transport in TLS 1.2).

Where this runs:
- in the customer's CI through `quantsiv scan --tls host` or `quantsiv tls host`, against the
  customer's own endpoints;
- in the control plane (`worker.scan_tls`) only for domains verified by DNS TXT record and only
  through `app.services.ssrf.resolve_scan_target`, connecting to the vetted IP with SNI so DNS
  cannot be rebound between the check and the connection.

No certificate chain is validated: an expired or self-signed certificate is still inventory.
"""

import socket
import ssl
import warnings
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from cryptography import x509

from app.services.errors import ScanError
from app.services.ssrf import resolve_scan_target

PORT = 443
TIMEOUT = 10.0
# Hybrid and pure post-quantum TLS groups (IANA TLS Supported Groups registry, draft-ietf-tls-ecdhe-mlkem)
PQC_GROUPS = frozenset(
    {
        "X25519MLKEM768",
        "SECP256R1MLKEM768",
        "SECP384R1MLKEM1024",
        "MLKEM512",
        "MLKEM768",
        "MLKEM1024",
    }
)
PROBE_GROUP = "X25519MLKEM768"  # offered alone on a second handshake when the runtime allows it
FORWARD_SECRET = ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA20")  # TLS 1.3 names start with TLS_


@dataclass(frozen=True)
class TlsProbe:
    domain: str
    ip_address: str | None
    port: int = PORT
    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange_group: str | None = None  # None: not observable on this runtime
    pqc_key_exchange: bool | None = None  # None: not observable
    cert_subject: str | None = None
    cert_expiry: datetime | None = None
    cert_algorithm: str | None = None
    cert_key_bits: int | None = None
    cert_signature_algorithm: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        data = asdict(self)
        if self.cert_expiry:
            data["cert_expiry"] = self.cert_expiry.isoformat()
        return data


def _context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inventory, not validation (see the module docstring)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1  # see what the server still negotiates
    except (ValueError, ssl.SSLError):  # a runtime that refuses legacy protocols outright
        pass
    return ctx


def _handshake(ctx: ssl.SSLContext, domain: str, ip: str, port: int, timeout: float):
    with (
        socket.create_connection((ip, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=domain) as tls,
    ):
        group = getattr(tls, "group", None)  # Python 3.14+
        return (
            tls.version(),
            tls.cipher(),
            tls.getpeercert(binary_form=True),
            group() if callable(group) else None,
        )


def _pqc_supported(domain: str, ip: str, port: int, timeout: float) -> bool | None:
    """A second handshake offering only the hybrid group: True if the server takes it, False if
    it refuses, None when this runtime cannot restrict the offered groups."""
    ctx = _context()
    setter = getattr(ctx, "set_groups", None) or getattr(ctx, "set_ecdh_curve", None)
    try:
        setter(PROBE_GROUP)  # ValueError / SSLError on an OpenSSL without ML-KEM
    except (ValueError, ssl.SSLError, AttributeError, TypeError):
        return None
    try:
        _handshake(ctx, domain, ip, port, timeout)
    except ssl.SSLError:
        return False
    except OSError:
        return None
    return True


def probe(domain: str, ip: str, port: int = PORT, timeout: float = TIMEOUT) -> TlsProbe:
    """Handshake with `ip` (already vetted by the caller) using SNI `domain`."""
    try:
        version, cipher, der, group = _handshake(_context(), domain, ip, port, timeout)
    except ssl.SSLError as exc:
        return TlsProbe(domain, ip, port, error=f"TLS handshake failed: {exc.reason or 'error'}")
    except OSError:
        return TlsProbe(domain, ip, port, error="Connection failed")
    cert = x509.load_der_x509_certificate(der) if der else None
    subject = algorithm = bits = signature = None
    expiry = None
    if cert is not None:
        from quantsiv_scanner.keyfiles import describe_public_key

        algorithm, _, bits = describe_public_key(cert.public_key())
        subject = cert.subject.rfc4514_string()[:200]
        expiry = cert.not_valid_after_utc.astimezone(UTC)
        signature = cert.signature_algorithm_oid._name
    pqc = (group in PQC_GROUPS) if group else None
    if pqc is None and version in ("TLSv1.3", "TLSv1.2"):
        pqc = _pqc_supported(domain, ip, port, timeout)
    return TlsProbe(
        domain=domain,
        ip_address=ip,
        port=port,
        tls_version=version,
        cipher_suite=cipher[0] if cipher else None,
        key_exchange_group=group,
        pqc_key_exchange=pqc,
        cert_subject=subject,
        cert_expiry=expiry,
        cert_algorithm=algorithm,
        cert_key_bits=bits,
        cert_signature_algorithm=signature,
    )


def probe_verified_endpoint(domain: str, port: int = PORT, timeout: float = TIMEOUT) -> TlsProbe:
    """The control-plane path: through the SSRF guard, SNI to the vetted address."""
    try:
        ip = resolve_scan_target(domain, port)
    except (ValueError, OSError):
        raise ScanError(f"{domain} does not resolve to a public address.") from None
    return probe(domain, ip, port, timeout)


def probe_endpoint(domain: str, port: int = PORT, timeout: float = TIMEOUT) -> TlsProbe:
    """The CLI path, in the customer's own network: plain resolution, no guard."""
    try:
        infos = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
    except OSError:
        return TlsProbe(domain, None, port, error="Name does not resolve")
    return probe(domain, infos[0][4][0], port, timeout)


def _group_algorithm(group: str) -> tuple[str, int | None]:
    name = group.upper()
    for curve, bits in (("X25519", 256), ("X448", 448), ("SECP256R1", 256), ("P-256", 256)):
        if name.startswith(curve):
            return ("X25519" if curve == "X25519" else "ECDH"), bits
    if name.startswith(("SECP384R1", "P-384")):
        return "ECDH", 384
    if name.startswith(("SECP521R1", "P-521")):
        return "ECDH", 521
    if name.startswith("FFDHE"):
        return "DH", int(name[5:]) if name[5:].isdigit() else None
    return group, None


def findings_from_probe(result: TlsProbe) -> list[dict]:
    """Engine-shaped findings (one per asset the handshake showed) for scoring and the CBOM."""
    if result.error:
        return []
    endpoint = f"{result.domain}:{result.port}"
    label = f"TLS endpoint {endpoint}"
    base = {
        # The endpoint is the asset's location, so the gate and the estate diff tell endpoints apart
        "file_path": f"tls://{endpoint}",
        "line_number": None,
        "source": "tls-probe",
        "test_code": False,
        "raw_match": "",
    }
    findings: list[dict] = []
    cipher = (result.cipher_suite or "").upper()
    forward_secret = cipher.startswith(FORWARD_SECRET)
    # 1. Key exchange: the HNDL-relevant asset
    if result.pqc_key_exchange and result.key_exchange_group in PQC_GROUPS:
        findings.append(
            {
                **base,
                "rule_id": "tls-key-exchange",
                "algorithm": result.key_exchange_group,
                "primitive": "kem",
                "key_size": None,
                "context_label": f"{label}: hybrid post-quantum key exchange",
                "confidence": 0.95,
                "quantum_safe": True,
            }
        )
    elif result.key_exchange_group:
        algorithm, bits = _group_algorithm(result.key_exchange_group)
        findings.append(
            {
                **base,
                "rule_id": "tls-key-exchange",
                "algorithm": algorithm,
                "primitive": "key-agree",
                "key_size": bits,
                "context_label": f"{label}: key exchange {result.key_exchange_group}",
                "confidence": 0.95,
                "quantum_safe": False,
            }
        )
    elif result.tls_version and not forward_secret and result.cert_algorithm == "RSA":
        findings.append(
            {
                **base,
                "rule_id": "tls-key-exchange",
                "algorithm": "RSA",
                "primitive": "pke",
                "key_size": result.cert_key_bits,
                "context_label": f"{label}: {result.tls_version} RSA key transport, no forward secrecy",
                "confidence": 0.9,
                "quantum_safe": False,
            }
        )
    elif result.tls_version:
        observed = "ECDHE" if "DHE" not in cipher or "ECDHE" in cipher else "DHE"
        pqc_note = {
            True: f"server accepts {PROBE_GROUP}",
            False: f"server refuses {PROBE_GROUP}",
            None: "group not observable on this runtime",
        }[result.pqc_key_exchange]
        findings.append(
            {
                **base,
                "rule_id": "tls-key-exchange",
                "algorithm": "ECDH" if observed == "ECDHE" else "DH",
                "primitive": "key-agree",
                "key_size": None,
                "context_label": f"{label}: {observed} key exchange, {pqc_note}"[:100],
                "confidence": 0.7 if result.pqc_key_exchange is None else 0.9,
                "quantum_safe": bool(result.pqc_key_exchange),
                **(
                    {"algorithm": PROBE_GROUP, "primitive": "kem"}
                    if result.pqc_key_exchange
                    else {}
                ),
            }
        )
    # 2. The certificate's public key: authentication (signature track)
    if result.cert_algorithm:
        expires = result.cert_expiry.date().isoformat() if result.cert_expiry else "unknown"
        findings.append(
            {
                **base,
                "rule_id": "tls-certificate",
                "algorithm": result.cert_algorithm,
                "primitive": "signature",
                "key_size": result.cert_key_bits,
                "context_label": f"{label}: certificate key, expires {expires}"[:100],
                "confidence": 0.95,
                "quantum_safe": False,
            }
        )
    return findings
