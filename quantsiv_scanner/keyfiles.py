"""Key and certificate files as cryptographic assets (metadata only).

PEM blocks (keys, certificates, requests) and OpenSSH public keys are parsed for their algorithm
and key size. Nothing else is kept: a finding records the block's header line, never the key
material. Private keys are reported because a key committed to a repository is part of the
estate; whether it should be there at all is a secret-hygiene question this tool does not judge.

Not parsed: DER (binary files are skipped), PKCS#12 (`.p12`, `.pfx`), Java keystores (`.jks`),
and PKCS#8 encrypted private keys, whose algorithm is not readable without the passphrase.
"""

import base64
import re
import struct
from datetime import UTC

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dh,
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

from quantsiv_scanner.engine import TEST_PATH, Finding

# File kinds walked for key material even though no source rule applies to them
KEY_FILE_KINDS = frozenset({"pem", "crt", "cer", "key", "pub", "csr", "p8", "pkcs8"})
SSH_FILE_NAMES = frozenset({"authorized_keys", "known_hosts"})
MAX_BLOCKS_PER_FILE = 100  # a CA bundle has this many certificates; larger files are truncated

PEM_BEGIN = re.compile(r"^-----BEGIN (?P<label>[A-Z0-9 ]+)-----\s*$")
PEM_END = re.compile(r"^-----END (?P<label>[A-Z0-9 ]+)-----\s*$")
SSH_KEY_LINE = re.compile(
    r"^(?:\S.*?\s+)??(?P<type>ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+(?P<b64>[A-Za-z0-9+/=]+)"
)
SSH_TYPES = {
    "ssh-rsa": ("RSA", None),
    "ssh-dss": ("DSA", "signature"),
    "ssh-ed25519": ("Ed25519", "signature"),
    "sk-ssh-ed25519@openssh.com": ("Ed25519", "signature"),
    "ecdsa-sha2-nistp256": ("ECDSA", "signature"),
    "ecdsa-sha2-nistp384": ("ECDSA", "signature"),
    "ecdsa-sha2-nistp521": ("ECDSA", "signature"),
    "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA", "signature"),
}
HEADER_ALGORITHMS = {  # fallback when a block names its algorithm but cannot be loaded
    "RSA PRIVATE KEY": "RSA",
    "RSA PUBLIC KEY": "RSA",
    "EC PRIVATE KEY": "EC",
    "DSA PRIVATE KEY": "DSA",
    "DH PARAMETERS": "DH",
    "X25519 PRIVATE KEY": "X25519",
}


def describe_public_key(key) -> tuple[str, str | None, int | None]:
    """(algorithm, primitive, key size) for a cryptography public or private key object."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA", None, key.key_size
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "EC", None, key.curve.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519", "signature", 256
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448", "signature", 448
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519", "key-agree", 256
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448", "key-agree", 448
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", "signature", key.key_size
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey)):
        return "DH", "key-agree", key.key_size
    name = type(key).__name__.removesuffix("PublicKey").removesuffix("PrivateKey")
    return name, None, None  # e.g. a post-quantum key type in a newer cryptography release


def _load_block(label: str, pem: bytes):
    """Return (key object, context, confidence) or None when the block is not loadable."""
    if label == "CERTIFICATE":
        cert = x509.load_pem_x509_certificate(pem)
        expires = cert.not_valid_after_utc.astimezone(UTC).date().isoformat()
        return cert.public_key(), f"X.509 certificate, expires {expires}", 0.95
    if label == "CERTIFICATE REQUEST" or label == "NEW CERTIFICATE REQUEST":
        return x509.load_pem_x509_csr(pem).public_key(), "certificate request", 0.95
    if label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        return serialization.load_pem_public_key(pem), "public key file", 0.95
    if label == "OPENSSH PRIVATE KEY":
        return serialization.load_ssh_private_key(pem, password=None), "OpenSSH private key", 0.95
    if label.endswith("PRIVATE KEY") and label != "ENCRYPTED PRIVATE KEY":
        return serialization.load_pem_private_key(pem, password=None), "private key file", 0.95
    return None


def scan_pem(text: str, rel_path: str) -> list[Finding]:
    """Parse every PEM block in a text; works on key files and on source with embedded keys."""
    findings: list[Finding] = []
    in_test = bool(TEST_PATH.search(rel_path))
    lines = text.splitlines()
    i = 0
    while i < len(lines) and len(findings) < MAX_BLOCKS_PER_FILE:
        begin = PEM_BEGIN.match(lines[i].strip())
        if not begin:
            i += 1
            continue
        label = begin.group("label")
        start = i
        end = next(
            (
                j
                for j in range(i + 1, min(len(lines), i + 20_000))
                if PEM_END.match(lines[j].strip())
            ),
            None,
        )
        if end is None:
            break
        i = end + 1
        block = "\n".join(line.strip() for line in lines[start : end + 1]).encode()
        algorithm = primitive = key_size = None
        context, confidence = "PEM block", 0.7
        try:
            loaded = _load_block(label, block)
        except Exception:  # noqa: BLE001 - malformed or encrypted; fall back to the header
            loaded = None
        if loaded is not None:
            key, context, confidence = loaded
            algorithm, primitive, key_size = describe_public_key(key)
        elif label in HEADER_ALGORITHMS:
            algorithm, context, confidence = HEADER_ALGORITHMS[label], f"PEM {label.lower()}", 0.8
        if algorithm is None:
            continue
        findings.append(
            Finding(
                rule_id="file-pem",
                algorithm=algorithm,
                primitive=primitive,
                key_size=key_size,
                file_path=rel_path,
                line_number=start + 1,
                context_label=context,
                confidence=confidence,
                quantum_safe=False,
                raw_match=lines[start].strip()[:80],  # the header only, never the material
                test_code=in_test,
            )
        )
    return findings


def _ssh_rsa_bits(blob: bytes) -> int | None:
    """Modulus size from the OpenSSH wire encoding: string type, mpint e, mpint n."""
    try:
        offset = 0
        for index in range(3):
            (length,) = struct.unpack(">I", blob[offset : offset + 4])
            offset += 4
            field = blob[offset : offset + length]
            offset += length
        n = int.from_bytes(field.lstrip(b"\0"), "big")
        return n.bit_length()
    except (struct.error, ValueError):
        return None


def scan_ssh_keys(text: str, rel_path: str) -> list[Finding]:
    """OpenSSH public key lines (`.pub`, `authorized_keys`, `known_hosts`)."""
    findings: list[Finding] = []
    in_test = bool(TEST_PATH.search(rel_path))
    for number, line in enumerate(text.splitlines(), start=1):
        if len(findings) >= MAX_BLOCKS_PER_FILE:
            break
        match = SSH_KEY_LINE.match(line.strip())
        if not match:
            continue
        key_type = match.group("type")
        algorithm, primitive = SSH_TYPES[key_type]
        key_size = None
        if key_type == "ssh-rsa":
            try:
                key_size = _ssh_rsa_bits(base64.b64decode(match.group("b64"), validate=True))
            except ValueError:
                key_size = None
        elif "nistp" in key_type:
            key_size = int(key_type.rsplit("nistp", 1)[1][:3])
        elif "ed25519" in key_type:
            key_size = 256
        findings.append(
            Finding(
                rule_id="file-ssh-public-key",
                algorithm=algorithm,
                primitive=primitive,
                key_size=key_size,
                file_path=rel_path,
                line_number=number,
                context_label=f"OpenSSH public key ({key_type})",
                confidence=0.95,
                quantum_safe=False,
                raw_match=key_type,
                test_code=in_test,
            )
        )
    return findings
