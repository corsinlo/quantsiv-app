"""Pattern rules for cryptographic asset detection (D2: Quantsiv's own rules engine).

Each rule matches one line of source (or script) and yields a finding: algorithm, CycloneDX
primitive where the usage is clear, key size where the code states it, and a confidence. This
is pattern matching without type resolution: it can miss aliased imports and dynamic calls, and
it can report test fixtures or comments. Every rule says so through its confidence (0.6-0.9).

Coverage (see docs/scanner.md): Python (PyCryptodome, pyca/cryptography, PyJWT), JavaScript and
TypeScript (Node crypto, WebCrypto, jose/jsonwebtoken, node-forge), Go (crypto/*), Java and
Kotlin (JCA), C# (.NET), Rust (openssl, rsa, ring, dalek), Ruby and PHP (OpenSSL), and OpenSSL,
ssh-keygen and keytool commands in shell scripts, Dockerfiles, Makefiles and CI YAML, C and C++
(OpenSSL, mbedTLS, libsodium, wolfSSL, Windows CNG), Swift and Objective-C (CryptoKit,
swift-crypto, Security framework) and Dart (pointycastle, package:cryptography).
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

PYTHON = ("py",)
JS = ("js", "mjs", "cjs", "jsx", "ts", "tsx")
GO = ("go",)
JAVA = ("java", "kt", "kts", "scala")
CSHARP = ("cs",)
RUST = ("rs",)
RUBY = ("rb",)
PHP = ("php",)
SCRIPTS = ("sh", "bash", "zsh", "yml", "yaml", "dockerfile", "makefile", "mk", "ps1", "bat")
C = ("c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "m", "mm")
SWIFT = ("swift", "m", "mm")  # Objective-C shares the Security framework
DART = ("dart",)

CURVE_BITS = {
    "P-256": 256,
    "P256": 256,
    "SECP256R1": 256,
    "PRIME256V1": 256,
    "NISTP256": 256,
    "P-384": 384,
    "P384": 384,
    "SECP384R1": 384,
    "NISTP384": 384,
    "P-521": 521,
    "P521": 521,
    "SECP521R1": 521,
    "NISTP521": 521,
    "SECP256K1": 256,
    "SECP224R1": 224,
    "SECP192R1": 192,
    "X25519": 256,
    "ED25519": 256,
    "CURVE25519": 256,
    "X448": 448,
    "CURVE448": 448,
    "ED448": 448,
    "BRAINPOOLP256R1": 256,
    "BP256R1": 256,
    "BP384R1": 384,
    "BP512R1": 512,
    "BRAINPOOLP384R1": 384,
    "BRAINPOOLP512R1": 512,
}

QUANTUM_SAFE_NAMES = {
    "ML-KEM": "ML-KEM",
    "MLKEM": "ML-KEM",
    "KYBER": "ML-KEM",
    "ML-DSA": "ML-DSA",
    "MLDSA": "ML-DSA",
    "DILITHIUM": "ML-DSA",
    "SLH-DSA": "SLH-DSA",
    "SLHDSA": "SLH-DSA",
    "SPHINCS": "SLH-DSA",
}


@dataclass(frozen=True)
class Rule:
    id: str
    extensions: tuple[str, ...]
    pattern: re.Pattern
    algorithm: str | Callable[[re.Match], str]
    primitive: str | None  # signature | key-agree | kem | pke | None (usage not clear)
    context: str
    confidence: float
    key_size: Callable[[re.Match], int | None] = field(default=lambda m: None)
    quantum_safe: bool = False
    needle: str = ""  # cheap substring pre-check before the regex


def _group_int(name: str):
    def extract(match: re.Match) -> int | None:
        try:
            value = match.group(name)
        except IndexError:
            return None
        return int(value) if value and value.isdigit() else None

    return extract


def _curve_bits(name: str):
    def extract(match: re.Match) -> int | None:
        try:
            value = match.group(name)
        except IndexError:
            return None
        return CURVE_BITS.get((value or "").upper().replace("_", "-"))

    return extract


def _curve_algorithm(match: re.Match) -> str:
    curve = (match.group("curve") or "").upper().replace("_", "-")
    if curve in ("X25519", "CURVE25519", "X448", "CURVE448"):
        return curve.replace("CURVE", "X")
    if curve in ("ED25519", "ED448"):
        return curve.replace("ED", "Ed")
    return "EC"


def _jwt_algorithm(match: re.Match) -> str:
    alg = match.group("alg").upper()
    return {"RS": "RSA", "PS": "RSA-PSS", "ES": "ECDSA"}[alg[:2]]


def _jwt_bits(match: re.Match) -> int | None:
    alg = match.group("alg").upper()
    if alg.startswith("ES"):
        return {"256": 256, "384": 384, "512": 521, "256K": 256}.get(alg[2:])
    return None


def _pqc_algorithm(match: re.Match) -> str:
    return QUANTUM_SAFE_NAMES[match.group("name").upper().replace("_", "-")]


def _nid_bits(match: re.Match) -> int | None:
    """OpenSSL NID_* names: NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1."""
    name = (match.group("curve") or "").upper().removeprefix("X9_62_")
    return CURVE_BITS.get(name.replace("_", "-"))


def _bytes_to_bits(name: str):
    def extract(match: re.Match) -> int | None:
        try:
            value = match.group(name)
        except IndexError:
            return None
        return int(value) * 8 if value and value.isdigit() else None

    return extract


def _cng_algorithm(match: re.Match) -> str:
    alg = match.group("alg").upper()
    for prefix, name in (("RSA", "RSA"), ("ECDSA", "ECDSA"), ("ECDH", "ECDH"), ("DSA", "DSA")):
        if alg.startswith(prefix):
            return name
    return "DH"


def _cryptokit_signing(match: re.Match) -> str:
    return "Ed25519" if match.group("curve").upper() == "CURVE25519" else "ECDSA"


def _cryptokit_agreement(match: re.Match) -> str:
    return "X25519" if match.group("curve").upper() == "CURVE25519" else "ECDH"


def _openssl_pkey_algorithm(match: re.Match) -> str:
    name = (match.group("alg") or match.group("name") or "").upper()
    return {"ED25519": "Ed25519", "ED448": "Ed448"}.get(name, name)


R = re.compile
_JWT_ALGS = r"(?P<alg>[RPE]S(?:256|384|512|256K))"

RULES: list[Rule] = [
    # Python: PyCryptodome (the gap CBOMkit does not cover)
    Rule(
        "py-pycryptodome-rsa-generate",
        PYTHON,
        R(r"\bRSA\.generate\(\s*(?P<bits>\d+)"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="RSA.generate",
    ),
    Rule(
        "py-pycryptodome-rsa-import",
        PYTHON,
        R(r"\bRSA\.import_key\("),
        "RSA",
        None,
        "Key import",
        0.7,
        needle="RSA.import_key",
    ),
    Rule(
        "py-pycryptodome-oaep",
        PYTHON,
        R(r"\bPKCS1_OAEP\.new\("),
        "RSA",
        "pke",
        "RSA-OAEP encryption",
        0.9,
        needle="PKCS1_OAEP",
    ),
    Rule(
        "py-pycryptodome-pkcs1-v15-cipher",
        PYTHON,
        R(r"\bPKCS1_v1_5\.new\("),
        "RSA",
        "pke",
        "RSA PKCS#1 v1.5 encryption",
        0.8,
        needle="PKCS1_v1_5",
    ),
    Rule(
        "py-pycryptodome-pkcs1-15-sign",
        PYTHON,
        R(r"\bpkcs1_15\.new\("),
        "RSA",
        "signature",
        "RSA PKCS#1 v1.5 signature",
        0.9,
        needle="pkcs1_15",
    ),
    Rule(
        "py-pycryptodome-pss",
        PYTHON,
        R(r"\bpss\.new\("),
        "RSA-PSS",
        "signature",
        "RSA-PSS signature",
        0.9,
        needle="pss.new",
    ),
    Rule(
        "py-pycryptodome-dsa",
        PYTHON,
        R(r"\bDSA\.(?:generate|import_key)\("),
        "DSA",
        "signature",
        "DSA key",
        0.9,
        needle="DSA.",
    ),
    Rule(
        "py-pycryptodome-ecc",
        PYTHON,
        R(r"\bECC\.generate\(\s*curve\s*=\s*['\"](?P<curve>[\w-]+)"),
        "EC",
        None,
        "EC key generation",
        0.8,
        _curve_bits("curve"),
        needle="ECC.generate",
    ),
    # Python: pyca/cryptography
    Rule(
        "py-pyca-rsa-generate",
        PYTHON,
        R(r"\brsa\.generate_private_key\((?:[^)]*key_size\s*=\s*(?P<bits>\d+))?"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="rsa.generate_private_key",
    ),
    Rule(
        "py-pyca-ec-generate",
        PYTHON,
        R(r"\bec\.generate_private_key\(\s*ec\.(?P<curve>\w+)"),
        "EC",
        None,
        "EC key generation",
        0.9,
        _curve_bits("curve"),
        needle="ec.generate_private_key",
    ),
    Rule(
        "py-pyca-ecdh",
        PYTHON,
        R(r"\bec\.ECDH\(\)"),
        "ECDH",
        "key-agree",
        "ECDH key agreement",
        0.9,
        needle="ec.ECDH",
    ),
    Rule(
        "py-pyca-ecdsa",
        PYTHON,
        R(r"\bec\.ECDSA\("),
        "ECDSA",
        "signature",
        "ECDSA signature",
        0.9,
        needle="ec.ECDSA",
    ),
    Rule(
        "py-pyca-oaep",
        PYTHON,
        R(r"\bpadding\.OAEP\("),
        "RSA",
        "pke",
        "RSA-OAEP encryption",
        0.9,
        needle="padding.OAEP",
    ),
    Rule(
        "py-pyca-pss",
        PYTHON,
        R(r"\bpadding\.PSS\("),
        "RSA-PSS",
        "signature",
        "RSA-PSS signature",
        0.9,
        needle="padding.PSS",
    ),
    Rule(
        "py-pyca-x25519",
        PYTHON,
        R(r"\bX25519PrivateKey\.(?:generate|from_private_bytes)\("),
        "X25519",
        "key-agree",
        "X25519 key agreement",
        0.9,
        lambda m: 256,
        needle="X25519",
    ),
    Rule(
        "py-pyca-x448",
        PYTHON,
        R(r"\bX448PrivateKey\.(?:generate|from_private_bytes)\("),
        "X448",
        "key-agree",
        "X448 key agreement",
        0.9,
        lambda m: 448,
        needle="X448",
    ),
    Rule(
        "py-pyca-ed25519",
        PYTHON,
        R(r"\bEd25519PrivateKey\.(?:generate|from_private_bytes)\("),
        "Ed25519",
        "signature",
        "Ed25519 signature",
        0.9,
        lambda m: 256,
        needle="Ed25519",
    ),
    Rule(
        "py-pyca-ed448",
        PYTHON,
        R(r"\bEd448PrivateKey\.(?:generate|from_private_bytes)\("),
        "Ed448",
        "signature",
        "Ed448 signature",
        0.9,
        lambda m: 448,
        needle="Ed448",
    ),
    Rule(
        "py-pyca-dh",
        PYTHON,
        R(
            r"\bdh\.(?:generate_parameters|DHParameterNumbers)\((?:[^)]*key_size\s*=\s*(?P<bits>\d+))?"
        ),
        "DH",
        "key-agree",
        "Diffie-Hellman key agreement",
        0.9,
        _group_int("bits"),
        needle="dh.",
    ),
    Rule(
        "py-pyca-dsa",
        PYTHON,
        R(r"\bdsa\.generate_private_key\((?:[^)]*key_size\s*=\s*(?P<bits>\d+))?"),
        "DSA",
        "signature",
        "DSA key generation",
        0.9,
        _group_int("bits"),
        needle="dsa.generate_private_key",
    ),
    # Python: JWTs (PyJWT, python-jose, authlib)
    Rule(
        "py-jwt-alg",
        PYTHON,
        R(r"algorithms?\s*=\s*(?:\[\s*)?['\"]" + _JWT_ALGS + r"['\"]"),
        _jwt_algorithm,
        "signature",
        "JWT signing",
        0.8,
        _jwt_bits,
        needle="algorithm",
    ),
    # JavaScript / TypeScript: Node crypto
    Rule(
        "js-node-generate-rsa",
        JS,
        R(
            r"generateKeyPair(?:Sync)?\(\s*['\"]rsa(?:-pss)?['\"](?:[^)]*modulusLength\s*:\s*(?P<bits>\d+))?"
        ),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="generateKeyPair",
    ),
    Rule(
        "js-node-generate-ec",
        JS,
        R(
            r"generateKeyPair(?:Sync)?\(\s*['\"]ec['\"](?:[^)]*namedCurve\s*:\s*['\"](?P<curve>[\w-]+))?"
        ),
        "EC",
        None,
        "EC key generation",
        0.9,
        _curve_bits("curve"),
        needle="generateKeyPair",
    ),
    Rule(
        "js-node-generate-curve",
        JS,
        R(r"generateKeyPair(?:Sync)?\(\s*['\"](?P<curve>ed25519|ed448|x25519|x448)['\"]"),
        _curve_algorithm,
        None,
        "Key generation",
        0.9,
        _curve_bits("curve"),
        needle="generateKeyPair",
    ),
    Rule(
        "js-node-ecdh",
        JS,
        R(r"\bcreateECDH\(\s*['\"](?P<curve>[\w-]+)"),
        "ECDH",
        "key-agree",
        "ECDH key agreement",
        0.9,
        _curve_bits("curve"),
        needle="createECDH",
    ),
    Rule(
        "js-node-dh",
        JS,
        R(r"\bcreateDiffieHellman\("),
        "DH",
        "key-agree",
        "Diffie-Hellman key agreement",
        0.9,
        needle="createDiffieHellman",
    ),
    Rule(
        "js-node-rsa-encrypt",
        JS,
        R(r"\b(?:publicEncrypt|privateDecrypt)\("),
        "RSA",
        "pke",
        "RSA encryption",
        0.8,
        needle="Encrypt(",
    ),
    Rule(
        "js-node-sign-rsa",
        JS,
        R(r"\b(?:createSign|createVerify|sign|verify)\(\s*['\"](?:RSA-)?SHA\d+['\"]"),
        "RSA",
        "signature",
        "RSA signature",
        0.7,
        needle="SHA",
    ),
    # JavaScript / TypeScript: WebCrypto
    Rule(
        "js-webcrypto-rsa-oaep",
        JS,
        R(r"name\s*:\s*['\"]RSA-OAEP['\"](?:[^}]*modulusLength\s*:\s*(?P<bits>\d+))?"),
        "RSA",
        "pke",
        "RSA-OAEP encryption",
        0.9,
        _group_int("bits"),
        needle="RSA-OAEP",
    ),
    Rule(
        "js-webcrypto-rsa-sign",
        JS,
        R(
            r"name\s*:\s*['\"](?:RSASSA-PKCS1-v1_5|RSA-PSS)['\"](?:[^}]*modulusLength\s*:\s*(?P<bits>\d+))?"
        ),
        "RSA",
        "signature",
        "RSA signature",
        0.9,
        _group_int("bits"),
        needle="RSA",
    ),
    Rule(
        "js-webcrypto-ecdsa",
        JS,
        R(r"name\s*:\s*['\"]ECDSA['\"](?:[^}]*namedCurve\s*:\s*['\"](?P<curve>[\w-]+))?"),
        "ECDSA",
        "signature",
        "ECDSA signature",
        0.9,
        _curve_bits("curve"),
        needle="ECDSA",
    ),
    Rule(
        "js-webcrypto-ecdh",
        JS,
        R(r"name\s*:\s*['\"]ECDH['\"](?:[^}]*namedCurve\s*:\s*['\"](?P<curve>[\w-]+))?"),
        "ECDH",
        "key-agree",
        "ECDH key agreement",
        0.9,
        _curve_bits("curve"),
        needle="ECDH",
    ),
    Rule(
        "js-webcrypto-x25519",
        JS,
        R(r"name\s*:\s*['\"]X25519['\"]"),
        "X25519",
        "key-agree",
        "X25519 key agreement",
        0.9,
        lambda m: 256,
        needle="X25519",
    ),
    Rule(
        "js-webcrypto-ed25519",
        JS,
        R(r"name\s*:\s*['\"]Ed25519['\"]"),
        "Ed25519",
        "signature",
        "Ed25519 signature",
        0.9,
        lambda m: 256,
        needle="Ed25519",
    ),
    # JavaScript / TypeScript: JWT libraries and node-forge
    Rule(
        "js-jwt-alg",
        JS,
        R(r"\b(?:alg|algorithms?)\s*:\s*(?:\[\s*)?['\"]" + _JWT_ALGS + r"['\"]"),
        _jwt_algorithm,
        "signature",
        "JWT signing",
        0.8,
        _jwt_bits,
        needle="alg",
    ),
    Rule(
        "js-forge-rsa",
        JS,
        R(r"\bpki\.rsa\.generateKeyPair\((?:[^)]*bits\s*:\s*(?P<bits>\d+))?"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="rsa.generateKeyPair",
    ),
    # Go
    Rule(
        "go-rsa-generate",
        GO,
        R(r"\brsa\.GenerateKey\([^,]+,\s*(?P<bits>\d+)"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="rsa.GenerateKey",
    ),
    Rule(
        "go-rsa-encrypt",
        GO,
        R(r"\brsa\.(?:EncryptOAEP|DecryptOAEP|EncryptPKCS1v15|DecryptPKCS1v15)\("),
        "RSA",
        "pke",
        "RSA encryption",
        0.9,
        needle="rsa.",
    ),
    Rule(
        "go-rsa-sign",
        GO,
        R(r"\brsa\.(?:SignPSS|VerifyPSS|SignPKCS1v15|VerifyPKCS1v15)\("),
        "RSA",
        "signature",
        "RSA signature",
        0.9,
        needle="rsa.",
    ),
    Rule(
        "go-ecdsa",
        GO,
        R(r"\becdsa\.GenerateKey\(\s*elliptic\.(?P<curve>P\d+)"),
        "ECDSA",
        "signature",
        "ECDSA key generation",
        0.9,
        _curve_bits("curve"),
        needle="ecdsa.GenerateKey",
    ),
    Rule(
        "go-ecdsa-sign",
        GO,
        R(r"\becdsa\.(?:Sign|SignASN1|Verify|VerifyASN1)\("),
        "ECDSA",
        "signature",
        "ECDSA signature",
        0.9,
        needle="ecdsa.",
    ),
    Rule(
        "go-ecdh",
        GO,
        R(r"\becdh\.(?P<curve>P256|P384|P521|X25519)\(\)"),
        "ECDH",
        "key-agree",
        "ECDH key agreement",
        0.9,
        _curve_bits("curve"),
        needle="ecdh.",
    ),
    Rule(
        "go-ed25519",
        GO,
        R(r"\bed25519\.(?:GenerateKey|Sign|Verify|NewKeyFromSeed)\("),
        "Ed25519",
        "signature",
        "Ed25519 signature",
        0.9,
        lambda m: 256,
        needle="ed25519.",
    ),
    Rule(
        "go-dsa",
        GO,
        R(r"\bdsa\.(?:GenerateKey|Sign|Verify)\("),
        "DSA",
        "signature",
        "DSA signature",
        0.9,
        needle="dsa.",
    ),
    Rule(
        "go-mlkem",
        GO,
        R(
            r"\bmlkem\.(?P<name>GenerateKey768|GenerateKey1024|NewDecapsulationKey768|NewDecapsulationKey1024)"
        ),
        "ML-KEM",
        "kem",
        "ML-KEM key encapsulation",
        0.9,
        lambda m: 768 if "768" in m.group("name") else 1024,
        quantum_safe=True,
        needle="mlkem.",
    ),
    # Java / Kotlin: JCA
    Rule(
        "java-keypairgen",
        JAVA,
        R(
            r"KeyPairGenerator\.getInstance\(\s*\"(?P<alg>RSA|RSASSA-PSS|DSA|EC|DH|DiffieHellman|X25519|X448|Ed25519|Ed448|EdDSA|XDH)\""
        ),
        lambda m: {"DiffieHellman": "DH", "EdDSA": "Ed25519", "XDH": "X25519"}.get(
            m.group("alg"), m.group("alg")
        ),
        None,
        "Key generation",
        0.9,
        needle="KeyPairGenerator",
    ),
    Rule(
        "java-cipher-rsa",
        JAVA,
        R(r"Cipher\.getInstance\(\s*\"RSA[^\"]*\""),
        "RSA",
        "pke",
        "RSA encryption",
        0.9,
        needle="Cipher.getInstance",
    ),
    Rule(
        "java-signature",
        JAVA,
        R(
            r"Signature\.getInstance\(\s*\"(?:\w+with)?(?P<alg>RSA|ECDSA|DSA|RSASSA-PSS|Ed25519|Ed448|EdDSA)[^\"]*\""
        ),
        lambda m: {"EdDSA": "Ed25519"}.get(m.group("alg"), m.group("alg")),
        "signature",
        "Signature",
        0.9,
        needle="Signature.getInstance",
    ),
    Rule(
        "java-keyagreement",
        JAVA,
        R(r"KeyAgreement\.getInstance\(\s*\"(?P<alg>ECDH|DH|DiffieHellman|X25519|X448|XDH)\""),
        lambda m: {"DiffieHellman": "DH", "XDH": "X25519"}.get(m.group("alg"), m.group("alg")),
        "key-agree",
        "Key agreement",
        0.9,
        needle="KeyAgreement",
    ),
    Rule(
        "java-initialize-bits",
        JAVA,
        R(r"\.initialize\(\s*(?P<bits>\d{3,4})\s*[,)]"),
        "RSA",
        None,
        "Key size",
        0.6,
        _group_int("bits"),
        needle=".initialize(",
    ),
    # C# / .NET
    Rule(
        "cs-rsa",
        CSHARP,
        R(r"\b(?:RSA\.Create|new RSACryptoServiceProvider|new RSACng)\(\s*(?P<bits>\d+)?"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="RSA",
    ),
    Rule(
        "cs-ecdsa",
        CSHARP,
        R(r"\bECDsa\.Create\("),
        "ECDSA",
        "signature",
        "ECDSA key",
        0.9,
        needle="ECDsa",
    ),
    Rule(
        "cs-ecdh",
        CSHARP,
        R(r"\bECDiffieHellman\.Create\("),
        "ECDH",
        "key-agree",
        "ECDH key agreement",
        0.9,
        needle="ECDiffieHellman",
    ),
    # Rust
    Rule(
        "rs-openssl-rsa",
        RUST,
        R(r"\bRsa::generate\(\s*(?P<bits>\d+)"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="Rsa::generate",
    ),
    Rule(
        "rs-rsa-crate",
        RUST,
        R(r"\bRsaPrivateKey::new\([^,]+,\s*(?P<bits>\d+)"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="RsaPrivateKey::new",
    ),
    Rule(
        "rs-ring-ecdsa",
        RUST,
        R(r"\bsignature::ECDSA_(?P<curve>P256|P384)_SHA\d+"),
        "ECDSA",
        "signature",
        "ECDSA signature",
        0.9,
        _curve_bits("curve"),
        needle="ECDSA_",
    ),
    Rule(
        "rs-ring-rsa",
        RUST,
        R(r"\bsignature::RSA_(?:PKCS1|PSS)_"),
        "RSA",
        "signature",
        "RSA signature",
        0.9,
        needle="signature::RSA_",
    ),
    Rule(
        "rs-x25519",
        RUST,
        R(r"\bx25519_dalek::|\bX25519\b"),
        "X25519",
        "key-agree",
        "X25519 key agreement",
        0.8,
        lambda m: 256,
        needle="25519",
    ),
    Rule(
        "rs-ed25519",
        RUST,
        R(r"\bed25519_dalek::|\bEd25519\b"),
        "Ed25519",
        "signature",
        "Ed25519 signature",
        0.8,
        lambda m: 256,
        needle="25519",
    ),
    # Ruby / PHP
    Rule(
        "rb-rsa",
        RUBY,
        R(r"OpenSSL::PKey::RSA\.(?:new|generate)\(\s*(?P<bits>\d+)?"),
        "RSA",
        None,
        "Key generation",
        0.9,
        _group_int("bits"),
        needle="PKey::RSA",
    ),
    Rule(
        "rb-ec",
        RUBY,
        R(r"OpenSSL::PKey::EC\.(?:new|generate)\(\s*['\"](?P<curve>[\w-]+)"),
        "EC",
        None,
        "EC key generation",
        0.9,
        _curve_bits("curve"),
        needle="PKey::EC",
    ),
    Rule(
        "php-rsa",
        PHP,
        R(r"openssl_pkey_new\((?:[^)]*private_key_bits['\"]?\s*=>\s*(?P<bits>\d+))?"),
        "RSA",
        None,
        "Key generation",
        0.8,
        _group_int("bits"),
        needle="openssl_pkey_new",
    ),
    # Shell, Dockerfiles, Makefiles, CI YAML: OpenSSL, ssh-keygen, keytool
    Rule(
        "sh-openssl-genrsa",
        SCRIPTS,
        R(r"\bopenssl\s+genrsa\b.*?\b(?P<bits>\d{4})\b"),
        "RSA",
        None,
        "openssl genrsa",
        0.9,
        _group_int("bits"),
        needle="genrsa",
    ),
    Rule(
        "sh-openssl-genpkey-rsa",
        SCRIPTS,
        R(r"\bopenssl\s+genpkey\b.*?-algorithm\s+RSA(?:.*?rsa_keygen_bits:(?P<bits>\d+))?"),
        "RSA",
        None,
        "openssl genpkey",
        0.9,
        _group_int("bits"),
        needle="genpkey",
    ),
    Rule(
        "sh-openssl-genpkey-curve",
        SCRIPTS,
        R(r"\bopenssl\s+genpkey\b.*?-algorithm\s+(?P<curve>X25519|X448|ED25519|ED448|EC)\b"),
        _curve_algorithm,
        None,
        "openssl genpkey",
        0.9,
        _curve_bits("curve"),
        needle="genpkey",
    ),
    Rule(
        "sh-openssl-ecparam",
        SCRIPTS,
        R(r"\bopenssl\s+ecparam\b.*?-name\s+(?P<curve>[\w-]+)"),
        "EC",
        None,
        "openssl ecparam",
        0.9,
        _curve_bits("curve"),
        needle="ecparam",
    ),
    Rule(
        "sh-ssh-keygen",
        SCRIPTS,
        R(r"\bssh-keygen\b.*?-t\s+(?P<type>rsa|ecdsa|ed25519|dsa)\b(?:.*?-b\s+(?P<bits>\d+))?"),
        lambda m: {"rsa": "RSA", "ecdsa": "ECDSA", "ed25519": "Ed25519", "dsa": "DSA"}[
            m.group("type")
        ],
        "signature",
        "ssh-keygen",
        0.9,
        _group_int("bits"),
        needle="ssh-keygen",
    ),
    Rule(
        "sh-keytool",
        SCRIPTS,
        R(r"\bkeytool\b.*?-keyalg\s+(?P<alg>RSA|EC|DSA)\b(?:.*?-keysize\s+(?P<bits>\d+))?"),
        lambda m: m.group("alg"),
        None,
        "keytool",
        0.9,
        _group_int("bits"),
        needle="keytool",
    ),
    # C and C++: OpenSSL 1.1 and 3.x (also BoringSSL and LibreSSL)
    Rule(
        "c-openssl-rsa-generate",
        C,
        R(r"\bRSA_generate_key(?:_ex)?\s*\(\s*(?:\w+\s*,\s*)?(?P<bits>\d{3,5})\b"),
        "RSA",
        None,
        "OpenSSL RSA_generate_key",
        0.9,
        _group_int("bits"),
        needle="RSA_generate_key",
    ),
    Rule(
        "c-openssl-rsa-keygen-bits",
        C,
        R(r"\bEVP_PKEY_CTX_set_rsa_keygen_bits\s*\(\s*\w+\s*,\s*(?P<bits>\d{3,5})\b"),
        "RSA",
        None,
        "OpenSSL EVP RSA keygen",
        0.9,
        _group_int("bits"),
        needle="rsa_keygen_bits",
    ),
    Rule(
        "c-openssl-evp-rsa-gen",
        C,
        R(r"\bEVP_RSA_gen\s*\(\s*(?P<bits>\d{3,5})?"),
        "RSA",
        None,
        "OpenSSL EVP_RSA_gen",
        0.9,
        _group_int("bits"),
        needle="EVP_RSA_gen",
    ),
    Rule(
        "c-openssl-evp-ec-gen",
        C,
        R(r"\bEVP_EC_gen\s*\(\s*\"(?P<curve>[\w-]+)\""),
        "EC",
        None,
        "OpenSSL EVP_EC_gen",
        0.9,
        _curve_bits("curve"),
        needle="EVP_EC_gen",
    ),
    Rule(
        "c-openssl-evp-ctx-rsa",
        C,
        R(
            r"\bEVP_PKEY_(?:CTX_new_id|CTX_new_from_name|Q_keygen)\s*\("
            r"(?:\s*\w+\s*,)*\s*(?:EVP_PKEY_(?P<alg>RSA(?:_PSS)?)\b|\"(?P<name>RSA(?:-PSS)?)\")"
        ),
        lambda m: (m.group("alg") or m.group("name")).replace("_", "-"),
        None,
        "OpenSSL EVP RSA context",
        0.9,
        needle="EVP_PKEY_",
    ),
    Rule(
        "c-openssl-evp-ctx-ec",
        C,
        R(
            r"\bEVP_PKEY_(?:CTX_new_id|CTX_new_from_name|Q_keygen)\s*\("
            r"(?:\s*\w+\s*,)*\s*(?:EVP_PKEY_EC\b|\"EC\")"
        ),
        "EC",
        None,
        "OpenSSL EVP EC context",
        0.9,
        needle="EVP_PKEY_",
    ),
    Rule(
        "c-openssl-evp-ctx-kx",
        C,
        R(
            r"\bEVP_PKEY_(?:CTX_new_id|CTX_new_from_name|Q_keygen)\s*\("
            r"(?:\s*\w+\s*,)*\s*(?:EVP_PKEY_(?P<alg>DH|X25519|X448)\b|\"(?P<name>DH|X25519|X448)\")"
        ),
        lambda m: m.group("alg") or m.group("name"),
        "key-agree",
        "OpenSSL EVP key-agreement context",
        0.9,
        lambda m: CURVE_BITS.get(m.group("alg") or m.group("name")),
        needle="EVP_PKEY_",
    ),
    Rule(
        "c-openssl-evp-ctx-sig",
        C,
        R(
            r"\bEVP_PKEY_(?:CTX_new_id|CTX_new_from_name|Q_keygen)\s*\("
            r"(?:\s*\w+\s*,)*\s*(?:EVP_PKEY_(?P<alg>DSA|ED25519|ED448)\b|\"(?P<name>DSA|ED25519|ED448)\")"
        ),
        _openssl_pkey_algorithm,
        "signature",
        "OpenSSL EVP signature context",
        0.9,
        lambda m: CURVE_BITS.get((m.group("alg") or m.group("name") or "").upper()),
        needle="EVP_PKEY_",
    ),
    Rule(
        "c-openssl-ec-curve",
        C,
        R(r"\bEC_KEY_new_by_curve_name\s*\(\s*NID_(?P<curve>\w+)"),
        "EC",
        None,
        "OpenSSL EC_KEY_new_by_curve_name",
        0.9,
        _nid_bits,
        needle="EC_KEY_new_by_curve_name",
    ),
    Rule(
        "c-openssl-rsa-pke",
        C,
        R(r"\bRSA_(?:public_encrypt|private_decrypt)\s*\("),
        "RSA",
        "pke",
        "OpenSSL RSA encryption",
        0.9,
        needle="RSA_p",
    ),
    Rule(
        "c-openssl-rsa-sign",
        C,
        R(r"\bRSA_(?:sign|verify)(?:_ASN1_OCTET_STRING)?\s*\("),
        "RSA",
        "signature",
        "OpenSSL RSA_sign",
        0.9,
        needle="RSA_",
    ),
    Rule(
        "c-openssl-ecdsa",
        C,
        R(r"\bECDSA_(?:do_)?(?:sign|verify)(?:_ex)?\s*\("),
        "ECDSA",
        "signature",
        "OpenSSL ECDSA_sign",
        0.9,
        needle="ECDSA_",
    ),
    Rule(
        "c-openssl-ecdh",
        C,
        R(r"\bECDH_compute_key\s*\("),
        "ECDH",
        "key-agree",
        "OpenSSL ECDH_compute_key",
        0.9,
        needle="ECDH_compute_key",
    ),
    Rule(
        "c-openssl-dh",
        C,
        R(r"\bDH_(?:generate_key|compute_key|generate_parameters(?:_ex)?)\s*\("),
        "DH",
        "key-agree",
        "OpenSSL DH",
        0.9,
        needle="DH_",
    ),
    # C and C++: mbedTLS
    Rule(
        "c-mbedtls-rsa-gen",
        C,
        R(r"\bmbedtls_rsa_gen_key\s*\(.*?,\s*(?P<bits>\d{3,5})\s*,"),
        "RSA",
        None,
        "mbedTLS mbedtls_rsa_gen_key",
        0.9,
        _group_int("bits"),
        needle="mbedtls_rsa_gen_key",
    ),
    Rule(
        "c-mbedtls-pk-rsa",
        C,
        R(r"\bMBEDTLS_PK_RSA(?:SSA_PSS)?\b"),
        "RSA",
        None,
        "mbedTLS MBEDTLS_PK_RSA",
        0.8,
        needle="MBEDTLS_PK_RSA",
    ),
    Rule(
        "c-mbedtls-ecp-group",
        C,
        R(r"\bMBEDTLS_ECP_DP_(?P<curve>\w+)\b"),
        _curve_algorithm,
        None,
        "mbedTLS curve",
        0.8,
        _curve_bits("curve"),
        needle="MBEDTLS_ECP_DP_",
    ),
    Rule(
        "c-mbedtls-rsa-pke",
        C,
        R(r"\bmbedtls_rsa_(?:pkcs1|rsaes_(?:pkcs1_v15|oaep))_(?:encrypt|decrypt)\s*\("),
        "RSA",
        "pke",
        "mbedTLS RSA encryption",
        0.9,
        needle="mbedtls_rsa_",
    ),
    Rule(
        "c-mbedtls-rsa-sign",
        C,
        R(r"\bmbedtls_rsa_(?:pkcs1|rsassa_(?:pkcs1_v15|pss))_(?:sign|verify)\s*\("),
        "RSA",
        "signature",
        "mbedTLS RSA signature",
        0.9,
        needle="mbedtls_rsa_",
    ),
    Rule(
        "c-mbedtls-ecdsa",
        C,
        R(r"\bmbedtls_ecdsa_(?:genkey|sign|verify|write_signature|read_signature)\w*\s*\("),
        "ECDSA",
        "signature",
        "mbedTLS ECDSA",
        0.9,
        needle="mbedtls_ecdsa_",
    ),
    Rule(
        "c-mbedtls-ecdh",
        C,
        R(
            r"\bmbedtls_ecdh_(?:gen_public|compute_shared|setup|make_params|make_public|calc_secret)\s*\("
        ),
        "ECDH",
        "key-agree",
        "mbedTLS ECDH",
        0.9,
        needle="mbedtls_ecdh_",
    ),
    Rule(
        "c-mbedtls-dhm",
        C,
        R(r"\bmbedtls_dhm_(?:make_params|make_public|calc_secret)\s*\("),
        "DH",
        "key-agree",
        "mbedTLS DHM",
        0.9,
        needle="mbedtls_dhm_",
    ),
    # C and C++: libsodium
    Rule(
        "c-sodium-box",
        C,
        R(
            r"\bcrypto_(?:box|kx)_(?:keypair|seed_keypair|easy|open_easy|detached|open_detached"
            r"|beforenm|afternm|client_session_keys|server_session_keys|seal|seal_open)\s*\("
        ),
        "X25519",
        "key-agree",
        "libsodium crypto_box",
        0.9,
        lambda m: 256,
        needle="crypto_",
    ),
    Rule(
        "c-sodium-scalarmult",
        C,
        R(r"\bcrypto_scalarmult(?:_curve25519)?(?:_base)?\s*\("),
        "X25519",
        "key-agree",
        "libsodium crypto_scalarmult",
        0.9,
        lambda m: 256,
        needle="crypto_scalarmult",
    ),
    Rule(
        "c-sodium-sign",
        C,
        R(
            r"\bcrypto_sign(?:_ed25519)?(?:_keypair|_seed_keypair|_detached|_verify_detached|_open)?\s*\("
        ),
        "Ed25519",
        "signature",
        "libsodium crypto_sign",
        0.9,
        lambda m: 256,
        needle="crypto_sign",
    ),
    # C and C++: wolfSSL / wolfCrypt
    Rule(
        "c-wolfssl-rsa-gen",
        C,
        R(r"\bwc_MakeRsaKey\s*\(\s*&?\w+\s*,\s*(?P<bits>\d{3,5})\b"),
        "RSA",
        None,
        "wolfCrypt wc_MakeRsaKey",
        0.9,
        _group_int("bits"),
        needle="wc_MakeRsaKey",
    ),
    Rule(
        "c-wolfssl-rsa-pke",
        C,
        R(r"\bwc_Rsa(?:Public|Private)(?:Encrypt|Decrypt)\w*\s*\("),
        "RSA",
        "pke",
        "wolfCrypt RSA encryption",
        0.9,
        needle="wc_Rsa",
    ),
    Rule(
        "c-wolfssl-rsa-sign",
        C,
        R(r"\bwc_Rsa(?:SSL|PSS)_(?:Sign|Verify)\w*\s*\("),
        "RSA",
        "signature",
        "wolfCrypt RSA signature",
        0.9,
        needle="wc_Rsa",
    ),
    Rule(
        "c-wolfssl-ecc-key",
        C,
        R(r"\bwc_ecc_make_key(?:_ex)?\s*\(\s*&?\w+\s*,\s*(?P<bytes>\d{2,3})\b"),
        "EC",
        None,
        "wolfCrypt wc_ecc_make_key",
        0.9,
        _bytes_to_bits("bytes"),
        needle="wc_ecc_make_key",
    ),
    Rule(
        "c-wolfssl-ecdsa",
        C,
        R(r"\bwc_ecc_(?:sign|verify)_hash\w*\s*\("),
        "ECDSA",
        "signature",
        "wolfCrypt ECDSA",
        0.9,
        needle="wc_ecc_",
    ),
    Rule(
        "c-wolfssl-ecdh",
        C,
        R(r"\bwc_ecc_shared_secret\w*\s*\("),
        "ECDH",
        "key-agree",
        "wolfCrypt ECDH",
        0.9,
        needle="wc_ecc_shared_secret",
    ),
    Rule(
        "c-wolfssl-curve25519",
        C,
        R(r"\bwc_curve25519_(?:make_key|shared_secret)\w*\s*\("),
        "X25519",
        "key-agree",
        "wolfCrypt curve25519",
        0.9,
        lambda m: 256,
        needle="wc_curve25519_",
    ),
    Rule(
        "c-wolfssl-ed25519",
        C,
        R(r"\bwc_ed25519_(?:make_key|sign_msg|verify_msg)\w*\s*\("),
        "Ed25519",
        "signature",
        "wolfCrypt ed25519",
        0.9,
        lambda m: 256,
        needle="wc_ed25519_",
    ),
    # C and C++: Windows CNG
    Rule(
        "c-cng-rsa",
        C,
        R(r"\bBCRYPT_(?P<alg>RSA(?:_SIGN)?)_ALGORITHM\b"),
        "RSA",
        None,
        "Windows CNG RSA",
        0.8,
        needle="BCRYPT_RSA",
    ),
    Rule(
        "c-cng-ecdsa",
        C,
        R(r"\bBCRYPT_ECDSA(?:_(?P<curve>P256|P384|P521))?_ALGORITHM\b"),
        "ECDSA",
        "signature",
        "Windows CNG ECDSA",
        0.8,
        _curve_bits("curve"),
        needle="BCRYPT_ECDSA",
    ),
    Rule(
        "c-cng-ecdh",
        C,
        R(r"\bBCRYPT_ECDH(?:_(?P<curve>P256|P384|P521))?_ALGORITHM\b"),
        "ECDH",
        "key-agree",
        "Windows CNG ECDH",
        0.8,
        _curve_bits("curve"),
        needle="BCRYPT_ECDH",
    ),
    Rule(
        "c-cng-legacy",
        C,
        R(r"\bBCRYPT_(?P<alg>DH|DSA)_ALGORITHM\b"),
        _cng_algorithm,
        None,
        "Windows CNG DH/DSA",
        0.8,
        needle="BCRYPT_D",
    ),
    # Swift and Objective-C: CryptoKit, swift-crypto, Security framework
    Rule(
        "swift-cryptokit-signing",
        SWIFT,
        R(r"\b(?P<curve>P256|P384|P521|Curve25519)\.Signing\b"),
        _cryptokit_signing,
        "signature",
        "CryptoKit Signing",
        0.9,
        _curve_bits("curve"),
        needle=".Signing",
    ),
    Rule(
        "swift-cryptokit-agreement",
        SWIFT,
        R(r"\b(?P<curve>P256|P384|P521|Curve25519)\.KeyAgreement\b"),
        _cryptokit_agreement,
        "key-agree",
        "CryptoKit KeyAgreement",
        0.9,
        _curve_bits("curve"),
        needle=".KeyAgreement",
    ),
    Rule(
        "swift-crypto-rsa-signing",
        SWIFT,
        R(r"\b_RSA\.Signing\.(?:PrivateKey|PublicKey)\b(?:.*?keySize:\s*\.bits(?P<bits>\d{4}))?"),
        "RSA",
        "signature",
        "swift-crypto _RSA.Signing",
        0.9,
        _group_int("bits"),
        needle="_RSA.Signing",
    ),
    Rule(
        "swift-crypto-rsa-encryption",
        SWIFT,
        R(
            r"\b_RSA\.Encryption\.(?:PrivateKey|PublicKey)\b(?:.*?keySize:\s*\.bits(?P<bits>\d{4}))?"
        ),
        "RSA",
        "pke",
        "swift-crypto _RSA.Encryption",
        0.9,
        _group_int("bits"),
        needle="_RSA.Encryption",
    ),
    Rule(
        "swift-seckey-rsa",
        SWIFT,
        R(r"\bkSecAttrKeyTypeRSA\b(?:.*?kSecAttrKeySizeInBits\D*(?P<bits>\d{3,5}))?"),
        "RSA",
        None,
        "Security framework kSecAttrKeyTypeRSA",
        0.8,
        _group_int("bits"),
        needle="kSecAttrKeyTypeRSA",
    ),
    Rule(
        "swift-seckey-ec",
        SWIFT,
        R(
            r"\bkSecAttrKeyTypeEC(?:SECPrimeRandom)?\b(?:.*?kSecAttrKeySizeInBits\D*(?P<bits>\d{3}))?"
        ),
        "EC",
        None,
        "Security framework kSecAttrKeyTypeEC",
        0.8,
        _group_int("bits"),
        needle="kSecAttrKeyTypeEC",
    ),
    Rule(
        "swift-seckey-rsa-pke",
        SWIFT,
        R(r"(?:\.rsaEncryption|\bkSecKeyAlgorithmRSAEncryption)\w*"),
        "RSA",
        "pke",
        "SecKeyAlgorithm RSA encryption",
        0.9,
        needle="Encryption",
    ),
    Rule(
        "swift-seckey-rsa-sign",
        SWIFT,
        R(r"(?:\.rsaSignature|\bkSecKeyAlgorithmRSASignature)\w*"),
        "RSA",
        "signature",
        "SecKeyAlgorithm RSA signature",
        0.9,
        needle="Signature",
    ),
    Rule(
        "swift-seckey-ecdsa",
        SWIFT,
        R(r"(?:\.ecdsaSignature|\bkSecKeyAlgorithmECDSASignature)\w*"),
        "ECDSA",
        "signature",
        "SecKeyAlgorithm ECDSA",
        0.9,
        needle="Signature",
    ),
    Rule(
        "swift-seckey-ecdh",
        SWIFT,
        R(r"(?:\.ecdhKeyExchange|\bkSecKeyAlgorithmECDHKeyExchange)\w*"),
        "ECDH",
        "key-agree",
        "SecKeyAlgorithm ECDH",
        0.9,
        needle="KeyExchange",
    ),
    # Dart and Flutter: pointycastle, package:cryptography, fast_rsa
    Rule(
        "dart-pointycastle-rsa-params",
        DART,
        R(r"\bRSAKeyGeneratorParameters\s*\(.*?,\s*(?P<bits>\d{3,5})\s*,"),
        "RSA",
        None,
        "pointycastle RSAKeyGeneratorParameters",
        0.9,
        _group_int("bits"),
        needle="RSAKeyGeneratorParameters",
    ),
    Rule(
        "dart-pointycastle-rsa-gen",
        DART,
        R(r"\bRSAKeyGenerator\s*\("),
        "RSA",
        None,
        "pointycastle RSAKeyGenerator",
        0.8,
        needle="RSAKeyGenerator",
    ),
    Rule(
        "dart-pointycastle-ec-curve",
        DART,
        R(r"\bECCurve_(?P<curve>\w+)\s*\("),
        "EC",
        None,
        "pointycastle ECCurve",
        0.9,
        _curve_bits("curve"),
        needle="ECCurve_",
    ),
    Rule(
        "dart-pointycastle-ec-domain",
        DART,
        R(r"\bECDomainParameters\s*\(\s*['\"](?P<curve>[\w-]+)"),
        "EC",
        None,
        "pointycastle ECDomainParameters",
        0.9,
        _curve_bits("curve"),
        needle="ECDomainParameters",
    ),
    Rule(
        "dart-pointycastle-ec-gen",
        DART,
        R(r"\bECKeyGenerator\s*\("),
        "EC",
        None,
        "pointycastle ECKeyGenerator",
        0.8,
        needle="ECKeyGenerator",
    ),
    Rule(
        "dart-pointycastle-rsa-engine",
        DART,
        R(r"\bRSAEngine\s*\("),
        "RSA",
        "pke",
        "pointycastle RSAEngine",
        0.8,
        needle="RSAEngine",
    ),
    Rule(
        "dart-pointycastle-rsa-signer",
        DART,
        R(r"\bRSASigner\s*\("),
        "RSA",
        "signature",
        "pointycastle RSASigner",
        0.9,
        needle="RSASigner",
    ),
    Rule(
        "dart-pointycastle-ecdsa",
        DART,
        R(r"\bECDSASigner\s*\("),
        "ECDSA",
        "signature",
        "pointycastle ECDSASigner",
        0.9,
        needle="ECDSASigner",
    ),
    Rule(
        "dart-cryptography-x25519",
        DART,
        R(r"\bX25519\s*\("),
        "X25519",
        "key-agree",
        "package:cryptography X25519",
        0.8,
        lambda m: 256,
        needle="X25519",
    ),
    Rule(
        "dart-cryptography-ed25519",
        DART,
        R(r"\bEd25519\s*\("),
        "Ed25519",
        "signature",
        "package:cryptography Ed25519",
        0.8,
        lambda m: 256,
        needle="Ed25519",
    ),
    Rule(
        "dart-cryptography-ecdsa",
        DART,
        R(r"\bEcdsa\.(?P<curve>p256|p384|p521)\s*\("),
        "ECDSA",
        "signature",
        "package:cryptography Ecdsa",
        0.9,
        _curve_bits("curve"),
        needle="Ecdsa.",
    ),
    Rule(
        "dart-cryptography-ecdh",
        DART,
        R(r"\bEcdh\.(?P<curve>p256|p384|p521)\s*\("),
        "ECDH",
        "key-agree",
        "package:cryptography Ecdh",
        0.9,
        _curve_bits("curve"),
        needle="Ecdh.",
    ),
    Rule(
        "dart-cryptography-rsa",
        DART,
        R(r"\bRsa(?P<kind>Pss|SsaPkcs1v15)\s*\("),
        lambda m: "RSA-PSS" if m.group("kind") == "Pss" else "RSA",
        "signature",
        "package:cryptography RSA signature",
        0.9,
        needle="Rsa",
    ),
    Rule(
        "dart-fast-rsa",
        DART,
        R(r"\bRSA\.generate\s*\(\s*(?P<bits>\d{3,5})"),
        "RSA",
        None,
        "fast_rsa RSA.generate",
        0.9,
        _group_int("bits"),
        needle="RSA.generate",
    ),
    # Post-quantum algorithms, any language: recorded as quantum-safe assets
    Rule(
        "any-pqc",
        PYTHON + JS + GO + JAVA + CSHARP + RUST + RUBY + PHP + C + SWIFT + DART,
        R(
            r"\b(?P<name>ML[-_]?KEM|Kyber|ML[-_]?DSA|Dilithium|SLH[-_]?DSA|SPHINCS)(?:[-_]?(?P<bits>\d{2,4}))?\b",
            re.IGNORECASE,
        ),
        _pqc_algorithm,
        None,
        "Post-quantum algorithm",
        0.7,
        _group_int("bits"),
        quantum_safe=True,
        needle="",
    ),
]


def pqc_primitive(algorithm: str) -> str:
    return "kem" if algorithm == "ML-KEM" else "signature"
