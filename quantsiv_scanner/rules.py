"""Pattern rules for cryptographic asset detection (D2: Quantsiv's own rules engine).

Each rule matches one line of source (or script) and yields a finding: algorithm, CycloneDX
primitive where the usage is clear, key size where the code states it, and a confidence. This
is pattern matching without type resolution: it can miss aliased imports and dynamic calls, and
it can report test fixtures or comments. Every rule says so through its confidence (0.6-0.9).

Coverage (see docs/scanner.md): Python (PyCryptodome, pyca/cryptography, PyJWT), JavaScript and
TypeScript (Node crypto, WebCrypto, jose/jsonwebtoken, node-forge), Go (crypto/*), Java and
Kotlin (JCA), C# (.NET), Rust (openssl, rsa, ring, dalek), Ruby and PHP (OpenSSL), and OpenSSL,
ssh-keygen and keytool commands in shell scripts, Dockerfiles, Makefiles and CI YAML.
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
    "ED448": 448,
    "BRAINPOOLP256R1": 256,
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
    if curve in ("X25519", "CURVE25519", "X448"):
        return curve.replace("CURVE25519", "X25519")
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
    # Post-quantum algorithms, any language: recorded as quantum-safe assets
    Rule(
        "any-pqc",
        PYTHON + JS + GO + JAVA + CSHARP + RUST + RUBY + PHP,
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
