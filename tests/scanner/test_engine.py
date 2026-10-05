"""The rules engine on a fixture checkout covering every supported language."""

import os
from pathlib import Path

import pytest

from quantsiv_scanner.engine import file_kind, scan_text, scan_tree

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample")


@pytest.fixture(scope="module")
def found():
    findings, scanned = scan_tree(FIXTURE)
    return {(f.file_path, f.line_number, f.algorithm): f for f in findings}, scanned


EXPECTED = [
    # (file, line, algorithm, primitive, key_size)
    ("src/app.py", 6, "RSA", None, 2048),
    ("src/app.py", 7, "RSA", "pke", None),
    ("src/app.py", 8, "EC", None, 384),
    ("src/app.py", 9, "ECDH", "key-agree", None),
    ("src/app.py", 10, "X25519", "key-agree", 256),
    ("src/app.py", 11, "RSA", "signature", None),
    ("src/auth.js", 2, "RSA", None, 4096),
    ("src/auth.js", 3, "ECDH", "key-agree", 256),
    ("src/auth.js", 4, "RSA", "pke", None),
    ("src/auth.js", 5, "ECDSA", "signature", 256),
    ("src/webcrypto.ts", 1, "RSA", "pke", 3072),
    ("src/webcrypto.ts", 2, "ECDSA", "signature", 521),
    ("src/main.go", 12, "RSA", None, 3072),
    ("src/main.go", 13, "RSA", "signature", None),
    ("src/main.go", 14, "ECDSA", "signature", 256),
    ("src/main.go", 15, "ML-KEM", "kem", 768),
    ("src/Crypto.java", 6, "RSA", None, None),
    ("src/Crypto.java", 7, "RSA", None, 2048),
    ("src/Crypto.java", 8, "RSA", "pke", None),
    ("src/Crypto.java", 9, "ECDSA", "signature", None),
    ("src/Crypto.java", 10, "ECDH", "key-agree", None),
    ("src/Program.cs", 2, "RSA", None, 2048),
    ("src/Program.cs", 3, "ECDH", "key-agree", None),
    ("src/lib.rs", 4, "RSA", None, 2048),
    ("src/lib.rs", 5, "ECDSA", "signature", 256),
    ("src/keys.rb", 1, "RSA", None, 2048),
    ("src/keys.rb", 2, "EC", None, 256),
    ("src/gen.php", 2, "RSA", None, 2048),
    ("setup.sh", 2, "RSA", None, 4096),
    ("setup.sh", 3, "EC", None, 384),
    ("setup.sh", 4, "Ed25519", "signature", None),
    ("Dockerfile", 2, "X25519", None, 256),
    (".github-workflow.yml", 2, "RSA", None, 3072),
    ("tests/test_keys.py", 3, "RSA", None, 1024),
    ("src/crypto.c", 5, "RSA", None, 2048),
    ("src/crypto.c", 6, "X25519", "key-agree", 256),
    ("src/crypto.c", 7, "EC", None, 256),
    ("src/crypto.c", 8, "ECDSA", "signature", None),
    ("src/crypto.c", 9, "RSA", "pke", None),
    ("src/crypto.c", 10, "RSA", None, 3072),
    ("src/crypto.c", 11, "EC", None, 384),
    ("src/crypto.c", 12, "X25519", "key-agree", 256),
    ("src/crypto.c", 13, "Ed25519", "signature", 256),
    ("src/crypto.c", 14, "RSA", None, 4096),
    ("src/crypto.c", 15, "ECDH", "key-agree", 256),
    ("src/crypto.c", 16, "ML-KEM", "kem", 768),
    ("src/Keys.swift", 2, "ECDSA", "signature", 256),
    ("src/Keys.swift", 3, "X25519", "key-agree", 256),
    ("src/Keys.swift", 4, "RSA", "signature", 2048),
    ("src/Keys.swift", 5, "RSA", None, 3072),
    ("src/Keys.swift", 6, "RSA", "pke", None),
    ("src/keys.dart", 2, "RSA", None, 2048),
    ("src/keys.dart", 4, "EC", None, 256),
    ("src/keys.dart", 5, "ECDSA", "signature", None),
    ("src/keys.dart", 6, "X25519", "key-agree", 256),
    ("src/keys.dart", 7, "Ed25519", "signature", 256),
    ("src/keys.dart", 8, "ECDH", "key-agree", 384),
    ("certs/server.crt", 1, "RSA", None, 2048),
    ("certs/ec_public.pub", 1, "EC", None, 384),
    ("certs/id_rsa.pub", 1, "RSA", None, 3072),
    ("certs/id_ed25519.pub", 1, "Ed25519", "signature", 256),
    ("certs/authorized_keys", 2, "Ed25519", "signature", 256),
]


@pytest.mark.parametrize("file,line,algorithm,primitive,key_size", EXPECTED)
def test_expected_findings(found, file, line, algorithm, primitive, key_size):
    findings, _ = found
    finding = findings.get((file, line, algorithm))
    assert finding is not None, f"missing {algorithm} at {file}:{line}"
    assert finding.primitive == primitive
    assert finding.key_size == key_size
    assert 0.5 <= finding.confidence <= 1.0


def test_aes_is_not_reported_as_an_asset_by_the_rules(found):
    findings, _ = found
    assert not any(f.algorithm.startswith("AES") for f in findings.values())


def test_skipped_locations(found):
    findings, scanned = found
    paths = {f.file_path for f in findings.values()}
    assert not any(p.startswith("node_modules/") for p in paths)
    assert not any(p.startswith(".hidden/") for p in paths)
    assert "src/blob.py" not in paths  # binary
    assert "README.md" not in paths  # prose
    assert scanned >= 12


def test_pqc_assets_are_quantum_safe(found):
    findings, _ = found
    mlkem = findings[("src/main.go", 15, "ML-KEM")]
    assert mlkem.quantum_safe is True


def test_one_finding_per_line_and_algorithm():
    text = 'KeyPairGenerator.getInstance("RSA"); kpg.initialize(2048);'
    findings = scan_text(text, "X.java")
    assert [(f.algorithm, f.key_size) for f in findings] == [("RSA", 2048)]


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("RSA.generate(2048)\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(outside, repo / "linked.py")
    findings, scanned = scan_tree(str(repo))
    assert findings == [] and scanned == 0


def test_long_lines_are_skipped():
    minified = "RSA.generate(2048);" + "x" * 5000
    assert scan_text(minified, "bundle.js") == []
    assert scan_text("rsa.generate_private_key(key_size=2048)", "a.py")[0].key_size == 2048


@pytest.mark.parametrize(
    "name,kind",
    [
        ("Dockerfile", "dockerfile"),
        ("Dockerfile.web", "dockerfile"),
        ("Makefile", "makefile"),
        ("a/b/c.TS", "ts"),
        ("noext", ""),
    ],
)
def test_file_kind(name, kind):
    assert file_kind(name) == kind


def test_import_lines_are_not_assets():
    text = (
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
        "import rsa\n"
        "def f(k: Ed25519PrivateKey): ...\n"
        "key = Ed25519PrivateKey.generate()\n"
    )
    assert [(f.line_number, f.algorithm) for f in scan_text(text, "a.py")] == [(4, "Ed25519")]
    assert scan_text('import { generateKeyPairSync } from "crypto";', "a.ts") == []
    assert scan_text("use openssl::rsa::Rsa;", "a.rs") == []
    assert scan_text("#include <openssl/rsa.h>", "a.c") == []


def test_c_headers_and_objective_c_use_the_c_and_security_rules():
    assert scan_text("EVP_RSA_gen(3072);", "keys.h")[0].key_size == 3072
    objc = scan_text(
        "SecKeyCreateRandomKey(@{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA});", "k.m"
    )
    assert [(f.algorithm, f.rule_id) for f in objc] == [("RSA", "swift-seckey-rsa")]
    cpp = scan_text('auto key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");', "k.cpp")
    assert [(f.algorithm, f.primitive, f.key_size) for f in cpp] == [("Ed25519", "signature", 256)]


def test_test_code_is_flagged_not_hidden(found):
    findings, _ = found
    assert findings[("tests/test_keys.py", 3, "RSA")].test_code is True
    assert findings[("src/app.py", 6, "RSA")].test_code is False


def test_key_files_record_metadata_only(found):
    findings, _ = found
    cert = findings[("certs/server.crt", 1, "RSA")]
    assert cert.rule_id == "file-pem"
    assert cert.context_label.startswith("X.509 certificate, expires 20")
    assert cert.raw_match == "-----BEGIN CERTIFICATE-----"
    broken = findings[("certs/authorized_keys", 3, "RSA")]
    assert broken.key_size is None  # not base64: the type is still an asset
    assert not any(
        f.file_path == "certs/ec_public.pub" and f.rule_id == "file-ssh-public-key"
        for f in findings.values()
    )
