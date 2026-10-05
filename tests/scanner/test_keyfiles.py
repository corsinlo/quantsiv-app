"""Key and certificate files: algorithm and size, never the material."""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from quantsiv_scanner.engine import scan_key_material, scan_tree
from quantsiv_scanner.keyfiles import scan_pem

PEM = serialization.Encoding.PEM
NO_ENC = serialization.NoEncryption()


def private_pem(key, fmt=serialization.PrivateFormat.PKCS8, enc=NO_ENC) -> str:
    return key.private_bytes(PEM, fmt, enc).decode()


def test_private_keys_in_pem_and_openssh_formats(tmp_path):
    rsa_key = rsa.generate_private_key(65537, 2048)
    (tmp_path / "server.key").write_text(private_pem(rsa_key))
    (tmp_path / "legacy.pem").write_text(
        private_pem(rsa_key, serialization.PrivateFormat.TraditionalOpenSSL)
    )
    (tmp_path / "id_ed25519").write_text(
        private_pem(ed25519.Ed25519PrivateKey.generate(), serialization.PrivateFormat.OpenSSH)
    )
    (tmp_path / "ec.key").write_text(private_pem(ec.generate_private_key(ec.SECP256R1())))
    findings, _ = scan_tree(str(tmp_path))
    by_file = {f.file_path: f for f in findings}
    assert (by_file["server.key"].algorithm, by_file["server.key"].key_size) == ("RSA", 2048)
    assert (by_file["legacy.pem"].algorithm, by_file["legacy.pem"].key_size) == ("RSA", 2048)
    assert (by_file["ec.key"].algorithm, by_file["ec.key"].key_size) == ("EC", 256)
    assert "id_ed25519" not in by_file  # no extension: not walked (DER and binaries neither)
    assert all(f.raw_match.startswith("-----BEGIN ") for f in findings)
    assert all("MII" not in f.raw_match for f in findings)


def test_openssh_private_key_block_in_a_text_file():
    text = private_pem(ed25519.Ed25519PrivateKey.generate(), serialization.PrivateFormat.OpenSSH)
    (finding,) = scan_pem("# key\n" + text, "notes.txt")
    assert (finding.algorithm, finding.primitive, finding.key_size) == ("Ed25519", "signature", 256)
    assert finding.line_number == 2


def test_encrypted_keys():
    rsa_key = rsa.generate_private_key(65537, 2048)
    pkcs8 = private_pem(rsa_key, enc=serialization.BestAvailableEncryption(b"pw"))
    assert scan_pem(pkcs8, "a.key") == []  # algorithm unreadable without the passphrase
    legacy = private_pem(
        rsa_key,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(b"pw"),
    )
    (finding,) = scan_pem(legacy, "a.key")
    assert (finding.algorithm, finding.key_size, finding.confidence) == ("RSA", None, 0.8)


def test_embedded_pem_in_source_is_found_and_flagged_as_test_code():
    cert = Path("tests/scanner/fixtures/sample/certs/server.crt").read_text()
    source = 'CERT = """\n' + cert + '"""\n'
    (finding,) = scan_key_material(source, "tests/conftest.py")
    assert (finding.algorithm, finding.key_size, finding.test_code) == ("RSA", 2048, True)
    assert scan_key_material("no keys here", "a.py") == []


def test_malformed_pem_is_ignored():
    assert (
        scan_pem("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n", "x.crt")
        == []
    )
    assert scan_pem("-----BEGIN CERTIFICATE-----\nunterminated\n", "x.crt") == []
