"""TLS probe, findings and domain verification (A17)."""

import ssl
from datetime import UTC, datetime

import pytest

from app.services import domains
from app.services.errors import ScanError
from app.services.tls import (
    TlsProbe,
    findings_from_probe,
    probe,
    probe_endpoint,
    probe_verified_endpoint,
)
from tests.tls_server import tls_server


def test_probe_reads_version_cipher_and_certificate(tmp_path):
    with tls_server(tmp_path) as port:
        result = probe("sample.example", "127.0.0.1", port, timeout=5)
    assert result.error is None
    assert result.tls_version in ("TLSv1.3", "TLSv1.2")
    assert result.cipher_suite
    assert (result.cert_algorithm, result.cert_key_bits) == ("RSA", 2048)
    assert result.cert_subject == "CN=sample.example"
    assert result.cert_signature_algorithm == "sha256WithRSAEncryption"
    assert result.cert_expiry > datetime.now(UTC)
    assert result.ip_address == "127.0.0.1"


def test_ec_certificate_and_tls12_cipher(tmp_path):
    with tls_server(tmp_path, key_kind="ec", max_version=ssl.TLSVersion.TLSv1_2) as port:
        result = probe("sample.example", "127.0.0.1", port, timeout=5)
    assert result.tls_version == "TLSv1.2"
    assert (result.cert_algorithm, result.cert_key_bits) == ("EC", 384)
    assert result.cipher_suite.startswith("ECDHE")


def test_connection_failures_become_errors_not_exceptions():
    assert probe("x.example", "127.0.0.1", 9, timeout=1).error == "Connection failed"


def test_findings_cover_key_exchange_and_certificate(tmp_path):
    with tls_server(tmp_path) as port:
        found = findings_from_probe(probe("sample.example", "127.0.0.1", port, timeout=5))
    by_rule = {f["rule_id"]: f for f in found}
    cert = by_rule["tls-certificate"]
    assert (cert["algorithm"], cert["primitive"], cert["key_size"]) == ("RSA", "signature", 2048)
    assert cert["file_path"] == f"tls://sample.example:{port}"
    assert cert["quantum_safe"] is False
    kx = by_rule["tls-key-exchange"]
    assert kx["primitive"] in ("key-agree", "kem")
    assert kx["source"] == "tls-probe"


def base(**kwargs) -> TlsProbe:
    return TlsProbe(
        **{"domain": "a.example", "ip_address": "203.0.113.7", "tls_version": "TLSv1.3", **kwargs}
    )


def test_observed_hybrid_group_is_quantum_safe_kem():
    (kx,) = [
        f
        for f in findings_from_probe(
            base(
                key_exchange_group="X25519MLKEM768",
                pqc_key_exchange=True,
                cipher_suite="TLS_AES_256_GCM_SHA384",
            )
        )
        if f["rule_id"] == "tls-key-exchange"
    ]
    assert (kx["algorithm"], kx["primitive"], kx["quantum_safe"]) == ("X25519MLKEM768", "kem", True)


def test_observed_classical_group_is_hndl_exposed():
    (kx,) = findings_from_probe(base(key_exchange_group="x25519", pqc_key_exchange=False))
    assert (kx["algorithm"], kx["primitive"], kx["key_size"]) == ("X25519", "key-agree", 256)
    assert kx["quantum_safe"] is False


def test_tls12_rsa_key_transport_is_pke_without_forward_secrecy():
    (kx, _cert) = findings_from_probe(
        base(
            tls_version="TLSv1.2",
            cipher_suite="AES256-GCM-SHA384",
            cert_algorithm="RSA",
            cert_key_bits=2048,
            cert_expiry=datetime(2030, 1, 1, tzinfo=UTC),
        )
    )
    assert (kx["algorithm"], kx["primitive"]) == ("RSA", "pke")


def test_unknown_group_is_stated_not_guessed():
    (kx,) = findings_from_probe(base(cipher_suite="TLS_AES_128_GCM_SHA256", pqc_key_exchange=None))
    assert "not observable" in kx["context_label"]
    assert kx["confidence"] < 0.9


def test_failed_probe_has_no_findings():
    assert findings_from_probe(base(error="Connection failed")) == []


def test_hosted_probe_goes_through_the_ssrf_guard():
    with pytest.raises(ScanError):
        probe_verified_endpoint("localhost")
    with pytest.raises(ScanError):
        probe_verified_endpoint("service.railway.internal")


def test_cli_probe_reports_unresolvable_names():
    assert probe_endpoint("does-not-exist.invalid").error == "Name does not resolve"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("API.Example.com", "api.example.com"),
        ("https://api.example.com/path?x=1", "api.example.com"),
        (" example.com. ", "example.com"),
    ],
)
def test_domain_normalisation(value, expected):
    assert domains.normalise_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "10.0.0.1",
        "redis.railway.internal",
        "a_b.example.com",
        "nodot",
        "",
        "x.y",
        "a" * 300 + ".com",
    ],
)
def test_domain_normalisation_refuses(value):
    with pytest.raises(ValueError):
        domains.normalise_domain(value)


def test_verification_needs_the_exact_token():
    token = domains.new_verification_token()
    name = domains.txt_record_name("example.com")
    assert name == "_quantsiv.example.com"
    ok = lambda n: [f"quantsiv-verify={token}"] if n == name else []
    assert domains.check_verification("example.com", token, ok)
    assert not domains.check_verification("example.com", token + "x", ok)
    assert not domains.check_verification("example.com", token, lambda n: [])
    assert not domains.check_verification("example.com", token, lambda n: ["v=spf1 -all"])
