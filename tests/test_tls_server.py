#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for agent server TLS (key + CSR + persist)."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from logstashagent import tls_server


def test_build_csr_and_persist(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)

    csr_pem = tls_server.build_csr_pem(sans=["myagent", "localhost"])
    assert b"BEGIN CERTIFICATE REQUEST" in csr_pem
    assert tls_server.key_path().is_file()

    # Self-sign-like fake: use a throwaway CA-less leaf from cryptography for persist test
    # Actually persist only needs parseable cert — build a quick self-signed
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    key = serialization.load_pem_private_key(tls_server.key_path().read_bytes(), password=None)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myagent")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    tls_server.persist_server_certificate(pem)
    assert tls_server.has_server_cert()
    # Self-signed test leaf lacks host SANs → re-issue is expected until UI signs full CSR
    assert tls_server.cert_needs_reissue(renew_within_days=7) is True
    kw = tls_server.uvicorn_ssl_kwargs()
    assert "ssl_certfile" in kw
    assert "ssl_keyfile" in kw


def test_cert_needs_reissue_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)
    assert tls_server.cert_needs_reissue()
