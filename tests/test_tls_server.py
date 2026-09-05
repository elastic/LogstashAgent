#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for agent server TLS (key + CSR + persist)."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from logstashagent import tls_server


def test_build_csr_and_persist(tmp_path, monkeypatch):
    from logstashagent import tls_trust

    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    monkeypatch.delenv("LOGSTASH_UI_URL", raising=False)
    monkeypatch.delenv("LOGSTASHUI_URL", raising=False)

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
    assert kw == {}


def test_cert_needs_reissue_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)
    assert tls_server.cert_needs_reissue()


def test_uvicorn_ssl_kwargs_empty_when_tls_env_false(tmp_path, monkeypatch):
    from logstashagent import tls_trust

    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "false")
    monkeypatch.setenv("LOGSTASH_UI_URL", "https://ui.example.com")
    (tmp_path / tls_trust.CA_FILENAME).write_text("x", encoding="utf-8")
    (tmp_path / tls_trust.FINGERPRINT_FILENAME).write_text("f" * 64, encoding="utf-8")
    (tmp_path / tls_server.CERT_FILENAME).write_text("cert", encoding="utf-8")
    (tmp_path / tls_server.KEY_FILENAME).write_text("key", encoding="utf-8")
    assert tls_server.uvicorn_ssl_kwargs() == {}


def test_uvicorn_ssl_kwargs_when_gate_open(tmp_path, monkeypatch):
    from logstashagent import tls_trust

    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "true")
    monkeypatch.setenv("LOGSTASH_UI_URL", "https://ui.example.com")
    (tmp_path / tls_trust.CA_FILENAME).write_text("x", encoding="utf-8")
    (tmp_path / tls_trust.FINGERPRINT_FILENAME).write_text("f" * 64, encoding="utf-8")
    (tmp_path / tls_server.CERT_FILENAME).write_text("cert", encoding="utf-8")
    (tmp_path / tls_server.KEY_FILENAME).write_text("key", encoding="utf-8")
    kw = tls_server.uvicorn_ssl_kwargs()
    assert kw["ssl_certfile"] == str(tls_server.cert_path())
    assert kw["ssl_keyfile"] == str(tls_server.key_path())


def test_ensure_agent_server_tls_skips_when_tls_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "false")
    monkeypatch.setenv("LOGSTASH_UI_URL", "https://ui.example.com")
    called = {"issue": 0}

    def boom(*a, **k):
        called["issue"] += 1
        raise AssertionError("must not issue")

    monkeypatch.setattr(tls_server, "issue_via_ui", boom)
    assert tls_server.ensure_agent_server_tls(retries=1, retry_interval_sec=0) is False
    assert called["issue"] == 0


def test_csr_pem_for_request_none_when_gate_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_server, "tls_server_dir", lambda: tmp_path)
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "false")
    monkeypatch.setenv("LOGSTASH_UI_URL", "https://ui.example.com")
    assert tls_server.csr_pem_for_request() is None
