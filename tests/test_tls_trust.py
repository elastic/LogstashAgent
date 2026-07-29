#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for product CA pin-and-fetch (tls_trust)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from logstashagent import tls_trust


def _make_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    fp = tls_trust.fingerprint_sha256_der(cert)
    return pem, fp


def test_ca_url_for_ui():
    assert tls_trust.ca_url_for_ui("https://ui.example.com") == (
        "https://ui.example.com/.well-known/logstashui/ca.crt"
    )
    assert tls_trust.ca_url_for_ui("https://ui.example.com/") == (
        "https://ui.example.com/.well-known/logstashui/ca.crt"
    )


def test_fetch_and_pin_success(tmp_path, monkeypatch):
    pem, fp = _make_ca()
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)

    mock_resp = MagicMock()
    mock_resp.content = pem
    mock_resp.raise_for_status = MagicMock()

    with patch.object(tls_trust.requests, "get", return_value=mock_resp) as get:
        path = tls_trust.fetch_and_pin_product_ca("https://ui.example", fp)

    get.assert_called_once()
    assert "well-known/logstashui/ca.crt" in get.call_args[0][0]
    assert path.is_file()
    assert tls_trust.load_persisted_fingerprint() == fp


def test_fetch_fingerprint_mismatch(tmp_path, monkeypatch):
    pem, fp = _make_ca()
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    mock_resp = MagicMock()
    mock_resp.content = pem
    mock_resp.raise_for_status = MagicMock()
    with patch.object(tls_trust.requests, "get", return_value=mock_resp):
        with pytest.raises(ValueError, match="mismatch"):
            tls_trust.fetch_and_pin_product_ca(
                "https://ui.example", "0" * 64
            )


def test_ensure_trust_no_fingerprint():
    assert tls_trust.ensure_trust_from_token_payload(
        "https://ui", {"enrollment_token": "x"}
    ) is None


def test_ensure_trust_with_fingerprint(tmp_path, monkeypatch):
    pem, fp = _make_ca()
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    mock_resp = MagicMock()
    mock_resp.content = pem
    mock_resp.raise_for_status = MagicMock()
    with patch.object(tls_trust.requests, "get", return_value=mock_resp):
        out = tls_trust.ensure_trust_from_token_payload(
            "https://ui", {"enrollment_token": "x", "fingerprint": fp}
        )
    assert out == fp
