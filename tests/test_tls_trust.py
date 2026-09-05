#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for product CA pin-and-fetch (tls_trust)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
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


def test_bootstrap_tofu_without_fingerprint(tmp_path, monkeypatch):
    pem, fp = _make_ca()
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    mock_resp = MagicMock()
    mock_resp.content = pem
    mock_resp.raise_for_status = MagicMock()
    with patch.object(tls_trust.requests, "get", return_value=mock_resp):
        path = tls_trust.fetch_product_ca_bootstrap("http://logstashui:8080")
    assert path.is_file()
    assert tls_trust.load_persisted_fingerprint() == fp


def test_ui_url_is_tls_https_and_http():
    assert tls_trust.ui_url_is_tls("https://ui.example.com") is True
    assert tls_trust.ui_url_is_tls("HTTPS://ui.example.com/path") is True
    assert tls_trust.ui_url_is_tls("http://ui.example.com") is False
    assert tls_trust.ui_url_is_tls("  https://ui.example.com  ") is True


def test_ui_url_is_tls_missing_or_unknown_scheme(monkeypatch):
    monkeypatch.delenv("LOGSTASH_UI_URL", raising=False)
    monkeypatch.delenv("LOGSTASHUI_URL", raising=False)
    assert tls_trust.ui_url_is_tls("") is False
    assert tls_trust.ui_url_is_tls(None) is False
    assert tls_trust.ui_url_is_tls("ui.example.com:8443") is False
    assert tls_trust.ui_url_is_tls("ftp://ui.example.com") is False


def test_agent_tls_enabled_defaults_true(monkeypatch):
    monkeypatch.delenv("LOGSTASH_AGENT_TLS", raising=False)
    assert tls_trust.agent_tls_enabled() is True
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "true")
    assert tls_trust.agent_tls_enabled() is True
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "garbage")
    assert tls_trust.agent_tls_enabled() is True
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "false")
    assert tls_trust.agent_tls_enabled() is False
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "0")
    assert tls_trust.agent_tls_enabled() is False
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "OFF")
    assert tls_trust.agent_tls_enabled() is False


def test_ui_tls_insecure_defaults_false(monkeypatch):
    monkeypatch.delenv("LOGSTASH_UI_TLS_INSECURE", raising=False)
    assert tls_trust.ui_tls_insecure() is False
    monkeypatch.setenv("LOGSTASH_UI_TLS_INSECURE", "true")
    assert tls_trust.ui_tls_insecure() is True
    monkeypatch.setenv("LOGSTASH_UI_TLS_INSECURE", "1")
    assert tls_trust.ui_tls_insecure() is True
    monkeypatch.setenv("LOGSTASH_UI_TLS_INSECURE", "nope")
    assert tls_trust.ui_tls_insecure() is False


def test_ssl_verify_argument_http_is_false(monkeypatch):
    monkeypatch.delenv("LOGSTASH_UI_TLS_INSECURE", raising=False)
    assert tls_trust.ssl_verify_argument("http://ui.example.com") is False


def test_ssl_verify_argument_https_insecure_is_false(monkeypatch):
    monkeypatch.setenv("LOGSTASH_UI_TLS_INSECURE", "true")
    assert tls_trust.ssl_verify_argument("https://ui.example.com") is False


def test_ssl_verify_argument_https_secure_true_without_pin(monkeypatch, tmp_path):
    monkeypatch.delenv("LOGSTASH_UI_TLS_INSECURE", raising=False)
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    assert tls_trust.ssl_verify_argument("https://ui.example.com") is True


def test_ensure_trust_skips_non_https(monkeypatch):
    monkeypatch.delenv("LOGSTASH_UI_TLS_INSECURE", raising=False)
    assert (
        tls_trust.ensure_trust_from_token_payload(
            "http://ui.example.com",
            {"fingerprint": "a" * 64},
        )
        is None
    )


def test_ensure_trust_insecure_https_does_not_raise(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGSTASH_UI_TLS_INSECURE", "true")
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    with patch.object(
        tls_trust.requests,
        "get",
        side_effect=requests.exceptions.ConnectionError("down"),
    ):
        assert (
            tls_trust.ensure_trust_from_token_payload(
                "https://ui.example.com",
                {"fingerprint": "a" * 64},
            )
            is None
        )


def test_start_bootstrap_skips_http(monkeypatch):
    monkeypatch.delenv("LOGSTASH_UI_TLS_INSECURE", raising=False)
    assert tls_trust.start_ui_ca_bootstrap_loop(ui_url="http://ui.example.com") is False


def test_inbound_tls_ok_requires_all_three(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "true")
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    assert tls_trust.inbound_tls_ok("https://ui.example.com") is False  # no CA
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "false")
    (tmp_path / tls_trust.CA_FILENAME).write_text("x", encoding="utf-8")
    (tmp_path / tls_trust.FINGERPRINT_FILENAME).write_text("f" * 64, encoding="utf-8")
    assert tls_trust.inbound_tls_ok("https://ui.example.com") is False
    monkeypatch.setenv("LOGSTASH_AGENT_TLS", "true")
    assert tls_trust.inbound_tls_ok("http://ui.example.com") is False
    assert tls_trust.inbound_tls_ok("https://ui.example.com") is True


def test_bootstrap_loop_retries_then_ok(tmp_path, monkeypatch):
    pem, fp = _make_ca()
    monkeypatch.setattr(tls_trust, "tls_dir", lambda: tmp_path)
    # Reset global bootstrap state
    tls_trust._bootstrap_state.update(
        {"status": "idle", "attempts": 0, "last_error": None}
    )

    calls = {"n": 0}

    def fake_get(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise requests.exceptions.ConnectionError("not ready")
        m = MagicMock()
        m.content = pem
        m.raise_for_status = MagicMock()
        return m

    with patch.object(tls_trust.requests, "get", side_effect=fake_get), patch.object(
        tls_trust.time, "sleep"
    ):
        tls_trust._bootstrap_loop("http://ui:8080", None, interval_sec=0.01, max_attempts=0)
        # force exit after success — loop returns on success
    assert tls_trust.product_ca_already_pinned()
    status = tls_trust.get_tls_status()
    assert status["secure"] is True
    assert status["bootstrap_status"] == "ok"
    assert calls["n"] >= 3
