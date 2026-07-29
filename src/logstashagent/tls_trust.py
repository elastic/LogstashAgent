#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
TLS trust for agent → LogstashUI.

Enrollment token may include an optional product-CA fingerprint (SHA-256 of DER,
lowercase hex). When present, the agent fetches:

  {logstash_ui_url}/.well-known/logstashui/ca.crt

verifies the fingerprint, persists the CA, and uses system CAs ∪ product CA for
TLS verification (never blind verify=False when a pin is active).
"""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
import tempfile
from pathlib import Path
from typing import Any, Optional, Tuple, Union

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

WELL_KNOWN_CA_SUFFIX = "/.well-known/logstashui/ca.crt"
CA_FILENAME = "product-ca.crt"
FINGERPRINT_FILENAME = "product-ca.fingerprint"


def tls_dir() -> Path:
    """Directory for persisted product CA (next to agent state)."""
    try:
        from logstashagent import agent_state

        # Prefer package data dir used for state.json
        base = Path(agent_state.__file__).resolve().parent / "data" / "tls"
    except Exception:
        base = Path.cwd() / "data" / "tls"
    # Prefer install path if present
    install_tls = Path("/var/lib/logstash-agent/tls")
    if install_tls.parent.is_dir() and os.access(install_tls.parent, os.W_OK):
        base = install_tls
    base.mkdir(parents=True, exist_ok=True)
    return base


def ca_cert_file() -> Path:
    return tls_dir() / CA_FILENAME


def fingerprint_file() -> Path:
    return tls_dir() / FINGERPRINT_FILENAME


def fingerprint_sha256_der(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def load_pem_cert(data: bytes) -> x509.Certificate:
    text = data.strip()
    if b"BEGIN CERTIFICATE" in text:
        return x509.load_pem_x509_certificate(text)
    return x509.load_der_x509_certificate(text)


def ca_url_for_ui(ui_url: str) -> str:
    return ui_url.rstrip("/") + WELL_KNOWN_CA_SUFFIX


def persist_product_ca(cert_pem: bytes, fingerprint_hex: str) -> None:
    ca_cert_file().write_bytes(
        cert_pem if b"BEGIN CERTIFICATE" in cert_pem
        else load_pem_cert(cert_pem).public_bytes(serialization.Encoding.PEM)
    )
    fingerprint_file().write_text(fingerprint_hex.strip().lower() + "\n", encoding="utf-8")
    try:
        ca_cert_file().chmod(0o644)
        fingerprint_file().chmod(0o644)
    except OSError:
        pass
    logger.info("Persisted product CA fingerprint=%s…", fingerprint_hex[:16])


def load_persisted_fingerprint() -> Optional[str]:
    path = fingerprint_file()
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip().lower() or None


def fetch_and_pin_product_ca(
    ui_url: str,
    fingerprint_hex: str,
    *,
    timeout: float = 30,
) -> Path:
    """
    Download CA from well-known path, verify SHA-256(DER) == fingerprint, persist.

    Uses verify=False only for this bootstrap GET (pin is the trust). Subsequent
    UI calls use the combined trust store.
    """
    expected = fingerprint_hex.strip().lower()
    if not expected or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("Invalid CA fingerprint (expect 64 lowercase hex chars)")

    url = ca_url_for_ui(ui_url)
    logger.info("Fetching product CA from %s", url)
    # Bootstrap: cannot verify UI cert until we have product CA (OOTB case).
    # Fingerprint binds the downloaded object.
    resp = requests.get(url, timeout=timeout, verify=False)
    resp.raise_for_status()
    body = resp.content
    cert = load_pem_cert(body)
    actual = fingerprint_sha256_der(cert)
    if actual != expected:
        raise ValueError(
            f"Product CA fingerprint mismatch: expected {expected}, got {actual}"
        )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    persist_product_ca(pem, actual)
    return ca_cert_file()


def ensure_trust_from_token_payload(
    ui_url: str,
    token_payload: dict,
) -> Optional[str]:
    """
    If token has fingerprint, pin CA (fetch if needed). Return fingerprint or None.
    """
    fp = (token_payload or {}).get("fingerprint") or (token_payload or {}).get(
        "ca_fingerprint_sha256"
    )
    if not fp:
        logger.info("Enrollment token has no CA fingerprint; using system trust only")
        return None
    fp = str(fp).strip().lower()
    existing = load_persisted_fingerprint()
    if existing == fp and ca_cert_file().is_file():
        logger.info("Product CA already pinned (fingerprint match)")
        return fp
    fetch_and_pin_product_ca(ui_url, fp)
    return fp


def requests_verify_param() -> Union[bool, str]:
    """
    Value for requests ``verify=``:

    - path to product CA PEM if pinned (and we merge system CAs via SSLContext
      when possible — see ``ssl_verify_argument``)
    - True for system CAs only
    """
    path = ca_cert_file()
    if path.is_file():
        return str(path)
    return True


def build_ssl_context() -> ssl.SSLContext:
    """SSLContext: system defaults + optional product CA."""
    ctx = ssl.create_default_context()
    path = ca_cert_file()
    if path.is_file():
        ctx.load_verify_locations(cafile=str(path))
        logger.debug("SSL context includes product CA %s", path)
    return ctx


def ssl_verify_argument() -> Union[bool, str]:
    """
    For requests: when product CA is present, pass CA file path.
    Note: requests replaces the default store when a path is given; for public
    UI certs we still need system CAs. Use certifi bundle + product CA temp file.
    """
    path = ca_cert_file()
    if not path.is_file():
        return True
    # Merge system + product CA into a combined bundle for requests
    try:
        import certifi

        system_pem = Path(certifi.where()).read_text(encoding="utf-8")
    except Exception:
        # Fall back to product CA only (OOTB UI) or True
        return str(path)
    product_pem = path.read_text(encoding="utf-8")
    combined = system_pem.rstrip() + "\n" + product_pem
    # Stable path next to product CA so we don't leak temp files
    bundle = tls_dir() / "combined-ca-bundle.pem"
    bundle.write_text(combined, encoding="utf-8")
    return str(bundle)


def ui_request(
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """requests wrapper that applies product CA + system trust when available."""
    if "verify" not in kwargs:
        kwargs["verify"] = ssl_verify_argument()
    return requests.request(method, url, **kwargs)
