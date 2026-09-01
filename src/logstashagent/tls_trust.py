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

Without a token (typical embedded compose), a background bootstrap loop can
TOFU-fetch the same well-known CA with verify=False until the UI is up, then
all later agent→UI calls use the pinned CA. That is not a per-request mode flag.
"""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

WELL_KNOWN_CA_SUFFIX = "/.well-known/logstashui/ca.crt"
CA_FILENAME = "product-ca.crt"
FINGERPRINT_FILENAME = "product-ca.fingerprint"

# Bootstrap loop status (for /_logstash/tls-status and UI indicators)
_bootstrap_lock = threading.Lock()
_bootstrap_state: dict[str, Any] = {
    "status": "idle",  # idle | running | ok | error
    "ui_url": None,
    "last_error": None,
    "last_attempt_at": None,
    "pinned_at": None,
    "attempts": 0,
}
_bootstrap_thread: Optional[threading.Thread] = None


def tls_dir() -> Path:
    """Directory for persisted product CA (next to agent state)."""
    try:
        from logstashagent import agent_state

        # Prefer package data dir used for state.json
        base = Path(agent_state.__file__).resolve().parent / "data" / "tls"
    except Exception:
        base = Path.cwd() / "data" / "tls"
    # Prefer install path if present
    for candidate in (
        Path("/opt/logstash-agent/state/tls"),
        Path("/var/lib/logstash-agent/tls"),  # legacy
    ):
        if candidate.parent.is_dir() and os.access(candidate.parent, os.W_OK):
            base = candidate
            break
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


def _set_bootstrap_state(**kwargs: Any) -> None:
    with _bootstrap_lock:
        _bootstrap_state.update(kwargs)


def get_tls_status() -> dict[str, Any]:
    """Status for UI indicators: online (UI CA reachable) / secure (CA pinned)."""
    with _bootstrap_lock:
        boot = dict(_bootstrap_state)
    fp = load_persisted_fingerprint()
    pinned = bool(fp and ca_cert_file().is_file())
    return {
        "ca_pinned": pinned,
        "secure": pinned,
        "fingerprint": fp,
        "ui_url": boot.get("ui_url"),
        "bootstrap_status": boot.get("status"),
        "bootstrap_attempts": boot.get("attempts"),
        "last_error": boot.get("last_error"),
        "last_attempt_at": boot.get("last_attempt_at"),
        "pinned_at": boot.get("pinned_at"),
        "ca_path": str(ca_cert_file()) if pinned else None,
        "well_known_path": WELL_KNOWN_CA_SUFFIX,
    }


def fetch_product_ca_bootstrap(
    ui_url: str,
    fingerprint_hex: Optional[str] = None,
    *,
    timeout: float = 15,
) -> Path:
    """
    Download CA from well-known path and persist.

    *always* uses verify=False for this single bootstrap GET (UI may still be
    presenting a product-CA leaf the agent does not yet trust).

    If fingerprint_hex is set, require SHA-256(DER) match (enroll pin).
    If omitted, TOFU: accept whatever CA is served (embedded compose bootstrap).
    """
    url = ca_url_for_ui(ui_url)
    logger.info("Bootstrap-fetching product CA from %s", url)
    resp = requests.get(url, timeout=timeout, verify=False)
    resp.raise_for_status()
    body = resp.content
    cert = load_pem_cert(body)
    actual = fingerprint_sha256_der(cert)
    if fingerprint_hex:
        expected = fingerprint_hex.strip().lower()
        if not expected or len(expected) != 64:
            raise ValueError("Invalid CA fingerprint (expect 64 hex chars)")
        if actual != expected:
            raise ValueError(
                f"Product CA fingerprint mismatch: expected {expected}, got {actual}"
            )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    persist_product_ca(pem, actual)
    return ca_cert_file()


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
    return fetch_product_ca_bootstrap(
        ui_url, fingerprint_hex=fingerprint_hex, timeout=timeout
    )


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


def resolve_ui_url_for_bootstrap(agent_config: Optional[dict] = None) -> Optional[str]:
    """logstash_ui_url from env, config, or agent state."""
    url = (os.environ.get("LOGSTASH_UI_URL") or os.environ.get("LOGSTASHUI_URL") or "").strip()
    if not url and agent_config:
        url = (agent_config.get("logstash_ui_url") or "").strip()
    if not url:
        try:
            from logstashagent import agent_state

            url = (agent_state.get_state().get("logstash_ui_url") or "").strip()
        except Exception:
            url = ""
    return url.rstrip("/") if url else None


def product_ca_already_pinned() -> bool:
    return bool(load_persisted_fingerprint() and ca_cert_file().is_file())


def _bootstrap_loop(
    ui_url: str,
    fingerprint: Optional[str],
    interval_sec: float,
    max_attempts: int,
) -> None:
    _set_bootstrap_state(
        status="running",
        ui_url=ui_url,
        last_error=None,
        attempts=0,
    )
    attempt = 0
    while True:
        attempt += 1
        _set_bootstrap_state(
            attempts=attempt,
            last_attempt_at=datetime.now(timezone.utc).isoformat(),
        )
        try:
            fetch_product_ca_bootstrap(ui_url, fingerprint_hex=fingerprint)
            _set_bootstrap_state(
                status="ok",
                last_error=None,
                pinned_at=datetime.now(timezone.utc).isoformat(),
            )
            logger.info(
                "UI product CA bootstrap succeeded after %s attempt(s) (ui=%s)",
                attempt,
                ui_url,
            )
            return
        except Exception as e:
            _set_bootstrap_state(last_error=str(e))
            if max_attempts > 0 and attempt >= max_attempts:
                _set_bootstrap_state(status="error")
                logger.error(
                    "UI product CA bootstrap failed after %s attempts: %s",
                    attempt,
                    e,
                )
                return
            logger.warning(
                "UI product CA bootstrap attempt %s failed (%s); retry in %ss",
                attempt,
                e,
                interval_sec,
            )
            time.sleep(interval_sec)


def start_ui_ca_bootstrap_loop(
    ui_url: Optional[str] = None,
    *,
    agent_config: Optional[dict] = None,
    fingerprint: Optional[str] = None,
    interval_sec: float = 5.0,
    max_attempts: int = 0,
) -> bool:
    """
    Start background retries to pin product CA from well-known URL.

    Returns True if a thread was started (or CA already pinned).
    max_attempts=0 means retry forever.

    Fingerprint may come from env LOGSTASHUI_CA_FINGERPRINT (optional TOFU if unset).
    """
    global _bootstrap_thread

    if product_ca_already_pinned():
        _set_bootstrap_state(
            status="ok",
            ui_url=ui_url or resolve_ui_url_for_bootstrap(agent_config),
            pinned_at=datetime.now(timezone.utc).isoformat(),
            last_error=None,
        )
        logger.info("Product CA already pinned; bootstrap loop not needed")
        return True

    url = (ui_url or resolve_ui_url_for_bootstrap(agent_config) or "").strip().rstrip("/")
    if not url:
        logger.info("No logstash_ui_url for CA bootstrap; skip")
        _set_bootstrap_state(status="idle", last_error="no logstash_ui_url")
        return False

    fp = fingerprint or (os.environ.get("LOGSTASHUI_CA_FINGERPRINT") or "").strip() or None

    with _bootstrap_lock:
        if _bootstrap_thread is not None and _bootstrap_thread.is_alive():
            logger.debug("CA bootstrap thread already running")
            return True
        t = threading.Thread(
            target=_bootstrap_loop,
            args=(url, fp, interval_sec, max_attempts),
            name="ui-ca-bootstrap",
            daemon=True,
        )
        _bootstrap_thread = t
        t.start()
    logger.info(
        "Started UI CA bootstrap loop (ui=%s, fingerprint=%s)",
        url,
        "yes" if fp else "tofu",
    )
    return True


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
