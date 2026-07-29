#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Agent server TLS: product-CA-signed leaf for uvicorn HTTPS on the agent API port.

Private key is generated and stored only on the agent. CSR is signed by LogstashUI
(product CA) at enroll, check-in re-issue, or IssueServerCert (API key / compose secret).
"""

from __future__ import annotations

import logging
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

KEY_FILENAME = "agent-server.key"
CERT_FILENAME = "agent-server.crt"
CSR_FILENAME = "agent-server.csr"


def tls_server_dir() -> Path:
    from logstashagent import tls_trust

    return tls_trust.tls_dir()


def key_path() -> Path:
    return tls_server_dir() / KEY_FILENAME


def cert_path() -> Path:
    return tls_server_dir() / CERT_FILENAME


def csr_path() -> Path:
    return tls_server_dir() / CSR_FILENAME


def ensure_private_key() -> Path:
    path = key_path()
    if path.is_file():
        return path
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass
    logger.info("Generated agent server private key at %s", path)
    return path


def _default_sans() -> list[str]:
    names = ["localhost", "logstashagent"]
    try:
        hn = socket.gethostname()
        if hn and hn not in names:
            names.append(hn)
    except Exception:
        pass
    try:
        fqdn = socket.getfqdn()
        if fqdn and fqdn not in names:
            names.append(fqdn)
    except Exception:
        pass
    extra = (os.environ.get("LOGSTASH_AGENT_TLS_SANS") or "").strip()
    if extra:
        for part in extra.split(","):
            p = part.strip()
            if p and p not in names:
                names.append(p)
    return names


def build_csr_pem(sans: Optional[list[str]] = None) -> bytes:
    ensure_private_key()
    key = serialization.load_pem_private_key(key_path().read_bytes(), password=None)
    dns_names = sans or _default_sans()
    import ipaddress

    san_list = [x509.DNSName(n) for n in dns_names]
    san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
    san_list.append(x509.IPAddress(ipaddress.IPv6Address("::1")))

    cn = dns_names[0]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LogstashAgent"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])
        )
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_path().write_bytes(pem)
    return pem


def persist_server_certificate(cert_pem: str | bytes) -> Path:
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("utf-8")
    # Validate parseable
    x509.load_pem_x509_certificate(cert_pem)
    path = cert_path()
    path.write_bytes(cert_pem)
    try:
        path.chmod(0o644)
    except OSError:
        pass
    logger.info("Persisted agent server certificate at %s", path)
    return path


def has_server_cert() -> bool:
    return cert_path().is_file() and key_path().is_file()


def cert_needs_reissue(*, renew_within_days: int = 30) -> bool:
    """True if missing, unreadable, expired/soon-expiring, or not signed by pinned product CA."""
    if not has_server_cert():
        return True
    try:
        leaf = x509.load_pem_x509_certificate(cert_path().read_bytes())
    except Exception:
        return True
    try:
        not_after = leaf.not_valid_after_utc
    except AttributeError:
        not_after = leaf.not_valid_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if not_after <= now + timedelta(days=renew_within_days):
        return True
    # If product CA is pinned, require issuer match
    try:
        from logstashagent import tls_trust

        ca_file = tls_trust.ca_cert_file()
        if ca_file.is_file():
            ca = x509.load_pem_x509_certificate(ca_file.read_bytes())
            if leaf.issuer != ca.subject:
                logger.info("Agent cert issuer differs from pinned product CA; re-issue")
                return True
    except Exception:
        pass
    return False


def apply_signed_response(result: dict) -> bool:
    """Persist server_certificate from enroll/check-in/issue API response."""
    pem = result.get("server_certificate") or result.get("certificate_pem")
    if not pem:
        return False
    persist_server_certificate(pem)
    return True


def issue_via_ui(
    ui_url: str,
    *,
    api_key: Optional[str] = None,
    connection_id: Optional[int] = None,
    agent_csr_secret: Optional[str] = None,
    timeout: float = 30,
) -> bool:
    """
    POST CSR to IssueServerCert. Prefer ApiKey; fall back to compose CSR secret.
    """
    from logstashagent.tls_trust import ssl_verify_argument
    import requests

    ui_url = ui_url.rstrip("/")
    csr_pem = build_csr_pem().decode("utf-8")
    url = f"{ui_url}/ConnectionManager/IssueServerCert/"
    headers = {"Content-Type": "application/json"}
    body: dict[str, Any] = {"csr_pem": csr_pem}
    if api_key and connection_id is not None:
        headers["Authorization"] = f"ApiKey {api_key}"
        body["connection_id"] = connection_id
    secret = (agent_csr_secret or os.environ.get("LOGSTASHUI_AGENT_CSR_SECRET") or "").strip()
    if secret and "Authorization" not in headers:
        headers["X-LogstashUI-Agent-Csr-Secret"] = secret
        body["agent_csr_secret"] = secret
    if "Authorization" not in headers and not secret:
        logger.warning("Cannot issue agent server cert: no API key or LOGSTASHUI_AGENT_CSR_SECRET")
        return False

    # IssueServerCert is HTTPS; bootstrap may still be racing — use verify when pinned
    verify = ssl_verify_argument()
    try:
        resp = requests.post(url, json=body, headers=headers, timeout=timeout, verify=verify)
        if resp.status_code >= 400:
            logger.error("IssueServerCert failed %s: %s", resp.status_code, resp.text[:500])
            return False
        data = resp.json()
        if not data.get("success"):
            logger.error("IssueServerCert error: %s", data.get("error"))
            return False
        return apply_signed_response(data)
    except Exception as e:
        logger.error("IssueServerCert request failed: %s", e)
        return False


def ensure_agent_server_tls(
    *,
    agent_config: Optional[dict] = None,
    force: bool = False,
    retries: int = 24,
    retry_interval_sec: float = 5.0,
) -> bool:
    """
    Ensure agent-server.key + agent-server.crt exist (issue from UI if needed).

    Returns True if cert+key are ready for uvicorn SSL.
    Retries while UI is still starting (compose).
    """
    if not force and not cert_needs_reissue():
        return True

    ensure_private_key()

    ui_url = None
    api_key = None
    connection_id = None
    try:
        from logstashagent import agent_state

        state = agent_state.get_state()
        ui_url = (state.get("logstash_ui_url") or "").strip() or None
        api_key = state.get("api_key")
        connection_id = state.get("connection_id")
    except Exception:
        pass

    if not ui_url:
        ui_url = (
            os.environ.get("LOGSTASH_UI_URL")
            or os.environ.get("LOGSTASHUI_URL")
            or (agent_config or {}).get("logstash_ui_url")
            or ""
        ).strip() or None

    if not ui_url:
        logger.warning("No logstash_ui_url; cannot issue agent server certificate")
        return has_server_cert()

    from logstashagent import tls_trust
    import time

    for attempt in range(1, max(1, retries) + 1):
        try:
            if not tls_trust.product_ca_already_pinned():
                tls_trust.fetch_product_ca_bootstrap(ui_url)
        except Exception as e:
            logger.warning(
                "CA bootstrap before cert issue attempt %s/%s failed: %s",
                attempt,
                retries,
                e,
            )
            time.sleep(retry_interval_sec)
            continue

        ok = issue_via_ui(
            ui_url,
            api_key=api_key,
            connection_id=connection_id,
            agent_csr_secret=os.environ.get("LOGSTASHUI_AGENT_CSR_SECRET"),
        )
        if ok:
            return True
        logger.warning(
            "Agent server cert issue attempt %s/%s failed; retry in %ss",
            attempt,
            retries,
            retry_interval_sec,
        )
        time.sleep(retry_interval_sec)

    return has_server_cert() and not cert_needs_reissue()


def uvicorn_ssl_kwargs() -> dict:
    """Kwargs for uvicorn.run when cert is ready; empty dict if not."""
    if not has_server_cert():
        return {}
    return {
        "ssl_certfile": str(cert_path()),
        "ssl_keyfile": str(key_path()),
    }


def csr_pem_for_request() -> Optional[str]:
    """CSR string to attach to enroll/check-in when re-issue needed."""
    if not cert_needs_reissue():
        return None
    return build_csr_pem().decode("utf-8")
