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


def _default_sans() -> tuple[list[str], list]:
    """Return (dns_names, ip_addresses) for agent server CSR."""
    import ipaddress

    names = ["localhost", "logstashagent"]
    ips: list = [
        ipaddress.IPv4Address("127.0.0.1"),
        ipaddress.IPv6Address("::1"),
    ]

    def add_dns(n: str) -> None:
        n = (n or "").strip()
        if n and n not in names:
            names.append(n)

    def add_ip(raw: str) -> None:
        raw = (raw or "").strip()
        if not raw:
            return
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            add_dns(raw)
            return
        if ip not in ips:
            ips.append(ip)

    try:
        hn = socket.gethostname()
        add_dns(hn)
    except Exception:
        pass
    try:
        fqdn = socket.getfqdn()
        add_dns(fqdn)
    except Exception:
        pass

    def _merge_csv_env(value: str) -> None:
        for part in (value or "").replace(";", ",").split(","):
            p = part.strip()
            if not p:
                continue
            try:
                ipaddress.ip_address(p)
                add_ip(p)
            except ValueError:
                add_dns(p)

    # Explicit callback host(s) for enroll/UI reachability
    for env_key in ("LOGSTASH_AGENT_CALLBACK_HOST", "LOGSTASH_AGENT_HOSTNAME"):
        raw = (os.environ.get(env_key) or "").strip()
        if raw:
            _merge_csv_env(raw)
            break
    # Optional extra SANs (comma-separated)
    _merge_csv_env(os.environ.get("LOGSTASH_AGENT_TLS_SANS") or "")

    # Non-loopback local IPv4s + PTR FQDNs (UI may connect by DNS name)
    local_ips: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ips.append(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    try:
        hn = socket.gethostname()
        for info in socket.getaddrinfo(hn, None):
            addr = info[4][0]
            if addr and addr not in local_ips:
                local_ips.append(addr)
    except Exception:
        pass
    for raw in local_ips:
        add_ip(raw)
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)
            try:
                ptr = socket.gethostbyaddr(raw)[0].rstrip(".")
            finally:
                socket.setdefaulttimeout(old)
            if ptr and "." in ptr:
                try:
                    ipaddress.ip_address(ptr)
                except ValueError:
                    add_dns(ptr)
        except Exception:
            pass

    return names, ips


def desired_san_keyset() -> set[str]:
    dns_names, ips = _default_sans()
    keys = {f"dns:{n.lower()}" for n in dns_names}
    for ip in ips:
        keys.add(f"ip:{ip.compressed}")
    return keys


def leaf_san_keyset_from_file() -> set[str]:
    if not cert_path().is_file():
        return set()
    try:
        leaf = x509.load_pem_x509_certificate(cert_path().read_bytes())
    except Exception:
        return set()
    keys: set[str] = set()
    try:
        ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                keys.add(f"dns:{name.value.lower()}")
            elif isinstance(name, x509.IPAddress):
                keys.add(f"ip:{name.value.compressed}")
    except x509.ExtensionNotFound:
        pass
    return keys


def build_csr_pem(sans: Optional[list[str]] = None) -> bytes:
    ensure_private_key()
    key = serialization.load_pem_private_key(key_path().read_bytes(), password=None)
    import ipaddress

    if sans is not None:
        dns_names = list(sans)
        ips = [
            ipaddress.IPv4Address("127.0.0.1"),
            ipaddress.IPv6Address("::1"),
        ]
    else:
        dns_names, ips = _default_sans()

    san_list = [x509.DNSName(n) for n in dns_names]
    for ip in ips:
        san_list.append(x509.IPAddress(ip))

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
    """True if missing, unreadable, expired/soon-expiring, SAN drift, or wrong issuer."""
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
    # Re-issue when hostname/IPs changed (missing desired SANs)
    desired = desired_san_keyset()
    actual = leaf_san_keyset_from_file()
    missing = desired - actual
    if missing:
        logger.info("Agent cert missing SANs %s; will re-issue", sorted(missing)[:20])
        return True
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
    verify = ssl_verify_argument(ui_url)
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
    from logstashagent import tls_trust

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

    if not tls_trust.agent_tls_enabled() or not tls_trust.ui_url_is_tls(ui_url):
        logger.warning(
            "Agent FastAPI TLS skipped (LOGSTASH_AGENT_TLS=%s, ui_tls=%s)",
            tls_trust.agent_tls_enabled(),
            tls_trust.ui_url_is_tls(ui_url),
        )
        return False

    if not force and not cert_needs_reissue() and tls_trust.product_ca_already_pinned():
        return True

    ensure_private_key()

    if not ui_url:
        logger.warning("No logstash_ui_url; cannot issue agent server certificate")
        return False

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

        if not tls_trust.product_ca_already_pinned():
            logger.warning(
                "Product CA not pinned after fetch attempt %s/%s; not issuing server cert",
                attempt,
                retries,
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

    if not tls_trust.product_ca_already_pinned():
        logger.warning(
            "Agent FastAPI TLS skipped: product CA absent after wait "
            "(env wants TLS; cannot terminate SSL)"
        )
        return False
    return has_server_cert() and not cert_needs_reissue()


def uvicorn_ssl_kwargs() -> dict:
    """Kwargs for uvicorn.run when cert is ready; empty dict if not."""
    from logstashagent.tls_trust import inbound_tls_ok

    if not inbound_tls_ok() or not has_server_cert():
        return {}
    return {
        "ssl_certfile": str(cert_path()),
        "ssl_keyfile": str(key_path()),
    }


def csr_pem_for_request() -> Optional[str]:
    """CSR string to attach to enroll/check-in when re-issue needed."""
    from logstashagent.tls_trust import inbound_tls_ok

    if not inbound_tls_ok():
        return None
    if not cert_needs_reissue():
        return None
    return build_csr_pem().decode("utf-8")
