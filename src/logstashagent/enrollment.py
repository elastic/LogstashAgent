#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import base64
import hashlib
import json
import logging
import os
import socket

import requests

from . import agent_state

logger = logging.getLogger(__name__)


def get_hostname():
    """Short OS hostname (display / fallback only)."""
    try:
        return socket.gethostname()
    except Exception as e:
        logger.warning(f"Failed to get hostname: {e}, using 'unknown-host'")
        return "unknown-host"


def _is_multi_label_dns(name: str) -> bool:
    """True for FQDN-like names (a.b), not bare hostnames or IP literals."""
    n = (name or "").strip().rstrip(".")
    if not n or "." not in n:
        return False
    try:
        import ipaddress

        ipaddress.ip_address(n)
        return False
    except ValueError:
        return True


def _non_loopback_ipv4s() -> list[str]:
    ips: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                ips.append(ip)
        finally:
            s.close()
    except Exception:
        pass
    try:
        hn = socket.gethostname()
        for info in socket.getaddrinfo(hn, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _is_ip_literal(host: str) -> bool:
    h = (host or "").strip()
    if not h:
        return False
    try:
        import ipaddress

        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def short_host_label(host: str) -> str:
    """First DNS label for UX (keep IPs unchanged)."""
    h = (host or "").strip()
    if not h:
        return h
    if _is_ip_literal(h):
        return h
    return h.split(".")[0]


def display_host_label(callback_host: str | None = None) -> str:
    """
    Short label for connection names / UX.

    When the callback host is an IP (typical default for Docker LogstashUI),
    use the OS short hostname so names stay human-readable.
    """
    host = (callback_host if callback_host is not None else get_callback_host()) or ""
    if _is_ip_literal(host):
        return get_hostname()
    label = short_host_label(host)
    return label or get_hostname()


def get_callback_ip() -> str | None:
    """Best-effort non-loopback IPv4 for UI→agent callbacks (None if unavailable)."""
    ips = _non_loopback_ipv4s()
    return ips[0] if ips else None


def get_callback_host() -> str:
    """
    Host identity the UI uses to reach this agent (HTTPS base URL host).

    Prefer a routable non-loopback IPv4. LogstashUI often runs in Docker where
    host DNS (short names and even some FQDNs) is not predictable, so IP is the
    reliable default for Connection.host / sim health / editor traffic.

    Override: ``LOGSTASH_AGENT_CALLBACK_HOST`` (or ``LOGSTASH_AGENT_HOSTNAME``)
    when you need a specific FQDN or interface address.

    Fallbacks: multi-label FQDN (PTR / getfqdn), then short hostname.
    """
    for env_key in ("LOGSTASH_AGENT_CALLBACK_HOST", "LOGSTASH_AGENT_HOSTNAME"):
        raw = (os.environ.get(env_key) or "").strip()
        if raw:
            return raw

    # 1) Routable IP first — works from containerized LogstashUI without DNS
    ips = _non_loopback_ipv4s()
    if ips:
        logger.info(
            "Callback host using IP %s (set LOGSTASH_AGENT_CALLBACK_HOST to "
            "override interface/FQDN)",
            ips[0],
        )
        return ips[0]

    # 2) OS FQDN when multi-label (no usable local IP)
    try:
        fqdn = (socket.getfqdn() or "").strip().rstrip(".")
        if _is_multi_label_dns(fqdn):
            logger.info("Callback host from getfqdn: %s", fqdn)
            return fqdn
    except Exception:
        pass

    # 3) Short hostname (last resort — may not resolve from UI containers)
    hn = get_hostname()
    logger.warning(
        "Callback host is short hostname %r — LogstashUI may not resolve it. "
        "Set LOGSTASH_AGENT_CALLBACK_HOST to an FQDN or IP.",
        hn,
    )
    return hn


def decode_enrollment_token(encoded_token: str) -> dict:
    """
    Decode the base64-encoded enrollment token.

    Payload (v2) may include optional ``fingerprint`` (SHA-256 of product CA DER,
    lowercase hex) and ``token_version``. Does not include ui_url (use CLI).

    Args:
        encoded_token: Base64-encoded JSON token

    Returns:
        dict: Decoded token payload containing enrollment_token

    Raises:
        ValueError: If token is invalid or cannot be decoded
    """
    try:
        decoded_json = base64.b64decode(encoded_token.encode('utf-8')).decode('utf-8')
        token_payload = json.loads(decoded_json)

        if 'enrollment_token' not in token_payload:
            raise ValueError("Invalid token payload: missing enrollment_token")

        return token_payload
    except Exception as e:
        raise ValueError(f"Failed to decode enrollment token: {str(e)}")


def enroll_agent(encoded_token: str, logstash_ui_url: str, agent_id: str) -> dict:
    """
    Enroll the agent with logstashui

    Args:
        encoded_token: Base64-encoded enrollment token
        logstash_ui_url: logstashui URL (from --logstash-ui-url)
        agent_id: Unique agent ID for this instance

    Returns:
        dict: Enrollment response containing api_key, policy_id, connection_id

    Raises:
        Exception: If enrollment fails
    """
    # Validate the enrollment token by decoding it
    token_payload = decode_enrollment_token(encoded_token)

    # Use provided URL (not taken from token — CLI / generated command)
    ui_url = logstash_ui_url.rstrip('/')

    # Pin product CA when token includes fingerprint (Approach A)
    try:
        from logstashagent.tls_trust import ensure_trust_from_token_payload, ssl_verify_argument

        ensure_trust_from_token_payload(ui_url, token_payload)
        verify = ssl_verify_argument()
    except Exception as e:
        logger.error(f"TLS trust setup from enrollment token failed: {e}")
        raise Exception(
            f"Failed to establish trust with LogstashUI CA: {e}. "
            f"Check fingerprint and that {ui_url}/.well-known/logstashui/ca.crt is reachable."
        ) from e

    # Host the UI will use to call back into this agent (IP preferred for Docker UI)
    callback_host = get_callback_host()
    callback_ip = get_callback_ip()
    short_name = display_host_label(callback_host)

    logger.info(f"Enrolling agent with logstashui at {ui_url}")
    logger.info(f"Callback host (UI → agent): {callback_host}")
    if callback_ip and callback_ip != callback_host:
        logger.info(f"Callback IP: {callback_ip}")
    if short_name != callback_host:
        logger.info(f"Short host label (display): {short_name}")
    logger.info(f"Agent ID: {agent_id}")

    # Prepare enrollment request - send the base64-encoded token, not the decoded one
    enrollment_url = f"{ui_url}/ConnectionManager/Enroll/"
    enrollment_data = {
        "enrollment_token": encoded_token,
        "host": callback_host,
        "host_short": short_name,
        "agent_id": agent_id,
    }
    if callback_ip:
        enrollment_data["callback_ip"] = callback_ip
    # Request product-CA-signed server cert for agent HTTPS (key stays local)
    try:
        from logstashagent import tls_server

        enrollment_data["csr_pem"] = tls_server.build_csr_pem().decode("utf-8")
    except Exception as e:
        logger.warning("Could not build agent server CSR for enroll: %s", e)

    try:
        # Send enrollment request (verify system CAs ± product CA)
        response = requests.post(
            enrollment_url,
            json=enrollment_data,
            timeout=30,
            verify=verify,
        )

        # Log response details for debugging
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response headers: {response.headers}")

        # Check for error status codes before raising
        if response.status_code >= 400:
            logger.error(f"Server returned error status {response.status_code}")
            logger.error(f"Response body: {response.text}")

        response.raise_for_status()

        # Try to parse JSON response
        try:
            result = response.json()
        except json.JSONDecodeError:
            logger.error(f"Server returned non-JSON response. Status: {response.status_code}")
            logger.error(f"Response text: {response.text[:500]}")  # First 500 chars
            raise Exception(f"Server returned non-JSON response (status {response.status_code}). Check that the enrollment endpoint exists at {enrollment_url}")

        if not result.get('success'):
            error_msg = result.get('error', 'Unknown error')
            raise Exception(f"Enrollment failed: {error_msg}")

        try:
            from logstashagent import tls_server

            if tls_server.apply_signed_response(result):
                logger.info("Agent server certificate issued at enroll")
        except Exception as e:
            logger.warning("Could not persist server certificate from enroll: %s", e)

        logger.info("Agent enrolled successfully!")
        logger.info(f"Connection ID: {result.get('connection_id')}")
        logger.info(f"Policy ID: {result.get('policy_id')}")

        return result

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to connect to logstashui: {e}")
        raise Exception(f"Failed to connect to logstashui at {ui_url}: {str(e)}")


def compute_hash(content: str) -> str:
    """
    Compute SHA256 hash of a string

    Args:
        content: String content to hash

    Returns:
        str: Hexadecimal hash string
    """
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def save_enrollment_config(api_key: str, logstash_ui_url: str, policy_id: int, connection_id: int, policy_config: dict):
    """
    Save enrollment configuration to state.json

    Args:
        api_key: API key returned from enrollment
        logstash_ui_url: logstashui URL
        policy_id: Policy ID assigned to this agent
        connection_id: Connection ID created for this agent
        policy_config: Policy configuration containing paths and config files
    """
    try:
        # Save enrollment data to state.json
        agent_state.update_state('enrolled', True)
        agent_state.update_state('logstash_ui_url', logstash_ui_url)
        agent_state.update_state('api_key', api_key)
        agent_state.update_state('policy_id', policy_id)
        agent_state.update_state('connection_id', connection_id)

        # Save paths
        agent_state.update_state('settings_path', policy_config.get('settings_path'))
        agent_state.update_state('logs_path', policy_config.get('logs_path'))
        agent_state.update_state('binary_path', policy_config.get('binary_path'))
        if policy_config.get('data_path') is not None:
            agent_state.update_state('data_path', policy_config.get('data_path'))
        if policy_config.get('config_path') is not None:
            agent_state.update_state('config_path', policy_config.get('config_path'))

        # Agent role fields (policy_type: PACKAGED|MANAGED|SIMULATE|EMBEDDED; DEFAULT→packaged)
        policy_type = (policy_config.get('policy_type') or 'PACKAGED').upper()
        if policy_type == 'DEFAULT':
            policy_type = 'PACKAGED'
        agent_state.update_state('policy_type', policy_type)
        if policy_type == 'SIMULATE':
            agent_state.update_state('mode', 'simulate')
        elif policy_type == 'MANAGED':
            agent_state.update_state('mode', 'managed')
        elif policy_type == 'EMBEDDED':
            agent_state.update_state('mode', 'embedded')
        else:
            # PACKAGED (and any unknown production type)
            agent_state.update_state('mode', 'packaged')

        if policy_config.get('instance_id') is not None:
            agent_state.update_state('instance_id', policy_config.get('instance_id'))
        if policy_config.get('agent_api_port') is not None:
            agent_state.update_state('agent_api_port', policy_config.get('agent_api_port'))
        if policy_config.get('logstash_api_port') is not None:
            agent_state.update_state('logstash_api_port', policy_config.get('logstash_api_port'))
        if policy_config.get('keystore_env_file') is not None:
            agent_state.update_state('keystore_env_file', policy_config.get('keystore_env_file'))
        if policy_config.get('logstash_unit'):
            agent_state.update_state('logstash_unit', policy_config.get('logstash_unit'))
        if policy_config.get('agent_unit'):
            agent_state.update_state('agent_unit', policy_config.get('agent_unit'))
        if policy_config.get('path_root'):
            agent_state.update_state('path_root', policy_config.get('path_root'))
        if policy_config.get('logstash_source'):
            agent_state.update_state('logstash_source', policy_config.get('logstash_source'))
        if policy_config.get('logstash_version') is not None:
            agent_state.update_state('logstash_version', policy_config.get('logstash_version'))
        if policy_config.get('logstash_download_dir'):
            agent_state.update_state(
                'logstash_download_dir', policy_config.get('logstash_download_dir')
            )
        # Full policy_config for deferred root setup (non-root --enroll)
        if policy_config:
            agent_state.update_state('policy_config', policy_config)
            # Multi-instance roles need host materialize (SIMULATE; MANAGED reuses setup for now)
            if policy_type in ('SIMULATE', 'MANAGED'):
                agent_state.update_state('simulate_setup_pending', True)

        # Set initial revision number to 0 (agent has no configuration yet)
        agent_state.update_state('revision_number', 0)

        logger.info(f"Enrollment configuration saved to state.json")
        logger.info(f"Mode/policy_type: {agent_state.get_state().get('mode')}/{policy_type}")
        logger.info(f"Settings path: {policy_config.get('settings_path')}")
        logger.info(f"Logs path: {policy_config.get('logs_path')}")
        logger.info(f"Binary path: {policy_config.get('binary_path')}")
        if policy_config.get('instance_id') is not None:
            logger.info(f"Simulate instance_id: {policy_config.get('instance_id')}")
        logger.info(f"Revision number set to 0 (no configuration deployed yet)")
        logger.info(f"Agent is now enrolled and managed by logstashui at {logstash_ui_url}")

    except Exception as e:
        logger.error(f"Failed to save enrollment configuration: {e}")
        raise Exception(f"Failed to save enrollment configuration: {str(e)}")


def perform_enrollment(encoded_token: str, logstash_ui_url: str, agent_id: str):
    """
    Perform the complete enrollment process

    Args:
        encoded_token: Base64-encoded enrollment token
        logstash_ui_url: logstashui URL (required)
        agent_id: Unique agent ID for this instance
    """
    try:
        # Use the provided UI URL
        ui_url = logstash_ui_url

        # Enroll the agent
        result = enroll_agent(encoded_token, ui_url, agent_id)

        # Save enrollment configuration
        policy_config = result.get('policy_config', {}) or {}
        save_enrollment_config(
            api_key=result['api_key'],
            logstash_ui_url=ui_url,
            policy_id=result['policy_id'],
            connection_id=result['connection_id'],
            policy_config=policy_config
        )

        # Multi-instance (SIMULATE / MANAGED): materialize dirs/units
        setup_result = None
        _pt = (policy_config.get('policy_type') or 'PACKAGED').upper()
        if _pt == 'DEFAULT':
            _pt = 'PACKAGED'
        if _pt in ('SIMULATE', 'MANAGED'):
            from logstashagent import installer as _installer
            role = 'managed' if _pt == 'MANAGED' else 'simulate'
            logger.info("Setting up %s instance (dirs, units, binary)...", role)
            setup_result = _installer.ensure_simulate_setup(policy_config)
            result['simulate_setup'] = setup_result
            if setup_result.get('status') == 'complete':
                agent_state.update_state('simulate_setup_pending', False)
            else:
                agent_state.update_state('simulate_setup_pending', True)

        logger.info("=" * 60)
        logger.info("ENROLLMENT SUCCESSFUL!")
        logger.info("=" * 60)
        logger.info(f"logstashui URL: {ui_url}")
        logger.info(f"Connection ID: {result['connection_id']}")
        logger.info(f"Policy ID: {result['policy_id']}")
        logger.info(f"API Key: {result['api_key'][:10]}...")
        if _pt in ('SIMULATE', 'MANAGED'):
            role = 'managed' if _pt == 'MANAGED' else 'simulate'
            logger.info(f"Mode: {role} instance_id={policy_config.get('instance_id')}")
            if setup_result and setup_result.get('status') == 'complete':
                iid = policy_config.get('instance_id')
                if _pt == 'MANAGED':
                    unit = policy_config.get('agent_unit') or f"logstash-agent@{iid}"
                else:
                    unit = policy_config.get('agent_unit') or f"lsagent-simulate@{iid}"
                logger.info(f"Setup complete. Start with: sudo systemctl start {unit}")
            else:
                logger.warning("=" * 60)
                logger.warning("%s SETUP INCOMPLETE (enrollment is still valid)", role.upper())
                for line in (setup_result or {}).get('messages') or []:
                    logger.warning("  %s", line)
                logger.warning(
                    "Finish with:  sudo logstash-agent setup-simulate"
                )
                logger.warning("=" * 60)
        else:
            logger.info("Configuration saved to state.json")
            logger.info("You can now start the agent using the --run flag")
        logger.info("=" * 60)

        return result

    except Exception as e:
        logger.error(f"Enrollment failed: {e}")
        raise
