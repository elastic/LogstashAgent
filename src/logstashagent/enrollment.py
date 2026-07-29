#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import os
import requests
import json
import base64
import logging
import socket
import hashlib
from . import agent_state

logger = logging.getLogger(__name__)


def get_hostname():
    """Get the hostname of the current machine"""
    try:
        return socket.gethostname()
    except Exception as e:
        logger.warning(f"Failed to get hostname: {e}, using 'unknown-host'")
        return "unknown-host"


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
    
    # Get hostname
    hostname = get_hostname()
    
    logger.info(f"Enrolling agent with logstashui at {ui_url}")
    logger.info(f"Hostname: {hostname}")
    logger.info(f"Agent ID: {agent_id}")
    
    # Prepare enrollment request - send the base64-encoded token, not the decoded one
    enrollment_url = f"{ui_url}/ConnectionManager/Enroll/"
    enrollment_data = {
        "enrollment_token": encoded_token,
        "host": hostname,
        "agent_id": agent_id
    }
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
        except json.JSONDecodeError as e:
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

        # Agent role / simulate instance fields (policy_type: DEFAULT|SIMULATE|EMBEDDED)
        policy_type = (policy_config.get('policy_type') or 'DEFAULT').upper()
        agent_state.update_state('policy_type', policy_type)
        if policy_type == 'SIMULATE':
            agent_state.update_state('mode', 'simulate')
        elif policy_type == 'EMBEDDED':
            agent_state.update_state('mode', 'embedded')
        else:
            agent_state.update_state('mode', 'default')

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
            if policy_type == 'SIMULATE':
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

        # SIMULATE: materialize dirs/units (root, passwordless sudo, or deferred)
        setup_result = None
        if (policy_config.get('policy_type') or '').upper() == 'SIMULATE':
            from logstashagent import installer as _installer
            logger.info("Setting up simulate instance (dirs, units, binary)...")
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
        if (policy_config.get('policy_type') or '').upper() == 'SIMULATE':
            logger.info(f"Mode: simulate instance_id={policy_config.get('instance_id')}")
            if setup_result and setup_result.get('status') == 'complete':
                logger.info(
                    f"Simulate setup complete. Start with: "
                    f"sudo systemctl start lsagent-simulate@{policy_config.get('instance_id')}"
                )
            else:
                logger.warning("=" * 60)
                logger.warning("SIMULATE SETUP INCOMPLETE (enrollment is still valid)")
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
