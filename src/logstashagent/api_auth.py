#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Inbound authentication for the agent's ``/_logstash/*`` API.

LogstashUI must send ``Authorization: ApiKey <key>`` on every request.  The
expected key is, in order of precedence:

1. ``inbound_api_key`` from agent state (enrolled agents; issued by LogstashUI
   at enrollment or delivered encrypted on check-in).
2. ``LOGSTASH_AGENT_API_KEY`` environment variable (embedded / compose agents,
   which never enroll).

Fails closed: if no key is configured, every protected route returns 503.
"""

import hashlib
import hmac
import logging
import os

from fastapi import Header, HTTPException

from logstashagent import agent_state

logger = logging.getLogger(__name__)

INBOUND_KEY_STATE = 'inbound_api_key'
INBOUND_KEY_ENV = 'LOGSTASH_AGENT_API_KEY'
_SCHEME = 'ApiKey '


def expected_inbound_key() -> str | None:
    """Return the key callers must present, or None if unprovisioned."""
    try:
        key = (agent_state.get_state() or {}).get(INBOUND_KEY_STATE)
    except Exception:
        logger.exception("Could not read agent state for inbound API key")
        key = None
    if key:
        return str(key)
    return os.environ.get(INBOUND_KEY_ENV) or None


def inbound_key_fingerprint(key: str | None) -> str | None:
    """SHA-256 hex of the key, reported at check-in so the UI can detect drift."""
    if not key:
        return None
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


async def require_agent_key(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency enforcing the inbound API key."""
    expected = expected_inbound_key()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail=(
                "Agent API key not provisioned: enroll the agent or set "
                f"{INBOUND_KEY_ENV}"
            ),
        )
    presented = ''
    if authorization and authorization.startswith(_SCHEME):
        presented = authorization[len(_SCHEME):].strip()
    if not presented or not hmac.compare_digest(
        presented.encode('utf-8'), expected.encode('utf-8')
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
            headers={'WWW-Authenticate': 'ApiKey'},
        )
