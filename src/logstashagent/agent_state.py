#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Per-process agent state (state.json).

Host coexistence: Packaged uses ``/opt/logstash-agent/state``; each managed-N /
simulate-N instance uses ``/opt/logstash-agent/{role}-{N}/state`` so multiple
roles on one host do not share agent_id / enrollment secrets.

Legacy packaged state at ``/var/lib/logstash-agent`` is still read if present
and the new path does not exist (pre-consolidation installs).
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
import logging

from . import encryption

logger = logging.getLogger(__name__)

# Keys that should be encrypted when stored
ENCRYPTED_KEYS = {'api_key', 'keystore_password'}

OPT_ROOT = Path('/opt/logstash-agent')
PACKAGED_STATE_DIR = OPT_ROOT / 'state'
_LEGACY_PACKAGED_STATE_DIR = Path('/var/lib/logstash-agent')

# Explicit override (tests / install relocate)
_state_dir_override: Path | None = None

# Tiny alias map (do not import main — cycle). Keep in sync with main.MODE_ALIASES.
_MODE_ALIASES = {
    'default': 'packaged',
    'agent': 'packaged',
    'host': 'managed',
}


def _peek_mode_and_instance_from_argv(argv: list[str] | None = None) -> tuple[str | None, int | None]:
    """Best-effort parse of --mode / --instance from argv (before argparse)."""
    argv = list(argv if argv is not None else sys.argv[1:])
    mode = None
    instance = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--mode' and i + 1 < len(argv):
            mode = str(argv[i + 1]).lower()
            i += 2
            continue
        if a.startswith('--mode='):
            mode = a.split('=', 1)[1].lower()
            i += 1
            continue
        if a == '--instance' and i + 1 < len(argv):
            try:
                instance = int(argv[i + 1])
            except (TypeError, ValueError):
                instance = None
            i += 2
            continue
        if a.startswith('--instance='):
            try:
                instance = int(a.split('=', 1)[1])
            except (TypeError, ValueError):
                instance = None
            i += 1
            continue
        i += 1
    if mode:
        mode = _MODE_ALIASES.get(mode, mode)
    return mode, instance


def instance_state_dir(role: str, instance_id: int) -> Path:
    """Canonical state dir for a multi-instance role."""
    r = (role or '').lower()
    if r in ('managed',):
        return OPT_ROOT / f'managed-{int(instance_id)}' / 'state'
    if r in ('simulate', 'simulation'):
        return OPT_ROOT / f'simulate-{int(instance_id)}' / 'state'
    raise ValueError(f'instance_state_dir: unknown role {role!r}')


def instance_config_path(role: str, instance_id: int) -> Path:
    r = (role or '').lower()
    if r in ('managed',):
        return OPT_ROOT / f'managed-{int(instance_id)}' / 'logstash-agent.yml'
    if r in ('simulate', 'simulation'):
        return OPT_ROOT / f'simulate-{int(instance_id)}' / 'logstash-agent.yml'
    raise ValueError(f'instance_config_path: unknown role {role!r}')


def resolve_state_dir(argv: list[str] | None = None) -> Path:
    """
    Resolve which state directory this process should use.

    Priority:
      1. configure_state_dir() override
      2. LOGSTASH_AGENT_STATE_DIR env (set by systemd agent.env)
      3. --mode managed|simulate + --instance N → instance tree
      4. Host admin CLI (install/uninstall/…) → packaged state dir
      5. Existing packaged dir if present
      6. Dev data/ under package
    """
    if _state_dir_override is not None:
        return _state_dir_override

    env_dir = (os.environ.get('LOGSTASH_AGENT_STATE_DIR') or '').strip()
    if env_dir:
        return Path(env_dir)

    mode, instance = _peek_mode_and_instance_from_argv(argv)
    if mode in ('managed', 'simulate') and instance is not None:
        return instance_state_dir(mode, instance)

    # Host-level admin commands always use packaged state dir for the registry
    # and package metadata (not instance enrollment secrets).
    if len(sys.argv) > 1 and sys.argv[1] in (
        'install', 'upgrade', 'uninstall', 'list-instances', 'list-versions',
        'ensure-version', 'prune-versions', 'configure', 'setup-simulate',
    ):
        if PACKAGED_STATE_DIR.exists():
            return PACKAGED_STATE_DIR
        if _LEGACY_PACKAGED_STATE_DIR.exists():
            return _LEGACY_PACKAGED_STATE_DIR
        return PACKAGED_STATE_DIR

    if PACKAGED_STATE_DIR.exists():
        return PACKAGED_STATE_DIR
    if _LEGACY_PACKAGED_STATE_DIR.exists():
        return _LEGACY_PACKAGED_STATE_DIR

    return Path(__file__).parent / 'data'


def configure_state_dir(path: str | Path | None) -> Path:
    """
    Force STATE_DIR for this process (install relocate, tests).

    Pass None to clear the override.
    """
    global _state_dir_override, STATE_DIR, STATE_FILE
    if path is None:
        _state_dir_override = None
    else:
        _state_dir_override = Path(path)
    STATE_DIR = resolve_state_dir()
    STATE_FILE = STATE_DIR / 'state.json'
    return STATE_DIR


def refresh_state_paths() -> Path:
    """Recompute STATE_DIR/STATE_FILE after env or argv context is known."""
    global STATE_DIR, STATE_FILE
    STATE_DIR = resolve_state_dir()
    STATE_FILE = STATE_DIR / 'state.json'
    return STATE_DIR


# Module-level paths (recomputed by refresh_state_paths / configure_state_dir)
STATE_DIR = resolve_state_dir()
STATE_FILE = STATE_DIR / 'state.json'


def get_or_create_agent_id() -> str:
    """
    Get the agent_id from state.json, or generate a new one if it doesn't exist.

    Returns:
        str: The unique agent ID for this instance
    """
    refresh_state_paths()
    # Ensure data directory exists
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Check if state file exists
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
                agent_id = state.get('agent_id')

                if agent_id:
                    logger.info(f"Loaded existing agent_id: {agent_id} ({STATE_FILE})")
                    return agent_id
                else:
                    # File exists but no agent_id, generate one
                    logger.warning("state.json exists but no agent_id found, generating new one")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to read state.json: {e}, generating new agent_id")

    # Generate new agent_id — merge into existing state; never wipe enrollment
    agent_id = str(uuid.uuid4())
    logger.info(f"Generated new agent_id: {agent_id}")

    existing: dict = {}
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, 'r') as f:
                existing = json.load(f) or {}
        except (json.JSONDecodeError, IOError):
            existing = {}
    existing['agent_id'] = agent_id
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(existing, f, indent=2)
        logger.info(f"Saved agent_id to {STATE_FILE}")
    except IOError as e:
        logger.error(f"Failed to save state.json: {e}")

    return agent_id


def get_state() -> dict:
    """
    Get the full state dictionary from state.json
    Automatically decrypts encrypted fields.

    Returns:
        dict: The state dictionary, or empty dict if file doesn't exist
    """
    refresh_state_paths()
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)

            # Decrypt encrypted fields
            for key in ENCRYPTED_KEYS:
                if key in state and state[key]:
                    try:
                        state[key] = encryption.decrypt_credential(state[key])
                    except Exception as e:
                        logger.error(f"Failed to decrypt {key}: {e}")
                        # Keep encrypted value if decryption fails

            return state
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to read state.json: {e}")
            return {}
    return {}


def update_state(key: str, value):
    """
    Update a specific key in the state file
    Automatically encrypts sensitive fields.

    Args:
        key: The key to update
        value: The value to set
    """
    refresh_state_paths()
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Load existing state (this will decrypt encrypted values)
    state = get_state()

    # Update the key
    state[key] = value

    # Encrypt sensitive fields before saving
    state_to_save = state.copy()
    for encrypted_key in ENCRYPTED_KEYS:
        if encrypted_key in state_to_save and state_to_save[encrypted_key]:
            try:
                state_to_save[encrypted_key] = encryption.encrypt_credential(state_to_save[encrypted_key])
            except Exception as e:
                logger.error(f"Failed to encrypt {encrypted_key}: {e}")
                # Save unencrypted if encryption fails

    # Save back to file
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state_to_save, f, indent=2)
        logger.debug(f"Updated state: {key} ({STATE_FILE})")
    except IOError as e:
        logger.error(f"Failed to update state.json: {e}")


def relocate_state_to(dest_dir: str | Path, *, leave_source: bool = False) -> Path:
    """
    Copy current state.json (and ``.secret_key``) into dest_dir and point this
    process at it.

    Used after multi-instance enroll (which initially writes packaged state dir)
    so instance secrets do not remain as the packaged agent's state. The Fernet
    key must move with state.json or encrypted fields become unreadable / a new
    root-owned key is generated in the instance tree.
    """
    import shutil

    refresh_state_paths()
    src = STATE_FILE
    src_dir = STATE_DIR
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / 'state.json'
    if src.exists():
        shutil.copy2(src, dest)
        logger.info("Relocated agent state %s → %s", src, dest)
        if not leave_source and src.resolve() != dest.resolve():
            # Only delete source if it is not the long-lived packaged state that
            # another role still needs — caller decides leave_source.
            try:
                src.unlink()
                logger.info("Removed transient enrollment state at %s", src)
            except OSError as e:
                logger.warning("Could not remove %s after relocate: %s", src, e)

    # Keep Fernet key with the state that was encrypted under it.
    # Copy via encryption helper when possible so ownership is correct even as root.
    src_key = Path(src_dir) / '.secret_key'
    dest_key = dest_dir / '.secret_key'
    if src_key.is_file():
        try:
            key_bytes = src_key.read_bytes()
            from logstashagent.encryption import _write_secret_key_file

            _write_secret_key_file(dest_key, key_bytes)
            logger.info("Relocated encryption key %s → %s", src_key, dest_key)
            if not leave_source and src_key.resolve() != dest_key.resolve():
                try:
                    src_key.unlink()
                except OSError:
                    pass
        except Exception as e:
            # Fallback: plain copy + chown
            logger.warning("Atomic key relocate failed (%s); falling back to copy2", e)
            try:
                shutil.copy2(src_key, dest_key)
                os.chmod(dest_key, 0o600)
                from logstashagent.encryption import _chown_to_logstash, ensure_secret_key_ownership

                _chown_to_logstash(dest_key)
                ensure_secret_key_ownership(dest_dir)
            except OSError as e2:
                logger.warning("Could not relocate .secret_key: %s", e2)
    else:
        try:
            from logstashagent.encryption import ensure_secret_key_ownership

            ensure_secret_key_ownership(dest_dir)
        except Exception as e:
            logger.debug("ensure_secret_key_ownership after relocate: %s", e)

    configure_state_dir(dest_dir)
    return dest
