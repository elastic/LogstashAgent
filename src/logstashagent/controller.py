#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import time
import random
import threading
import logging
import requests
from typing import Optional
import json
import hashlib
import base64
import subprocess
import os
from pathlib import Path
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from . import agent_state
from . import log_analyzer
from .ls_keystore_utils import LogstashKeystore
from .ls_keystore_utils.exceptions import (
    LogstashKeystoreException,
    IncorrectPassword,
    LogstashKeystoreModified
)
from importlib.metadata import version as get_version, PackageNotFoundError

logger = logging.getLogger(__name__)


def _decrypt_from_server(raw_api_key: str, encrypted: str) -> str:
    """
    Decrypt a value that was encrypted by the server specifically for this agent.
    The server derives a Fernet key from SHA-256(api_key); we do the same here.
    """
    key = base64.urlsafe_b64encode(hashlib.sha256(raw_api_key.encode('utf-8')).digest())
    return Fernet(key).decrypt(encrypted.encode('utf-8')).decode('utf-8')


def _managed_rollup(pipelines, keystore):
    """
    Canonical single-hash summary of a managed source's pipeline + keystore hash
    maps, used for the cheap per-source "dirty?" check at check-in (Phase 2).

    MUST stay byte-for-byte identical to the server's implementation
    (PipelineManager.agent_api._managed_rollup) so both sides derive the same
    rollup from the same {name: hash} maps.
    """
    parts = []
    for name in sorted(pipelines or {}):
        parts.append(f"p:{name}={pipelines[name]}")
    for name in sorted(keystore or {}):
        parts.append(f"k:{name}={keystore[name]}")
    return hashlib.sha256("\n".join(parts).encode('utf-8')).hexdigest()


def _record_last_apply(source, success, failed_operations, revision=None):
    """
    Record the most recent apply result for a managed source ('user', 'snmp', …)
    in agent state under `last_apply[source]`, so each channel's status is
    tracked independently even though they now share one merged apply/restart.
    """
    last_apply = agent_state.get_state().get('last_apply', {})
    entry = {
        'success': success,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'failed_operations': failed_operations,
    }
    if revision is not None:
        entry['revision'] = revision
    last_apply[source] = entry
    agent_state.update_state('last_apply', last_apply)


# Default environment file sourced by the package Logstash systemd unit.
_LOGSTASH_ENV_FILE = Path('/etc/default/logstash')


def _resolve_keystore_env_file(env_file: Optional[str] = None) -> Path:
    """Prefer explicit path, then agent state, then package default."""
    if env_file:
        return Path(env_file)
    try:
        state_path = agent_state.get_state().get('keystore_env_file')
        if state_path:
            return Path(state_path)
    except Exception:
        pass
    return _LOGSTASH_ENV_FILE


def update_logstash_env_file(
    password: Optional[str],
    env_file: Optional[str] = None,
) -> None:
    """
    Write, update, or clear LOGSTASH_KEYSTORE_PASS in the Logstash env file.

    When ``password`` is a non-empty string, the variable is set so the Logstash
    systemd service can open a password-protected keystore on startup.
    When ``password`` is None or empty, any existing LOGSTASH_KEYSTORE_PASS line
    is removed (unauthenticated / trailer keystores).

    ``env_file`` overrides the path (policy ``keystore_env_file``). For package
    Logstash the default is ``/etc/default/logstash`` (sudo cat/tee). For simulate
    instances the path is typically ``/opt/LogstashAgent/simulate-N/env`` and is
    written directly when the agent owns the tree.

    Raises:
        FileNotFoundError: If a required package env file doesn't exist
        OSError: If unable to read or write the file
    """
    var_name = 'LOGSTASH_KEYSTORE_PASS'
    env_path = _resolve_keystore_env_file(env_file)
    use_sudo = str(env_path) == str(_LOGSTASH_ENV_FILE) or str(env_path).startswith('/etc/')

    # Package env file must already exist; simulate instance env may be created.
    if use_sudo and not env_path.exists():
        logger.error(f"{env_path} does not exist - Logstash may not be properly installed")
        raise FileNotFoundError(
            f"{env_path} not found. "
            "This file should be created by the Logstash package installation. "
            "Please verify Logstash is properly installed."
        )

    # Read existing lines
    existing_lines = []
    try:
        if use_sudo:
            result = subprocess.run(
                ['sudo', 'cat', str(env_path)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                existing_lines = result.stdout.splitlines()
            else:
                logger.error(f"Failed to read {env_path}: {result.stderr}")
                raise OSError(f"Cannot read {env_path}")
        elif env_path.exists():
            existing_lines = env_path.read_text(encoding='utf-8').splitlines()
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout reading {env_path}")
        raise
    except OSError:
        raise
    except Exception as e:
        logger.error(f"Failed to read {env_path}: {e}")
        raise

    # Drop any existing LOGSTASH_KEYSTORE_PASS line; re-add only when setting a password
    filtered = [ln for ln in existing_lines if not ln.startswith(f'{var_name}=')]
    if password:
        filtered.append(f'{var_name}={password}')
        logger.info(f"Setting {var_name} in {env_path}")
    else:
        logger.info(f"Clearing {var_name} from {env_path} (unauthenticated keystore)")

    content = '\n'.join(filtered) + '\n'

    try:
        if use_sudo:
            result = subprocess.run(
                ['sudo', 'tee', str(env_path)],
                input=content,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                logger.error(f"Failed to write {env_path}: {result.stderr}")
                raise OSError(f"Cannot write to {env_path}")
            chmod_result = subprocess.run(
                ['sudo', 'chmod', '640', str(env_path)],
                capture_output=True,
                timeout=5,
                check=False
            )
            if chmod_result.returncode != 0:
                logger.warning(f"Failed to set permissions on {env_path}: {chmod_result.stderr}")
        else:
            env_path.parent.mkdir(parents=True, exist_ok=True)
            env_path.write_text(content, encoding='utf-8')
            try:
                os.chmod(env_path, 0o640)
            except OSError as chmod_err:
                logger.warning(f"Failed to set permissions on {env_path}: {chmod_err}")
        logger.info(f"Updated {var_name} in {env_path}")
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout writing {env_path}")
        raise
    except OSError:
        raise
    except Exception as e:
        logger.error(f"Failed to write {env_path}: {e}")
        raise


def ensure_keystore(settings_path: str, password: Optional[str] = None) -> LogstashKeystore:
    """
    Load an existing keystore or create one in the requested password mode.

    Args:
        settings_path: Logstash settings directory (path.settings).
        password: Explicit password for authenticated mode, or None for an
            unauthenticated (default-password trailer) keystore.

    Returns:
        Loaded or newly created LogstashKeystore instance.
    """
    if settings_path:
        settings_path = settings_path.replace('\\', '/')
    if not settings_path.endswith('/'):
        settings_path = settings_path + '/'

    keystore_file = Path(settings_path) / 'logstash.keystore'
    if keystore_file.exists():
        return LogstashKeystore.load(path_settings=settings_path, password=password)
    mode = "authenticated" if password else "unauthenticated"
    logger.info(f"Creating {mode} keystore at {settings_path}")
    return LogstashKeystore.create(path_settings=settings_path, password=password)


def set_keystore_password(settings_path: str, new_password: str) -> dict:
    """
    Apply an authenticated keystore password, preferring secret-preserving migrate.

    - Existing unauthenticated keystore: migrate_to_authenticated (keeps secrets).
    - Existing authenticated keystore with known agent password: migrate in place.
    - No keystore file: create authenticated empty keystore.
    - Authenticated file that cannot be opened: wipe and recreate (secrets lost).

    Updates agent state (keystore_password, keystore_password_hash) and
    LOGSTASH_KEYSTORE_PASS in the Logstash env file.

    Args:
        settings_path: Logstash settings directory.
        new_password: Non-empty password to apply.

    Returns:
        dict with keys: success (bool), wiped (bool), action (str).

    Raises:
        ValueError: If new_password is empty.
    """
    if not new_password:
        raise ValueError("new_password must be a non-empty string")

    if settings_path:
        settings_path = settings_path.replace('\\', '/')
    if not settings_path.endswith('/'):
        settings_path = settings_path + '/'

    keystore_file = Path(settings_path) / 'logstash.keystore'
    state = agent_state.get_state()
    current_password = state.get('keystore_password') or None
    wiped = False
    action = 'none'

    try:
        if keystore_file.exists():
            # Prefer opening as unauthenticated (trailer) first when we have no
            # stored password — common path when server first sets a password.
            try:
                if current_password:
                    ks = LogstashKeystore.load(
                        path_settings=settings_path, password=current_password
                    )
                else:
                    ks = LogstashKeystore.load(
                        path_settings=settings_path, password=None
                    )
                ks.migrate_to_authenticated(new_password)
                action = 'migrated'
                logger.info("Migrated keystore to authenticated password (secrets preserved)")
            except Exception as open_err:
                logger.warning(
                    f"Could not migrate existing keystore ({open_err}); "
                    "recreating authenticated keystore (secrets will be wiped)"
                )
                try:
                    keystore_file.unlink(missing_ok=True)
                except Exception as del_e:
                    logger.error(f"Failed to delete keystore for recreate: {del_e}")
                    return {'success': False, 'wiped': False, 'action': 'failed'}
                LogstashKeystore.create(
                    path_settings=settings_path, password=new_password
                )
                wiped = True
                action = 'recreated'
        else:
            LogstashKeystore.create(path_settings=settings_path, password=new_password)
            action = 'created'
            logger.info("Created new authenticated keystore")

        new_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
        agent_state.update_state('keystore_password', new_password)
        agent_state.update_state('keystore_password_hash', new_hash)

        if wiped and state.get('snmp_keystore'):
            agent_state.update_state('snmp_keystore', {})
            logger.info(
                "Cleared SNMP keystore state after password recreate; "
                "SNMP keys will be re-provisioned on next check-in"
            )

        try:
            update_logstash_env_file(new_password)
        except Exception as env_err:
            logger.warning(f"Keystore password applied but env file update failed: {env_err}")

        return {'success': True, 'wiped': wiped, 'action': action}
    except Exception as e:
        logger.error(f"set_keystore_password failed: {e}")
        logger.exception("set_keystore_password exception details:")
        return {'success': False, 'wiped': wiped, 'action': 'failed'}


def clear_keystore_password(settings_path: str) -> dict:
    """
    Convert an authenticated keystore to unauthenticated (embedded trailer).

    Invoked from check-in when GetConfigChanges returns ``keystore_password: null``
    (policy no longer has a password; agent still reported a hash).

    Requires the current password in agent state so secrets can be re-encrypted.
    Clears keystore_password from agent state and removes LOGSTASH_KEYSTORE_PASS
    from the Logstash env file.

    Args:
        settings_path: Logstash settings directory.

    Returns:
        dict with keys: success (bool), action (str).
    """
    if settings_path:
        settings_path = settings_path.replace('\\', '/')
    if not settings_path.endswith('/'):
        settings_path = settings_path + '/'

    state = agent_state.get_state()
    current_password = state.get('keystore_password') or None
    keystore_file = Path(settings_path) / 'logstash.keystore'

    try:
        if not keystore_file.exists():
            ensure_keystore(settings_path, password=None)
            agent_state.update_state('keystore_password', None)
            agent_state.update_state('keystore_password_hash', '')
            try:
                update_logstash_env_file(None)
            except Exception as env_err:
                logger.warning(f"Unauth keystore ready but env clear failed: {env_err}")
            return {'success': True, 'action': 'created_unauth'}

        if current_password:
            ks = LogstashKeystore.load(
                path_settings=settings_path, password=current_password
            )
        else:
            # Already unauthenticated
            ks = LogstashKeystore.load(path_settings=settings_path, password=None)
            if ks.uses_embedded_password:
                agent_state.update_state('keystore_password', None)
                agent_state.update_state('keystore_password_hash', '')
                try:
                    update_logstash_env_file(None)
                except Exception:
                    pass
                return {'success': True, 'action': 'already_unauth'}

        ks.migrate_to_unauthenticated()
        agent_state.update_state('keystore_password', None)
        agent_state.update_state('keystore_password_hash', '')
        try:
            update_logstash_env_file(None)
        except Exception as env_err:
            logger.warning(f"Migrated to unauth but env clear failed: {env_err}")
        logger.info("Migrated keystore to unauthenticated mode (secrets preserved)")
        return {'success': True, 'action': 'migrated_unauth'}
    except Exception as e:
        logger.error(f"clear_keystore_password failed: {e}")
        logger.exception("clear_keystore_password exception details:")
        return {'success': False, 'action': 'failed'}


def apply_keystore_password_change(
    settings_path: str,
    keystore_password_response,
    api_key: str,
) -> dict:
    """
    Apply the ``keystore_password`` field from GetConfigChanges.

    Protocol:
      - ``False``: no change
      - ``None`` (JSON null): clear → unauthenticated (``clear_keystore_password``)
      - encrypted string: set/rotate via ``set_keystore_password``

    Returns:
        dict: applied (bool), success (bool), requires_restart (bool),
        error (str|None), action (str|None)
    """
    if keystore_password_response is False:
        return {
            'applied': False,
            'success': True,
            'requires_restart': False,
            'error': None,
            'action': None,
        }

    if keystore_password_response is None:
        logger.info("Keystore password clear requested (policy has no password)")
        result = clear_keystore_password(settings_path)
        if result.get('success'):
            logger.info(
                "Keystore password cleared (action=%s)",
                result.get('action'),
            )
            return {
                'applied': True,
                'success': True,
                'requires_restart': True,
                'error': None,
                'action': result.get('action'),
            }
        return {
            'applied': True,
            'success': False,
            'requires_restart': False,
            'error': 'keystore password clear failed',
            'action': result.get('action'),
        }

    # Encrypted password string from server
    logger.info("Keystore password change detected")
    try:
        actual_password = _decrypt_from_server(api_key, keystore_password_response)
        logger.info("Successfully decrypted new keystore password")
        result = set_keystore_password(settings_path, actual_password)
        if result.get('success'):
            logger.info(
                "Keystore password applied (action=%s, wiped=%s)",
                result.get('action'),
                result.get('wiped'),
            )
            return {
                'applied': True,
                'success': True,
                'requires_restart': True,
                'error': None,
                'action': result.get('action'),
            }
        return {
            'applied': True,
            'success': False,
            'requires_restart': False,
            'error': 'keystore password apply failed',
            'action': result.get('action'),
        }
    except Exception as decrypt_error:
        logger.error(
            "Failed to decrypt keystore password from server: %s",
            decrypt_error,
        )
        keystore_file = Path(settings_path) / 'logstash.keystore'
        try:
            keystore_file.unlink(missing_ok=True)
            logger.warning(
                "Deleted keystore file - will recreate with correct password "
                "on next successful sync"
            )
        except Exception as del_e:
            logger.warning("Could not delete keystore file: %s", del_e)
        return {
            'applied': True,
            'success': False,
            'requires_restart': False,
            'error': f'keystore_password decrypt failed: {decrypt_error}',
            'action': 'decrypt_failed',
        }


# Module-level watcher — started once by run_controller(), consulted by check_in()
_log_watcher: Optional[log_analyzer.LogstashLogWatcher] = None


def update_env_logstash_binary(env_file: Optional[str], binary: str) -> bool:
    """
    Set or replace LOGSTASH_BINARY= in a simulate instance env file
    (e.g. /opt/LogstashAgent/simulate-N/env) without using sudo when the
    agent owns the tree.
    """
    if not env_file or not binary:
        return False
    path = Path(env_file)
    try:
        lines = []
        if path.exists():
            lines = path.read_text(encoding='utf-8').splitlines()
        filtered = [ln for ln in lines if not ln.startswith('LOGSTASH_BINARY=')]
        filtered.append(f'LOGSTASH_BINARY={binary}')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('\n'.join(filtered) + '\n', encoding='utf-8')
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass
        logger.info(f"Updated LOGSTASH_BINARY in {path} -> {binary}")
        return True
    except Exception as e:
        logger.error(f"Failed to update LOGSTASH_BINARY in {env_file}: {e}")
        return False


def apply_logstash_runtime(runtime: dict) -> dict:
    """
    Apply policy Logstash binary source (SYSTEM vs VERSION download).

    Downloads VERSION artifacts when needed, updates agent state and the
    simulate instance EnvironmentFile LOGSTASH_BINARY line.

    Returns:
        dict: success (bool), requires_restart (bool), binary (str|None),
              error (str|None), source, version
    """
    from .logstash_download import (
        resolve_binary_from_policy,
        LogstashDownloadError,
        DEFAULT_DOWNLOAD_ROOT,
    )

    if not runtime or runtime is False:
        return {
            'success': True,
            'requires_restart': False,
            'binary': None,
            'error': None,
            'source': None,
            'version': None,
        }

    source = (runtime.get('source') or 'SYSTEM').upper()
    version = (runtime.get('version') or '').strip()
    download_dir = (runtime.get('download_dir') or DEFAULT_DOWNLOAD_ROOT).strip()
    binary_path = runtime.get('binary_path') or '/usr/share/logstash/bin'

    logger.info(
        "Applying logstash_runtime: source=%s version=%s download_dir=%s binary_path=%s",
        source, version or '(none)', download_dir, binary_path,
    )

    try:
        binary = resolve_binary_from_policy(
            logstash_source=source,
            logstash_version=version,
            logstash_download_dir=download_dir,
            binary_path=binary_path,
        )
    except LogstashDownloadError as e:
        logger.error(f"Logstash runtime apply failed: {e}")
        return {
            'success': False,
            'requires_restart': False,
            'binary': None,
            'error': str(e),
            'source': source,
            'version': version,
        }
    except Exception as e:
        logger.error(f"Unexpected error applying logstash_runtime: {e}", exc_info=True)
        return {
            'success': False,
            'requires_restart': False,
            'binary': None,
            'error': str(e),
            'source': source,
            'version': version,
        }

    binary = str(binary)
    # State binary_path is historically a directory used for existence checks
    bin_dir = str(Path(binary).parent) if Path(binary).name in ('logstash', 'logstash.bat') else binary

    prev_binary = agent_state.get_state().get('logstash_binary') or agent_state.get_state().get('binary_path')
    agent_state.update_state('logstash_source', source)
    agent_state.update_state('logstash_version', version)
    agent_state.update_state('logstash_download_dir', download_dir)
    agent_state.update_state('binary_path', bin_dir)
    agent_state.update_state('logstash_binary', binary)
    if version:
        agent_state.update_state('logstash_version_resolved', version)

    state = agent_state.get_state()
    env_file = state.get('keystore_env_file')
    mode = (state.get('mode') or '').lower()
    if mode == 'simulate' or (env_file and str(env_file).endswith('/env')):
        update_env_logstash_binary(env_file, binary)

    requires_restart = (str(prev_binary) != binary) if prev_binary else True
    logger.info(
        "Logstash runtime applied: binary=%s requires_restart=%s",
        binary, requires_restart,
    )
    return {
        'success': True,
        'requires_restart': requires_restart,
        'binary': binary,
        'error': None,
        'source': source,
        'version': version,
    }


def update_logstash_yml(settings_path, content):
    """
    Update logstash.yml file with new content.
    
    Args:
        settings_path: Path to Logstash settings directory
        content: New content for logstash.yml
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logstash_yml_path = settings_path + 'logstash.yml'
        logger.info(f"Updating logstash.yml at {logstash_yml_path}")
        
        with open(logstash_yml_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info("Successfully updated logstash.yml")
        return True
    except Exception as e:
        logger.error(f"Failed to update logstash.yml: {e}")
        return False


def update_jvm_options(settings_path, content):
    """
    Update jvm.options file with new content.
    
    Args:
        settings_path: Path to Logstash settings directory
        content: New content for jvm.options
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        jvm_options_path = settings_path + 'jvm.options'
        logger.info(f"Updating jvm.options at {jvm_options_path}")
        
        with open(jvm_options_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info("Successfully updated jvm.options")
        return True
    except Exception as e:
        logger.error(f"Failed to update jvm.options: {e}")
        return False


def update_log4j2_properties(settings_path, content):
    """
    Update log4j2.properties file with new content.
    
    Args:
        settings_path: Path to Logstash settings directory
        content: New content for log4j2.properties
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        log4j2_properties_path = settings_path + 'log4j2.properties'
        logger.info(f"Updating log4j2.properties at {log4j2_properties_path}")
        
        with open(log4j2_properties_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info("Successfully updated log4j2.properties")
        return True
    except Exception as e:
        logger.error(f"Failed to update log4j2.properties: {e}")
        return False


def update_keystore(settings_path, keystore_changes):
    """
    Update the Logstash keystore with set/delete operations.

    Supports authenticated keystores (password in agent state) and unauthenticated
    Logstash keystores (password=None; default-password trailer on disk). Uses
    pure-Python PKCS#12 writes by default.

    Args:
        settings_path: Path to Logstash settings directory
        keystore_changes: Dictionary with 'set' and 'delete' keys
            - 'set': Dictionary of {key_name: key_value} to add/update
            - 'delete': List of key names to remove

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"Starting keystore update at {settings_path}")
        logger.debug(f"Keystore changes requested: {keystore_changes}")

        # Get keystore password from agent state.
        # Pass None (not empty string) for unauthenticated keystores — LogstashKeystore
        # recovers the embedded trailer password when password is None.
        state = agent_state.get_state()
        keystore_password = state.get('keystore_password') or None

        if keystore_password:
            logger.info("Keystore password: CONFIGURED (using provided password)")
        else:
            logger.info("Keystore password: NOT CONFIGURED (unauthenticated keystore)")
        
        # Normalize path separators
        if settings_path:
            settings_path = settings_path.replace('\\', '/')
        if not settings_path.endswith('/'):
            settings_path = settings_path + '/'
        
        logger.debug(f"Normalized settings path: {settings_path}")
        
        # Extract set and delete operations
        keys_to_set = keystore_changes.get('set', {})
        keys_to_delete = keystore_changes.get('delete', [])
        
        logger.info(f"Operations summary: {len(keys_to_set)} keys to set, {len(keys_to_delete)} keys to delete")
        
        if not keys_to_set and not keys_to_delete:
            logger.info("No keystore changes to apply - skipping keystore operations")
            return False
        
        # Load the keystore, recreating it if the password is wrong or it doesn't exist
        logger.info("Attempting to load existing keystore...")
        try:
            ks = LogstashKeystore.load(
                path_settings=settings_path,
                password=keystore_password
            )
            logger.info("Successfully loaded existing keystore")
            logger.debug(f"Keystore contains {len(ks.keys)} existing keys")
        except IncorrectPassword:
            logger.warning("Incorrect keystore password - deleting incompatible keystore and recreating")
            keystore_file = Path(settings_path) / 'logstash.keystore'
            try:
                keystore_file.unlink(missing_ok=True)
                logger.info("Deleted incompatible keystore file")
            except Exception as del_e:
                logger.warning(f"Could not delete keystore file: {del_e}")
            try:
                ks = LogstashKeystore.create(
                    path_settings=settings_path,
                    password=keystore_password
                )
                logger.info("Recreated keystore with current stored password")
            except Exception as create_error:
                logger.error(f"Failed to recreate keystore: {create_error}")
                return False
        except LogstashKeystoreException as e:
            logger.warning(f"Failed to load keystore: {e}")
            try:
                mode = "authenticated" if keystore_password else "unauthenticated"
                logger.info(f"Keystore does not exist - creating new {mode} keystore...")
                ks = LogstashKeystore.create(
                    path_settings=settings_path,
                    password=keystore_password
                )
                logger.info("Successfully created new keystore")
            except Exception as create_error:
                logger.error(f"Failed to create keystore: {create_error}")
                return False
        except ValueError as e:
            # Authenticated file but no password in state (or no trailer).
            logger.error(f"Cannot open keystore without a password: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error loading keystore: {e}")
            return False
        
        # Perform delete operations first
        if keys_to_delete:
            logger.info(f"Processing DELETE operations for {len(keys_to_delete)} key(s): {keys_to_delete}")
            try:
                # Filter out keys that don't exist
                existing_keys = ks.keys
                logger.debug(f"Current keystore keys: {existing_keys}")
                keys_to_actually_delete = [k for k in keys_to_delete if k.upper() in existing_keys]
                
                if keys_to_actually_delete:
                    logger.info(f"Deleting keys: {keys_to_actually_delete}")
                    ks.remove_key(keys_to_actually_delete)
                    logger.info(f"Successfully deleted {len(keys_to_actually_delete)} key(s) from keystore")
                    for key in keys_to_actually_delete:
                        logger.debug(f"  - Deleted key: {key}")
                else:
                    logger.info("No keys to delete - all specified keys don't exist in keystore")
                    for key in keys_to_delete:
                        logger.debug(f"  - Key not found: {key}")
            except LogstashKeystoreModified as e:
                logger.error(f"Keystore was modified externally during delete operation: {e}")
                logger.error("Cannot proceed - keystore state has changed")
                return False
            except Exception as e:
                logger.error(f"Failed to delete keys: {e}")
                logger.exception("Delete operation exception details:")
                return False
        
        # Perform set operations
        if keys_to_set:
            logger.info(f"Processing SET operations for {len(keys_to_set)} key(s): {list(keys_to_set.keys())}")
            
            # Decrypt keystore values using API key from agent state
            state = agent_state.get_state()
            api_key_decrypted = state.get('api_key')
            
            if not api_key_decrypted:
                logger.error("No API key found in agent state - cannot decrypt keystore values")
                return False
            
            try:
                # Decrypt all keystore values using the API key
                decrypted_keys = {}
                for key_name, encrypted_value in keys_to_set.items():
                    try:
                        actual_value = _decrypt_from_server(api_key_decrypted, encrypted_value)
                        decrypted_keys[key_name] = actual_value
                        logger.debug(f"  - Decrypted key: {key_name}")
                    except Exception as e:
                        logger.error(f"Failed to decrypt keystore value for {key_name}: {e}")
                        return False
                
                # Use decrypted keys instead of encrypted ones
                keys_to_set = decrypted_keys
                logger.info(f"Successfully decrypted {len(keys_to_set)} keystore value(s)")
                
            except Exception as e:
                logger.error(f"Failed to decrypt keystore values: {e}")
                logger.exception("Decryption exception details:")
                return False
            
            try:
                # Log each key being set (without values for security)
                for key_name in keys_to_set.keys():
                    logger.debug(f"  - Setting key: {key_name}")
                
                ks.add_key(keys_to_set)
                logger.info(f"Successfully set {len(keys_to_set)} key(s) in keystore")
                
                # Verify keys were set
                for key_name in keys_to_set.keys():
                    if key_name.upper() in ks.keys:
                        logger.debug(f"  - Verified key exists: {key_name}")
                    else:
                        logger.warning(f"  - Key verification failed: {key_name}")
            except LogstashKeystoreModified as e:
                logger.error(f"Keystore was modified externally during set operation: {e}")
                logger.error("Cannot proceed - keystore state has changed")
                return False
            except Exception as e:
                logger.error(f"Failed to set keys: {e}")
                logger.exception("Set operation exception details:")
                return False
        
        # Update keystore state with hashes
        logger.info("Updating agent state with new keystore hashes...")
        new_keystore_state = {}
        try:
            all_keys = ks.keys
            logger.debug(f"Reading {len(all_keys)} keys from keystore for state update")
            
            for key_name in all_keys:
                key_value = ks.get_key(key_name)
                if key_value is not None:
                    # Normalize key_name to lowercase for hashing.  The Logstash
                    # keystore CLI uppercases all key names internally, but the
                    # server stores and hashes them as-is (lowercase for SNMP
                    # entries).  Using lowercase here keeps the formula consistent
                    # with the server's kv_hash = SHA256(key_name + value) and
                    # makes snmp_ks_state lookups work without case gymnastics.
                    normalized = key_name.lower()
                    hash_input = f"{normalized}{key_value}"
                    key_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
                    new_keystore_state[normalized] = key_hash
                    logger.debug(f"  - Computed hash for key: {normalized}")
                else:
                    logger.warning(f"  - Key {key_name} returned None value")
            
            # Update agent state with new keystore hashes
            agent_state.update_state('keystore', new_keystore_state)
            logger.info(f"Successfully updated agent state with {len(new_keystore_state)} keystore key hash(es)")
        except Exception as e:
            logger.error(f"Failed to update keystore state: {e}")
            logger.exception("State update exception details:")
            logger.warning("Keystore was updated successfully, but state update failed")
            # Don't return False here - the keystore was updated successfully
        
        logger.info("Keystore update completed successfully")
        logger.info(f"Final keystore contains {len(ks.keys)} key(s)")
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error in update_keystore: {e}")
        logger.exception("Keystore update exception details:")
        return False


def build_pipelines_state(settings_path):
    """
    Scans {settings_path}/conf.d/*.conf and {settings_path}/pipelines.yml to build
    the current pipelines state dict from agent state (stored pipeline_hash values).

    Returns:
        dict: {pipeline_name: {config_hash: str, settings: {...}}}
              config_hash is the server's pipeline_hash stored after the last apply.
    """
    try:
        import os
        import yaml

        if settings_path:
            settings_path = settings_path.replace('\\', '/')
        if not settings_path.endswith('/'):
            settings_path = settings_path + '/'

        conf_d_path = settings_path + 'conf.d/'

        # Start from persisted state so config_hash values are the server's pipeline_hash
        state = agent_state.get_state()
        persisted_pipelines = state.get('pipelines', {})
        # SNMP-managed pipelines are reconciled via the check-in loop, not the
        # regular policy channel. Exclude them here so get_config_changes never
        # tries to delete or re-push them.
        snmp_pipeline_names = set(state.get('snmp_pipelines', {}).keys())

        if not os.path.isdir(conf_d_path):
            logger.debug(f"conf.d directory not found at {conf_d_path}, returning empty pipelines state")
            return {}

        conf_files = [f for f in os.listdir(conf_d_path) if f.endswith('.conf')]
        if not conf_files:
            logger.debug("No .conf files found in conf.d")
            return {}

        # Parse pipelines.yml for per-pipeline settings
        pipelines_yml_path = settings_path + 'pipelines.yml'
        pipeline_settings_map = {}
        try:
            with open(pipelines_yml_path, 'r', encoding='utf-8') as f:
                pipeline_list = yaml.safe_load(f)
            if isinstance(pipeline_list, list):
                for entry in pipeline_list:
                    pid = entry.get('pipeline.id')
                    if pid:
                        pipeline_settings_map[pid] = {
                            'pipeline_workers': entry.get('pipeline.workers', 1),
                            'pipeline_batch_size': entry.get('pipeline.batch.size', 128),
                            'pipeline_batch_delay': entry.get('pipeline.batch.delay', 50),
                            'queue_type': entry.get('queue.type', 'memory'),
                            'queue_max_bytes': entry.get('queue.max_bytes', '1gb'),
                            'queue_checkpoint_writes': entry.get('queue.checkpoint.writes', 1024),
                        }
        except FileNotFoundError:
            logger.debug(f"pipelines.yml not found at {pipelines_yml_path}")
        except Exception as e:
            logger.warning(f"Failed to parse pipelines.yml: {e}")

        pipelines_state = {}
        for conf_file in conf_files:
            pipeline_name = conf_file[:-5]  # strip .conf
            # Skip SNMP-managed pipelines (synced via the check-in loop)
            if pipeline_name in snmp_pipeline_names:
                continue
            # Use the stored server pipeline_hash as config_hash for stable comparison
            stored = persisted_pipelines.get(pipeline_name, {})
            config_hash = stored.get('config_hash', '')
            settings = pipeline_settings_map.get(pipeline_name, stored.get('settings', {}))
            pipelines_state[pipeline_name] = {
                'config_hash': config_hash,
                'settings': settings,
            }
            # Preserve metadata flags and revision from state
            if stored.get('non_reloadable'):
                pipelines_state[pipeline_name]['non_reloadable'] = True
            if stored.get('revision') is not None:
                pipelines_state[pipeline_name]['revision'] = stored.get('revision')

        # Include no_input pipelines from state (they don't have .conf files)
        for pipeline_name, stored in persisted_pipelines.items():
            if pipeline_name in snmp_pipeline_names:
                continue
            if stored.get('no_input') and pipeline_name not in pipelines_state:
                pipelines_state[pipeline_name] = {
                    'config_hash': stored.get('config_hash', ''),
                    'no_input': True,
                    'settings': stored.get('settings', {})
                }

        logger.debug(f"Built pipelines state: {list(pipelines_state.keys())}")
        return pipelines_state

    except Exception as e:
        logger.error(f"Failed to build pipelines state: {e}")
        return {}


def update_pipelines(settings_path, pipeline_changes):
    """
    Apply pipeline set/delete directives from the server.

    - Writes {settings_path}/conf.d/{name}.conf for each entry in 'set' (unless no_input=True)
    - Deletes {settings_path}/conf.d/{name}.conf for each entry in 'delete'
    - Rewrites {settings_path}/pipelines.yml from current conf.d state
    - Updates agent state with new pipelines dict (using server pipeline_hash values)
    - Handles no_input flag: skips writing .conf but updates state with hash
    - Handles non_reloadable flag: appends revision number to pipeline_id to force recreation

    Args:
        settings_path: Path to Logstash settings directory
        pipeline_changes: {'set': {name: {lscl, pipeline_hash, settings, no_input, non_reloadable}}, 'delete': [name, ...]}

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        import os
        import yaml

        if settings_path:
            settings_path = settings_path.replace('\\', '/')
        if not settings_path.endswith('/'):
            settings_path = settings_path + '/'

        conf_d_path = settings_path + 'conf.d/'
        pipelines_yml_path = settings_path + 'pipelines.yml'

        pipelines_to_set = pipeline_changes.get('set', {})
        pipelines_to_delete = pipeline_changes.get('delete', [])

        logger.info(f"Pipeline update: {len(pipelines_to_set)} to set, {len(pipelines_to_delete)} to delete")

        if not pipelines_to_set and not pipelines_to_delete:
            logger.info("No pipeline changes to apply")
            return False

        # Ensure conf.d directory exists
        os.makedirs(conf_d_path, exist_ok=True)

        # Process deletes
        for pipeline_name in pipelines_to_delete:
            conf_path = conf_d_path + pipeline_name + '.conf'
            try:
                if os.path.isfile(conf_path):
                    os.remove(conf_path)
                    logger.info(f"Deleted pipeline config: {conf_path}")
                else:
                    logger.debug(f"Pipeline config not found (already gone): {conf_path}")
            except Exception as e:
                logger.error(f"Failed to delete pipeline config {conf_path}: {e}")
                return False

        # Process sets
        for pipeline_name, pipeline_data in pipelines_to_set.items():
            lscl_content = pipeline_data.get('lscl', '')
            no_input = pipeline_data.get('no_input', False)
            conf_path = conf_d_path + pipeline_name + '.conf'
            
            # Skip writing .conf file if pipeline has no input
            if no_input:
                logger.info(f"Pipeline {pipeline_name} has no_input=True, skipping .conf write")
                # Delete the .conf file if it exists from a previous version
                try:
                    if os.path.isfile(conf_path):
                        os.remove(conf_path)
                        logger.info(f"Deleted existing .conf for no_input pipeline: {conf_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete existing .conf for no_input pipeline {conf_path}: {e}")
                continue
            
            # Write .conf file for pipelines with input
            try:
                with open(conf_path, 'w', encoding='utf-8') as f:
                    f.write(lscl_content)
                logger.info(f"Wrote pipeline config: {conf_path}")
            except Exception as e:
                logger.error(f"Failed to write pipeline config {conf_path}: {e}")
                return False

        # Build current state from conf.d (all .conf files now present)
        try:
            conf_files = [f for f in os.listdir(conf_d_path) if f.endswith('.conf')]
        except Exception as e:
            logger.error(f"Failed to list conf.d directory: {e}")
            return False

        # Load existing agent state for settings of pipelines we didn't just receive
        existing_state = agent_state.get_state()
        existing_pipelines = existing_state.get('pipelines', {})

        # Build pipelines.yml entries and new agent state
        yml_entries = []
        new_pipelines_state = {}

        for conf_file in sorted(conf_files):
            pipeline_name = conf_file[:-5]  # strip .conf

            # Get settings: prefer freshly received, fall back to existing state
            if pipeline_name in pipelines_to_set:
                settings = pipelines_to_set[pipeline_name].get('settings', {})
                config_hash = pipelines_to_set[pipeline_name].get('pipeline_hash', '')
                non_reloadable = pipelines_to_set[pipeline_name].get('non_reloadable', False)
            else:
                existing = existing_pipelines.get(pipeline_name, {})
                settings = existing.get('settings', {})
                config_hash = existing.get('config_hash', '')
                non_reloadable = existing.get('non_reloadable', False)

            workers = settings.get('pipeline_workers', 1)
            batch_size = settings.get('pipeline_batch_size', 128)
            batch_delay = settings.get('pipeline_batch_delay', 50)
            queue_type = settings.get('queue_type', 'memory')
            queue_max_bytes = settings.get('queue_max_bytes', '1gb')
            checkpoint_writes = settings.get('queue_checkpoint_writes', 1024)

            # For non-reloadable pipelines, append revision number to force recreation
            if non_reloadable:
                # Get or increment revision for this pipeline
                existing = existing_pipelines.get(pipeline_name, {})
                current_revision = existing.get('revision', 0)
                new_revision = current_revision + 1
                pipeline_id = f"{pipeline_name}-{new_revision}"
                logger.info(f"Pipeline {pipeline_name} is non_reloadable, using pipeline.id: {pipeline_id}")
            else:
                pipeline_id = pipeline_name
                new_revision = None

            yml_entry = {
                'pipeline.id': pipeline_id,
                'path.config': f"{conf_d_path}{pipeline_name}.conf",
                'pipeline.workers': workers,
                'pipeline.batch.size': batch_size,
                'pipeline.batch.delay': batch_delay,
                'queue.type': queue_type,
                'queue.max_bytes': queue_max_bytes,
                'queue.checkpoint.writes': checkpoint_writes,
            }
            yml_entries.append(yml_entry)

            new_pipelines_state[pipeline_name] = {
                'config_hash': config_hash,
                'non_reloadable': non_reloadable,
                'settings': {
                    'pipeline_workers': workers,
                    'pipeline_batch_size': batch_size,
                    'pipeline_batch_delay': batch_delay,
                    'queue_type': queue_type,
                    'queue_max_bytes': queue_max_bytes,
                    'queue_checkpoint_writes': checkpoint_writes,
                }
            }
            if new_revision is not None:
                new_pipelines_state[pipeline_name]['revision'] = new_revision

        # Write pipelines.yml
        try:
            with open(pipelines_yml_path, 'w', encoding='utf-8') as f:
                yaml.dump(yml_entries, f, default_flow_style=False, allow_unicode=True)
            logger.info(f"Rewrote pipelines.yml with {len(yml_entries)} pipeline(s)")
        except Exception as e:
            logger.error(f"Failed to write pipelines.yml: {e}")
            return False

        # Handle no_input pipelines - add to state but not to pipelines.yml
        for pipeline_name, pipeline_data in pipelines_to_set.items():
            no_input = pipeline_data.get('no_input', False)
            if no_input and pipeline_name not in new_pipelines_state:
                # Pipeline has no input, store in state but don't write to pipelines.yml
                config_hash = pipeline_data.get('pipeline_hash', '')
                settings = pipeline_data.get('settings', {})
                logger.info(f"Storing no_input pipeline {pipeline_name} in state only (hash: {config_hash[:8]}...)")
                new_pipelines_state[pipeline_name] = {
                    'config_hash': config_hash,
                    'no_input': True,
                    'settings': settings
                }

        # Update agent state
        agent_state.update_state('pipelines', new_pipelines_state)
        logger.info(f"Updated agent pipelines state with {len(new_pipelines_state)} pipeline(s)")

        return True

    except Exception as e:
        logger.error(f"Unexpected error in update_pipelines: {e}")
        logger.exception("update_pipelines exception details:")
        return False


def _logstash_unit_name() -> str:
    """
    Systemd unit for this agent role.

    - default: ``logstash``
    - simulate: ``ls-simulate@N`` from state (or derived from instance_id)
    """
    state = agent_state.get_state()
    unit = state.get('logstash_unit')
    if unit:
        return unit
    mode = (state.get('mode') or 'default').lower()
    if mode == 'simulate':
        instance_id = state.get('instance_id')
        if instance_id is not None:
            return f'ls-simulate@{instance_id}'
    return 'logstash'


def restart_logstash():
    """
    Restart the Logstash service for this agent role.
    Uses sudo as configured in /etc/sudoers.d/logstash-agent

    Default agents restart ``logstash``; simulate agents restart ``ls-simulate@N``.

    Returns:
        bool: True if successful, False otherwise
    """
    unit = _logstash_unit_name()
    try:
        logger.info(f"Restarting Logstash service ({unit})...")

        # Try systemctl first (most common on Linux)
        # Use sudo since agent runs as logstash user
        try:
            result = subprocess.run(
                ['sudo', 'systemctl', 'restart', unit],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info(f"Logstash service restarted successfully via systemctl ({unit})")
                return True
            else:
                logger.warning(f"systemctl restart {unit} failed: {result.stderr}")
        except FileNotFoundError:
            logger.debug("systemctl not found, trying service command")

        # Try service command as fallback (default unit only)
        if unit == 'logstash':
            try:
                result = subprocess.run(
                    ['sudo', 'service', 'logstash', 'restart'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    logger.info("Logstash service restarted successfully via service command")
                    return True
                else:
                    logger.warning(f"service restart failed: {result.stderr}")
            except FileNotFoundError:
                logger.debug("service command not found")

        logger.error(f"Failed to restart Logstash unit {unit} - no suitable service manager found")
        return False

    except subprocess.TimeoutExpired:
        logger.error(f"Logstash restart timed out after 30 seconds ({unit})")
        return False
    except Exception as e:
        logger.error(f"Failed to restart Logstash service ({unit}): {e}")
        return False


def _merge_keystore_into(plan_keystore, incoming):
    """
    Merge an incoming {'set': {...}, 'delete': [...]} keystore delta into the
    shared apply plan. Later sources override earlier ones on key-name conflict
    (collisions across sources are not expected today — see handoff).
    """
    if not incoming or incoming is False:
        return
    for name, value in (incoming.get('set') or {}).items():
        plan_keystore['set'][name] = value
    for name in (incoming.get('delete') or []):
        if name not in plan_keystore['delete']:
            plan_keystore['delete'].append(name)


def _merge_pipelines_into(plan_pipelines, incoming):
    """
    Merge an incoming {'set': {...}, 'delete': [...]} pipeline delta into the
    shared apply plan.
    """
    if not incoming or incoming is False:
        return
    for name, data in (incoming.get('set') or {}).items():
        plan_pipelines['set'][name] = data
    for name in (incoming.get('delete') or []):
        if name not in plan_pipelines['delete']:
            plan_pipelines['delete'].append(name)


def _apply_merged_plan(settings_path, plan, policy_res, snmp_res):
    """
    Apply a merged policy + SNMP change plan in a SINGLE pass:
    one keystore write batch (pure-Python PKCS#12 by default), one pipelines.yml
    rewrite, and at most one Logstash restart — instead of each channel applying
    and restarting on its own.

    Config files and the keystore-password rebuild are applied earlier, inline in
    `get_config_changes` (they are policy-only and order-sensitive). This function
    only applies the merged keystore-key + pipeline deltas, restarts once if
    needed, then updates the SNMP hash namespaces and finalizes the policy
    revision / last_policy_apply bookkeeping.

    Args:
        settings_path: Logstash settings directory
        plan: {'keystore': {'set': {}, 'delete': []},
               'pipelines': {'set': {}, 'delete': []}}
        policy_res: dict returned by get_config_changes(plan=...) or None if the
                    policy channel did not run this cycle
        snmp_res: dict returned by apply_snmp_changes(plan=...) or None
    """
    ks = plan['keystore']
    pl = plan['pipelines']

    # A key/pipeline being set supersedes a delete of the same name.
    ks['delete'] = [n for n in ks['delete'] if n not in ks['set']]
    pl['delete'] = [n for n in pl['delete'] if n not in pl['set']]

    ks_has = bool(ks['set'] or ks['delete'])
    pl_has = bool(pl['set'] or pl['delete'])

    ks_ok = True
    pl_ok = True

    # Keystore first — pipelines may reference these keys. Single batched
    # keystore write covers both policy and SNMP keys (pure-Python by default).
    if ks_has:
        logger.info(f"Merged keystore apply: {len(ks['set'])} set, {len(ks['delete'])} delete")
        ks_ok = update_keystore(settings_path, ks)
        if not ks_ok:
            logger.error("Merged keystore apply failed")

    # Pipelines — single pipelines.yml rewrite covering policy + SNMP.
    if pl_has:
        logger.info(f"Merged pipeline apply: {len(pl['set'])} set, {len(pl['delete'])} delete")
        pl_ok = update_pipelines(settings_path, pl)
        if not pl_ok:
            logger.error("Merged pipeline apply failed")

    # Restart is required for config-file / keystore-password changes (policy
    # channel) or whenever keystore VALUES were added/updated. Pipeline changes
    # and pure keystore deletes reload dynamically — no restart.
    requires_restart = bool(ks['set'])
    if policy_res:
        requires_restart = requires_restart or policy_res.get('requires_restart', False)

    keystore_apply_ok = (not ks_has) or ks_ok
    restart_failed = False
    if requires_restart and keystore_apply_ok:
        logger.info("Applying merged changes — restarting Logstash once...")
        if restart_logstash():
            logger.info("Logstash restart completed successfully")
        else:
            logger.error("Logstash restart failed - manual intervention may be required")
            restart_failed = True
    elif pl_has and pl_ok and not ks['set']:
        logger.info("Pipeline-only changes applied - Logstash restart not required")

    # --- Update SNMP hash namespaces (only for parts that applied cleanly) ---
    if snmp_res and snmp_res.get('ran'):
        if (snmp_res.get('pipeline_set') or snmp_res.get('pipeline_delete_names')) and pl_ok:
            snmp_pl_state = agent_state.get_state().get('snmp_pipelines', {})
            for name in snmp_res.get('pipeline_delete_names', []):
                snmp_pl_state.pop(name, None)
            for name, phash in (snmp_res.get('pipeline_set') or {}).items():
                snmp_pl_state[name] = phash
            agent_state.update_state('snmp_pipelines', snmp_pl_state)
            logger.info(
                f"Applied SNMP pipeline changes: {len(snmp_res.get('pipeline_set') or {})} set, "
                f"{len(snmp_res.get('pipeline_delete_names') or [])} delete"
            )
        if (snmp_res.get('keystore_set_names') or snmp_res.get('keystore_delete_names')) \
                and ks_ok and not snmp_res.get('keystore_skipped'):
            regular_ks = agent_state.get_state().get('keystore', {})
            snmp_ks_state = agent_state.get_state().get('snmp_keystore', {})
            for name in snmp_res.get('keystore_delete_names', []):
                snmp_ks_state.pop(name, None)
            for name in snmp_res.get('keystore_set_names', []):
                if name in regular_ks:
                    snmp_ks_state[name] = regular_ks[name]
            agent_state.update_state('snmp_keystore', snmp_ks_state)
            logger.info(
                f"Applied SNMP keystore changes: {len(snmp_res.get('keystore_set_names') or [])} set, "
                f"{len(snmp_res.get('keystore_delete_names') or [])} delete"
            )

        # Record this source's independent apply status (Phase 2). Note:
        # `keystore_skipped` is checked directly because in that case
        # apply_snmp_changes leaves keystore_set/delete names empty.
        snmp_failed = []
        if snmp_res.get('keystore_skipped'):
            snmp_failed.append('keystore skipped - no keystore password set')
        elif (snmp_res.get('keystore_set_names') or snmp_res.get('keystore_delete_names')) \
                and ks_has and not ks_ok:
            snmp_failed.append('keystore update failed')
        if (snmp_res.get('pipeline_set') or snmp_res.get('pipeline_delete_names')) and pl_has and not pl_ok:
            snmp_failed.append('pipelines update failed')
        # Only attribute the shared restart failure to SNMP if SNMP actually
        # needed one (it added/updated keystore values); pipeline-only SNMP
        # changes reload dynamically and don't depend on the restart.
        if restart_failed and snmp_res.get('keystore_set_names'):
            snmp_failed.append('logstash restart failed')
        _record_last_apply('snmp', len(snmp_failed) == 0, snmp_failed)

    # --- Finalize policy revision + last_policy_apply (only if policy ran) ---
    if policy_res and policy_res.get('ran'):
        policy_failed = list(policy_res.get('failed_operations', []))
        if ks_has and not ks_ok:
            policy_failed.append('keystore update failed')
        if pl_has and not pl_ok:
            policy_failed.append('pipelines update failed')
        if restart_failed:
            policy_failed.append('logstash restart failed')

        aborted = policy_res.get('aborted', False)
        policy_files_updated = policy_res.get('files_updated', False)

        # Bump revision unless the rollout aborted or a policy change failed to
        # apply (mirrors the legacy standalone get_config_changes semantics).
        if (not aborted) and not (policy_files_updated and policy_failed):
            server_revision = policy_res.get('current_revision')
            if server_revision is not None:
                agent_state.update_state('revision_number', server_revision)
                logger.info(f"Updated agent revision number to {server_revision}")

        apply_success = len(policy_failed) == 0
        agent_state.update_state('last_policy_apply', {
            'success': apply_success,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'revision': policy_res.get('current_revision'),
            'failed_operations': policy_failed,
        })
        # Mirror into the per-source structure (Phase 2). last_policy_apply is
        # retained for the existing UI; last_apply['user'] is the generic form.
        _record_last_apply(
            'user', apply_success, policy_failed, revision=policy_res.get('current_revision')
        )
        logger.info(f"Saved last_policy_apply: success={apply_success}, failed={policy_failed}")


def get_config_changes(server_settings_path=None, server_logs_path=None, server_binary_path=None, plan=None):
    """
    Check for configuration changes by reading local config files and comparing hashes with server.
    Reads logstash.yml, jvm.options, and log4j2.properties from settings_path and computes SHA256 hashes.
    
    Args:
        server_settings_path: Optional settings path from server (used if paths changed)
        server_logs_path: Optional logs path from server (used if paths changed)
        server_binary_path: Optional binary path from server (used if paths changed)
    """
    try:
        # Load agent state
        state = agent_state.get_state()
        
        # Get required fields
        logstash_ui_url = state.get('logstash_ui_url')
        api_key = state.get('api_key')
        connection_id = state.get('connection_id')
        
        # Use server-provided paths if available, otherwise fall back to state
        # This allows the agent to check new paths even if state hasn't been updated yet
        settings_path = server_settings_path if server_settings_path else state.get('settings_path')
        logs_path = server_logs_path if server_logs_path else state.get('logs_path')
        binary_path = server_binary_path if server_binary_path else state.get('binary_path')
        
        # Normalize path separators for cross-platform compatibility
        # Convert Windows backslashes to forward slashes (works on both Windows and Linux)
        if settings_path:
            settings_path = settings_path.replace('\\', '/')
        if logs_path:
            logs_path = logs_path.replace('\\', '/')
        if binary_path:
            binary_path = binary_path.replace('\\', '/')
        
        if not all([logstash_ui_url, api_key, connection_id, settings_path]):
            logger.error("Missing required data for config change detection")
            return None
        
        # Ensure settings_path ends with forward slash for consistent concatenation
        if not settings_path.endswith('/'):
            settings_path = settings_path + '/'
        
        logger.info(f"Checking for config files at: {settings_path}")
        
        # Read and hash config files
        config_hashes = {}
        
        # Track if any files existed initially (to determine if we should restart Logstash)
        files_existed = False
        
        # Read logstash.yml
        logstash_yml_path = settings_path + 'logstash.yml'
        try:
            with open(logstash_yml_path, 'r', encoding='utf-8') as f:
                logstash_yml_content = f.read()
                config_hashes['logstash_yml_hash'] = hashlib.sha256(logstash_yml_content.encode('utf-8')).hexdigest()
                files_existed = True
        except FileNotFoundError:
            logger.warning(f"logstash.yml not found at {logstash_yml_path}")
            config_hashes['logstash_yml_hash'] = ''
        except Exception as e:
            logger.error(f"Error reading logstash.yml: {e}")
            config_hashes['logstash_yml_hash'] = ''
        
        # Read jvm.options
        jvm_options_path = settings_path + 'jvm.options'
        try:
            with open(jvm_options_path, 'r', encoding='utf-8') as f:
                jvm_options_content = f.read()
                config_hashes['jvm_options_hash'] = hashlib.sha256(jvm_options_content.encode('utf-8')).hexdigest()
                files_existed = True
        except FileNotFoundError:
            logger.warning(f"jvm.options not found at {jvm_options_path}")
            config_hashes['jvm_options_hash'] = ''
        except Exception as e:
            logger.error(f"Error reading jvm.options: {e}")
            config_hashes['jvm_options_hash'] = ''
        
        # Read log4j2.properties
        log4j2_properties_path = settings_path + 'log4j2.properties'
        try:
            with open(log4j2_properties_path, 'r', encoding='utf-8') as f:
                log4j2_properties_content = f.read()
                config_hashes['log4j2_properties_hash'] = hashlib.sha256(log4j2_properties_content.encode('utf-8')).hexdigest()
                files_existed = True
        except FileNotFoundError:
            logger.warning(f"log4j2.properties not found at {log4j2_properties_path}")
            config_hashes['log4j2_properties_hash'] = ''
        except Exception as e:
            logger.error(f"Error reading log4j2.properties: {e}")
            config_hashes['log4j2_properties_hash'] = ''
        
        # If no files existed, error out immediately
        logger.info(f"files_existed flag: {files_existed}")
        if not files_existed:
            logger.error(f"Provided file path of {settings_path} was not found. Do you have Logstash installed and is this the correct settings path?")
            return None
        
        logger.info(f"Files found, proceeding to check with server")
        
        # Get keystore state from agent state
        keystore_state = state.get('keystore', {})
        logger.debug(f"Current keystore state: {keystore_state}")

        # Get pipelines state
        pipelines_state = build_pipelines_state(settings_path)
        logger.debug(f"Current pipelines state: {list(pipelines_state.keys())}")

        # Prepare request data
        request_data = {
            'connection_id': connection_id,
            'logstash_yml_hash': config_hashes['logstash_yml_hash'],
            'jvm_options_hash': config_hashes['jvm_options_hash'],
            'log4j2_properties_hash': config_hashes['log4j2_properties_hash'],
            'settings_path': settings_path,
            'logs_path': logs_path,
            'binary_path': binary_path,
            'logstash_source': state.get('logstash_source') or 'SYSTEM',
            'logstash_version': state.get('logstash_version') or '',
            'logstash_download_dir': state.get('logstash_download_dir') or '',
            'keystore': keystore_state,
            'keystore_password_hash': state.get('keystore_password_hash', ''),
            'pipelines': pipelines_state,
            # Phase 2: the full SNMP hash maps ride along in this fetch so the
            # server can compute the exact SNMP delta (set/delete + decrypt of
            # only changed keys) and return it alongside the policy delta.
            'snmp_pipelines': state.get('snmp_pipelines', {}),
            'snmp_keystore': state.get('snmp_keystore', {}),
        }
        
        # Send request to server
        config_changes_url = f"{logstash_ui_url}/ConnectionManager/GetConfigChanges/"
        headers = {
            'Authorization': f'ApiKey {api_key}',
            'Content-Type': 'application/json'
        }
        
        logger.debug(f"Checking config changes with {config_changes_url}")
        
        from logstashagent.tls_trust import ssl_verify_argument

        response = requests.post(
            config_changes_url,
            json=request_data,
            headers=headers,
            timeout=30,
            verify=ssl_verify_argument(),
        )
        
        if response.status_code >= 400:
            logger.error(f"Config changes check failed with status {response.status_code}")
            logger.error(f"Response: {response.text}")
            return None
        
        # Try to parse JSON response
        try:
            result = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response from server")
            logger.error(f"Status code: {response.status_code}")
            logger.error(f"Response headers: {dict(response.headers)}")
            logger.error(f"Response body: {response.text[:500]}")
            raise
        
        if result.get('success'):
            changes = result.get('changes', {})
            
            # Debug: Log what server returned
            logger.debug(f"Server response - changes: {changes}")
            logger.debug(f"files_existed flag: {files_existed}")
            
            # Fail-fast rollout: each step must succeed before proceeding.
            # On any failure, stop immediately — no restart, no revision increment.
            # requires_restart is only set for changes that need a full Logstash restart
            # (logstash.yml, jvm.options, log4j2.properties, keystore).
            # Pipeline changes are applied dynamically and do not require a restart.
            files_updated = False
            requires_restart = False
            failed_operations = []
            rollout_aborted = False

            # Update logstash.yml if changed
            logstash_yml_content = changes.get('logstash_yml')
            if logstash_yml_content and logstash_yml_content != False:
                logger.info("Configuration change found for logstash.yml")
                if update_logstash_yml(settings_path, logstash_yml_content):
                    files_updated = True
                    requires_restart = True
                else:
                    logger.error("Failed to update logstash.yml - aborting rollout")
                    failed_operations.append('logstash.yml write failed')
                    rollout_aborted = True

            # Update jvm.options if changed
            if not rollout_aborted:
                jvm_options_content = changes.get('jvm_options')
                if jvm_options_content and jvm_options_content != False:
                    logger.info("Configuration change found for jvm.options")
                    if update_jvm_options(settings_path, jvm_options_content):
                        files_updated = True
                        requires_restart = True
                    else:
                        logger.error("Failed to update jvm.options - aborting rollout")
                        failed_operations.append('jvm.options write failed')
                        rollout_aborted = True

            # Update log4j2.properties if changed
            if not rollout_aborted:
                log4j2_properties_content = changes.get('log4j2_properties')
                if log4j2_properties_content and log4j2_properties_content != False:
                    logger.info("Configuration change found for log4j2.properties")
                    if update_log4j2_properties(settings_path, log4j2_properties_content):
                        files_updated = True
                        requires_restart = True
                    else:
                        logger.error("Failed to update log4j2.properties - aborting rollout")
                        failed_operations.append('log4j2.properties write failed')
                        rollout_aborted = True

            # Check for path changes (informational only - can't update these automatically)
            if changes.get('settings_path') and changes.get('settings_path') != False:
                logger.info(f"Configuration change found for settings_path: {changes.get('settings_path')}")
            if changes.get('logs_path') and changes.get('logs_path') != False:
                logger.info(f"Configuration change found for logs_path: {changes.get('logs_path')}")

            # Apply Logstash binary source (SYSTEM vs VERSION download) before keystore/pipelines
            if not rollout_aborted:
                runtime = changes.get('logstash_runtime')
                if runtime and runtime != False:
                    logger.info("Logstash runtime change detected (source/version/binary)")
                    rt_result = apply_logstash_runtime(runtime)
                    if rt_result.get('success'):
                        files_updated = True
                        if rt_result.get('requires_restart'):
                            requires_restart = True
                        # Prefer server binary_path state already updated inside apply
                        if rt_result.get('binary'):
                            binary_path = str(Path(rt_result['binary']).parent)
                    else:
                        logger.error(
                            "Failed to apply logstash_runtime: %s — aborting rollout",
                            rt_result.get('error'),
                        )
                        failed_operations.append(
                            f"logstash_runtime apply failed: {rt_result.get('error')}"
                        )
                        rollout_aborted = True

            # Handle keystore password change/clear (must run BEFORE keystore key changes)
            # Protocol: false=no-op, null=clear to unauth, string=encrypted set/rotate
            if not rollout_aborted and 'keystore_password' in changes:
                pw_result = apply_keystore_password_change(
                    settings_path,
                    changes.get('keystore_password'),
                    api_key,
                )
                if pw_result.get('applied'):
                    if pw_result.get('success'):
                        state = agent_state.get_state()
                        files_updated = True
                        if pw_result.get('requires_restart'):
                            requires_restart = True
                    else:
                        failed_operations.append(
                            pw_result.get('error') or 'keystore password change failed'
                        )
                        # Decrypt failure leaves keystore deleted; still abort key writes
                        if pw_result.get('action') != 'decrypt_failed':
                            rollout_aborted = True
                        else:
                            # Match prior behavior: do not hard-abort entire rollout on
                            # decrypt fail, but skip subsequent keystore key updates
                            # by leaving state without password (keys still attempted
                            # only if password in state — update_keystore handles unauth).
                            pass

            # Handle keystore changes — skip if keystore password is not yet in state
            # (e.g. decrypt failed this cycle; will be retried next sync)
            if not rollout_aborted:
                keystore_changes = changes.get('keystore')
                if keystore_changes and keystore_changes != False:
                    # Unauthenticated keystores (no password in state) are supported;
                    # secret values are still decrypted with the agent API key.
                    if plan is not None:
                        # Merge mode: defer the actual keystore write so it can be
                        # batched with SNMP (and any other source) into ONE
                        # keystore apply and ONE restart in the caller.
                        logger.info("Keystore changes detected (deferred to merged apply)")
                        _merge_keystore_into(plan['keystore'], keystore_changes)
                        files_updated = True
                    else:
                        logger.info("Keystore changes detected")
                        if update_keystore(settings_path, keystore_changes):
                            files_updated = True
                            # Only restart when keys were added or overwritten.
                            # Logstash reads the keystore at startup, so new/updated
                            # values require a restart. Delete-only operations don't:
                            # the pipeline referencing the key is removed dynamically
                            # and Logstash continues running without it.
                            if keystore_changes.get('set'):
                                requires_restart = True
                        else:
                            logger.error("Failed to update keystore - aborting rollout")
                            failed_operations.append('keystore update failed')
                            rollout_aborted = True

            # Handle pipeline changes (no restart needed — Logstash reloads pipelines dynamically)
            if not rollout_aborted:
                pipeline_changes = changes.get('pipelines')
                if pipeline_changes and pipeline_changes != False:
                    if plan is not None:
                        # Merge mode: defer so policy + SNMP pipelines share ONE
                        # pipelines.yml rewrite in the caller.
                        logger.info("Pipeline changes detected (deferred to merged apply)")
                        _merge_pipelines_into(plan['pipelines'], pipeline_changes)
                        files_updated = True
                    else:
                        logger.info("Pipeline changes detected")
                        if update_pipelines(settings_path, pipeline_changes):
                            files_updated = True
                        else:
                            logger.error("Failed to update pipelines - aborting rollout")
                            failed_operations.append('pipelines update failed')
                            rollout_aborted = True

            if plan is not None:
                # Merge mode: the caller applies the merged keystore/pipeline plan,
                # restarts once, and finalizes the revision / last_policy_apply.
                # Config files + keystore-password rebuild were already applied above.
                # `snmp_changes` (Phase 2) rides along in this same response so the
                # caller can contribute the SNMP delta into the same merged plan.
                return {
                    'success': True,
                    'ran': True,
                    'current_revision': result.get('current_revision'),
                    'files_updated': files_updated,
                    'requires_restart': requires_restart,
                    'failed_operations': failed_operations,
                    'aborted': rollout_aborted,
                    'snmp_changes': result.get('snmp_changes'),
                }

            if rollout_aborted:
                logger.error(f"Rollout aborted due to failures: {failed_operations}")
            elif files_updated:
                # All updates succeeded — restart if needed and increment revision
                if requires_restart:
                    if files_existed:
                        logger.info("Configuration files updated, restarting Logstash service...")
                        if restart_logstash():
                            logger.info("Logstash restart completed successfully")
                        else:
                            logger.error("Logstash restart failed - manual intervention may be required")
                            failed_operations.append('logstash restart failed')
                    else:
                        logger.info("Configuration files created - Logstash restart skipped (files didn't exist previously)")
                else:
                    logger.info("Pipeline-only changes applied - Logstash restart not required")

                # Update agent's revision number to match server after successful changes
                if not failed_operations:
                    server_revision = result.get('current_revision')
                    if server_revision is not None:
                        agent_state.update_state('revision_number', server_revision)
                        logger.info(f"Updated agent revision number to {server_revision}")
            else:
                logger.info("No configuration file changes detected")
                # Still sync revision number so future check-ins don't re-trigger get_config_changes
                server_revision = result.get('current_revision')
                if server_revision is not None:
                    agent_state.update_state('revision_number', server_revision)
                    logger.info(f"Updated agent revision number to {server_revision} (no config changes needed)")

            # Persist policy apply result to state (fires regardless of whether files changed)
            server_revision = result.get('current_revision')
            apply_success = len(failed_operations) == 0
            agent_state.update_state('last_policy_apply', {
                'success': apply_success,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'revision': server_revision,
                'failed_operations': failed_operations,
            })
            logger.info(f"Saved last_policy_apply: success={apply_success}, failed={failed_operations}")

            return result
        else:
            logger.warning(f"Config changes check returned success=false: {result.get('message', 'Unknown error')}")
            return result
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to check config changes with logstashui: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during config changes check: {e}")
        return None


def get_logstash_api_status(api_port=9600):
    """
    Query the Logstash node info API at http://localhost:{api_port}/.

    Returns:
        dict with keys: accessible, status, version, host, error
    """
    from .logstash_api import LogstashAPI
    base_url = f"http://localhost:{api_port}"
    try:
        api = LogstashAPI(base_url=base_url)
        data = api.get_node_info()
        return {
            'accessible': True,
            'status': data.get('status', 'unknown'),
            'version': data.get('version'),
            'host': data.get('host'),
            'error': None,
        }
    except Exception as e:
        logger.warning(f"Logstash API not accessible at {base_url}: {e}")
        return {
            'accessible': False,
            'status': 'unknown',
            'version': None,
            'host': None,
            'error': str(e)[:200],
        }


def get_logstash_health_report(api_port=9600):
    """
    Query the Logstash /_health_report endpoint.

    The raw Logstash response is stripped down to only the fields the UI needs
    (status, symptom, diagnosis, nested indicators) before being sent to
    LogstashUI. This avoids shipping large/unpredictable sub-objects (impacts,
    details, flow metrics) that could contain non-JSON-serializable values and
    silently break the check-in POST.

    All interpretation of the indicator tree stays on the LogstashUI side.

    Returns:
        dict with keys: accessible, status, symptom, indicators, error
    """
    from .logstash_api import LogstashAPI
    base_url = f"http://localhost:{api_port}"

    def strip_indicators(indicators_dict):
        """
        Recursively keep only the fields the UI renders:
        status, symptom, diagnosis (cause + action only), and nested indicators.
        Everything else (impacts, details, flow, help_url, ids, …) is dropped.
        """
        result = {}
        for name, ind in (indicators_dict or {}).items():
            result[name] = {
                'status': ind.get('status'),
                'symptom': ind.get('symptom'),
                'diagnosis': [
                    {'cause': d.get('cause'), 'action': d.get('action')}
                    for d in ind.get('diagnosis', [])
                ],
                'indicators': strip_indicators(ind.get('indicators', {})),
            }
        return result

    try:
        api = LogstashAPI(base_url=base_url)
        data = api.get_instance_health()
        indicators = strip_indicators(data.get('indicators', {}))
        logger.debug(f"Health report: status={data.get('status')}, indicators={list(indicators.keys())}")
        return {
            'accessible': True,
            'status': data.get('status', 'unknown'),
            'symptom': data.get('symptom'),
            'indicators': indicators,
            'error': None,
        }
    except Exception as e:
        logger.warning(f"Logstash health report not accessible at {base_url}: {e}")
        return {
            'accessible': False,
            'status': 'unknown',
            'symptom': None,
            'indicators': {},
            'error': str(e)[:200],
        }


def get_logstash_node_stats(api_port=9600):
    """
    Query the Logstash /_node/stats endpoint and return condensed node-level
    statistics. Pipeline-level detail is intentionally excluded.

    Returns:
        dict with keys: accessible, jvm, process, events, pipeline, reloads, error
    """
    from .logstash_api import LogstashAPI
    base_url = f"http://localhost:{api_port}"
    try:
        api = LogstashAPI(base_url=base_url)
        data = api.get_node_stats()

        jvm      = data.get('jvm', {})
        mem      = jvm.get('mem', {})
        gc       = jvm.get('gc', {}).get('collectors', {})
        process  = data.get('process', {})
        cpu      = process.get('cpu', {})
        events   = data.get('events', {})
        pipeline = data.get('pipeline', {})
        reloads  = data.get('reloads', {})

        return {
            'accessible': True,
            'jvm': {
                'heap_used_percent':        mem.get('heap_used_percent'),
                'uptime_in_millis':         jvm.get('uptime_in_millis'),
                'gc_old_collection_count':  gc.get('old', {}).get('collection_count'),
                'gc_young_collection_count': gc.get('young', {}).get('collection_count'),
            },
            'process': {
                'cpu_percent':           cpu.get('percent'),
                'open_file_descriptors': process.get('open_file_descriptors'),
            },
            'events': {
                'in':       events.get('in', 0),
                'filtered': events.get('filtered', 0),
                'out':      events.get('out', 0),
            },
            'pipeline': {
                'workers':    pipeline.get('workers'),
                'batch_size': pipeline.get('batch_size'),
            },
            'reloads': {
                'successes': reloads.get('successes', 0),
                'failures':  reloads.get('failures', 0),
            },
            'error': None,
        }
    except Exception as e:
        logger.warning(f"Logstash node stats not accessible at {base_url}: {e}")
        return {
            'accessible': False,
            'error': str(e)[:200],
        }


def get_logstash_process_info():
    """
    Use psutil to locate the Logstash JVM process and return OS-level stats.

    Logstash runs as a Java process whose command-line contains 'logstash'.
    We iterate all processes and match on that heuristic.

    Returns:
        dict with keys: available, running, and (if running) pid, status,
        cpu_percent, memory_rss_mb, memory_percent, num_threads, uptime
    """
    try:
        import psutil
    except ImportError:
        logger.debug("psutil not installed — process info unavailable")
        return {'available': False, 'running': False}

    try:
        logstash_proc = None
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                name    = (proc.info.get('name') or '').lower()
                # Logstash ships as a JVM app; 'logstash' always appears in the
                # command line even when the process is named 'java'.
                if 'logstash' in cmdline and ('java' in name or 'logstash' in name):
                    logstash_proc = proc
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if logstash_proc is None:
            return {'available': True, 'running': False}

        # Snapshot the stats we care about in one call where possible.
        with logstash_proc.oneshot():
            status      = logstash_proc.status()
            num_threads = logstash_proc.num_threads()
            mem         = logstash_proc.memory_info()
            mem_pct     = round(logstash_proc.memory_percent(), 1)
            # cpu_percent with a tiny interval gives a reasonable instantaneous
            # reading without a long blocking call.
            cpu_pct     = round(logstash_proc.cpu_percent(interval=0.2), 1)
            create_time = logstash_proc.create_time()
            pid         = logstash_proc.pid

        uptime_seconds = int(datetime.now(timezone.utc).timestamp() - create_time)
        hours, rem  = divmod(uptime_seconds, 3600)
        minutes, secs = divmod(rem, 60)
        if hours:
            uptime_str = f"{hours}h {minutes}m"
        elif minutes:
            uptime_str = f"{minutes}m {secs}s"
        else:
            uptime_str = f"{secs}s"

        return {
            'available': True,
            'running': True,
            'pid': pid,
            'status': status,
            'cpu_percent': cpu_pct,
            'memory_rss_mb': round(mem.rss / (1024 * 1024), 1),
            'memory_percent': mem_pct,
            'num_threads': num_threads,
            'uptime': uptime_str,
            'uptime_seconds': uptime_seconds,
        }

    except Exception as e:
        logger.warning(f"Failed to collect Logstash process info: {e}")
        return {'available': True, 'running': False, 'error': str(e)[:200]}


def apply_snmp_changes(settings_path, snmp_changes, plan=None):
    """
    Apply SNMP-managed pipeline and keystore changes received during check-in.

    SNMP changes are delivered independently of the policy revision number and
    are tracked in dedicated agent-state namespaces ('snmp_pipelines' and
    'snmp_keystore') so they never interfere with policy revision history.

    Two modes:
    - `plan is None` (standalone/legacy): apply keystore + pipelines directly and
      restart if keystore values changed. Returns bool.
    - `plan` provided (merge mode): contribute the SNMP deltas into the shared
      apply plan and return a metadata dict; the caller (`_apply_merged_plan`)
      applies keystore/pipelines ONCE alongside the policy channel, restarts once,
      and — on success — updates the SNMP hash namespaces from this metadata.

    Args:
        settings_path: Path to Logstash settings directory
        snmp_changes: {'pipelines': {'set': {...}, 'delete': [...]},
                       'keystore':  {'set': {...}, 'delete': [...]}}
        plan: optional shared apply plan for merged single-restart application

    Returns:
        bool (standalone mode) or dict (merge mode)
    """
    try:
        pipeline_changes = snmp_changes.get('pipelines') or {}
        keystore_changes = snmp_changes.get('keystore') or {}

        keys_to_set = keystore_changes.get('set', {})
        keys_to_delete = keystore_changes.get('delete', [])
        pipelines_to_set = pipeline_changes.get('set', {})
        pipelines_to_delete = pipeline_changes.get('delete', [])

        if plan is not None:
            # Merge mode: contribute the SNMP deltas into the shared apply plan.
            # The caller applies keystore/pipelines once and, on success, updates
            # the SNMP hash namespaces from the returned metadata below.
            state = agent_state.get_state()
            contributed = {
                'ran': True,
                'keystore_set_names': [],
                'keystore_delete_names': [],
                'keystore_skipped': False,
                'pipeline_set': {
                    name: data.get('pipeline_hash', '')
                    for name, data in pipelines_to_set.items()
                },
                'pipeline_delete_names': list(pipelines_to_delete),
            }
            if keys_to_set or keys_to_delete:
                # Unauthenticated keystores are supported (password may be absent).
                _merge_keystore_into(plan['keystore'], keystore_changes)
                contributed['keystore_set_names'] = list(keys_to_set.keys())
                contributed['keystore_delete_names'] = list(keys_to_delete)
            if pipelines_to_set or pipelines_to_delete:
                _merge_pipelines_into(plan['pipelines'], pipeline_changes)
            return contributed

        ok = True

        keystore_changed = False

        # --- Keystore first (pipelines may reference these keys) ---
        if keys_to_set or keys_to_delete:
            state = agent_state.get_state()
            # Unauthenticated keystores are supported when keystore_password is absent.
            if update_keystore(settings_path, keystore_changes):
                # regular_ks now uses lowercase key names (normalized in update_keystore),
                # matching the lowercase names the server sends for SNMP entries.
                # The lookup is now a direct match with no case conversion needed.
                regular_ks = agent_state.get_state().get('keystore', {})
                snmp_ks_state = agent_state.get_state().get('snmp_keystore', {})
                for key_name in keys_to_delete:
                    snmp_ks_state.pop(key_name, None)
                for key_name in keys_to_set:
                    if key_name in regular_ks:
                        snmp_ks_state[key_name] = regular_ks[key_name]
                agent_state.update_state('snmp_keystore', snmp_ks_state)
                logger.info(
                    f"Applied SNMP keystore changes: {len(keys_to_set)} set, "
                    f"{len(keys_to_delete)} delete"
                )
                # Only restart when keys were added or overwritten — Logstash reads
                # the keystore at startup, so new/updated values require a restart.
                # Deletes don't need one: the pipeline referencing the key is being
                # removed dynamically anyway, and Logstash continues running fine.
                if keys_to_set:
                    keystore_changed = True
            else:
                ok = False
                logger.error("Failed to apply SNMP keystore changes")

        # --- Pipelines (written first so Logstash picks them up on restart) ---
        if pipelines_to_set or pipelines_to_delete:
            if update_pipelines(settings_path, pipeline_changes):
                snmp_pl_state = agent_state.get_state().get('snmp_pipelines', {})
                for name in pipelines_to_delete:
                    snmp_pl_state.pop(name, None)
                for name, data in pipelines_to_set.items():
                    snmp_pl_state[name] = data.get('pipeline_hash', '')
                agent_state.update_state('snmp_pipelines', snmp_pl_state)
                logger.info(
                    f"Applied SNMP pipeline changes: {len(pipelines_to_set)} set, "
                    f"{len(pipelines_to_delete)} delete"
                )
            else:
                ok = False
                logger.error("Failed to apply SNMP pipeline changes")

        # Keystore values are only read by Logstash at startup, so a restart is
        # required whenever keystore entries were added or removed.
        if ok and keystore_changed:
            logger.info("Keystore updated — restarting Logstash to apply new keystore values...")
            if restart_logstash():
                logger.info("Logstash restarted successfully after SNMP keystore update")
            else:
                logger.error("Logstash restart failed after SNMP keystore update — manual intervention may be required")

        return ok

    except Exception as e:
        logger.error(f"Unexpected error in apply_snmp_changes: {e}")
        logger.exception("apply_snmp_changes exception details:")
        return False


def check_in():
    """
    Send check-in to logstashui with current agent state
    
    Returns:
        dict: Response from logstashui or None if check-in fails
    """
    try:
        # Load agent state
        state = agent_state.get_state()
        
        # Verify agent is enrolled
        if not state.get('enrolled'):
            logger.error("Agent is not enrolled. Please enroll first using --enroll")
            return None
        
        # Get required fields
        logstash_ui_url = state.get('logstash_ui_url')
        api_key = state.get('api_key')
        connection_id = state.get('connection_id')
        
        if not all([logstash_ui_url, api_key, connection_id]):
            logger.error("Missing required enrollment data. Please re-enroll the agent.")
            return None
        
        # Get paths from state
        settings_path = state.get('settings_path', '')
        logs_path = state.get('logs_path', '')
        binary_path = state.get('binary_path', '')
        
        # Normalize path separators for cross-platform compatibility
        if settings_path:
            settings_path = settings_path.replace('\\', '/')
        if logs_path:
            logs_path = logs_path.replace('\\', '/')
        if binary_path:
            binary_path = binary_path.replace('\\', '/')
        
        # Check if paths exist and capture detailed error information
        import os
        from datetime import datetime
        problems = []
        
        def check_path(path, path_name):
            """Check if path exists and is accessible, return status and capture problems"""
            if not path:
                problems.append(f"{path_name} is not configured")
                return False
            
            if not os.path.exists(path):
                problems.append(f"{path_name} does not exist: {path}")
                return False
            
            # Check if we can read the path
            try:
                if os.path.isdir(path):
                    os.listdir(path)
                else:
                    with open(path, 'r') as f:
                        pass
            except PermissionError:
                problems.append(f"{path_name} exists but permission denied: {path}")
                return False
            except Exception as e:
                problems.append(f"{path_name} exists but error accessing: {path} ({str(e)})")
                return False
            
            return True
        
        def check_file_exists(directory, filename):
            """Check if a specific file exists in a directory"""
            if not directory or not os.path.exists(directory):
                return False
            file_path = os.path.join(directory, filename)
            return os.path.isfile(file_path)
        
        def check_executable_exists(directory, executable_name):
            """Check if an executable exists in a directory (with or without bin/ subdirectory)"""
            if not directory or not os.path.exists(directory):
                return False
            
            # Check in bin/ subdirectory first
            bin_path = os.path.join(directory, 'bin', executable_name)
            if os.path.isfile(bin_path):
                return True
            
            # Check directly in the directory
            direct_path = os.path.join(directory, executable_name)
            return os.path.isfile(direct_path)
        
        def get_log_file_info(logs_path, log_filename):
            """Get information about a log file including last modified time"""
            if not logs_path or not os.path.exists(logs_path):
                return None
            
            log_file_path = os.path.join(logs_path, log_filename)
            if not os.path.isfile(log_file_path):
                return None
            
            try:
                stat_info = os.stat(log_file_path)
                last_modified = datetime.fromtimestamp(stat_info.st_mtime)
                return {
                    'exists': True,
                    'last_modified': last_modified.isoformat(),
                    'size_bytes': stat_info.st_size
                }
            except Exception as e:
                problems.append(f"Error reading log file {log_filename}: {str(e)}")
                return None
        
        # Basic path validation
        settings_path_valid = check_path(settings_path, 'Settings path')
        logs_path_valid = check_path(logs_path, 'Logs path')
        binary_path_valid = check_path(binary_path, 'Binary path')
        
        # Check for specific config files in settings_path
        config_files = {
            'logstash_yml': check_file_exists(settings_path, 'logstash.yml'),
            'jvm_options': check_file_exists(settings_path, 'jvm.options'),
            'log4j2_properties': check_file_exists(settings_path, 'log4j2.properties'),
            'logstash_keystore': check_file_exists(settings_path, 'logstash.keystore')
        }
        
        # Add problems for missing config files
        if settings_path_valid:
            if not config_files['logstash_yml']:
                problems.append(f"logstash.yml not found in {settings_path}")
            if not config_files['jvm_options']:
                problems.append(f"jvm.options not found in {settings_path}")
            if not config_files['log4j2_properties']:
                problems.append(f"log4j2.properties not found in {settings_path}")
            if not config_files['logstash_keystore']:
                problems.append(f"logstash.keystore not found in {settings_path}")
        
        # Check for binaries in binary_path
        binaries = {
            'logstash': check_executable_exists(binary_path, 'logstash'),
            'logstash_keystore': check_executable_exists(binary_path, 'logstash-keystore')
        }
        
        # Add problems for missing binaries
        if binary_path_valid:
            if not binaries['logstash']:
                problems.append(f"logstash binary not found in {binary_path} or {binary_path}/bin")
            if not binaries['logstash_keystore']:
                problems.append(f"logstash-keystore binary not found in {binary_path} or {binary_path}/bin")
        
        # Check for log file
        log_info = get_log_file_info(logs_path, 'logstash-json.log')
        if logs_path_valid and not log_info:
            problems.append(f"logstash-json.log not found in {logs_path}")
        
        status_blob = {
            'settings_path_found': settings_path_valid,
            'logs_path_found': logs_path_valid,
            'binary_path_found': binary_path_valid,
            'config_files': config_files,
            'binaries': binaries,
            'log_file': log_info,
            'problems': '\n'.join(problems) if problems else None,
            'agent_version': state.get('agent_version', '0.0.0+unknown')
        }

        api_port = state.get('api_port', 9600)
        status_blob['logstash_api'] = get_logstash_api_status(api_port)
        status_blob['health_report'] = get_logstash_health_report(api_port)
        status_blob['node_stats'] = get_logstash_node_stats(api_port)
        status_blob['process_info'] = get_logstash_process_info()
        status_blob['last_policy_apply'] = state.get('last_policy_apply')
        status_blob['last_apply'] = state.get('last_apply')

        # Log state — prefer live watcher (near-realtime, clears warnings/errors
        # after each checkin); fall back to snapshot if watcher not yet started.
        if _log_watcher is not None:
            status_blob['logwatcher'] = _log_watcher.consume_for_checkin()
        else:
            status_blob['logwatcher'] = None

        logger.debug(f"Path validation status: {status_blob}")
        
        # Prepare check-in data. Check-in stays cheap (Phase 2): instead of the
        # full SNMP hash maps, send only a per-source rollup hash. The server
        # compares it against the deployed state (no decryption) and returns a
        # `managed_changes_available` flag; the actual delta is fetched via
        # GetConfigChanges only when something is dirty.
        check_in_data = {
            'connection_id': connection_id,
            'revision_number': state.get('revision_number', 0),
            'status_blob': status_blob,
            'managed_state_hashes': {
                'snmp': _managed_rollup(
                    state.get('snmp_pipelines', {}),
                    state.get('snmp_keystore', {}),
                ),
            },
        }
        
        # Send check-in request
        check_in_url = f"{logstash_ui_url}/ConnectionManager/CheckIn/"
        headers = {
            'Authorization': f'ApiKey {api_key}',
            'Content-Type': 'application/json'
        }
        
        logger.debug(f"Sending check-in to {check_in_url}")
        
        from logstashagent.tls_trust import ssl_verify_argument

        response = requests.post(
            check_in_url,
            json=check_in_data,
            headers=headers,
            timeout=30,
            verify=ssl_verify_argument(),
        )
        
        # Check for error status codes
        if response.status_code >= 400:
            logger.error(f"Check-in failed with status {response.status_code}")
            logger.error(f"Response: {response.text}")
            response.raise_for_status()
        
        # Try to parse JSON response
        try:
            result = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response from server")
            logger.error(f"Status code: {response.status_code}")
            logger.error(f"Response headers: {dict(response.headers)}")
            logger.error(f"Response body: {response.text[:500]}")
            raise
        
        if result.get('success'):
            logger.info("Check-in successful")

            # Decide what's dirty from the cheap check-in response (Phase 2):
            #   - policy: revision number differs
            #   - snmp (and any future managed source): per-source rollup flag
            agent_revision = state.get('revision_number', 0)
            server_revision = result.get('current_revision_number', 0)
            policy_dirty = agent_revision != server_revision
            managed_available = result.get('managed_changes_available', {}) or {}
            snmp_dirty = bool(managed_available.get('snmp'))

            # Detect Logstash runtime drift (VERSION/SYSTEM) even if revision matches
            # (e.g. partial enroll) so ensure_logstash_version can still run.
            server_source = (result.get('logstash_source') or 'SYSTEM').upper()
            server_version = result.get('logstash_version') or ''
            server_download_dir = result.get('logstash_download_dir') or ''
            agent_source = (state.get('logstash_source') or 'SYSTEM').upper()
            agent_version = state.get('logstash_version') or ''
            agent_download_dir = state.get('logstash_download_dir') or ''
            runtime_dirty = (
                server_source != agent_source
                or (server_source == 'VERSION' and server_version != agent_version)
                or (
                    server_source == 'VERSION'
                    and server_download_dir
                    and server_download_dir != agent_download_dir
                )
            )
            if runtime_dirty:
                logger.info(
                    "Logstash runtime drift detected (agent %s/%s vs server %s/%s)",
                    agent_source, agent_version or '-',
                    server_source, server_version or '-',
                )

            # Build ONE merged apply plan so the policy channel and the SNMP
            # channel share a single keystore batch, a single pipelines.yml
            # rewrite, and a single Logstash restart when both change in the same
            # cycle (previously each applied + restarted independently).
            plan = {
                'keystore': {'set': {}, 'delete': []},
                'pipelines': {'set': {}, 'delete': []},
            }

            policy_res = None
            snmp_res = None
            snmp_settings_path = result.get('settings_path') or state.get('settings_path')

            if not policy_dirty and not snmp_dirty and not runtime_dirty:
                logger.info(f"Agent is up-to-date (revision {agent_revision})")
            else:
                # Single unified fetch: GetConfigChanges returns BOTH the policy
                # delta AND the SNMP delta for this agent, so both are applied in
                # one merged pass. We fetch whenever EITHER source is dirty.
                if policy_dirty:
                    logger.warning(
                        f"New revision detected, checking config difference. "
                        f"Agent revision: {agent_revision}, Server revision: {server_revision}"
                    )
                if snmp_dirty:
                    logger.info("SNMP-managed changes flagged at check-in — fetching delta")
                if runtime_dirty and not policy_dirty:
                    logger.info("Fetching config changes for logstash_runtime (VERSION/SYSTEM) apply")

                # In merge mode get_config_changes applies config files + keystore
                # password inline and defers keystore-key/pipeline changes into
                # `plan`, and returns the SNMP delta from the same response.
                fetch_res = get_config_changes(
                    result.get('settings_path'),
                    result.get('logs_path'),
                    result.get('binary_path'),
                    plan=plan,
                )

                # Finalize/restart the policy channel only when it actually did
                # (or staged) work: either the revision changed, OR the fetch
                # detected config/keystore/pipeline drift and applied it
                # (files_updated). This restarts Logstash if a real policy change
                # rode along on an SNMP-triggered fetch (e.g. self-healing manual
                # config drift), while avoiding last_policy_apply churn + no-op
                # revision writes on true SNMP-only cycles.
                policy_did_work = fetch_res.get('files_updated') if fetch_res else False
                policy_res = fetch_res if (policy_dirty or policy_did_work or runtime_dirty) else None

                snmp_changes = (fetch_res or {}).get('snmp_changes')
                if snmp_changes:
                    logger.info("Applying SNMP-managed changes from fetch")
                    snmp_res = apply_snmp_changes(snmp_settings_path, snmp_changes, plan=plan)

            # Apply the merged plan once: one keystore batch, one pipelines.yml
            # rewrite, one restart; then finalize revision + SNMP hash state.
            apply_settings_path = snmp_settings_path
            if apply_settings_path:
                apply_settings_path = apply_settings_path.replace('\\', '/')
            _apply_merged_plan(apply_settings_path, plan, policy_res, snmp_res)

            if result.get('restart'):
                logger.warning("Server requested Logstash restart — restarting now")
                restart_logstash()

            return result
        else:
            logger.warning(f"Check-in returned success=false: {result.get('message', 'Unknown error')}")
            return result
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to check in with logstashui: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during check-in: {e}")
        return None


def run_controller():
    """
    Main controller loop - runs indefinitely and checks in every 60 seconds
    """
    logger.info("=" * 60)
    logger.info("LOGSTASH AGENT CONTROLLER STARTED")
    logger.info("=" * 60)
    
    # Load agent state to verify enrollment
    state = agent_state.get_state()
    
    if not state.get('enrolled'):
        logger.error("Agent is not enrolled!")
        logger.error("Please enroll the agent first using:")
        logger.error("  python main.py --enroll <TOKEN> --logstash-ui-url <URL>")
        return

    # Confirm role for upgraded installs (no re-enroll required for default agents)
    raw_mode = (state.get('mode') or 'default')
    mode = str(raw_mode).lower()
    if mode in ('agent', 'host'):
        logger.info(f"mode=default (legacy '{mode}' mapped) [state]")
        mode = 'default'
        try:
            agent_state.update_state('mode', 'default')
        except Exception:
            pass
    elif mode in ('default', 'simulate', 'embedded'):
        logger.info(f"mode={mode} [state]")
    else:
        logger.info(f"mode={mode} [state]")
    
    logger.info(f"Agent ID: {state.get('agent_id')}")
    logger.info(f"Connection ID: {state.get('connection_id')}")
    logger.info(f"logstashui URL: {state.get('logstash_ui_url')}")
    logger.info(f"Policy ID: {state.get('policy_id')}")
    if state.get('instance_id') is not None:
        logger.info(f"Simulate instance_id: {state.get('instance_id')}")
    if state.get('logstash_unit'):
        logger.info(f"Logstash unit: {state.get('logstash_unit')}")
    logger.info("=" * 60)
    logger.info("Starting check-in loop (every 60 seconds)")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 60)
    
    global _log_watcher
    check_in_interval = 60  # seconds

    # Event shared with the watcher — set when shutdown/startup is detected so
    # the controller loop wakes up early and fires an immediate check-in.
    _checkin_event = threading.Event()

    # --- Start the continuous log watcher ---
    initial_state = agent_state.get_state()
    logs_path = initial_state.get('logs_path', '')
    if logs_path:
        _log_watcher = log_analyzer.LogstashLogWatcher(
            log_dir=logs_path, checkin_event=_checkin_event
        )
        _log_watcher.start()
    else:
        logger.warning(
            "logs_path not set in agent state — LogstashLogWatcher not started. "
            "Restart detection will fall back to snapshot reads."
        )

    # Restart state tracking: detect transitions for controller-level logging.
    # The watcher fires log lines within ~0.5s of a shutdown/startup signal.
    was_restarting: bool = False
    
    # Track if upgrade has been initiated in this session
    # Once we spawn an upgrade, don't attempt another until service restarts
    upgrade_initiated: bool = False

    try:
        while True:
            # Start watcher if it wasn't ready at startup (logs_path set later)
            if _log_watcher is None:
                current_state = agent_state.get_state()
                logs_path = current_state.get('logs_path', '')
                if logs_path:
                    _log_watcher = log_analyzer.LogstashLogWatcher(
                        log_dir=logs_path, checkin_event=_checkin_event
                    )
                    _log_watcher.start()

            # Perform check-in
            result = check_in()

            if result:
                logger.debug(f"Check-in response: {result}")
                
                # Check for upgrade notification from desired_agent_version field
                if result.get('desired_agent_version') and not upgrade_initiated:
                    upgrade_version = result['desired_agent_version']
                    
                    # Get current version

                    try:
                        current_version = get_version("LogstashAgent")
                    except PackageNotFoundError:
                        # Fallback to reading from pyproject.toml
                        try:
                            import tomllib
                            from pathlib import Path
                            agent_root = Path(__file__).resolve().parent.parent.parent
                            pyproject_path = agent_root / "pyproject.toml"
                            if pyproject_path.exists():
                                with open(pyproject_path, "rb") as f:
                                    pyproject_data = tomllib.load(f)
                                    current_version = pyproject_data.get("project", {}).get("version", "unknown")
                            else:
                                current_version = "unknown"
                        except Exception:
                            current_version = "unknown"
                    
                    # Skip upgrade if already on desired version
                    if current_version == upgrade_version:
                        logger.info(f"Already on the desired Agent version {upgrade_version}")
                    else:
                        logger.info("=" * 60)
                        logger.info(f"UPGRADE AVAILABLE: {upgrade_version} (current: {current_version})")
                        logger.info("=" * 60)
                        logger.info(f"Initiating automatic upgrade to version {upgrade_version}...")
                        
                        try:
                            # Spawn upgrade process as separate command
                            # This will stop the service (killing us), replace binary, and restart
                            import subprocess
                            import sys
                            
                            # Get path to the installed binary
                            binary_path = '/opt/logstash-agent/bin/logstash-agent'
                            if not os.path.exists(binary_path):
                                # Fallback to current executable if not installed
                                binary_path = sys.executable
                            
                            logger.info(f"Spawning upgrade process: sudo {binary_path} upgrade --version {upgrade_version} --yes")
                            
                            # Spawn upgrade subprocess with full detachment
                            # The upgrade will stop the service (killing us), replace binary, and restart
                            # Let stdout/stderr go to systemd journal for error visibility
                            subprocess.Popen(
                                ['sudo', binary_path, 'upgrade', '--version', upgrade_version, '--yes'],
                                stdin=subprocess.DEVNULL,
                                start_new_session=True,
                                close_fds=True
                            )
                            
                            logger.info("Upgrade process spawned")
                            logger.info("Waiting for upgrade to stop service and replace binary...")
                            logger.info("=" * 60)
                            
                            # Mark upgrade as initiated to prevent spawning another
                            upgrade_initiated = True
                            
                            # Continue running - upgrade will stop the service which kills us
                            # Then upgrade will restart the service with the new binary
                            
                        except Exception as e:
                            logger.error(f"Failed to initiate automatic upgrade: {e}")
                            logger.error("Manual upgrade required:")
                            logger.error(f"  sudo logstash-agent upgrade --version {upgrade_version}")
            else:
                logger.warning("Check-in failed, will retry in 60 seconds")

            # --- Restart state transition logging ---
            if _log_watcher is not None:
                currently_restarting = _log_watcher.get_state()['logstash_state'] == 'restarting'
            else:
                current_state = agent_state.get_state()
                logs_path = current_state.get('logs_path', '')
                currently_restarting = log_analyzer.is_logstash_restarting(log_dir=logs_path)

            if currently_restarting and not was_restarting:
                logger.warning("Logstash restart detected — monitoring until it comes back online")
            elif not currently_restarting and was_restarting:
                logger.info("Logstash is back online")

            was_restarting = currently_restarting
            # --- End restart state tracking ---

            # Wait for next check-in — wakes up early if watcher fires an event
            _checkin_event.wait(timeout=check_in_interval + random.uniform(-10, 10))
            _checkin_event.clear()
            
    except KeyboardInterrupt:
        logger.info("\n" + "=" * 60)
        logger.info("Controller stopped by user")
        logger.info("=" * 60)
    except Exception as e:
        logger.error(f"Controller error: {e}")
        raise
