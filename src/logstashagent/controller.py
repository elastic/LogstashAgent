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
import shutil
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
    instances the path is typically ``/opt/logstash-agent/simulate-N/env`` and is
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


def _set_env_file_var(env_file: Optional[str], key: str, value: Optional[str]) -> bool:
    """
    Set, replace, or remove ``key=`` in a multi-instance env file
    (e.g. /opt/logstash-agent/simulate-N/env or managed-N/env) without sudo
    when the agent owns the tree. ``value=None`` deletes the line.

    Every other line is preserved verbatim, so LOGSTASH_KEYSTORE_PASS and the
    path flags survive.
    """
    if not env_file or not key:
        return False
    path = Path(env_file)
    try:
        lines = []
        if path.exists():
            lines = path.read_text(encoding='utf-8').splitlines()
        prefix = f'{key}='
        filtered = [ln for ln in lines if not ln.startswith(prefix)]
        if value is not None:
            filtered.append(f'{prefix}{value}')
        elif len(filtered) == len(lines):
            return True  # nothing to remove
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('\n'.join(filtered) + '\n', encoding='utf-8')
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass
        if value is None:
            logger.info(f"Removed {key} from {path}")
        else:
            logger.info(f"Updated {key} in {path} -> {value}")
        return True
    except Exception as e:
        logger.error(f"Failed to update {key} in {env_file}: {e}")
        return False


def update_env_logstash_binary(env_file: Optional[str], binary: str) -> bool:
    """Set or replace LOGSTASH_BINARY= in a multi-instance env file."""
    if not binary:
        return False
    return _set_env_file_var(env_file, 'LOGSTASH_BINARY', binary)


def ensure_env_jvm_opts(env_file: Optional[str], settings_path: Optional[str]) -> bool:
    """
    Keep LS_JVM_OPTS in a multi-instance env file pointed at the policy-pushed
    jvm.options under path.settings.

    Without this, Logstash finds jvm.options only via the argv scan in
    logstash.lib.sh, which matches an argv entry *equal to* ``--path.settings``
    and reads the next one. Anything else (notably ``--path.settings=<dir>``)
    silently falls back to the stock jvm.options in LOGSTASH_HOME, so
    policy-pushed heap settings never reach the JVM.

    The line is removed when the file is absent: LS_JVM_OPTS naming a missing
    file makes JvmOptionsParser fail and Logstash refuse to start.
    """
    if not env_file or not settings_path:
        return False
    jvm_options = Path(settings_path) / 'jvm.options'
    if not jvm_options.is_file():
        return _set_env_file_var(env_file, 'LS_JVM_OPTS', None)
    return _set_env_file_var(env_file, 'LS_JVM_OPTS', str(jvm_options))


def _installed_unit_is_stale(unit_path: Path) -> bool:
    """
    True when an installed Logstash unit still uses ``--path.settings=<dir>``.

    Deliberately a marker check rather than a diff against the bundled template,
    so a deliberate operator edit elsewhere in the unit is not clobbered.
    """
    try:
        if not unit_path.is_file():
            return False
        return '--path.settings=' in unit_path.read_text(encoding='utf-8')
    except OSError as exc:
        logger.debug("Could not read %s: %s", unit_path, exc)
        return False


def heal_stale_logstash_launch(state: Optional[dict] = None) -> bool:
    """
    Repair managed/simulate instances installed before the jvm.options fix.

    Two things go stale on such a host, with different privileges:

    * the instance env file, which the agent owns and can rewrite directly —
      adding LS_JVM_OPTS here is on its own enough to fix the bug;
    * the unit file under /etc/systemd/system, which is root-owned. The agent
      now runs as ``User=logstash``, so this goes through the existing
      root → ``sudo -n … setup-simulate`` escalation in ensure_simulate_setup().

    Returns True if anything was changed. Either way the Logstash unit must be
    restarted for a new ExecStart or env value to take effect — daemon-reload
    does not re-exec a running process.
    """
    from logstashagent import installer

    state = state if state is not None else agent_state.get_state()
    mode = str(state.get('mode') or '').lower()
    if mode not in ('managed', 'simulate'):
        return False

    changed = False
    settings_path = state.get('settings_path')
    env_file = state.get('keystore_env_file')
    if env_file and settings_path:
        before = ''
        try:
            before = Path(env_file).read_text(encoding='utf-8')
        except OSError:
            pass
        if ensure_env_jvm_opts(env_file, settings_path):
            try:
                changed = Path(env_file).read_text(encoding='utf-8') != before
            except OSError:
                changed = True

    unit_key = 'logstash_managed_unit' if mode == 'managed' else 'ls_simulate_unit'
    unit_path = Path(installer.INSTALL_PATHS.get(unit_key, ''))
    if not _installed_unit_is_stale(unit_path):
        return changed

    logger.warning(
        "%s still launches Logstash with --path.settings=<dir>; jvm.options is "
        "ignored in that form. Reinstalling unit templates.",
        unit_path,
    )
    try:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            installer.install_multi_instance_unit_templates()
            logger.info("✓ Reinstalled multi-instance unit templates")
            changed = True
        else:
            result = installer.ensure_simulate_setup(
                installer.policy_config_from_state(state)
            )
            if result.get('status') == 'complete':
                logger.info("✓ Unit templates refreshed via %s", result.get('via'))
                changed = True
            else:
                logger.warning(
                    "Could not refresh unit templates (%s). LS_JVM_OPTS in the "
                    "instance env file still applies jvm.options; run "
                    "'sudo logstash-agent configure' to update ExecStart.",
                    result.get('status'),
                )
    except Exception as exc:
        logger.warning(
            "Unit template refresh failed: %s. LS_JVM_OPTS in the instance env "
            "file still applies jvm.options.",
            exc,
        )

    if changed:
        logger.warning(
            "Restart the Logstash unit (%s) to pick up the corrected launch "
            "configuration.",
            state.get('logstash_unit') or unit_path.name,
        )
    return changed


RUNTIME_SNAPSHOT_NAME = '.runtime-snapshot'
RUNTIME_UPGRADE_HEALTH_TIMEOUT = 180.0
RUNTIME_UPGRADE_HEALTH_POLL = 2.0

_VERSION_DOWNLOAD_LOCK = threading.Lock()
_VERSION_DOWNLOAD_THREADS: dict[str, threading.Thread] = {}
_VERSION_DOWNLOAD_STATUS: dict[str, dict] = {}
_IGNORED_VERSION_PINS: set[str] = set()

_SNAPSHOT_SETTING_FILES = (
    'logstash.yml',
    'jvm.options',
    'log4j2.properties',
    'pipelines.yml',
    'logstash.keystore',
)
# Pipeline .conf files live in conf.d (update_pipelines). Copy pipelines/ too if present.
_SNAPSHOT_SETTING_DIRS = (
    'pipelines',
    'conf.d',
)


def _empty_runtime_prep(**overrides) -> dict:
    prep = {
        'ok': True,
        'changed': False,
        'held': False,
        'desired_binary': None,
        'snapshot_dir': None,
        'previous': {},
        'error': None,
        'source': None,
        'version': None,
        'download_dir': None,
    }
    prep.update(overrides)
    return prep


def _stamp_runtime_download(fields: dict, *, overwrite: bool = False) -> None:
    current = dict((agent_state.get_state() or {}).get('runtime_download') or {})
    new_ver = fields.get('version')
    cur_ver = current.get('version')
    if not overwrite and cur_ver and new_ver and cur_ver != new_ver:
        return
    if overwrite:
        current = dict(fields)
    else:
        current.update(fields)
    agent_state.update_state('runtime_download', current)


def _set_download_memory(version: str, **fields) -> dict:
    with _VERSION_DOWNLOAD_LOCK:
        cur = dict(_VERSION_DOWNLOAD_STATUS.get(version) or {})
        cur.update(fields)
        cur['version'] = version
        _VERSION_DOWNLOAD_STATUS[version] = cur
        return dict(cur)


def _download_thread_alive(version: str) -> threading.Thread | None:
    with _VERSION_DOWNLOAD_LOCK:
        t = _VERSION_DOWNLOAD_THREADS.get(version)
        if t is not None and t.is_alive():
            return t
        return None


def _download_memory(version: str) -> dict | None:
    with _VERSION_DOWNLOAD_LOCK:
        st = _VERSION_DOWNLOAD_STATUS.get(version)
        return dict(st) if st else None


def _flush_runtime_download(version: str, download_dir: str | None = None) -> None:
    """Persist in-memory worker status onto agent_state (controller thread only)."""
    mem = _download_memory(version)
    alive = _download_thread_alive(version)
    ddir = download_dir or (mem or {}).get('dir') or ''
    if alive is not None:
        blob = {
            'status': (mem or {}).get('status') or 'running',
            'version': version,
            'dir': ddir,
            'error': None,
            'started_at': (mem or {}).get('started_at'),
        }
        _stamp_runtime_download(blob)
        return
    if not mem:
        return
    present = False
    if ddir:
        from .logstash_download import version_is_present

        present = version_is_present(version, ddir)
    if present:
        blob = {
            'status': 'ready',
            'version': version,
            'dir': ddir,
            'error': None,
            'started_at': mem.get('started_at'),
        }
    else:
        blob = {
            'status': 'failed',
            'version': version,
            'dir': ddir,
            'error': mem.get('error'),
            'started_at': mem.get('started_at'),
        }
    _stamp_runtime_download(blob)


def _flush_runtime_downloads_for_checkin() -> None:
    with _VERSION_DOWNLOAD_LOCK:
        versions = list(_VERSION_DOWNLOAD_STATUS.keys())
    state = agent_state.get_state() or {}
    rd = state.get('runtime_download') or {}
    ver = (rd.get('version') or '').strip()
    if ver and ver not in versions:
        versions.append(ver)
    ddir = rd.get('dir') or state.get('logstash_download_dir') or ''
    for v in versions:
        mem = _download_memory(v)
        _flush_runtime_download(v, (mem or {}).get('dir') or ddir)


def _maybe_persist_via_ui(payload) -> None:
    if not isinstance(payload, dict):
        return
    if 'logstash_via_ui' in payload:
        agent_state.update_state('logstash_via_ui', payload['logstash_via_ui'])
    elif 'via_ui' in payload:
        agent_state.update_state('logstash_via_ui', payload['via_ui'])


def _version_download_worker(version: str, download_dir: str) -> None:
    try:
        _set_download_memory(
            version, status='running', dir=download_dir, error=None
        )
        from .logstash_download import ensure_logstash_version

        ensure_logstash_version(version, download_dir)
        _set_download_memory(
            version, status='ready', dir=download_dir, error=None
        )
    except Exception as e:
        logger.error('VERSION download failed for %s: %s', version, e)
        _set_download_memory(
            version, status='failed', dir=download_dir, error=str(e)
        )
    finally:
        with _VERSION_DOWNLOAD_LOCK:
            cur = _VERSION_DOWNLOAD_THREADS.get(version)
            if cur is threading.current_thread():
                _VERSION_DOWNLOAD_THREADS.pop(version, None)


def _start_version_download(version: str, download_dir: str) -> threading.Thread:
    with _VERSION_DOWNLOAD_LOCK:
        existing = _VERSION_DOWNLOAD_THREADS.get(version)
        if existing is not None and existing.is_alive():
            return existing
        started_at = datetime.now(timezone.utc).isoformat()
        _VERSION_DOWNLOAD_STATUS[version] = {
            'status': 'pending',
            'version': version,
            'dir': download_dir,
            'error': None,
            'started_at': started_at,
        }
        blob = dict(_VERSION_DOWNLOAD_STATUS[version])
        t = threading.Thread(
            target=_version_download_worker,
            args=(version, download_dir),
            daemon=True,
            name=f'logstash-download-{version}',
        )
        _VERSION_DOWNLOAD_THREADS[version] = t
        t.start()
    _stamp_runtime_download(blob, overwrite=True)
    return t


def _canonical_run_mode(mode: str | None) -> str:
    raw = (mode or '').strip().lower()
    if raw in ('default', 'agent'):
        return 'packaged'
    if raw == 'host':
        return 'managed'
    return raw


def _runtime_path_root(state: dict) -> Path | None:
    raw = (state.get('path_root') or '').strip()
    if raw:
        return Path(raw)
    env_file = (state.get('keystore_env_file') or '').strip()
    if env_file.replace('\\', '/').endswith('/env'):
        return Path(env_file).parent
    settings = (state.get('settings_path') or '').strip()
    if settings:
        return Path(settings)
    return None


def _copy_if_exists(src: Path, dest: Path) -> None:
    if src.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    elif src.is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)


def _write_runtime_snapshot(state: dict, previous: dict, desired: dict) -> Path:
    root = _runtime_path_root(state)
    if root is None:
        raise RuntimeError('no path_root for runtime snapshot')
    snap = root / RUNTIME_SNAPSHOT_NAME
    if snap.exists():
        raise RuntimeError(f'refusing to overwrite existing runtime snapshot at {snap}')
    snap.mkdir(parents=True, exist_ok=True)
    settings = Path(state.get('settings_path') or '')
    settings_dest = snap / 'settings'
    settings_dest.mkdir(parents=True, exist_ok=True)
    if settings.is_dir() or str(settings):
        for name in _SNAPSHOT_SETTING_FILES:
            _copy_if_exists(settings / name, settings_dest / name)
        for dirname in _SNAPSHOT_SETTING_DIRS:
            _copy_if_exists(settings / dirname, settings_dest / dirname)
    env_file = previous.get('env_file')
    if env_file and Path(env_file).is_file():
        shutil.copy2(env_file, snap / 'env')
    meta = {
        'previous': previous,
        'desired': desired,
    }
    (snap / 'meta.json').write_text(json.dumps(meta, indent=2) + '\n', encoding='utf-8')
    return snap


def _restore_runtime_snapshot(prep: dict) -> bool:
    snap = Path(prep.get('snapshot_dir') or '')
    if not snap.is_dir():
        return False
    try:
        meta = json.loads((snap / 'meta.json').read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        logger.error('Invalid runtime snapshot meta: %s', e)
        return False
    previous = meta.get('previous') or prep.get('previous') or {}
    try:
        settings = Path(previous.get('settings_path') or '')
        src_settings = snap / 'settings'
        if src_settings.is_dir() and settings:
            settings.mkdir(parents=True, exist_ok=True)
            for name in _SNAPSHOT_SETTING_FILES:
                _copy_if_exists(src_settings / name, settings / name)
            for dirname in _SNAPSHOT_SETTING_DIRS:
                dir_src = src_settings / dirname
                if dir_src.exists():
                    _copy_if_exists(dir_src, settings / dirname)
        env_file = previous.get('env_file')
        env_src = snap / 'env'
        if env_file and env_src.is_file():
            Path(env_file).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(env_src, env_file)
    except (OSError, shutil.Error) as e:
        logger.error('Failed to restore runtime snapshot at %s: %s', snap, e)
        return False
    return True


def prepare_runtime_upgrade(runtime: dict | None) -> dict:
    """
    Resolve the desired Logstash binary and snapshot current config.

    Missing VERSION trees start one background download and hold the revision
    (ok=True, changed=False, held=True). Does not flip LOGSTASH_BINARY or
    agent-state pin fields.
    """
    if not runtime or runtime is False:
        return _empty_runtime_prep()
    state = agent_state.get_state() or {}
    mode = _canonical_run_mode(state.get('mode'))
    _maybe_persist_via_ui(runtime)
    if mode not in ('managed', 'simulate'):
        source = (runtime.get('source') or '').upper()
        if source == 'VERSION':
            ver = (runtime.get('version') or '').strip() or '(none)'
            key = f'{mode}:{ver}'
            if key not in _IGNORED_VERSION_PINS:
                _IGNORED_VERSION_PINS.add(key)
                logger.warning(
                    'Ignoring VERSION pin %s in %s mode (no download)',
                    ver,
                    mode or 'unknown',
                )
        return _empty_runtime_prep()

    from .logstash_download import (
        resolve_binary_from_policy,
        LogstashDownloadError,
        DEFAULT_DOWNLOAD_ROOT,
        normalize_download_dir,
        version_is_present,
    )

    source = (runtime.get('source') or 'SYSTEM').upper()
    version = (runtime.get('version') or '').strip()
    download_dir = normalize_download_dir(
        (runtime.get('download_dir') or DEFAULT_DOWNLOAD_ROOT).strip()
    )
    binary_path = runtime.get('binary_path') or '/usr/share/logstash/bin'

    if source == 'VERSION' and version:
        inflight = _download_thread_alive(version)
        present = version_is_present(version, download_dir)
        if inflight is not None or not present:
            _flush_runtime_download(version, download_dir)
            if inflight is None:
                _start_version_download(version, download_dir)
            logger.info(
                'Holding policy revision until VERSION %s download finishes (present=%s inflight=%s)',
                version,
                present,
                inflight is not None,
            )
            return _empty_runtime_prep(
                held=True, source=source, version=version, download_dir=download_dir
            )
        _flush_runtime_download(version, download_dir)

    try:
        binary = str(
            resolve_binary_from_policy(
                logstash_source=source,
                logstash_version=version,
                logstash_download_dir=download_dir,
                binary_path=binary_path,
            )
        )
    except LogstashDownloadError as e:
        logger.error('Logstash runtime prepare failed: %s', e)
        return _empty_runtime_prep(ok=False, error=str(e), source=source, version=version)
    except Exception as e:
        logger.error('Unexpected error preparing logstash_runtime: %s', e, exc_info=True)
        return _empty_runtime_prep(ok=False, error=str(e), source=source, version=version)

    if source == 'VERSION' and version:
        try:
            from logstashagent import install_registry as _reg

            _reg.register_logstash_version(
                version=version,
                binary=binary,
                download_dir=download_dir,
                used_by=state.get('agent_id') or state.get('deployment_id'),
            )
        except Exception as e:
            logger.debug('Could not record VERSION tree in install registry: %s', e)

    prev_binary = str(state.get('logstash_binary') or '')
    prev_source = (state.get('logstash_source') or 'SYSTEM').upper()
    prev_version = (state.get('logstash_version') or '').strip()
    if prev_binary == binary and prev_source == source and prev_version == version:
        return _empty_runtime_prep(
            desired_binary=binary, source=source, version=version, download_dir=download_dir
        )

    previous = {
        'binary': prev_binary,
        'source': prev_source,
        'version': prev_version,
        'env_file': state.get('keystore_env_file'),
        'settings_path': state.get('settings_path'),
        'api_port': state.get('logstash_api_port') or 9600,
    }
    desired = {'binary': binary, 'source': source, 'version': version, 'download_dir': download_dir}
    root = _runtime_path_root(state)
    preexisting_snapshot = bool(root is not None and (root / RUNTIME_SNAPSHOT_NAME).exists())
    try:
        snap = _write_runtime_snapshot(state, previous, desired)
    except Exception as e:
        logger.error('Runtime snapshot failed: %s', e, exc_info=True)
        if root is not None and not preexisting_snapshot:
            shutil.rmtree(root / RUNTIME_SNAPSHOT_NAME, ignore_errors=True)
        return _empty_runtime_prep(ok=False, error=str(e), source=source, version=version)

    logger.info('Runtime upgrade prepared: %s -> %s snapshot=%s', prev_binary, binary, snap)
    return {
        'ok': True,
        'changed': True,
        'held': False,
        'desired_binary': binary,
        'snapshot_dir': str(snap),
        'previous': previous,
        'error': None,
        'source': source,
        'version': version,
        'download_dir': download_dir,
    }


def flip_runtime_env(prep: dict) -> bool:
    if not prep or not prep.get('changed'):
        return True
    env_file = (prep.get('previous') or {}).get('env_file')
    binary = prep.get('desired_binary')
    return update_env_logstash_binary(env_file, binary)


def commit_runtime_upgrade(prep: dict) -> None:
    if not prep or not prep.get('changed'):
        return
    source = prep.get('source') or 'SYSTEM'
    version = (prep.get('version') or '').strip()
    binary = prep.get('desired_binary')
    download_dir = prep.get('download_dir')
    bin_dir = str(Path(binary).parent) if binary and Path(binary).name in ('logstash', 'logstash.bat') else binary
    agent_state.update_state('logstash_source', source)
    agent_state.update_state('logstash_version', version)
    if download_dir:
        agent_state.update_state('logstash_download_dir', download_dir)
    if bin_dir:
        agent_state.update_state('binary_path', bin_dir)
    if binary:
        agent_state.update_state('logstash_binary', binary)
    if source == 'VERSION' and version:
        agent_state.update_state('logstash_version_resolved', version)
    elif source == 'SYSTEM':
        agent_state.update_state('logstash_version_resolved', '')
    state = agent_state.get_state() or {}
    try:
        from logstashagent import install_registry as _reg

        role = _canonical_run_mode(state.get('mode'))
        iid = state.get('instance_id')
        if role in ('managed', 'simulate') and iid is not None:
            key = _reg.instance_key(role, int(iid))
            reg = _reg.load_registry()
            inst = (reg.get('instances') or {}).get(key)
            if inst:
                inst['logstash_source'] = source
                inst['logstash_version'] = version
                inst['logstash_binary'] = binary
                reg['instances'][key] = inst
                _reg.save_registry(reg)
    except Exception as e:
        logger.debug('Could not stamp instance VERSION pin: %s', e)
    snap = prep.get('snapshot_dir')
    if snap:
        shutil.rmtree(snap, ignore_errors=True)
    logger.info('Runtime upgrade committed: binary=%s version=%s', binary, version or '(none)')


def rollback_runtime_upgrade(prep: dict, *, restart: bool = True) -> bool:
    if not prep or not prep.get('changed'):
        return True
    restored = _restore_runtime_snapshot(prep)
    if not restored:
        logger.error('Runtime upgrade rollback failed to restore snapshot at %s', prep.get('snapshot_dir'))
        return False
    if restart:
        if not restart_logstash():
            logger.error('Runtime upgrade rollback restored files but restart failed')
            return False
    snap = prep.get('snapshot_dir')
    if snap:
        shutil.rmtree(snap, ignore_errors=True)
    logger.warning('Runtime upgrade rolled back to binary=%s', (prep.get('previous') or {}).get('binary'))
    return True


def recover_incomplete_runtime_upgrade() -> bool:
    state = agent_state.get_state() or {}
    if _canonical_run_mode(state.get('mode')) not in ('managed', 'simulate'):
        return False
    root = _runtime_path_root(state)
    if root is None:
        return False
    snap = root / RUNTIME_SNAPSHOT_NAME
    if not snap.is_dir():
        return False
    try:
        meta = json.loads((snap / 'meta.json').read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        logger.error('Cannot recover runtime snapshot: %s — discarding unreadable snapshot at %s', e, snap)
        shutil.rmtree(snap, ignore_errors=True)
        return False
    desired = meta.get('desired') or {}
    cur_source = (state.get('logstash_source') or 'SYSTEM').upper()
    cur_version = (state.get('logstash_version') or '').strip()
    cur_binary = str(state.get('logstash_binary') or '')
    desired_source = (desired.get('source') or 'SYSTEM').upper()
    desired_version = (desired.get('version') or '').strip()
    desired_binary = str(desired.get('binary') or '')
    if cur_source == desired_source and cur_version == desired_version and cur_binary == desired_binary:
        logger.info('Leftover runtime snapshot matches committed pin; discarding %s', snap)
        shutil.rmtree(snap, ignore_errors=True)
        return True
    logger.warning('Incomplete runtime upgrade snapshot found at %s — rolling back', snap)
    prep = {
        'ok': True,
        'changed': True,
        'snapshot_dir': str(snap),
        'previous': meta.get('previous') or {},
        'desired_binary': desired.get('binary'),
        'source': desired.get('source'),
        'version': desired.get('version'),
        'download_dir': desired.get('download_dir'),
        'error': None,
    }
    return rollback_runtime_upgrade(prep, restart=True)


def wait_for_logstash_api(api_port: int, timeout: float | None = None) -> bool:
    """Poll node info until accessible or timeout (seconds)."""
    limit = RUNTIME_UPGRADE_HEALTH_TIMEOUT if timeout is None else timeout
    deadline = time.monotonic() + max(0.0, float(limit))
    while True:
        status = get_logstash_api_status(api_port)
        if status.get('accessible'):
            return True
        if time.monotonic() >= deadline:
            logger.error('Logstash API at port %s did not answer within %ss', api_port, limit)
            return False
        time.sleep(RUNTIME_UPGRADE_HEALTH_POLL)


def finalize_runtime_upgrade(prep: dict, restart_ok: bool) -> bool:
    """Commit if the new process answers; otherwise rollback. True = keep new pin."""
    if not prep or not prep.get('changed'):
        return True
    if restart_ok:
        previous = prep.get('previous') or {}
        state = agent_state.get_state() or {}
        api_port = int(previous.get('api_port') or state.get('logstash_api_port') or 9600)
        if wait_for_logstash_api(api_port):
            commit_runtime_upgrade(prep)
            return True
    rollback_runtime_upgrade(prep, restart=True)
    return False


def apply_logstash_runtime(runtime: dict) -> dict:
    """
    Apply policy Logstash binary source (SYSTEM vs VERSION download).

    Downloads VERSION artifacts when needed, updates agent state and the
    multi-instance EnvironmentFile LOGSTASH_BINARY line (simulate + managed).

    Returns:
        dict: success (bool), requires_restart (bool), binary (str|None),
              error (str|None), source, version
    """
    from .logstash_download import (
        resolve_binary_from_policy,
        LogstashDownloadError,
        DEFAULT_DOWNLOAD_ROOT,
        normalize_download_dir,
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
    download_dir = normalize_download_dir(
        (runtime.get('download_dir') or DEFAULT_DOWNLOAD_ROOT).strip()
    )
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

    prev_state = agent_state.get_state() or {}
    prev_binary = prev_state.get('logstash_binary') or ''
    prev_source = (prev_state.get('logstash_source') or 'SYSTEM').upper()
    prev_version = (prev_state.get('logstash_version') or '').strip()

    agent_state.update_state('logstash_source', source)
    agent_state.update_state('logstash_version', version)
    agent_state.update_state('logstash_download_dir', download_dir)
    agent_state.update_state('binary_path', bin_dir)
    agent_state.update_state('logstash_binary', binary)
    if source == 'VERSION' and version:
        agent_state.update_state('logstash_version_resolved', version)
    elif source == 'SYSTEM':
        # Clear resolved pin so UI does not show a stale VERSION
        agent_state.update_state('logstash_version_resolved', '')

    state = agent_state.get_state() or {}
    env_file = state.get('keystore_env_file')
    mode = (state.get('mode') or '').lower()
    # Multi-instance units (simulate + managed) read LOGSTASH_BINARY from */env
    if mode in ('simulate', 'managed') or (env_file and str(env_file).endswith('/env')):
        if env_file:
            update_env_logstash_binary(env_file, binary)

    # Track VERSION install in host registry (best-effort)
    if source == 'VERSION' and version:
        try:
            from logstashagent import install_registry as _reg

            _reg.register_logstash_version(
                version=version,
                binary=binary,
                download_dir=download_dir,
                used_by=state.get('agent_id') or state.get('deployment_id'),
            )
            # Also stamp current instance entry when known
            role = mode if mode in ('managed', 'simulate') else None
            iid = state.get('instance_id')
            if role and iid is not None:
                key = _reg.instance_key(role, int(iid))
                reg = _reg.load_registry()
                inst = (reg.get('instances') or {}).get(key)
                if inst:
                    inst['logstash_source'] = 'VERSION'
                    inst['logstash_version'] = version
                    inst['logstash_binary'] = binary
                    reg['instances'][key] = inst
                    _reg.save_registry(reg)
        except Exception as e:
            logger.debug("Could not record VERSION in install registry: %s", e)

    requires_restart = (
        str(prev_binary) != binary
        or prev_source != source
        or (source == 'VERSION' and prev_version != version)
    )
    if not prev_binary and not prev_version and source == 'SYSTEM':
        # First apply of same default system path — still restart if unit never
        # picked up env; prefer restart on first runtime apply for multi-instance.
        requires_restart = mode in ('simulate', 'managed') or requires_restart

    from datetime import datetime, timezone

    agent_state.update_state(
        'last_runtime_apply',
        {
            'source': source,
            'version': version or None,
            'binary': binary,
            'requires_restart': requires_restart,
            'at': datetime.now(timezone.utc).isoformat(),
        },
    )

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
            f.write(content if content.endswith('\n') else content + '\n')

        # World-readable on purpose: logstash.lib.sh only honours the file when
        # `[ -r "$dir/jvm.options" ]` passes for the logstash user, and a
        # restrictive umask would otherwise revert Logstash to stock JVM settings.
        try:
            os.chmod(jvm_options_path, 0o644)
        except OSError as exc:
            logger.warning("Could not set mode 0644 on %s: %s", jvm_options_path, exc)

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

    - packaged/default: ``logstash``
    - simulate: ``ls-simulate@N`` from state (or derived from instance_id)
    - managed: ``logstash-managed@N`` from state (or derived from instance_id)
    """
    state = agent_state.get_state()
    unit = state.get('logstash_unit')
    if unit:
        return unit
    # Keep in sync with agent_state._MODE_ALIASES (do not import main).
    _mode_aliases = {
        'default': 'packaged',
        'agent': 'packaged',
        'host': 'managed',
    }
    mode = (state.get('mode') or 'default').lower()
    mode = _mode_aliases.get(mode, mode)
    instance_id = state.get('instance_id')
    if mode == 'managed' and instance_id is not None:
        return f'logstash-managed@{instance_id}'
    if mode == 'simulate' and instance_id is not None:
        return f'ls-simulate@{instance_id}'
    return 'logstash'


def restart_logstash():
    """
    Restart the Logstash service for this agent role.
    Uses sudo as configured in /etc/sudoers.d/logstash-agent

    Packaged agents restart ``logstash``; simulate uses ``ls-simulate@N``;
    managed uses ``logstash-managed@N``.

    Returns:
        bool: True if successful, False otherwise
    """
    unit = _logstash_unit_name()
    try:
        logger.info(f"Restarting Logstash service ({unit})...")

        # Prefer validated helper (sudo-rs compatible); falls back to sudo systemctl
        try:
            from logstashagent.installer import systemctl_via_sudo

            result = systemctl_via_sudo('restart', unit, timeout=30)

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
    aborted = bool((policy_res or {}).get('aborted'))

    # Do not apply keystore/pipelines after an aborted config rollout.
    # Restore the runtime snapshot first (existing rollback branch below).
    if not aborted:
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
    runtime_prep = (policy_res or {}).get('runtime_prep') or _empty_runtime_prep()
    requires_restart = bool(ks['set'])
    if policy_res:
        requires_restart = requires_restart or policy_res.get('requires_restart', False)
    if runtime_prep.get('changed'):
        requires_restart = True

    keystore_apply_ok = (not ks_has) or ks_ok
    restart_failed = False
    upgrade_rolled_back = False

    writes_ok = keystore_apply_ok and ((not pl_has) or pl_ok)
    if runtime_prep.get('changed') and (not writes_ok or aborted):
        rollback_runtime_upgrade(runtime_prep, restart=False)
        upgrade_rolled_back = True
    elif requires_restart and writes_ok and not aborted:
        if runtime_prep.get('changed') and not flip_runtime_env(runtime_prep):
            logger.error('Failed to flip LOGSTASH_BINARY — restoring snapshot')
            rollback_runtime_upgrade(runtime_prep, restart=False)
            upgrade_rolled_back = True
        else:
            logger.info("Applying merged changes — restarting Logstash once...")
            if restart_logstash():
                logger.info("Logstash restart completed successfully")
                if runtime_prep.get('changed'):
                    if not finalize_runtime_upgrade(runtime_prep, restart_ok=True):
                        upgrade_rolled_back = True
            else:
                logger.error("Logstash restart failed - manual intervention may be required")
                restart_failed = True
                if runtime_prep.get('changed'):
                    finalize_runtime_upgrade(runtime_prep, restart_ok=False)
                    upgrade_rolled_back = True
    elif pl_has and pl_ok and not ks['set'] and not runtime_prep.get('changed') and not aborted:
        logger.info("Pipeline-only changes applied - Logstash restart not required")

    # --- Update SNMP hash namespaces (only for parts that applied cleanly) ---
    if snmp_res and snmp_res.get('ran'):
        if not upgrade_rolled_back and not aborted:
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
        if upgrade_rolled_back:
            policy_failed.append('logstash runtime upgrade rolled back')

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
            # Participates in the server's runtime_changed comparison. Without
            # it the server assumes False, so ticking the proxy checkbox on an
            # otherwise unchanged policy would yield no delta and no error — the
            # agent would keep pulling from Elastic forever. Deliberately the
            # persisted state value, not logstash_via_ui_enabled(): reporting the
            # env override would disagree with policy permanently and re-trigger
            # a runtime delta on every check-in.
            'logstash_via_ui': bool(state.get('logstash_via_ui')),
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

            runtime_prep = _empty_runtime_prep()
            runtime = changes.get('logstash_runtime')
            if runtime and runtime != False:
                logger.info("Logstash runtime change detected (source/version/binary) — prepare first")
                runtime_prep = prepare_runtime_upgrade(runtime)
                if not runtime_prep.get('ok'):
                    logger.error(
                        "Failed to prepare logstash_runtime: %s — aborting rollout",
                        runtime_prep.get('error'),
                    )
                    failed_operations.append(
                        f"logstash_runtime apply failed: {runtime_prep.get('error')}"
                    )
                    rollout_aborted = True
                elif runtime_prep.get('held'):
                    logger.info(
                        "Holding policy revision until Logstash %s is downloaded",
                        runtime_prep.get('version') or 'VERSION',
                    )
                    rollout_aborted = True
                elif runtime_prep.get('changed'):
                    files_updated = True
                    requires_restart = True
                    if runtime_prep.get('desired_binary'):
                        binary_path = str(Path(runtime_prep['desired_binary']).parent)

            # Update logstash.yml if changed
            if not rollout_aborted:
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
                        # A first-time jvm.options needs LS_JVM_OPTS added to the
                        # instance env file before the restart below picks it up.
                        ensure_env_jvm_opts(state.get('keystore_env_file'), settings_path)
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
                    'runtime_prep': runtime_prep,
                }

            if rollout_aborted and runtime_prep.get('changed'):
                logger.error("Config apply failed after runtime prepare — restoring snapshot (no env flip)")
                rollback_runtime_upgrade(runtime_prep, restart=False)

            if rollout_aborted:
                if runtime_prep.get('held') and not failed_operations:
                    logger.info(
                        "Rollout held pending VERSION download (revision not bumped)"
                    )
                else:
                    logger.error(f"Rollout aborted due to failures: {failed_operations}")
            elif files_updated:
                if requires_restart:
                    if files_existed:
                        flipped = True
                        if runtime_prep.get('changed'):
                            flipped = flip_runtime_env(runtime_prep)
                            if not flipped:
                                rollback_runtime_upgrade(runtime_prep, restart=False)
                                failed_operations.append('logstash runtime upgrade rolled back')
                        if flipped:
                            logger.info("Configuration files updated, restarting Logstash service...")
                            restart_ok = restart_logstash()
                            if not restart_ok:
                                logger.error("Logstash restart failed - manual intervention may be required")
                                failed_operations.append('logstash restart failed')
                            if runtime_prep.get('changed'):
                                if not finalize_runtime_upgrade(runtime_prep, restart_ok=restart_ok):
                                    failed_operations.append('logstash runtime upgrade rolled back')
                    else:
                        logger.info("Configuration files created - Logstash restart skipped (files didn't exist previously)")
                else:
                    logger.info("Pipeline-only changes applied - Logstash restart not required")

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


def get_logstash_api_status(api_port=None):
    """
    Query the Logstash node info API at http://localhost:{api_port}/.

    Returns:
        dict with keys: accessible, status, version, host, error
    """
    from .logstash_api import LogstashAPI, resolve_logstash_api_port
    if api_port is None:
        api_port = resolve_logstash_api_port()
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


def get_logstash_health_report(api_port=None):
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
    from .logstash_api import LogstashAPI, resolve_logstash_api_port
    if api_port is None:
        api_port = resolve_logstash_api_port()
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


def get_logstash_node_stats(api_port=None):
    """
    Query the Logstash /_node/stats endpoint and return condensed node-level
    statistics. Pipeline-level detail is intentionally excluded.

    Returns:
        dict with keys: accessible, jvm, process, events, pipeline, reloads, error
    """
    from .logstash_api import LogstashAPI, resolve_logstash_api_port
    if api_port is None:
        api_port = resolve_logstash_api_port()
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

        recover_incomplete_runtime_upgrade()
        _flush_runtime_downloads_for_checkin()
        state = agent_state.get_state() or state

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
            'agent_version': state.get('agent_version', '0.0.0+unknown'),
            # VERSION lifecycle — UI surfaces resolved pin on connections / sim targets
            'mode': state.get('mode'),
            'logstash_source': state.get('logstash_source') or 'SYSTEM',
            'logstash_version': state.get('logstash_version') or '',
            'logstash_version_resolved': state.get('logstash_version_resolved')
            or state.get('logstash_version')
            or '',
            'logstash_binary': state.get('logstash_binary') or '',
            'logstash_download_dir': state.get('logstash_download_dir') or '',
            'last_runtime_apply': state.get('last_runtime_apply'),
            'runtime_download': state.get('runtime_download'),
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
        # Callback host/IP for UI → agent HTTPS (IP preferred; keep Connection.host current)
        callback_host = None
        callback_ip = None
        try:
            from logstashagent.enrollment import get_callback_host, get_callback_ip

            callback_host = get_callback_host()
            callback_ip = get_callback_ip()
        except Exception:
            pass
        if callback_host:
            status_blob['callback_host'] = callback_host
        if callback_ip:
            status_blob['callback_ip'] = callback_ip

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
        if callback_host:
            check_in_data['host'] = callback_host
        if callback_ip:
            check_in_data['callback_ip'] = callback_ip

        # Upgrade path: re-issue product-CA server cert without re-enroll
        try:
            from logstashagent import tls_server

            csr = tls_server.csr_pem_for_request()
            if csr:
                check_in_data['csr_pem'] = csr
                status_blob['tls_server'] = {'needs_cert': True}
            elif tls_server.has_server_cert():
                status_blob['tls_server'] = {'has_cert': True}
        except Exception as e:
            logger.debug("Agent TLS server CSR for check-in skipped: %s", e)
        
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
            # Snapshot before persisting: the via-UI drift check below compares
            # what we had against what the server just sent.
            agent_via_ui = bool(state.get('logstash_via_ui'))
            server_via_ui = bool(
                result.get('logstash_via_ui', result.get('via_ui', agent_via_ui))
            )
            _maybe_persist_via_ui(result)

            try:
                from logstashagent import tls_server

                if tls_server.apply_signed_response(result):
                    logger.info("Agent server certificate issued/renewed on check-in")
            except Exception as e:
                logger.warning("Could not persist server certificate from check-in: %s", e)

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
                # A proxy-checkbox flip on an otherwise unchanged policy does not
                # move the revision number, so without this the fetch below never
                # happens and the agent keeps using its old source forever.
                or (server_source == 'VERSION' and server_via_ui != agent_via_ui)
            )
            if runtime_dirty:
                logger.info(
                    "Logstash runtime drift detected (agent %s/%s via_ui=%s vs server %s/%s via_ui=%s)",
                    agent_source, agent_version or '-', agent_via_ui,
                    server_source, server_version or '-', server_via_ui,
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

    # Wait for enrollment state. Multi-instance install can start the unit
    # while state.json is still being relocated; previously we returned
    # immediately and never checked in — UI shows Offline while FastAPI stays up.
    import time as _time

    max_wait_sec = 120
    poll_sec = 2.0
    deadline = _time.monotonic() + max_wait_sec
    state: dict = {}
    while True:
        state = agent_state.get_state()
        if state.get('enrolled') and state.get('api_key') and state.get('connection_id'):
            break
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            logger.error("Agent is not enrolled (gave up after %ss)!", max_wait_sec)
            logger.error("State dir: %s", agent_state.STATE_DIR)
            logger.error("Please enroll the agent first using:")
            logger.error(
                "  sudo logstash-agent install --enroll <TOKEN> --logstash-ui-url <URL>"
            )
            hint_unit = state.get('agent_unit') or (
                f"lsagent-simulate@{state.get('instance_id')}"
                if state.get('instance_id') is not None
                else "logstash-agent"
            )
            logger.error(
                "If enrollment is already on disk, restart the unit: sudo systemctl restart %s",
                hint_unit,
            )
            return
        logger.warning(
            "Waiting for enrollment in %s (%.0fs left)…",
            agent_state.STATE_DIR,
            remaining,
        )
        _time.sleep(poll_sec)

    # Confirm role for upgraded installs (no re-enroll required for packaged agents)
    raw_mode = (state.get('mode') or 'packaged')
    mode = str(raw_mode).lower()
    if mode in ('default', 'agent'):
        logger.info(f"mode=packaged (legacy '{mode}' mapped) [state]")
        mode = 'packaged'
        try:
            agent_state.update_state('mode', 'packaged')
        except Exception:
            pass
    elif mode == 'host':
        logger.info("mode=managed (legacy 'host' mapped) [state]")
        mode = 'managed'
        try:
            agent_state.update_state('mode', 'managed')
        except Exception:
            pass
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
    recover_incomplete_runtime_upgrade()
    try:
        heal_stale_logstash_launch(state)
    except Exception as exc:
        logger.warning("jvm.options launch self-heal failed: %s", exc)
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
