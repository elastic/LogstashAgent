#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Resolve Logstash install locations, binaries, and keystore password sources.

Constants (env names, package defaults, Homebrew paths) live in
:mod:`ls_keystore_utils.settings`. This module implements resolution only.

Resolution order (high level)
-----------------------------
Binary (``resolve_logstash_bin_from_env``):
  1. ``LOGSTASH_KEYSTORE_BIN`` if the path is a file
  2. ``$LOGSTASH_HOME/bin/logstash-keystore`` if present
  3. Package default ``DEFAULT_PACKAGE_KEYSTORE_BIN`` if present

path.settings (``resolve_path_settings_from_env``):
  1. ``LOGSTASH_PATH_SETTINGS`` or ``PATH_SETTINGS`` if a directory
  2. ``$LOGSTASH_HOME/config`` if present
  3. Entries from :data:`settings.CANDIDATES` (package then share config)

Password (``resolve_logstash_password``):
  1. Non-empty ``LOGSTASH_KEYSTORE_PASS`` in the process environment
  2. Explicit ``LOGSTASH_ENV_FILE`` dotenv-style file if set
  3. Package defaults, systemd order: ``/etc/default/logstash`` then
     ``/etc/sysconfig/logstash`` (later file overrides keys from earlier)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Mapping, Optional

from .settings import (
    CANDIDATES,
    DEFAULT_PACKAGE_ENV_FILES,
    DEFAULT_PACKAGE_KEYSTORE_BIN,
    ENV_LOGSTASH_ENV_FILE,
    ENV_LOGSTASH_HOME,
    ENV_LOGSTASH_KEYSTORE_BIN,
    ENV_LOGSTASH_KEYSTORE_PASS,
    ENV_LOGSTASH_PATH_SETTINGS,
    ENV_PATH_SETTINGS_ALIAS,
)

logger = logging.getLogger(__name__)


def _nonempty(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _nonempty_env(name: str) -> Optional[str]:
    return _nonempty(os.environ.get(name))


def load_env_file(path: str | Path) -> dict[str, str]:
    """Parse a simple dotenv-style file into a string mapping.

    Supports ``KEY=VALUE`` lines, optional surrounding quotes on values,
    and ``#`` comments. Does not expand variables or interpolate. Stdlib only
    (no python-dotenv dependency in the library runtime).
    """
    result: dict[str, str] = {}
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.debug("Cannot read env file %s: %s", file_path, exc)
        return result

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key] = value
    return result


def load_env_files(paths: list[str | Path] | tuple[str | Path, ...]) -> dict[str, str]:
    """Load multiple dotenv-style files in order, later files overriding keys.

    Matches systemd ``EnvironmentFile=`` semantics: each existing file is
    applied in sequence; missing files are skipped.
    """
    merged: dict[str, str] = {}
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            continue
        merged.update(load_env_file(path))
    return merged


def resolve_logstash_home() -> Optional[Path]:
    """Return ``LOGSTASH_HOME`` if set to an existing directory."""
    raw = _nonempty_env(ENV_LOGSTASH_HOME)
    if not raw:
        return None
    home = Path(raw).expanduser()
    if home.is_dir():
        return home.resolve()
    logger.debug("%s=%s is not a directory", ENV_LOGSTASH_HOME, raw)
    return None


def default_bin_from_home(home: Path) -> Path:
    """Return ``$LOGSTASH_HOME/bin/logstash-keystore``."""
    return (home / "bin" / "logstash-keystore").resolve()


def default_path_settings_from_home(home: Path) -> Path:
    """Return ``$LOGSTASH_HOME/config`` (tarball / non-package default)."""
    return (home / "config").resolve()


def resolve_logstash_bin_from_env() -> Optional[Path]:
    """Resolve the keystore binary using env vars and package default only.

    Order:
      1. ``LOGSTASH_KEYSTORE_BIN`` if the path is a file
      2. ``$LOGSTASH_HOME/bin/logstash-keystore`` if present
      3. Package default binary if present

    Does not crawl Homebrew patterns or ``which`` (see
    :func:`ls_keystore_utils.subprocess_utils.find_keystore_binary`).
    """
    configured = _nonempty_env(ENV_LOGSTASH_KEYSTORE_BIN)
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()
        logger.debug("%s=%s is not a file", ENV_LOGSTASH_KEYSTORE_BIN, configured)

    home = resolve_logstash_home()
    if home is not None:
        candidate = default_bin_from_home(home)
        if candidate.is_file():
            return candidate

    package_bin = Path(DEFAULT_PACKAGE_KEYSTORE_BIN)
    if package_bin.is_file():
        return package_bin.resolve()

    return None


def resolve_path_settings_from_env(
    *,
    require_writable: bool = False,
) -> Optional[Path]:
    """Resolve ``--path.settings`` using env vars and package defaults.

    Order:
      1. ``LOGSTASH_PATH_SETTINGS`` or ``PATH_SETTINGS`` if it is a directory
      2. ``$LOGSTASH_HOME/config`` if present
      3. :data:`settings.CANDIDATES` (``/etc/logstash``, then share config)

    Args:
        require_writable: When True, skip directories that are not writable
            (used by library helpers that create keystores).

    Returns:
        A directory path, or None if nothing matches.
    """
    for name in (ENV_LOGSTASH_PATH_SETTINGS, ENV_PATH_SETTINGS_ALIAS):
        configured = _nonempty_env(name)
        if not configured:
            continue
        path = Path(configured).expanduser()
        if path.is_dir():
            if require_writable and not os.access(path, os.W_OK):
                logger.debug("%s=%s is not writable", name, path)
                continue
            return path.resolve()
        logger.debug("%s=%s is not a directory", name, configured)

    candidates: list[Path] = []
    home = resolve_logstash_home()
    if home is not None:
        candidates.append(default_path_settings_from_home(home))
    candidates.extend(Path(p) for p in CANDIDATES)

    for path in candidates:
        if not path.is_dir():
            continue
        if require_writable and not os.access(path, os.W_OK):
            continue
        return path.resolve()

    return None


def resolve_logstash_password(
    *,
    environ: Optional[Mapping[str, str]] = None,
    env_file: Optional[str | Path] = None,
) -> Optional[str]:
    """Resolve ``LOGSTASH_KEYSTORE_PASS`` from env and/or dotenv-style files.

    Order:
      1. Non-empty ``LOGSTASH_KEYSTORE_PASS`` in ``environ`` (default: ``os.environ``)
      2. Explicit ``env_file`` argument, or ``LOGSTASH_ENV_FILE`` from environ
      3. Package defaults in systemd unit order
         (``/etc/default/logstash`` then ``/etc/sysconfig/logstash``);
         later files override keys from earlier files when both exist

    Args:
        environ: Mapping to read env vars from (defaults to ``os.environ``).
        env_file: Optional explicit path to a dotenv-style file. When set, this
            is tried before the package defaults. When omitted,
            ``LOGSTASH_ENV_FILE`` from environ is used if set.

    Returns:
        The password string, or None if unresolved.
    """
    env: Mapping[str, str] = environ if environ is not None else os.environ

    direct = _nonempty(env.get(ENV_LOGSTASH_KEYSTORE_PASS))
    if direct:
        return direct

    # Explicit single file (argument or LOGSTASH_ENV_FILE)
    explicit: Optional[Path] = None
    if env_file is not None:
        explicit = Path(env_file).expanduser()
    else:
        configured = _nonempty(env.get(ENV_LOGSTASH_ENV_FILE))
        if configured:
            explicit = Path(configured).expanduser()

    if explicit is not None and explicit.is_file():
        password = _nonempty(load_env_file(explicit).get(ENV_LOGSTASH_KEYSTORE_PASS))
        if password:
            return password

    # Package defaults: merge in systemd EnvironmentFile= order
    package_values = load_env_files(DEFAULT_PACKAGE_ENV_FILES)
    return _nonempty(package_values.get(ENV_LOGSTASH_KEYSTORE_PASS))
