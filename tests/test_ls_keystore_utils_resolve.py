#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Unit tests for Logstash install/env resolution and settings composition."""

from __future__ import annotations

from pathlib import Path

import pytest

from logstashagent.ls_keystore_utils.resolve import (
    default_bin_from_home,
    default_path_settings_from_home,
    load_env_file,
    load_env_files,
    resolve_logstash_bin_from_env,
    resolve_logstash_home,
    resolve_logstash_password,
    resolve_path_settings_from_env,
)
from logstashagent.ls_keystore_utils.settings import (
    CANDIDATES,
    DEFAULT_PACKAGE_ENV_FILE,
    DEFAULT_PACKAGE_ENV_FILES,
    DEFAULT_PACKAGE_HOME,
    DEFAULT_PACKAGE_KEYSTORE_BIN,
    DEFAULT_PACKAGE_PATH_SETTINGS,
    DEFAULT_SHARE_CONFIG,
    ENV_LOGSTASH_ENV_FILE,
    ENV_LOGSTASH_HOME,
    ENV_LOGSTASH_KEYSTORE_BIN,
    ENV_LOGSTASH_KEYSTORE_PASS,
    ENV_LOGSTASH_PATH_SETTINGS,
    ENV_PATH_SETTINGS_ALIAS,
    HOME_BREW_PATTERN,
    PATTERNS,
)

# pylint: disable=C0115,C0116


@pytest.fixture
def clear_logstash_env(monkeypatch: pytest.MonkeyPatch):
    """Remove Logstash-related env vars for isolated resolution tests."""
    for key in (
        ENV_LOGSTASH_HOME,
        ENV_LOGSTASH_KEYSTORE_BIN,
        ENV_LOGSTASH_PATH_SETTINGS,
        ENV_PATH_SETTINGS_ALIAS,
        ENV_LOGSTASH_ENV_FILE,
        ENV_LOGSTASH_KEYSTORE_PASS,
    ):
        monkeypatch.delenv(key, raising=False)


class TestSettingsComposition:
    def test_package_defaults_derived_from_home(self):
        assert DEFAULT_PACKAGE_KEYSTORE_BIN == (
            f"{DEFAULT_PACKAGE_HOME}/bin/logstash-keystore"
        )
        assert DEFAULT_SHARE_CONFIG == f"{DEFAULT_PACKAGE_HOME}/config"

    def test_patterns_and_candidates_use_primitives(self):
        assert PATTERNS[0] == DEFAULT_PACKAGE_KEYSTORE_BIN
        assert PATTERNS[1] == HOME_BREW_PATTERN
        assert CANDIDATES == [
            DEFAULT_PACKAGE_PATH_SETTINGS,
            DEFAULT_SHARE_CONFIG,
        ]

    def test_package_env_file_defaults(self):
        assert DEFAULT_PACKAGE_ENV_FILES == (
            "/etc/default/logstash",
            "/etc/sysconfig/logstash",
        )
        assert DEFAULT_PACKAGE_ENV_FILE == DEFAULT_PACKAGE_ENV_FILES[-1]


class TestLogstashPathResolution:
    def test_resolve_home_missing(self, clear_logstash_env):
        assert resolve_logstash_home() is None

    def test_resolve_home_from_env(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        home = tmp_path / "logstash"
        home.mkdir()
        monkeypatch.setenv(ENV_LOGSTASH_HOME, str(home))
        assert resolve_logstash_home() == home.resolve()

    def test_default_paths_from_home(self, tmp_path: Path):
        home = tmp_path / "ls"
        home.mkdir()
        assert default_bin_from_home(home) == (
            home / "bin" / "logstash-keystore"
        ).resolve()
        assert default_path_settings_from_home(home) == (home / "config").resolve()

    def test_bin_from_logstash_home(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        home = tmp_path / "logstash"
        bindir = home / "bin"
        bindir.mkdir(parents=True)
        binary = bindir / "logstash-keystore"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        monkeypatch.setenv(ENV_LOGSTASH_HOME, str(home))
        assert resolve_logstash_bin_from_env() == binary.resolve()

    def test_bin_explicit_overrides_home(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        home = tmp_path / "logstash"
        (home / "bin").mkdir(parents=True)
        home_bin = home / "bin" / "logstash-keystore"
        home_bin.write_text("home")
        explicit = tmp_path / "custom-keystore"
        explicit.write_text("custom")
        monkeypatch.setenv(ENV_LOGSTASH_HOME, str(home))
        monkeypatch.setenv(ENV_LOGSTASH_KEYSTORE_BIN, str(explicit))
        assert resolve_logstash_bin_from_env() == explicit.resolve()

    def test_path_settings_from_home(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        home = tmp_path / "logstash"
        cfg = home / "config"
        cfg.mkdir(parents=True)
        monkeypatch.setenv(ENV_LOGSTASH_HOME, str(home))
        assert resolve_path_settings_from_env() == cfg.resolve()

    def test_path_settings_explicit_override(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        home = tmp_path / "logstash"
        (home / "config").mkdir(parents=True)
        package_cfg = tmp_path / "etc" / "logstash"
        package_cfg.mkdir(parents=True)
        monkeypatch.setenv(ENV_LOGSTASH_HOME, str(home))
        monkeypatch.setenv(ENV_LOGSTASH_PATH_SETTINGS, str(package_cfg))
        assert resolve_path_settings_from_env() == package_cfg.resolve()

    def test_path_settings_alias(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        cfg = tmp_path / "settings"
        cfg.mkdir()
        monkeypatch.setenv(ENV_PATH_SETTINGS_ALIAS, str(cfg))
        assert resolve_path_settings_from_env() == cfg.resolve()

    def test_path_settings_require_writable(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        cfg = tmp_path / "readonly"
        cfg.mkdir()
        cfg.chmod(0o555)
        monkeypatch.setenv(ENV_LOGSTASH_PATH_SETTINGS, str(cfg))
        try:
            assert resolve_path_settings_from_env(require_writable=True) is None
            assert resolve_path_settings_from_env(require_writable=False) == cfg.resolve()
        finally:
            cfg.chmod(0o755)

    def test_bin_missing_returns_none_without_defaults(
        self, clear_logstash_env, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv(
            ENV_LOGSTASH_KEYSTORE_BIN, "/nonexistent/logstash-keystore"
        )
        result = resolve_logstash_bin_from_env()
        if result is not None:
            assert result.is_file()
            assert str(result) != "/nonexistent/logstash-keystore"


class TestLogstashPasswordResolution:
    def test_direct_env_password(
        self, clear_logstash_env, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv(ENV_LOGSTASH_KEYSTORE_PASS, "s3cret")
        assert resolve_logstash_password() == "s3cret"

    def test_empty_pass_falls_through_to_env_file(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        env_file = tmp_path / "sysconfig"
        env_file.write_text(f"{ENV_LOGSTASH_KEYSTORE_PASS}=fromfile\n")
        monkeypatch.setenv(ENV_LOGSTASH_KEYSTORE_PASS, "   ")
        monkeypatch.setenv(ENV_LOGSTASH_ENV_FILE, str(env_file))
        assert resolve_logstash_password() == "fromfile"

    def test_explicit_env_file_argument(
        self, clear_logstash_env, tmp_path: Path
    ):
        env_file = tmp_path / "ls.env"
        env_file.write_text(f'{ENV_LOGSTASH_KEYSTORE_PASS}="quoted"\n')
        assert (
            resolve_logstash_password(environ={}, env_file=env_file) == "quoted"
        )

    def test_load_env_file_ignores_comments(self, tmp_path: Path):
        env_file = tmp_path / "x.env"
        env_file.write_text(
            "# comment\n"
            f"export {ENV_LOGSTASH_KEYSTORE_PASS}=abc\n"
            "OTHER=1\n"
        )
        values = load_env_file(env_file)
        assert values[ENV_LOGSTASH_KEYSTORE_PASS] == "abc"
        assert values["OTHER"] == "1"

    def test_unresolved_password(self, clear_logstash_env, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv(ENV_LOGSTASH_ENV_FILE, "/nonexistent/envfile")
        result = resolve_logstash_password(environ={})
        # Only assert None when none of the package default files exist
        if not any(Path(p).is_file() for p in DEFAULT_PACKAGE_ENV_FILES):
            assert result is None

    def test_package_env_files_merge_order(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Later package env file overrides earlier (systemd EnvironmentFile order)."""
        default_f = tmp_path / "default"
        sysconfig_f = tmp_path / "sysconfig"
        default_f.write_text(
            f"{ENV_LOGSTASH_KEYSTORE_PASS}=from-default\nOTHER=default\n"
        )
        sysconfig_f.write_text(
            f"{ENV_LOGSTASH_KEYSTORE_PASS}=from-sysconfig\n"
        )
        monkeypatch.setattr(
            "logstashagent.ls_keystore_utils.resolve.DEFAULT_PACKAGE_ENV_FILES",
            (str(default_f), str(sysconfig_f)),
        )
        assert resolve_logstash_password(environ={}) == "from-sysconfig"

        merged = load_env_files((default_f, sysconfig_f))
        assert merged[ENV_LOGSTASH_KEYSTORE_PASS] == "from-sysconfig"
        assert merged["OTHER"] == "default"

    def test_package_env_files_first_only(
        self, clear_logstash_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        default_f = tmp_path / "default"
        default_f.write_text(f"{ENV_LOGSTASH_KEYSTORE_PASS}=only-default\n")
        monkeypatch.setattr(
            "logstashagent.ls_keystore_utils.resolve.DEFAULT_PACKAGE_ENV_FILES",
            (str(default_f), str(tmp_path / "missing-sysconfig")),
        )
        assert resolve_logstash_password(environ={}) == "only-default"
