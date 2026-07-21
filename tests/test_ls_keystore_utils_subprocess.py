#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.ls_keystore_utils.subprocess_utils."""

import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from logstashagent.ls_keystore_utils.subprocess_utils import (
    run_keystore_cli,
    create_keystore,
    find_keystore_binary,
)
from logstashagent.ls_keystore_utils.exceptions import (
    KeystoreBinaryException,
    LogstashKeystoreException,
)


def _make_fake_bin(tmp_path: Path) -> Path:
    """Create a tiny executable script in tmp_path and return its path."""
    import os
    bin_path = tmp_path / "logstash-keystore"
    bin_path.write_text("#!/bin/sh\necho ok\n")
    os.chmod(bin_path, 0o755)
    return bin_path


def _make_fake_settings(tmp_path: Path) -> Path:
    """Return a writable directory to use as path_settings."""
    settings = tmp_path / "config"
    settings.mkdir()
    return settings


class TestRunKeystoreCli:
    def test_returns_stdout_on_success(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success output\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            out = run_keystore_cli(fake_bin, settings, ["list"])

        assert out == "success output\n"

    def test_raises_on_nonzero_returncode(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error message"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(LogstashKeystoreException, match="Command failed"):
                run_keystore_cli(fake_bin, settings, ["create"])

    def test_sets_password_env_variable(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        captured_env = {}

        def capture_run(cmd, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            return mock_result

        with patch("subprocess.run", side_effect=capture_run):
            run_keystore_cli(fake_bin, settings, ["list"], password="mypass")

        assert captured_env.get("LOGSTASH_KEYSTORE_PASS") == "mypass"

    def test_passes_input_text_to_stdin(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        captured_kwargs: dict = {}

        def capture(cmd, **kwargs):
            captured_kwargs.update(kwargs)
            return mock_result

        with patch("subprocess.run", side_effect=capture):
            run_keystore_cli(fake_bin, settings, ["add", "KEY"], input_text="value\n")

        assert captured_kwargs["input"] == "value\n"

    def test_raises_file_not_found_for_missing_binary(self, tmp_path):
        settings = _make_fake_settings(tmp_path)
        with pytest.raises(FileNotFoundError):
            run_keystore_cli(tmp_path / "missing-bin", settings, ["list"])

    def test_raises_file_not_found_for_missing_settings(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        with pytest.raises(FileNotFoundError):
            run_keystore_cli(fake_bin, tmp_path / "nosuchdir", ["list"])


class TestCreateKeystore:
    def test_calls_run_keystore_cli_with_create(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = create_keystore(fake_bin, settings)

        assert result is True

    def test_raises_file_exists_if_keystore_already_present(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)
        (settings / "logstash.keystore").write_bytes(b"existing")

        with pytest.raises(FileExistsError):
            create_keystore(fake_bin, settings)

    def test_raises_when_settings_dir_missing(self, tmp_path):
        """create_keystore requires path_settings to already exist (path_exists decorator)."""
        fake_bin = _make_fake_bin(tmp_path)
        missing_settings = tmp_path / "new_config"

        with pytest.raises(FileNotFoundError):
            create_keystore(fake_bin, missing_settings)


class TestFindKeystoreBinary:
    def test_returns_path_when_found_via_glob(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)

        with patch(
            "logstashagent.ls_keystore_utils.subprocess_utils.PATTERNS",
            [str(tmp_path / "logstash-keystore")],
        ):
            result = find_keystore_binary()

        assert result == fake_bin

    def test_raises_when_not_found(self, tmp_path):
        with patch(
            "logstashagent.ls_keystore_utils.subprocess_utils.PATTERNS", []
        ), patch(
            "subprocess.run",
            return_value=MagicMock(returncode=1, stdout=""),
        ):
            with pytest.raises(KeystoreBinaryException, match="not found"):
                find_keystore_binary()

    def test_falls_back_to_which(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)

        which_result = MagicMock()
        which_result.returncode = 0
        which_result.stdout = str(fake_bin) + "\n"

        with patch(
            "logstashagent.ls_keystore_utils.subprocess_utils.PATTERNS", []
        ), patch(
            "subprocess.run", return_value=which_result
        ):
            result = find_keystore_binary()

        assert result == fake_bin
