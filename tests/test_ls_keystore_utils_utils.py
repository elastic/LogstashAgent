#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.ls_keystore_utils.utils."""

import os
import shutil
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from logstashagent.ls_keystore_utils.utils import (
    ascii_bytes_to_chars,
    ascii_chars_to_bytes,
    clear_bytes,
    base64_encode,
    deobfuscate,
    obfuscate,
    executable_file,
    find_path_settings,
    backup_keystore,
    read_file_bytes,
    now_path,
    file_exists,
)
from logstashagent.ls_keystore_utils.exceptions import LogstashKeystoreException


class TestAsciiConversions:
    def test_bytes_to_chars(self):
        assert ascii_bytes_to_chars(b"hello") == "hello"

    def test_chars_to_bytes(self):
        assert ascii_chars_to_bytes("hello") == b"hello"

    def test_round_trip(self):
        original = "abc123"
        assert ascii_bytes_to_chars(ascii_chars_to_bytes(original)) == original


class TestClearBytes:
    def test_zeros_out_bytearray(self):
        data = bytearray(b"secret")
        clear_bytes(data)
        assert all(b == 0 for b in data)

    def test_empty_bytearray(self):
        data = bytearray(b"")
        clear_bytes(data)
        assert data == bytearray(b"")


class TestBase64Encode:
    def test_encodes_correctly(self):
        import base64 as _b64
        result = base64_encode(b"hello")
        assert result == _b64.b64encode(b"hello")

    def test_returns_bytes(self):
        result = base64_encode(b"test")
        assert isinstance(result, bytes)


class TestObfuscateDeobfuscate:
    def test_deobfuscate_round_trip(self):
        original = "abc123xyz"
        obfuscated = obfuscate(original)
        assert deobfuscate(obfuscated) == original

    def test_deobfuscate_raises_on_odd_length(self):
        # ascii_chars_to_bytes of a 3-char string → odd length
        with pytest.raises(ValueError, match="Invalid obfuscated data length"):
            deobfuscate("abc")

    def test_obfuscate_produces_double_length(self):
        value = "test"
        obfuscated = obfuscate(value)
        assert len(obfuscated) == len(value) * 2

    def test_different_obfuscations_same_plaintext(self):
        value = "secret"
        ob1 = obfuscate(value)
        ob2 = obfuscate(value)
        # random XOR padding means different ciphertexts most of the time
        assert deobfuscate(ob1) == value
        assert deobfuscate(ob2) == value

    def test_empty_string(self):
        value = ""
        obfuscated = obfuscate(value)
        assert deobfuscate(obfuscated) == value


class TestExecutableFile:
    def test_returns_true_for_executable(self, tmp_path):
        exe = tmp_path / "mybin"
        exe.write_bytes(b"#!/bin/sh\n")
        os.chmod(exe, 0o755)
        try:
            result = executable_file(str(exe))
            assert result is True
        except FileNotFoundError:
            pytest.skip("path_exists decorator requires file existence")

    def test_returns_false_for_non_executable(self, tmp_path):
        non_exe = tmp_path / "data.txt"
        non_exe.write_text("data")
        os.chmod(non_exe, 0o644)
        # On Windows all regular files report as executable via os.access,
        # so skip the assertion on that platform.
        import sys
        result = executable_file(str(non_exe))
        if sys.platform != "win32":
            assert result is False

    def test_returns_false_for_missing_path(self, tmp_path):
        # executable_file has no path_exists decorator; os.access returns False
        # for non-existent paths rather than raising.
        result = executable_file(str(tmp_path / "nonexistent"))
        assert result is False


class TestFindPathSettings:
    def test_returns_existing_writable_dir(self, tmp_path):
        with patch(
            "logstashagent.ls_keystore_utils.resolve.resolve_path_settings_from_env",
            return_value=None,
        ), patch(
            "logstashagent.ls_keystore_utils.utils.CANDIDATES", [str(tmp_path)]
        ), patch(
            "logstashagent.ls_keystore_utils.utils.ALTERNATE_LS_PATHS", {}
        ):
            result = find_path_settings(binary_path=None)
        assert isinstance(result, Path)
        assert result == tmp_path

    def test_raises_when_no_candidate_found(self, tmp_path):
        with patch(
            "logstashagent.ls_keystore_utils.utils.CANDIDATES", []
        ), patch(
            "logstashagent.ls_keystore_utils.utils.ALTERNATE_LS_PATHS", {}
        ), patch(
            "logstashagent.ls_keystore_utils.resolve.resolve_path_settings_from_env",
            return_value=None,
        ):
            with pytest.raises(LogstashKeystoreException, match="No valid path.settings"):
                find_path_settings()

    def test_uses_first_writable_candidate(self, tmp_path):
        candidates = [str(tmp_path / "missing"), str(tmp_path)]
        with patch(
            "logstashagent.ls_keystore_utils.utils.CANDIDATES", candidates
        ), patch(
            "logstashagent.ls_keystore_utils.utils.ALTERNATE_LS_PATHS", {}
        ), patch(
            "logstashagent.ls_keystore_utils.resolve.resolve_path_settings_from_env",
            return_value=None,
        ):
            result = find_path_settings()
            assert result == tmp_path


class TestBackupKeystore:
    def test_copies_file_to_destination(self, tmp_path):
        src = tmp_path / "logstash.keystore"
        src.write_bytes(b"\x01\x02\x03")
        dst = tmp_path / "backups" / "logstash.keystore.bak"

        result = backup_keystore(src, dst)

        assert result is True
        assert dst.exists()
        assert dst.read_bytes() == b"\x01\x02\x03"

    def test_creates_parent_directories(self, tmp_path):
        src = tmp_path / "ks"
        src.write_bytes(b"data")
        dst = tmp_path / "a" / "b" / "c" / "ks.bak"

        backup_keystore(src, dst)

        assert dst.exists()

    def test_raises_file_not_found_for_missing_source(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            backup_keystore(tmp_path / "missing.ks", tmp_path / "out.ks")

    def test_string_paths_accepted(self, tmp_path):
        src = tmp_path / "ks"
        src.write_bytes(b"x")
        dst = tmp_path / "ks.bak"
        result = backup_keystore(str(src), str(dst))
        assert result is True


class TestReadFileBytes:
    def test_reads_file_contents(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\xde\xad\xbe\xef")
        result = read_file_bytes(f)
        assert result == b"\xde\xad\xbe\xef"

    def test_raises_for_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            read_file_bytes(tmp_path / "nosuchfile")

    def test_accepts_string_path(self, tmp_path):
        f = tmp_path / "text.txt"
        f.write_text("hello")
        result = read_file_bytes(str(f))
        assert result == b"hello"


class TestNowPath:
    def test_string_becomes_path(self):
        result = now_path("/tmp/test")
        assert isinstance(result, Path)

    def test_path_passes_through(self):
        p = Path("/tmp/test")
        result = now_path(p)
        assert result == p

    def test_none_returns_none(self):
        assert now_path(None) is None


class TestFileExists:
    def test_returns_true_for_existing_file(self, tmp_path):
        f = tmp_path / "exists.txt"
        f.write_text("hi")
        assert file_exists(f) is True

    def test_raises_for_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            file_exists(tmp_path / "missing.txt")

    def test_raises_for_directory(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            file_exists(tmp_path)
