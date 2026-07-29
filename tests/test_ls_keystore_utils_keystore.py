#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.ls_keystore_utils.keystore.LogstashKeystore."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from logstashagent.ls_keystore_utils.keystore import LogstashKeystore
from logstashagent.ls_keystore_utils.crypto import (
    ObfuscatedValue,
    KeyEntry,
    generate_salt_iv,
)
from logstashagent.ls_keystore_utils.exceptions import (
    IncorrectPassword,
    LogstashKeystoreException,
    LogstashKeystoreModified,
)


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

def _make_fake_bin(tmp_path: Path) -> Path:
    import os
    bin_path = tmp_path / "logstash-keystore"
    bin_path.write_text("#!/bin/sh\necho ok\n")
    os.chmod(bin_path, 0o755)
    return bin_path


def _make_fake_settings(tmp_path: Path) -> Path:
    settings = tmp_path / "config"
    settings.mkdir()
    return settings


def _make_salt_iv() -> bytes:
    return generate_salt_iv()


def _make_ks(tmp_path: Path, keys: dict = None, *, password="testpass"):
    """Create a LogstashKeystore with fully mocked internals.

    Patches valid_ks, read_keystore so no real keystore file is needed.
    ``keys`` is a plain {KEY: value} dict that the mock reports.
    """
    if keys is None:
        keys = {}

    fake_bin = _make_fake_bin(tmp_path)
    settings = _make_fake_settings(tmp_path)
    salt_iv = _make_salt_iv()

    # Build KeyEntry objects the way the real code does
    key_entries = {
        k.upper(): KeyEntry(ObfuscatedValue(v, salt_iv), 1234)
        for k, v in keys.items()
    }

    with patch(
        "logstashagent.ls_keystore_utils.keystore.valid_ks", return_value=True
    ), patch(
        "logstashagent.ls_keystore_utils.keystore.find_keystore_binary",
        return_value=fake_bin,
    ):
        ks = LogstashKeystore(
            path_settings=settings,
            password=password,
            exepath=fake_bin,
            salt_iv=salt_iv,
        )
        ks._current = key_entries
        ks._last_timestamp = max((e.timestamp for e in key_entries.values()), default=None)

    return ks, settings, fake_bin, salt_iv


# ---------------------------------------------------------------------------
# __init__ and basic properties
# ---------------------------------------------------------------------------

class TestLogstashKeystoreInit:
    def test_init_with_password(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        with patch("logstashagent.ls_keystore_utils.keystore.find_keystore_binary", return_value=fake_bin):
            ks = LogstashKeystore(
                path_settings=settings,
                password="mypass",
                exepath=fake_bin,
            )

        assert ks.password is not None
        assert ks.keystore == settings / "logstash.keystore"

    def test_init_with_obvpassword_and_salt_iv(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)
        salt_iv = generate_salt_iv()
        obv = ObfuscatedValue("secret", salt_iv)

        with patch("logstashagent.ls_keystore_utils.keystore.find_keystore_binary", return_value=fake_bin):
            ks = LogstashKeystore(
                path_settings=settings,
                exepath=fake_bin,
                salt_iv=salt_iv,
                obvpassword=obv,
            )

        assert ks.password is obv

    def test_init_raises_if_obvpassword_without_salt_iv(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)
        salt_iv = generate_salt_iv()
        obv = ObfuscatedValue("secret", salt_iv)

        with patch("logstashagent.ls_keystore_utils.keystore.find_keystore_binary", return_value=fake_bin):
            with pytest.raises(ValueError, match="salt_iv must be provided"):
                LogstashKeystore(
                    path_settings=settings,
                    exepath=fake_bin,
                    obvpassword=obv,
                )

    def test_repr_contains_path_info(self, tmp_path):
        ks, settings, _, _ = _make_ks(tmp_path)
        r = repr(ks)
        assert "LogstashKeystore" in r
        assert "path_settings" in r

    def test_generates_salt_iv_when_not_provided(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        with patch("logstashagent.ls_keystore_utils.keystore.find_keystore_binary", return_value=fake_bin):
            ks = LogstashKeystore(path_settings=settings, password="p", exepath=fake_bin)

        assert len(ks.salt_iv) == 32


# ---------------------------------------------------------------------------
# timestamp property
# ---------------------------------------------------------------------------

class TestTimestamp:
    def test_returns_none_when_no_keys(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})
        assert ks.timestamp is None

    def test_returns_max_timestamp(self, tmp_path):
        salt_iv = generate_salt_iv()
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        with patch("logstashagent.ls_keystore_utils.keystore.find_keystore_binary", return_value=fake_bin):
            ks = LogstashKeystore(path_settings=settings, password="p", exepath=fake_bin, salt_iv=salt_iv)

        ks._current = {
            "KEY1": KeyEntry(ObfuscatedValue("a", salt_iv), 100),
            "KEY2": KeyEntry(ObfuscatedValue("b", salt_iv), 200),
        }
        assert ks.timestamp == 200


# ---------------------------------------------------------------------------
# delete_keystore
# ---------------------------------------------------------------------------

class TestDeleteKeystore:
    def test_deletes_existing_keystore(self, tmp_path):
        ks, settings, _, _ = _make_ks(tmp_path)
        ks.keystore.write_bytes(b"dummy")

        result = ks.delete_keystore()

        assert result is True
        assert not ks.keystore.exists()
        assert ks.needs_restart is True

    def test_returns_false_when_keystore_missing(self, tmp_path):
        ks, *_ = _make_ks(tmp_path)
        assert not ks.keystore.exists()

        result = ks.delete_keystore()

        assert result is False


# ---------------------------------------------------------------------------
# valid_keystore (instance method)
# ---------------------------------------------------------------------------

class TestValidKeystore:
    def test_delegates_to_valid_ks(self, tmp_path):
        ks, *_ = _make_ks(tmp_path)

        with patch(
            "logstashagent.ls_keystore_utils.keystore.valid_ks", return_value=True
        ) as mock_vk:
            result = ks.valid_keystore()

        assert result is True
        mock_vk.assert_called_once_with(ks.keystore)


# ---------------------------------------------------------------------------
# read_key / get_key
# ---------------------------------------------------------------------------

class TestReadKey:
    def test_returns_value_for_existing_key(self, tmp_path):
        ks, _, _, salt_iv = _make_ks(tmp_path, {"mykey": "myvalue"})

        with patch.object(ks, "_check_timestamp"):
            result = ks.read_key("MYKEY")

        assert result == "myvalue"

    def test_returns_none_for_missing_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "_check_timestamp"):
            result = ks.read_key("NOSUCHKEY")

        assert result is None

    def test_get_key_delegates_to_read_key(self, tmp_path):
        ks, _, _, salt_iv = _make_ks(tmp_path, {"k": "v"})

        with patch.object(ks, "_check_timestamp"):
            assert ks.get_key("K") == "v"


# ---------------------------------------------------------------------------
# keys property
# ---------------------------------------------------------------------------

class TestKeysProperty:
    def test_lists_all_keys(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {"alpha": "1", "beta": "2"})

        with patch.object(ks, "_check_timestamp"):
            result = ks.keys

        assert set(result) == {"ALPHA", "BETA"}

    def test_empty_when_no_keys(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "_check_timestamp"):
            assert ks.keys == []


# ---------------------------------------------------------------------------
# key_exists
# ---------------------------------------------------------------------------

class TestKeyExists:
    def test_returns_true_for_existing_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {"mykey": "val"})

        with patch.object(ks, "_check_timestamp"):
            assert ks.key_exists("MYKEY") is True

    def test_returns_false_for_missing_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "_check_timestamp"):
            assert ks.key_exists("NOSUCHKEY") is False


# ---------------------------------------------------------------------------
# create_key / add_key
# ---------------------------------------------------------------------------

class TestCreateKey:
    def test_single_key_calls_add_single_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "_check_timestamp"), \
             patch.object(ks, "_add_single_key") as mock_add, \
             patch.object(ks, "_post_operation_update"), \
             patch.object(ks, "_verify_keys"):
            result = ks.create_key("mykey", "myvalue")

        assert result is True
        mock_add.assert_called_once_with("mykey", "myvalue", use_cli=False)

    def test_dict_calls_add_batch_keys(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "_check_timestamp"), \
             patch.object(ks, "_add_batch_keys") as mock_batch, \
             patch.object(ks, "_post_operation_update"), \
             patch.object(ks, "_verify_keys"):
            result = ks.create_key({"key1": "val1", "key2": "val2"})

        assert result is True
        mock_batch.assert_called_once_with({"key1": "val1", "key2": "val2"}, use_cli=False)

    def test_raises_value_error_when_value_missing_for_single_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "_check_timestamp"):
            with pytest.raises(ValueError, match="value must be provided"):
                ks.create_key("mykey")

    def test_add_key_delegates_to_create_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "create_key", return_value=True) as mock_ck:
            result = ks.add_key("k", "v")

        assert result is True
        mock_ck.assert_called_once_with("k", "v", use_cli=False)


# ---------------------------------------------------------------------------
# delete_key / remove_key
# ---------------------------------------------------------------------------

class TestDeleteKey:
    def test_single_key_deletion(self, tmp_path):
        ks, settings, fake_bin, salt_iv = _make_ks(tmp_path, {"k": "v"})

        with patch.object(ks, "_check_timestamp"), \
             patch.object(ks, "_post_operation_update"), \
             patch.object(ks, "_verify_removed_keys"), \
             patch.object(ks, "_remove_batch_keys") as mock_rb:
            result = ks.delete_key("K")

        assert result is True
        mock_rb.assert_called_once_with(["K"], use_cli=False)

    def test_list_key_deletion_calls_remove_batch(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {"k1": "v1", "k2": "v2"})

        with patch.object(ks, "_check_timestamp"), \
             patch.object(ks, "_remove_batch_keys") as mock_rb, \
             patch.object(ks, "_post_operation_update"), \
             patch.object(ks, "_verify_removed_keys"):
            ks.delete_key(["K1", "K2"])

        mock_rb.assert_called_once_with(["K1", "K2"], use_cli=False)

    def test_remove_key_delegates_to_delete_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {})

        with patch.object(ks, "delete_key", return_value=True) as mock_dk:
            result = ks.remove_key("K")

        assert result is True
        mock_dk.assert_called_once_with("K", use_cli=False)


# ---------------------------------------------------------------------------
# update_key
# ---------------------------------------------------------------------------

class TestUpdateKey:
    def test_delegates_to_create_key(self, tmp_path):
        ks, *_ = _make_ks(tmp_path, {"existing": "old"})

        with patch.object(ks, "create_key", return_value=True) as mock_ck:
            result = ks.update_key("existing", "new")

        assert result is True
        mock_ck.assert_called_once_with("existing", "new", use_cli=False)


# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------

class TestBackup:
    def test_backup_calls_backup_keystore(self, tmp_path):
        ks, *_ = _make_ks(tmp_path)
        ks.keystore.write_bytes(b"keystore data")
        backup_path = tmp_path / "backup" / "ks.bak"

        with patch(
            "logstashagent.ls_keystore_utils.keystore.backup_keystore",
            return_value=True,
        ) as mock_bk:
            result = ks.backup(backup_path)

        assert result is True
        mock_bk.assert_called_once_with(ks.keystore, backup_path)


# ---------------------------------------------------------------------------
# _check_timestamp
# ---------------------------------------------------------------------------

class TestCheckTimestamp:
    def test_raises_modified_on_removed_keys(self, tmp_path):
        ks, _, _, salt_iv = _make_ks(tmp_path, {"KEY1": "v1", "KEY2": "v2"})

        # read_all returns only KEY1 (KEY2 was removed)
        fresh = {"KEY1": KeyEntry(ObfuscatedValue("v1", salt_iv), 1234)}
        with patch.object(ks, "read_all", return_value=fresh):
            with pytest.raises(LogstashKeystoreModified):
                ks._check_timestamp()

    def test_does_not_raise_when_unchanged(self, tmp_path):
        salt_iv = generate_salt_iv()
        ks, _, _, _ = _make_ks(tmp_path, {"KEY1": "v1"})
        # Align salt_iv
        ks.salt_iv = salt_iv
        ks._current = {"KEY1": KeyEntry(ObfuscatedValue("v1", salt_iv), 1234)}
        ks._last_timestamp = 1234

        fresh = {"KEY1": KeyEntry(ObfuscatedValue("v1", salt_iv), 1234)}
        with patch.object(ks, "read_all", return_value=fresh):
            ks._check_timestamp()  # should not raise


# ---------------------------------------------------------------------------
# load / create class methods
# ---------------------------------------------------------------------------

class TestClassMethods:
    def test_load_raises_for_invalid_keystore(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        with patch(
            "logstashagent.ls_keystore_utils.keystore.valid_ks", return_value=False
        ), patch(
            "logstashagent.ls_keystore_utils.keystore.find_keystore_binary",
            return_value=fake_bin,
        ):
            with pytest.raises(LogstashKeystoreException, match="Invalid keystore"):
                LogstashKeystore.load(settings, password="p", exepath=fake_bin)

    def test_create_uses_pure_python_by_default(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        with patch(
            "logstashagent.ls_keystore_utils.keystore.create_keystore"
        ) as mock_ck, patch(
            "logstashagent.ls_keystore_utils.keystore.find_keystore_binary",
            return_value=fake_bin,
        ):
            ks = LogstashKeystore.create(settings, password="p", exepath=fake_bin)

        mock_ck.assert_not_called()
        assert isinstance(ks, LogstashKeystore)
        assert ks.keystore.exists()
        assert ks.uses_embedded_password is False

    def test_create_with_use_cli_calls_create_keystore(self, tmp_path):
        fake_bin = _make_fake_bin(tmp_path)
        settings = _make_fake_settings(tmp_path)

        with patch(
            "logstashagent.ls_keystore_utils.keystore.create_keystore"
        ) as mock_ck, patch(
            "logstashagent.ls_keystore_utils.keystore.valid_ks", return_value=True
        ), patch(
            "logstashagent.ls_keystore_utils.keystore.find_keystore_binary",
            return_value=fake_bin,
        ), patch(
            "logstashagent.ls_keystore_utils.keystore.read_keystore",
            return_value={},
        ):
            ks = LogstashKeystore.create(
                settings, password="p", exepath=fake_bin, use_cli=True
            )

        mock_ck.assert_called_once()
        assert isinstance(ks, LogstashKeystore)

    def test_create_unauthenticated_without_password(self, tmp_path):
        settings = _make_fake_settings(tmp_path)
        ks = LogstashKeystore.create(settings, password=None, exepath=None)
        assert ks.uses_embedded_password is True
        assert ks.keystore.exists()
        reloaded = LogstashKeystore.load(settings, password=None, exepath=None)
        assert reloaded.uses_embedded_password is True
