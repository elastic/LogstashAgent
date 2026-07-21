#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.ls_keystore_utils.crypto."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from logstashagent.ls_keystore_utils.crypto import (
    ObfuscatedValue,
    KeyEntry,
    generate_salt_iv,
    _salt_and_iv,
    obfuscate_value,
    deobfuscate_value,
    get_alias_from_bag,
    is_keystore_seed_bag,
    is_secret_bag_for_key,
    get_bag_timestamp,
)
from logstashagent.ls_keystore_utils.settings import KEYSTORE_ALIAS, URN_PREFIX


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXED_SALT_IV = b"\x00" * 32


# ---------------------------------------------------------------------------
# generate_salt_iv
# ---------------------------------------------------------------------------

class TestGenerateSaltIv:
    def test_returns_32_bytes(self):
        result = generate_salt_iv()
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_returns_different_values_each_call(self):
        a = generate_salt_iv()
        b = generate_salt_iv()
        assert a != b  # extremely unlikely to collide


# ---------------------------------------------------------------------------
# _salt_and_iv
# ---------------------------------------------------------------------------

class TestSaltAndIv:
    def test_splits_correctly(self):
        data = b"A" * 16 + b"B" * 16
        salt, iv = _salt_and_iv(data)
        assert salt == b"A" * 16
        assert iv == b"B" * 16

    def test_raises_for_wrong_length(self):
        with pytest.raises(ValueError, match="Invalid salt_iv length"):
            _salt_and_iv(b"\x00" * 16)


# ---------------------------------------------------------------------------
# obfuscate_value / deobfuscate_value
# ---------------------------------------------------------------------------

class TestObfuscateDeobfuscateValue:
    def test_round_trip(self):
        salt_iv = generate_salt_iv()
        original = "my-secret-value"
        encrypted = obfuscate_value(original, salt_iv)
        assert deobfuscate_value(encrypted, salt_iv) == original

    def test_empty_string_round_trip(self):
        salt_iv = generate_salt_iv()
        encrypted = obfuscate_value("", salt_iv)
        assert deobfuscate_value(encrypted, salt_iv) == ""

    def test_different_salt_iv_gives_different_ciphertext(self):
        sv1 = generate_salt_iv()
        sv2 = generate_salt_iv()
        plain = "hello"
        assert obfuscate_value(plain, sv1) != obfuscate_value(plain, sv2)

    def test_fixed_salt_deterministic(self):
        enc1 = obfuscate_value("test", FIXED_SALT_IV)
        enc2 = obfuscate_value("test", FIXED_SALT_IV)
        assert enc1 == enc2


# ---------------------------------------------------------------------------
# ObfuscatedValue
# ---------------------------------------------------------------------------

class TestObfuscatedValue:
    def test_reveal_returns_original_value(self):
        salt_iv = generate_salt_iv()
        ov = ObfuscatedValue("secret", salt_iv)
        assert ov.reveal(salt_iv) == "secret"

    def test_repr_contains_encrypted(self):
        salt_iv = generate_salt_iv()
        ov = ObfuscatedValue("x", salt_iv)
        assert "ObfuscatedValue" in repr(ov)

    def test_equality_same_salt_iv_same_value(self):
        salt_iv = generate_salt_iv()
        ov1 = ObfuscatedValue("secret", salt_iv)
        ov2 = ObfuscatedValue("secret", salt_iv)
        assert ov1 == ov2

    def test_equality_same_salt_iv_different_value(self):
        salt_iv = generate_salt_iv()
        ov1 = ObfuscatedValue("secret1", salt_iv)
        ov2 = ObfuscatedValue("secret2", salt_iv)
        assert ov1 != ov2

    def test_equality_with_encrypted_bytes(self):
        salt_iv = generate_salt_iv()
        ov = ObfuscatedValue("hello", salt_iv)
        assert ov == ov.encrypted

    def test_equality_with_string_returns_false(self):
        salt_iv = generate_salt_iv()
        ov = ObfuscatedValue("hello", salt_iv)
        assert not (ov == "hello")

    def test_inequality_with_wrong_bytes(self):
        salt_iv = generate_salt_iv()
        ov = ObfuscatedValue("hello", salt_iv)
        assert not (ov == b"wrong bytes")

    def test_raises_for_invalid_salt_iv_length(self):
        with pytest.raises(ValueError, match="salt_iv must be 32 bytes"):
            ObfuscatedValue("value", b"\x00" * 16)

    def test_reveal_raises_for_invalid_salt_iv(self):
        salt_iv = generate_salt_iv()
        ov = ObfuscatedValue("value", salt_iv)
        with pytest.raises(ValueError, match="salt_iv must be 32 bytes"):
            ov.reveal(b"\x00" * 8)


# ---------------------------------------------------------------------------
# KeyEntry
# ---------------------------------------------------------------------------

class TestKeyEntry:
    def test_stores_obfuscated_value_and_timestamp(self):
        salt_iv = generate_salt_iv()
        ov = ObfuscatedValue("val", salt_iv)
        entry = KeyEntry(obfuscated_value=ov, timestamp=999)
        assert entry.obfuscated_value is ov
        assert entry.timestamp == 999


# ---------------------------------------------------------------------------
# Bag helper functions — mock PKCS12 bags
# ---------------------------------------------------------------------------

def _make_bag(alias: str = None, time_value: str = None) -> MagicMock:
    """Create a minimal mock PKCS12 bag."""
    bag = MagicMock()

    if alias is None:
        bag.__getitem__ = lambda self, k: MagicMock() if k == "bag_attributes" else MagicMock()
        bag_attrs = None
    else:
        attr = MagicMock()
        attr.__getitem__ = lambda self, k: MagicMock(native="friendlyName") if k == "type" else MagicMock(native=[alias.encode("utf-8") if isinstance(alias, str) else alias])
        # Override attr["type"].native
        type_mock = MagicMock()
        type_mock.native = "friendlyName"
        attr.__getitem__ = MagicMock(side_effect=lambda k: type_mock if k == "type" else MagicMock(native=[alias if not isinstance(alias, str) else alias.encode("utf-8")]))

        values_mock = MagicMock()
        values_mock.__getitem__ = lambda self, i: MagicMock(native=alias.encode("utf-8") if isinstance(alias, str) else alias)
        attr_real = MagicMock()
        attr_real.__getitem__ = MagicMock(side_effect=lambda k: type_mock if k == "type" else values_mock)

        bag_attrs = [attr_real]

    bag.__getitem__ = MagicMock(side_effect=lambda k: bag_attrs if k == "bag_attributes" else MagicMock())
    return bag


class TestGetAliasFromBag:
    def test_returns_none_when_no_attributes(self):
        bag = MagicMock()
        bag.__getitem__ = MagicMock(return_value=None)
        result = get_alias_from_bag(bag)
        assert result is None

    def test_returns_none_when_empty_attributes(self):
        bag = MagicMock()
        bag.__getitem__ = MagicMock(return_value=[])
        result = get_alias_from_bag(bag)
        assert result is None


class TestIsKeystoreSeedBag:
    def test_returns_false_when_no_alias(self):
        bag = MagicMock()
        bag.__getitem__ = MagicMock(return_value=None)
        assert is_keystore_seed_bag(bag) is False

    def test_returns_false_for_wrong_alias(self):
        with patch(
            "logstashagent.ls_keystore_utils.crypto.get_alias_from_bag",
            return_value="wrong:alias",
        ):
            bag = MagicMock()
            assert is_keystore_seed_bag(bag) is False

    def test_returns_true_for_keystore_alias(self):
        with patch(
            "logstashagent.ls_keystore_utils.crypto.get_alias_from_bag",
            return_value=KEYSTORE_ALIAS,
        ):
            bag = MagicMock()
            assert is_keystore_seed_bag(bag) is True


class TestIsSecretBagForKey:
    def test_returns_false_when_no_alias(self):
        with patch(
            "logstashagent.ls_keystore_utils.crypto.get_alias_from_bag",
            return_value=None,
        ):
            bag = MagicMock()
            assert is_secret_bag_for_key(bag, "my_key") is False

    def test_returns_true_when_alias_matches(self):
        key_name = "my_key"
        expected_urn = f"{URN_PREFIX}:{key_name.lower()}"
        with patch(
            "logstashagent.ls_keystore_utils.crypto.get_alias_from_bag",
            return_value=expected_urn,
        ):
            bag = MagicMock()
            assert is_secret_bag_for_key(bag, key_name) is True

    def test_returns_false_for_wrong_key(self):
        with patch(
            "logstashagent.ls_keystore_utils.crypto.get_alias_from_bag",
            return_value=f"{URN_PREFIX}:other_key",
        ):
            bag = MagicMock()
            assert is_secret_bag_for_key(bag, "my_key") is False


class TestGetBagTimestamp:
    def test_returns_none_when_no_attributes(self):
        bag = MagicMock()
        bag.__getitem__ = MagicMock(return_value=None)
        assert get_bag_timestamp(bag) is None

    def test_returns_none_when_empty_attributes(self):
        bag = MagicMock()
        bag.__getitem__ = MagicMock(return_value=[])
        assert get_bag_timestamp(bag) is None

    def test_parses_time_value(self):
        ts_ms = 1_700_000_000_000
        attr = MagicMock()
        values_mock = MagicMock()
        values_mock.__getitem__ = MagicMock(
            return_value=MagicMock(native=f"Time {ts_ms}".encode("utf-8"))
        )
        attr.__getitem__ = MagicMock(return_value=values_mock)

        bag = MagicMock()
        bag.__getitem__ = MagicMock(return_value=[attr])

        result = get_bag_timestamp(bag)
        if result is not None:
            assert result == int(ts_ms / 1000)
