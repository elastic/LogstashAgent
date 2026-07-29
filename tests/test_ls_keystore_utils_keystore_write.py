#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Unit tests for pure-Python Logstash keystore write support."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from logstashagent.ls_keystore_utils import LogstashKeystore
from logstashagent.ls_keystore_utils.crypto import read_keystore, valid_keystore
from logstashagent.ls_keystore_utils.exceptions import IncorrectPassword
from logstashagent.ls_keystore_utils.keystore_write import (
    build_keystore_bytes,
    create_keystore_file,
    delete_secrets,
    extract_embedded_password,
    has_embedded_password,
    migrate_keystore_password,
    resolve_keystore_password,
    upsert_secrets,
    write_keystore_secrets,
)

# pylint: disable=C0115,C0116,R0904,W0212,W0621


class TestKeystoreWriteUnit:
    """Unit tests that do not require the logstash-keystore binary."""

    def test_build_and_read_roundtrip(self):
        password = "unit-test-pass"
        data = build_keystore_bytes(
            password, {"alpha": "value-a", "Beta.Key": "value-b"}
        )
        assert isinstance(data, bytes)
        assert len(data) > 100

        with tempfile.NamedTemporaryFile(suffix=".keystore", delete=False) as handle:
            path = Path(handle.name)
        try:
            path.write_bytes(data)
            assert valid_keystore(path)
            secrets = read_keystore(path, password)
            assert secrets["ALPHA"][0] == "value-a"
            assert secrets["BETA.KEY"][0] == "value-b"
            assert "KEYSTORE.SEED" not in secrets
        finally:
            path.unlink(missing_ok=True)

    def test_create_keystore_file_and_upsert(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, "pass123")
        assert ks_path.exists()
        assert valid_keystore(ks_path)
        assert read_keystore(ks_path, "pass123") == {}

        upsert_secrets(ks_path, "pass123", {"one": "1", "two": "2"})
        secrets = read_keystore(ks_path, "pass123")
        assert secrets["ONE"][0] == "1"
        assert secrets["TWO"][0] == "2"

        upsert_secrets(ks_path, "pass123", {"one": "1b"})
        secrets = read_keystore(ks_path, "pass123")
        assert secrets["ONE"][0] == "1b"
        assert secrets["TWO"][0] == "2"

        delete_secrets(ks_path, "pass123", ["two"])
        secrets = read_keystore(ks_path, "pass123")
        assert "TWO" not in secrets
        assert secrets["ONE"][0] == "1b"

    def test_create_file_exists_raises(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, "pass123")
        with pytest.raises(FileExistsError):
            create_keystore_file(ks_path, "pass123")

    def test_invalid_key_name(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, "pass123")
        with pytest.raises(ValueError, match="Invalid secret key name"):
            upsert_secrets(ks_path, "pass123", {"9bad": "x"})
        with pytest.raises(ValueError, match="Invalid secret key name"):
            upsert_secrets(ks_path, "pass123", {"bad-name": "x"})

    def test_empty_and_non_ascii_values(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, "pass123")
        with pytest.raises(ValueError, match="cannot be empty"):
            upsert_secrets(ks_path, "pass123", {"k": ""})
        with pytest.raises(ValueError, match="ASCII"):
            upsert_secrets(ks_path, "pass123", {"k": "café"})

    def test_empty_password_rejected(self):
        with pytest.raises(ValueError, match="password"):
            build_keystore_bytes("", {"a": "b"})

    def test_delete_missing_key(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, "pass123")
        upsert_secrets(ks_path, "pass123", {"present": "yes"})
        with pytest.raises(ValueError, match="not found"):
            delete_secrets(ks_path, "pass123", ["missing"])

    def test_wrong_password_on_upsert(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, "correct")
        upsert_secrets(ks_path, "correct", {"k": "v"})
        with pytest.raises(IncorrectPassword):
            upsert_secrets(ks_path, "wrong", {"k2": "v2"})

    def test_write_secrets_full_replace(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, "pass")
        upsert_secrets(ks_path, "pass", {"a": "1", "b": "2"})
        write_keystore_secrets(ks_path, "pass", {"c": "3"})
        secrets = read_keystore(ks_path, "pass")
        assert list(secrets.keys()) == ["C"]
        assert secrets["C"][0] == "3"

    def test_logstash_keystore_pure_python_api(self, tmp_path: Path):
        ks = LogstashKeystore.create(tmp_path, "api-pass")
        assert ks.keystore.exists()
        assert ks.keys == []
        assert ks.add_key("api_key", "secret") is True
        assert ks.get_key("api_key") == "secret"
        assert ks.needs_restart is True
        assert ks.update_key("api_key", "secret2") is True
        assert ks.get_key("api_key") == "secret2"
        assert ks.add_key({"batch1": "b1", "batch2": "b2"}) is True
        assert set(ks.keys) == {"API_KEY", "BATCH1", "BATCH2"}
        assert ks.remove_key("batch1") is True
        assert "BATCH1" not in ks.keys
        assert ks.remove_key(["batch2", "api_key"]) is True
        assert ks.keys == []

        loaded = LogstashKeystore.load(tmp_path, "api-pass")
        assert loaded.keys == []


class TestUnauthenticatedKeystore:
    """Default-password trailer (unauthenticated) keystore support."""

    def test_create_without_password_embeds_trailer(self, tmp_path: Path):
        ks = LogstashKeystore.create(tmp_path)
        assert ks.uses_embedded_password is True
        assert has_embedded_password(ks.keystore)
        extracted = extract_embedded_password(ks.keystore)
        assert extracted is not None
        assert len(extracted) == 44  # base64 of 32 bytes

    def test_unauth_crud_and_reload_without_password(self, tmp_path: Path):
        ks = LogstashKeystore.create(tmp_path)
        ks.add_key("alpha", "a1")
        ks.add_key({"beta": "b1", "gamma": "g1"})
        assert set(ks.keys) == {"ALPHA", "BETA", "GAMMA"}
        assert has_embedded_password(ks.keystore)

        reloaded = LogstashKeystore.load(tmp_path)  # no password
        assert reloaded.uses_embedded_password is True
        assert reloaded.get_key("alpha") == "a1"
        assert reloaded.get_key("beta") == "b1"
        reloaded.update_key("alpha", "a2")
        reloaded.remove_key("gamma")
        assert reloaded.get_key("alpha") == "a2"
        assert reloaded.get_key("gamma") is None
        assert has_embedded_password(reloaded.keystore)

        again = LogstashKeystore.load(tmp_path)
        assert again.get_key("alpha") == "a2"
        assert set(again.keys) == {"ALPHA", "BETA"}

    def test_migrate_unauth_to_auth_and_back(self, tmp_path: Path):
        ks = LogstashKeystore.create(tmp_path)
        ks.add_key("keep_me", "secret-value")
        assert ks.migrate_to_authenticated("NewAuthPass") is True
        assert ks.uses_embedded_password is False
        assert not has_embedded_password(ks.keystore)
        assert ks.get_key("keep_me") == "secret-value"

        with pytest.raises(ValueError, match="Password required"):
            LogstashKeystore.load(tmp_path)

        auth = LogstashKeystore.load(tmp_path, "NewAuthPass")
        assert auth.get_key("keep_me") == "secret-value"
        assert auth.migrate_to_unauthenticated() is True
        assert auth.uses_embedded_password is True
        assert has_embedded_password(auth.keystore)

        unauth = LogstashKeystore.load(tmp_path)
        assert unauth.get_key("keep_me") == "secret-value"

    def test_resolve_password_helpers(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        create_keystore_file(ks_path, password=None)
        plain, embedded = resolve_keystore_password(ks_path)
        assert embedded is True
        assert plain == extract_embedded_password(ks_path)

        plain2, embedded2 = resolve_keystore_password(ks_path, password="explicit")
        assert embedded2 is False
        assert plain2 == "explicit"

    def test_auth_keystore_has_no_trailer(self, tmp_path: Path):
        ks = LogstashKeystore.create(tmp_path, "auth-pass")
        assert ks.uses_embedded_password is False
        assert not has_embedded_password(ks.keystore)
        with pytest.raises(ValueError, match="Password required"):
            LogstashKeystore.load(tmp_path)

    def test_migrate_helpers_low_level(self, tmp_path: Path):
        ks_path = tmp_path / "logstash.keystore"
        _, password, embedded = create_keystore_file(ks_path, password=None)
        assert embedded is True
        upsert_secrets(
            ks_path, password, {"x": "1"}, embed_password=True
        )
        migrate_keystore_password(
            ks_path, password, "rotated", embed_password=False
        )
        assert not has_embedded_password(ks_path)
        assert read_keystore(ks_path, "rotated")["X"][0] == "1"
