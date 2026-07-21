#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.ls_keystore_utils.exceptions."""

import pytest

from logstashagent.ls_keystore_utils.exceptions import (
    LogstashKeystoreException,
    KeystoreBinaryException,
    LogstashKeystoreModified,
    IncorrectPassword,
)


class TestLogstashKeystoreException:
    def test_can_be_raised_and_caught(self):
        with pytest.raises(LogstashKeystoreException):
            raise LogstashKeystoreException("base error")

    def test_repr(self):
        exc = LogstashKeystoreException("msg")
        assert repr(exc) == "LogstashKeystoreException()"

    def test_is_exception_subclass(self):
        assert issubclass(LogstashKeystoreException, Exception)


class TestKeystoreBinaryException:
    def test_can_be_raised_and_caught(self):
        with pytest.raises(KeystoreBinaryException):
            raise KeystoreBinaryException("binary not found")

    def test_repr(self):
        exc = KeystoreBinaryException()
        assert repr(exc) == "KeystoreBinaryException()"

    def test_is_subclass_of_logstash_keystore_exception(self):
        assert issubclass(KeystoreBinaryException, LogstashKeystoreException)

    def test_caught_as_base(self):
        with pytest.raises(LogstashKeystoreException):
            raise KeystoreBinaryException("binary error")


class TestLogstashKeystoreModified:
    def test_stores_modified_keys_and_timestamp(self):
        exc = LogstashKeystoreModified(["KEY1", "KEY2"], 1234567890.0)
        assert exc.modified_keys == ["KEY1", "KEY2"]
        assert exc.discovered_timestamp == 1234567890.0

    def test_message_contains_key_info(self):
        exc = LogstashKeystoreModified(["KEY1"], 42.0)
        assert "KEY1" in str(exc)
        assert "42.0" in str(exc)

    def test_none_timestamp_accepted(self):
        exc = LogstashKeystoreModified(["KEY1"], None)
        assert exc.discovered_timestamp is None

    def test_repr_shows_fields(self):
        exc = LogstashKeystoreModified(["A"], 1.0)
        r = repr(exc)
        assert "LogstashKeystoreModified" in r
        assert "modified_keys" in r
        assert "discovered_timestamp" in r

    def test_is_subclass_of_base(self):
        assert issubclass(LogstashKeystoreModified, LogstashKeystoreException)

    def test_can_be_caught_as_base(self):
        with pytest.raises(LogstashKeystoreException):
            raise LogstashKeystoreModified([], None)


class TestIncorrectPassword:
    def test_can_be_raised_and_caught(self):
        with pytest.raises(IncorrectPassword):
            raise IncorrectPassword("bad password")

    def test_repr(self):
        exc = IncorrectPassword()
        assert repr(exc) == "IncorrectPassword()"

    def test_is_subclass_of_base(self):
        assert issubclass(IncorrectPassword, LogstashKeystoreException)

    def test_caught_as_base(self):
        with pytest.raises(LogstashKeystoreException):
            raise IncorrectPassword()
