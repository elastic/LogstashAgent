#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Inbound API authentication and /_logstash/validate path-traversal hardening."""

import asyncio
import base64
import hashlib
import os
import re
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from conftest import AUTH_HEADERS
from logstashagent import api_auth, controller, main


def _protected_routes():
    """(method, concrete path) for every registered /_logstash/* route."""
    out = []
    for route in main.app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/_logstash"):
            path = re.sub(r"\{[^}]+\}", "x", route.path)
            for method in sorted(route.methods):
                out.append((method, path))
    return out


PROTECTED = _protected_routes()


def test_every_logstash_route_is_registered_with_auth():
    assert len(PROTECTED) >= 16
    for route in main.app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/_logstash"):
            calls = [d.call for d in route.dependant.dependencies]
            assert api_auth.require_agent_key in calls, route.path


@pytest.mark.parametrize("method,path", PROTECTED)
def test_missing_key_rejected(method, path):
    resp = TestClient(main.app).request(method, path)
    assert resp.status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED)
def test_wrong_key_rejected(method, path):
    resp = TestClient(main.app).request(
        method, path, headers={"Authorization": "ApiKey not-the-key"}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED)
def test_unprovisioned_agent_fails_closed(method, path, monkeypatch):
    monkeypatch.delenv(api_auth.INBOUND_KEY_ENV, raising=False)
    with patch.object(api_auth.agent_state, "get_state", return_value={}):
        resp = TestClient(main.app).request(method, path, headers=AUTH_HEADERS)
    assert resp.status_code == 503


def test_root_healthcheck_stays_open():
    assert TestClient(main.app).get("/").status_code == 200


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_schema_not_exposed(path):
    assert TestClient(main.app).get(path).status_code == 404


class TestRequireAgentKey:
    def _call(self, header):
        return asyncio.run(api_auth.require_agent_key(header))

    def test_state_key_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv(api_auth.INBOUND_KEY_ENV, "env-key")
        with patch.object(api_auth.agent_state, "get_state",
                          return_value={"inbound_api_key": "state-key"}):
            assert self._call("ApiKey state-key") is None
            with pytest.raises(HTTPException) as exc:
                self._call("ApiKey env-key")
        assert exc.value.status_code == 401

    def test_env_key_used_when_not_enrolled(self, monkeypatch):
        monkeypatch.setenv(api_auth.INBOUND_KEY_ENV, "env-key")
        with patch.object(api_auth.agent_state, "get_state", return_value={}):
            assert self._call("ApiKey env-key") is None

    @pytest.mark.parametrize("header", [None, "", "ApiKey ", "Bearer env-key", "env-key"])
    def test_malformed_headers_rejected(self, header, monkeypatch):
        monkeypatch.setenv(api_auth.INBOUND_KEY_ENV, "env-key")
        with patch.object(api_auth.agent_state, "get_state", return_value={}):
            with pytest.raises(HTTPException) as exc:
                self._call(header)
        assert exc.value.status_code == 401

    def test_fingerprint(self):
        assert api_auth.inbound_key_fingerprint(None) is None
        assert api_auth.inbound_key_fingerprint("k") == hashlib.sha256(b"k").hexdigest()


class TestValidatePathTraversal:
    @pytest.mark.parametrize("name", [
        "../../app/src/logstashagent/data/pwn",
        "/etc/passwd",
        "a/b",
        "..",
        "x..y",
        "",
    ])
    def test_unsafe_pipeline_name_rejected(self, client, name):
        with patch("subprocess.run") as run:
            resp = client.post(
                "/_logstash/validate",
                json={"pipeline_name": name, "config": "input {}"},
            )
        assert resp.status_code == 400
        run.assert_not_called()

    def test_non_string_pipeline_name_rejected(self, client):
        resp = client.post(
            "/_logstash/validate", json={"pipeline_name": ["x"], "config": "input {}"}
        )
        assert resp.status_code == 400

    def test_valid_name_uses_private_temp_file(self, client):
        seen = {}

        def fake_run(cmd, **kwargs):
            path = cmd[cmd.index("-f") + 1]
            seen["path"] = path
            with open(path) as f:
                seen["content"] = f.read()
            return MagicMock(stdout="Configuration OK\n", returncode=0)

        with patch("subprocess.run", side_effect=fake_run):
            resp = client.post(
                "/_logstash/validate",
                json={"pipeline_name": "my-pipeline", "config": "input { ${X} }"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "OK"
        path = seen["path"]
        assert os.path.dirname(path) == tempfile.gettempdir()
        assert "my-pipeline" not in os.path.basename(path)
        assert seen["content"] == "input { ${X:test} }"
        assert not os.path.exists(path)


class TestCheckInKeyDelivery:
    @staticmethod
    def _encrypt(raw_api_key, plaintext):
        key = base64.urlsafe_b64encode(hashlib.sha256(raw_api_key.encode()).digest())
        return Fernet(key).encrypt(plaintext.encode()).decode()

    def test_persists_decrypted_key(self):
        result = {"inbound_api_key_encrypted": self._encrypt("agent-key", "inbound")}
        with patch.object(controller.agent_state, "update_state") as upd:
            controller._maybe_persist_inbound_key("agent-key", result)
        upd.assert_called_once_with("inbound_api_key", "inbound")

    def test_absent_field_is_noop(self):
        with patch.object(controller.agent_state, "update_state") as upd:
            controller._maybe_persist_inbound_key("agent-key", {})
        upd.assert_not_called()

    def test_undecryptable_value_ignored(self):
        result = {"inbound_api_key_encrypted": self._encrypt("other-key", "inbound")}
        with patch.object(controller.agent_state, "update_state") as upd:
            controller._maybe_persist_inbound_key("agent-key", result)
        upd.assert_not_called()
