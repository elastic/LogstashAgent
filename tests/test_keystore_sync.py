#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from logstashagent import main, agent_state
from logstashagent.ls_keystore_utils.keystore_write import (
    generate_default_keystore_password,
    write_keystore_secrets,
)


@pytest.fixture
def client(temp_dir, mock_dirs):
    return TestClient(main.app)


def test_keystore_sync_writes_when_different(client, temp_dir, mock_dirs):
    settings = temp_dir
    env_file = f"{temp_dir}/env"

    with patch.object(agent_state, "get_state", return_value={
        "settings_path": settings,
        "keystore_env_file": env_file,
        "mode": "simulate",
        "instance_id": 1,
        "logstash_unit": "ls-simulate@1",
    }), patch.object(agent_state, "update_state"), patch(
        "logstashagent.controller.restart_logstash", return_value=True
    ) as restart, patch(
        "logstashagent.controller.update_logstash_env_file"
    ) as env_update:
        resp = client.post(
            "/_logstash/keystore/sync",
            json={
                "secrets": {"ES_HOST": "https://es.example:9200"},
                "password": "s3cret-pass",
                "restart": True,
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success"
    assert body.get("unchanged") is False
    assert body["secrets_count"] == 1
    assert body["authenticated"] is True
    assert body["restarted"] is True
    assert (Path(settings) / "logstash.keystore").is_file()
    env_update.assert_called()
    restart.assert_called()


def test_keystore_sync_skips_when_unchanged(client, temp_dir, mock_dirs):
    settings = temp_dir
    password = "s3cret-pass"
    secrets = {"es_host": "https://es.example:9200"}
    ks_path = Path(settings) / "logstash.keystore"
    write_keystore_secrets(ks_path, password, secrets, embed_password=False)

    with patch.object(agent_state, "get_state", return_value={
        "settings_path": settings,
        "keystore_password": password,
        "mode": "simulate",
        "logstash_unit": "ls-simulate@1",
    }), patch.object(agent_state, "update_state"), patch(
        "logstashagent.controller.restart_logstash", return_value=True
    ) as restart:
        resp = client.post(
            "/_logstash/keystore/sync",
            json={
                "secrets": {"ES_HOST": "https://es.example:9200"},
                "password": password,
                "restart": True,
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["unchanged"] is True
    assert body["restarted"] is False
    restart.assert_not_called()


def test_keystore_get(client, temp_dir, mock_dirs):
    settings = temp_dir
    password = "s3cret-pass"
    write_keystore_secrets(
        Path(settings) / "logstash.keystore",
        password,
        {"token": "abc"},
        embed_password=False,
    )
    with patch.object(agent_state, "get_state", return_value={
        "settings_path": settings,
        "keystore_password": password,
    }):
        resp = client.get("/_logstash/keystore")
    assert resp.status_code == 200
    body = resp.json()
    assert body["exists"] is True
    assert body["secrets"].get("token") == "abc"


def test_keystore_sync_unauthenticated(client, temp_dir, mock_dirs):
    settings = temp_dir
    with patch.object(agent_state, "get_state", return_value={
        "settings_path": settings,
        "mode": "embedded",
    }), patch.object(agent_state, "update_state"), patch.object(
        main, "logstash_supervisor"
    ) as sup:
        sup.get_supervisor.return_value = MagicMock()
        resp = client.post(
            "/_logstash/keystore/sync",
            json={"secrets": {"K": "v"}, "password": None, "restart": False},
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["authenticated"] is False
    assert (Path(settings) / "logstash.keystore").is_file()
