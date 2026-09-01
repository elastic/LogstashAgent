#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from logstashagent import controller, agent_state


def test_apply_logstash_runtime_version_downloads_and_updates_env(tmp_path):
    env_file = tmp_path / "env"
    env_file.write_text("LOGSTASH_BINARY=/old/bin/logstash\nOTHER=1\n", encoding="utf-8")
    binary = tmp_path / "logstash-9.4.3" / "bin" / "logstash"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    with patch.object(agent_state, "get_state", return_value={
        "mode": "simulate",
        "keystore_env_file": str(env_file),
        "logstash_binary": "/old/bin/logstash",
        "binary_path": "/old/bin",
    }), patch.object(agent_state, "update_state") as upd, patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(binary),
    ) as resolve, patch(
        "logstashagent.install_registry.register_logstash_version",
        return_value={},
    ):
        result = controller.apply_logstash_runtime({
            "source": "VERSION",
            "version": "9.4.3",
            "download_dir": str(tmp_path / "versions"),
            "binary_path": "/usr/share/logstash/bin",
        })

    assert result["success"] is True
    assert result["requires_restart"] is True
    assert result["binary"] == str(binary)
    resolve.assert_called_once()
    assert f"LOGSTASH_BINARY={binary}" in env_file.read_text()
    assert "OTHER=1" in env_file.read_text()
    keys = [c[0][0] for c in upd.call_args_list]
    assert "logstash_source" in keys
    assert "logstash_version" in keys
    assert "logstash_binary" in keys


def test_apply_logstash_runtime_managed_updates_env(tmp_path):
    env_file = tmp_path / "managed-1" / "env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("LOGSTASH_BINARY=/old\n", encoding="utf-8")
    binary = tmp_path / "bin" / "logstash"
    binary.parent.mkdir(parents=True)
    binary.write_text("x", encoding="utf-8")

    state = {
        "mode": "managed",
        "instance_id": 1,
        "keystore_env_file": str(env_file),
        "logstash_binary": "/old",
        "logstash_source": "SYSTEM",
        "agent_id": "a1",
    }
    with patch.object(agent_state, "get_state", return_value=state), patch.object(
        agent_state, "update_state"
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(binary),
    ), patch(
        "logstashagent.install_registry.register_logstash_version",
        return_value={},
    ), patch(
        "logstashagent.install_registry.load_registry",
        return_value={"instances": {}},
    ):
        result = controller.apply_logstash_runtime({
            "source": "VERSION",
            "version": "8.19.0",
            "download_dir": str(tmp_path / "versions"),
            "binary_path": "/usr/share/logstash/bin",
        })
    assert result["success"] is True
    assert f"LOGSTASH_BINARY={binary}" in env_file.read_text()


def test_apply_logstash_runtime_system_no_download():
    with patch.object(agent_state, "get_state", return_value={
        "mode": "default",
        "logstash_binary": "/usr/share/logstash/bin/logstash",
        "binary_path": "/usr/share/logstash/bin",
    }), patch.object(agent_state, "update_state"), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ) as resolve:
        result = controller.apply_logstash_runtime({
            "source": "SYSTEM",
            "version": "",
            "download_dir": "",
            "binary_path": "/usr/share/logstash/bin",
        })
    assert result["success"] is True
    assert result["requires_restart"] is False  # same binary
    resolve.assert_called_once()


def test_apply_logstash_runtime_download_failure():
    from logstashagent.logstash_download import LogstashDownloadError

    with patch.object(agent_state, "get_state", return_value={"mode": "simulate"}), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        side_effect=LogstashDownloadError("network down"),
    ):
        result = controller.apply_logstash_runtime({
            "source": "VERSION",
            "version": "9.4.3",
            "download_dir": "/opt/logstash-agent/logstash-versions",
            "binary_path": "/usr/share/logstash/bin",
        })
    assert result["success"] is False
    assert "network down" in (result.get("error") or "")


def test_update_env_logstash_binary(tmp_path):
    env = tmp_path / "env"
    env.write_text("FOO=bar\nLOGSTASH_BINARY=/old\n", encoding="utf-8")
    assert controller.update_env_logstash_binary(str(env), "/new/bin/logstash")
    text = env.read_text()
    assert "LOGSTASH_BINARY=/new/bin/logstash" in text
    assert "FOO=bar" in text
    assert text.count("LOGSTASH_BINARY=") == 1
