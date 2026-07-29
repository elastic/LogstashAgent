#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from logstashagent import installer


SIM_POLICY = {
    "policy_type": "SIMULATE",
    "instance_id": 1,
    "settings_path": None,  # filled in test with tmp
    "config_path": None,
    "logs_path": None,
    "data_path": None,
    "keystore_env_file": None,
    "binary_path": "/usr/share/logstash/bin",
    "logstash_source": "SYSTEM",
    "logstash_version": "",
    "logstash_download_dir": "",
    "agent_api_port": 9501,
    "logstash_api_port": 9561,
    "logstash_yml": "api.http.port: 9561\n",
    "jvm_options": "-Xms1g\n-Xmx1g\n",
    "log4j2_properties": "status=error\n",
}


def test_write_config_default_mode(tmp_path):
    with patch.dict(installer.INSTALL_PATHS, {"config_dir": str(tmp_path)}), patch.object(
        installer, "get_logstash_uid_gid", return_value=(0, 0)
    ), patch.object(installer.os, "chown"), patch.object(installer.os, "chmod"):
        installer.write_config_file("http://ui.example")
    content = (tmp_path / "logstash-agent.yml").read_text()
    assert "mode: default" in content
    assert "mode: agent" not in content


def test_write_config_simulate_mode(tmp_path):
    with patch.dict(installer.INSTALL_PATHS, {"config_dir": str(tmp_path)}), patch.object(
        installer, "get_logstash_uid_gid", return_value=(0, 0)
    ), patch.object(installer.os, "chown"), patch.object(installer.os, "chmod"):
        installer.write_config_file(
            "http://ui.example",
            policy_config={
                "policy_type": "SIMULATE",
                "instance_id": 2,
                "settings_path": "/opt/LogstashAgent/simulate-2/settings",
                "logs_path": "/opt/LogstashAgent/simulate-2/logs",
                "binary_path": "/usr/share/logstash/bin",
                "agent_api_port": 9502,
                "logstash_api_port": 9562,
                "logstash_source": "VERSION",
                "logstash_version": "9.4.3",
            },
        )
    content = (tmp_path / "logstash-agent.yml").read_text()
    assert "mode: simulate" in content
    assert "instance_id: 2" in content
    assert "port: 9502" in content
    assert "logstash_api_port: 9562" in content


def test_materialize_simulate_instance(tmp_path):
    root = tmp_path / "LogstashAgent"
    policy = dict(SIM_POLICY)
    policy["settings_path"] = str(tmp_path / "simulate-1" / "settings")
    policy["config_path"] = str(tmp_path / "simulate-1" / "config")
    policy["logs_path"] = str(tmp_path / "simulate-1" / "logs")
    policy["data_path"] = str(tmp_path / "simulate-1" / "data")
    policy["keystore_env_file"] = str(tmp_path / "simulate-1" / "env")

    with patch.dict(
        installer.INSTALL_PATHS, {"simulate_root": str(tmp_path)}
    ), patch.object(
        installer, "get_logstash_uid_gid", return_value=(os.getuid(), os.getgid())
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ):
        result = installer.materialize_simulate_instance(policy)

    assert result["instance_id"] == 1
    assert Path(policy["settings_path"]).is_dir()
    assert (Path(policy["settings_path"]) / "logstash.yml").read_text().startswith(
        "api.http.port: 9561"
    )
    env = Path(policy["keystore_env_file"]).read_text()
    assert "LOGSTASH_BINARY=/usr/share/logstash/bin/logstash" in env
    assert "LOGSTASH_PATH_SETTINGS=" in env
    agent_env = Path(result["agent_env"]).read_text()
    assert "AGENT_API_PORT=9501" in agent_env
    assert "INSTANCE_ID=1" in agent_env


def test_sudoers_includes_simulate_units():
    # configure_logstash writes sudoers — extract content via building the string
    # by calling the inner portion; use a partial mock.
    written = {}

    def fake_open(path, mode="r", *a, **k):
        if path == "/etc/sudoers.d/logstash-agent" and "w" in mode:
            from io import StringIO

            buf = StringIO()
            # capture on close
            original_close = buf.close

            def close():
                written["content"] = buf.getvalue()
                original_close()

            buf.close = close
            return buf
        raise FileNotFoundError(path)

    with patch.object(installer, "get_logstash_uid_gid", return_value=(0, 0)), patch.object(
        installer, "is_sudo_rs", return_value=True
    ), patch("builtins.open", side_effect=fake_open), patch.object(
        installer.os, "chmod"
    ), patch.object(installer.os.path, "exists", return_value=False), patch.object(
        installer.subprocess, "run", return_value=MagicMock(returncode=0, stderr=b"")
    ):
        # Only exercise sudoers writing path — walk empty dirs
        installer.configure_logstash()

    assert "content" in written
    assert "ls-simulate@*" in written["content"]
    assert "lsagent-simulate@*" in written["content"]
