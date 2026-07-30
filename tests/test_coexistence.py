#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Host coexistence: packaged + managed/simulate state/config isolation."""

from pathlib import Path
from unittest.mock import patch

import pytest

from logstashagent import agent_state, installer


def test_peek_mode_instance_from_argv():
    mode, inst = agent_state._peek_mode_and_instance_from_argv(
        ["--run", "--mode", "managed", "--instance", "3"]
    )
    assert mode == "managed"
    assert inst == 3
    mode, inst = agent_state._peek_mode_and_instance_from_argv(
        ["--mode=simulate", "--instance=2"]
    )
    assert mode == "simulate"
    assert inst == 2


def test_resolve_state_dir_from_env(tmp_path, monkeypatch):
    agent_state.configure_state_dir(None)
    monkeypatch.setenv("LOGSTASH_AGENT_STATE_DIR", str(tmp_path / "m1-state"))
    d = agent_state.resolve_state_dir([])
    assert d == tmp_path / "m1-state"
    monkeypatch.delenv("LOGSTASH_AGENT_STATE_DIR", raising=False)
    agent_state.configure_state_dir(None)


def test_resolve_state_dir_from_argv_managed(monkeypatch):
    agent_state.configure_state_dir(None)
    monkeypatch.delenv("LOGSTASH_AGENT_STATE_DIR", raising=False)
    d = agent_state.resolve_state_dir(["--mode", "managed", "--instance", "1"])
    assert d == Path("/opt/logstash-agent/managed-1/state")


def test_instance_state_and_config_paths():
    assert agent_state.instance_state_dir("managed", 2) == Path(
        "/opt/logstash-agent/managed-2/state"
    )
    assert agent_state.instance_config_path("simulate", 4) == Path(
        "/opt/logstash-agent/simulate-4/logstash-agent.yml"
    )


def test_relocate_state_to_isolates(tmp_path):
    agent_state.configure_state_dir(tmp_path / "packaged")
    (tmp_path / "packaged").mkdir()
    agent_state.update_state("api_key", "secret-key")
    agent_state.update_state("mode", "managed")
    src = agent_state.STATE_FILE
    assert src.is_file()

    dest = tmp_path / "managed-1" / "state"
    agent_state.relocate_state_to(dest, leave_source=True)
    assert (dest / "state.json").is_file()
    assert src.is_file()  # leave_source
    # Process now points at instance state
    assert agent_state.STATE_DIR == dest
    assert agent_state.get_state().get("mode") == "managed"
    agent_state.configure_state_dir(None)


def test_write_config_multi_does_not_use_etc(tmp_path, monkeypatch):
    root = tmp_path / "managed-1"
    root.mkdir()
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    with patch.object(installer, "get_logstash_uid_gid", side_effect=Exception("x")):
        path = installer.write_config_file(
            "https://ui.example",
            policy_config={
                "policy_type": "MANAGED",
                "instance_id": 1,
                "path_root": str(root),
                "settings_path": str(root / "settings"),
                "logs_path": str(root / "logs"),
                "binary_path": "/usr/share/logstash/bin",
                "agent_api_port": 9601,
                "logstash_api_port": 9701,
            },
        )
    assert path == str(root / "logstash-agent.yml")
    text = Path(path).read_text()
    assert "mode: managed" in text
    assert "instance_id: 1" in text
    # Must not have written packaged path
    assert not (tmp_path / "etc").exists()


def test_write_config_packaged_uses_etc(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "etc-agent"
    cfg_dir.mkdir()
    monkeypatch.setitem(installer.INSTALL_PATHS, "config_dir", str(cfg_dir))
    with patch.object(installer, "get_logstash_uid_gid", side_effect=Exception("x")), patch(
        "os.path.isdir", return_value=True
    ):
        path = installer.write_config_file(
            "https://ui.example",
            policy_config={"policy_type": "PACKAGED"},
        )
    assert path == str(cfg_dir / "logstash-agent.yml")
    assert "mode: packaged" in Path(path).read_text()


def test_materialize_agent_env_sets_isolation(tmp_path, monkeypatch):
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    root = tmp_path / "managed-1"
    with patch.object(installer, "get_logstash_uid_gid", side_effect=Exception("x")), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ):
        result = installer.materialize_simulate_instance(
            {
                "policy_type": "MANAGED",
                "instance_id": 1,
                "path_root": str(root),
                "settings_path": str(root / "settings"),
                "config_path": str(root / "config"),
                "logs_path": str(root / "logs"),
                "data_path": str(root / "data"),
                "keystore_env_file": str(root / "env"),
                "binary_path": "/usr/share/logstash/bin",
                "logstash_source": "SYSTEM",
                "agent_api_port": 9601,
                "logstash_api_port": 9701,
            }
        )
    env = Path(result["agent_env"]).read_text()
    assert "LOGSTASH_AGENT_STATE_DIR=" in env
    assert "managed-1/state" in env.replace("\\", "/")
    assert "LOGSTASH_AGENT_CONFIG=" in env
    assert "logstash-agent.yml" in env
