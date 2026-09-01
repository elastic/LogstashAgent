#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for host install registry."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from logstashagent import install_registry as reg


@pytest.fixture
def reg_dir(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setitem(
        __import__("logstashagent.installer", fromlist=["INSTALL_PATHS"]).INSTALL_PATHS,
        "state_dir",
        str(state),
    )
    # Avoid chown noise
    monkeypatch.setattr(reg, "save_registry", reg.save_registry)
    with patch("logstashagent.install_registry.get_logstash_uid_gid", create=True):
        pass
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("no user")):
        yield state


def test_instance_key():
    assert reg.instance_key("packaged") == "packaged"
    assert reg.instance_key("default") == "packaged"
    assert reg.instance_key("managed", 3) == "managed-3"
    assert reg.instance_key("simulate", 1) == "simulate-1"
    with pytest.raises(ValueError):
        reg.instance_key("managed")


def test_register_package_and_instance(reg_dir):
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_package(agent_version="0.5.1", agent_id="aid", state_dir=str(reg_dir))
        reg.register_instance(
            role="managed",
            instance_id=1,
            agent_unit="logstash-agent@1",
            logstash_unit="logstash-managed@1",
            path_root="/opt/logstash-agent/managed-1",
            agent_api_port=9601,
            logstash_api_port=9701,
            policy_type="MANAGED",
            agent_id="aid",
            state_dir=str(reg_dir),
        )
    path = reg.registry_path(str(reg_dir))
    assert path.is_file()
    data = json.loads(path.read_text())
    assert data["package"]["agent_version"] == "0.5.1"
    assert "managed-1" in data["instances"]
    assert data["instances"]["managed-1"]["agent_unit"] == "logstash-agent@1"

    instances = reg.list_instances(str(reg_dir), include_discovered=False)
    assert any(i["id"] == "managed-1" for i in instances)


def test_unregister_instance(reg_dir):
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_instance(
            role="simulate",
            instance_id=2,
            agent_unit="lsagent-simulate@2",
            logstash_unit="ls-simulate@2",
            path_root="/opt/logstash-agent/simulate-2",
            state_dir=str(reg_dir),
        )
        assert reg.unregister_instance("simulate-2", state_dir=str(reg_dir)) is True
        assert reg.unregister_instance("simulate-2", state_dir=str(reg_dir)) is False
    data = reg.load_registry(str(reg_dir))
    assert "simulate-2" not in data["instances"]


def test_discover_instances_from_disk(tmp_path):
    (tmp_path / "managed-1").mkdir()
    (tmp_path / "simulate-2").mkdir()
    (tmp_path / "logstash-versions").mkdir()
    (tmp_path / "bin").mkdir()
    found = reg.discover_instances_from_disk(str(tmp_path))
    ids = {f["id"] for f in found}
    assert ids == {"managed-1", "simulate-2"}
    m = next(f for f in found if f["id"] == "managed-1")
    assert m["agent_unit"] == "logstash-agent@1"
    assert m["logstash_unit"] == "logstash-managed@1"


def test_remove_path_tree_safety(tmp_path):
    # Refuse non-instance path
    bad = tmp_path / "logstash-agent" / "bin"
    bad.mkdir(parents=True)
    assert reg.remove_path_tree(str(bad)) is False

    good = tmp_path / "logstash-agent" / "managed-1"
    good.mkdir(parents=True)
    (good / "settings").mkdir()
    # path must resolve with logstash-agent in parts and managed-N name
    assert reg.remove_path_tree(str(good)) is True
    assert not good.exists()


def test_format_instances_table_empty():
    assert "no registered" in reg.format_instances_table([])


def test_teardown_instance_stops_units(reg_dir, monkeypatch):
    calls = []

    def fake_stop(unit):
        calls.append(unit)

    monkeypatch.setattr(reg, "stop_disable_unit", fake_stop)
    entry = {
        "id": "managed-1",
        "role": "managed",
        "agent_unit": "logstash-agent@1",
        "logstash_unit": "logstash-managed@1",
        "path_root": None,
    }
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_instance(
            role="managed",
            instance_id=1,
            agent_unit="logstash-agent@1",
            logstash_unit="logstash-managed@1",
            state_dir=str(reg_dir),
        )
        reg.teardown_instance(entry, purge_paths=False, state_dir=str(reg_dir), unregister=True)
    assert "logstash-agent@1" in calls
    assert "logstash-managed@1" in calls
    assert "managed-1" not in reg.load_registry(str(reg_dir))["instances"]


def test_perform_uninstall_instance_only(reg_dir, monkeypatch, tmp_path):
    from logstashagent import installer

    tree = tmp_path / "logstash-agent" / "managed-1"
    tree.mkdir(parents=True)
    (tree / "settings").mkdir()

    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(reg_dir))
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_instance(
            role="managed",
            instance_id=1,
            agent_unit="logstash-agent@1",
            logstash_unit="logstash-managed@1",
            path_root=str(tree),
            state_dir=str(reg_dir),
        )

    stopped = []
    monkeypatch.setattr(reg, "stop_disable_unit", lambda u: stopped.append(u))
    with patch.object(installer, "verify_root"), patch.object(
        installer, "verify_platform"
    ), patch.object(installer.subprocess, "run"):
        # Default instance uninstall deletes the path tree
        installer.perform_uninstallation(purge=False, instance="managed-1")

    assert "logstash-agent@1" in stopped
    assert "managed-1" not in reg.load_registry(str(reg_dir))["instances"]
    assert not tree.exists()


def test_perform_uninstall_instance_keep_data(reg_dir, monkeypatch, tmp_path):
    from logstashagent import installer

    tree = tmp_path / "logstash-agent" / "simulate-3"
    tree.mkdir(parents=True)

    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(reg_dir))
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_instance(
            role="simulate",
            instance_id=3,
            agent_unit="lsagent-simulate@3",
            logstash_unit="ls-simulate@3",
            path_root=str(tree),
            state_dir=str(reg_dir),
        )

    stopped = []
    monkeypatch.setattr(reg, "stop_disable_unit", lambda u: stopped.append(u))
    with patch.object(installer, "verify_root"), patch.object(
        installer, "verify_platform"
    ), patch.object(installer.subprocess, "run"):
        installer.perform_uninstallation(
            purge=False, instance="simulate-3", keep_data=True
        )

    assert "lsagent-simulate@3" in stopped
    assert "simulate-3" not in reg.load_registry(str(reg_dir))["instances"]
    assert tree.exists()
