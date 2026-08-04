#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Offline E2E-style smoke for agent modes (no root / no systemd required).

Covers host coexistence isolation, multi-instance materialize, install registry,
and VERSION cache helpers used by Packaged / Managed / Simulate on one host.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from logstashagent import agent_state, installer
from logstashagent import install_registry as reg
from logstashagent import logstash_download as ld


@pytest.fixture
def host_tree(tmp_path, monkeypatch):
    """Isolated faux /opt + /var/lib layout for multi-role smoke."""
    opt = tmp_path / "opt" / "logstash-agent"
    var = tmp_path / "var" / "lib" / "logstash-agent"
    etc = tmp_path / "etc" / "logstash-agent"
    opt.mkdir(parents=True)
    var.mkdir(parents=True)
    etc.mkdir(parents=True)
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(opt))
    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(var))
    monkeypatch.setitem(installer.INSTALL_PATHS, "config_dir", str(etc))
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary_dir", str(opt / "bin"))
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(opt / "bin" / "logstash-agent"))
    monkeypatch.setitem(installer.INSTALL_PATHS, "cache_dir", str(tmp_path / "cache"))
    agent_state.configure_state_dir(var)
    yield {"opt": opt, "var": var, "etc": etc}
    agent_state.configure_state_dir(None)


def test_smoke_packaged_and_managed_configs_do_not_collide(host_tree):
    """Packaged /etc config and managed-N config are separate files."""
    with patch.object(installer, "get_logstash_uid_gid", side_effect=Exception("x")), patch(
        "os.path.isdir", return_value=True
    ):
        packaged = installer.write_config_file(
            "https://ui.example",
            policy_config={"policy_type": "PACKAGED"},
        )
        managed_root = host_tree["opt"] / "managed-1"
        managed_root.mkdir(parents=True)
        managed = installer.write_config_file(
            "https://ui.example",
            policy_config={
                "policy_type": "MANAGED",
                "instance_id": 1,
                "path_root": str(managed_root),
                "settings_path": str(managed_root / "settings"),
                "logs_path": str(managed_root / "logs"),
                "binary_path": "/usr/share/logstash/bin",
                "agent_api_port": 9601,
                "logstash_api_port": 9701,
            },
        )
    assert packaged == str(host_tree["etc"] / "logstash-agent.yml")
    assert managed == str(managed_root / "logstash-agent.yml")
    assert "mode: packaged" in Path(packaged).read_text()
    assert "mode: managed" in Path(managed).read_text()
    # Packaged file still packaged after managed write
    assert "mode: packaged" in Path(packaged).read_text()


def test_smoke_registry_tracks_packaged_and_multi(host_tree):
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_package(agent_version="0.5.1", agent_id="pack-1", state_dir=str(host_tree["var"]))
        reg.register_instance(
            role="packaged",
            agent_unit="logstash-agent",
            logstash_unit="logstash",
            state_dir=str(host_tree["var"]),
            agent_id="pack-1",
            policy_type="PACKAGED",
        )
        reg.register_instance(
            role="managed",
            instance_id=1,
            agent_unit="logstash-agent@1",
            logstash_unit="logstash-managed@1",
            path_root=str(host_tree["opt"] / "managed-1"),
            agent_api_port=9601,
            logstash_api_port=9701,
            policy_type="MANAGED",
            agent_id="man-1",
            state_dir=str(host_tree["var"]),
        )
        reg.register_instance(
            role="simulate",
            instance_id=1,
            agent_unit="lsagent-simulate@1",
            logstash_unit="ls-simulate@1",
            path_root=str(host_tree["opt"] / "simulate-1"),
            agent_api_port=9501,
            logstash_api_port=9561,
            policy_type="SIMULATE",
            agent_id="sim-1",
            state_dir=str(host_tree["var"]),
        )
    instances = reg.list_instances(str(host_tree["var"]), include_discovered=False)
    ids = {i["id"] for i in instances}
    assert ids == {"packaged", "managed-1", "simulate-1"}
    table = reg.format_instances_table(instances)
    assert "logstash-agent@1" in table
    assert "lsagent-simulate@1" in table
    data = json.loads(reg.registry_path(str(host_tree["var"])).read_text())
    assert data["package"]["agent_version"] == "0.5.1"


def test_smoke_materialize_managed_and_simulate_isolated(host_tree):
    with patch.object(installer, "get_logstash_uid_gid", side_effect=Exception("x")), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ):
        m = installer.materialize_simulate_instance(
            {
                "policy_type": "MANAGED",
                "instance_id": 1,
                "path_root": str(host_tree["opt"] / "managed-1"),
                "settings_path": str(host_tree["opt"] / "managed-1" / "settings"),
                "config_path": str(host_tree["opt"] / "managed-1" / "config"),
                "logs_path": str(host_tree["opt"] / "managed-1" / "logs"),
                "data_path": str(host_tree["opt"] / "managed-1" / "data"),
                "keystore_env_file": str(host_tree["opt"] / "managed-1" / "env"),
                "binary_path": "/usr/share/logstash/bin",
                "logstash_source": "SYSTEM",
                "agent_api_port": 9601,
                "logstash_api_port": 9701,
            }
        )
        s = installer.materialize_simulate_instance(
            {
                "policy_type": "SIMULATE",
                "instance_id": 1,
                "path_root": str(host_tree["opt"] / "simulate-1"),
                "settings_path": str(host_tree["opt"] / "simulate-1" / "settings"),
                "config_path": str(host_tree["opt"] / "simulate-1" / "config"),
                "logs_path": str(host_tree["opt"] / "simulate-1" / "logs"),
                "data_path": str(host_tree["opt"] / "simulate-1" / "data"),
                "keystore_env_file": str(host_tree["opt"] / "simulate-1" / "env"),
                "binary_path": "/usr/share/logstash/bin",
                "logstash_source": "SYSTEM",
                "agent_api_port": 9501,
                "logstash_api_port": 9561,
            }
        )
    assert m["mode"] == "managed"
    assert s["mode"] == "simulate"
    assert m["agent_unit"] == "logstash-agent@1"
    assert s["agent_unit"] == "lsagent-simulate@1"
    # Isolation env vars for coexistence
    m_env = Path(m["agent_env"]).read_text()
    assert "LOGSTASH_AGENT_STATE_DIR=" in m_env
    assert "managed-1/state" in m_env.replace("\\", "/")
    assert (host_tree["opt"] / "managed-1" / "settings").is_dir()
    assert (host_tree["opt"] / "simulate-1" / "settings").is_dir()
    # Distinct trees
    assert (host_tree["opt"] / "managed-1").resolve() != (host_tree["opt"] / "simulate-1").resolve()


def test_smoke_version_cache_list_and_prune(host_tree):
    root = host_tree["opt"] / "logstash-versions"
    for ver in ("9.4.3", "8.19.0"):
        b = root / f"logstash-{ver}" / "bin" / "logstash"
        b.parent.mkdir(parents=True)
        b.write_text("#!/bin/sh\n", encoding="utf-8")
        b.chmod(0o755)
    found = ld.list_installed_versions(str(root))
    assert {v["version"] for v in found} == {"9.4.3", "8.19.0"}
    with patch.object(ld, "collect_in_use_versions", return_value={"9.4.3"}):
        result = ld.prune_versions(str(root), keep=set(), keep_used=True, dry_run=False)
    assert "8.19.0" in result["removed"]
    assert "9.4.3" in result["kept"]
    assert (root / "logstash-9.4.3").is_dir()
    assert not (root / "logstash-8.19.0").exists()


def test_smoke_state_relocate_preserves_packaged(host_tree):
    """Multi enroll must not permanently overwrite packaged state when protected."""
    packaged = host_tree["var"]
    agent_state.configure_state_dir(packaged)
    agent_state.update_state("agent_id", "packaged-agent-id")
    agent_state.update_state("mode", "packaged")
    backup = (packaged / "state.json").read_bytes()

    # Simulate multi enroll writing into same dir then relocate
    agent_state.update_state("agent_id", "managed-agent-id")
    agent_state.update_state("mode", "managed")
    inst = host_tree["opt"] / "managed-1" / "state"
    agent_state.relocate_state_to(inst, leave_source=True)
    # Restore packaged backup (install does this when has_packaged)
    (packaged / "state.json").write_bytes(backup)

    agent_state.configure_state_dir(packaged)
    assert agent_state.get_state().get("agent_id") == "packaged-agent-id"
    agent_state.configure_state_dir(inst)
    assert agent_state.get_state().get("agent_id") == "managed-agent-id"
    agent_state.configure_state_dir(None)


def test_smoke_unit_templates_shipped():
    d = installer._systemd_template_dir()
    for name in (
        "logstash-agent@.service",
        "logstash-managed@.service",
        "lsagent-simulate@.service",
        "ls-simulate@.service",
    ):
        assert (d / name).is_file(), name
    agent_unit = (d / "logstash-agent@.service").read_text()
    assert "LOGSTASH_AGENT_STATE_DIR" in agent_unit or "managed-%i" in agent_unit
    assert "--mode managed" in agent_unit
