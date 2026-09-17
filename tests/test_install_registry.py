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
            agent_unit="managed-agent@1",
            logstash_unit="managed-logstash@1",
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
    assert data["instances"]["managed-1"]["agent_unit"] == "managed-agent@1"

    instances = reg.list_instances(str(reg_dir), include_discovered=False)
    assert any(i["id"] == "managed-1" for i in instances)


def test_unregister_instance(reg_dir):
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_instance(
            role="simulate",
            instance_id=2,
            agent_unit="simulate-agent@2",
            logstash_unit="simulate-logstash@2",
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
    # acceptance A2: discovery returns canonical names
    assert m["agent_unit"] == "managed-agent@1"
    assert m["logstash_unit"] == "managed-logstash@1"


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
        "agent_unit": "managed-agent@1",
        "logstash_unit": "managed-logstash@1",
        "path_root": None,
    }
    with patch("logstashagent.installer.get_logstash_uid_gid", side_effect=Exception("x")):
        reg.register_instance(
            role="managed",
            instance_id=1,
            agent_unit="managed-agent@1",
            logstash_unit="managed-logstash@1",
            state_dir=str(reg_dir),
        )
        reg.teardown_instance(entry, purge_paths=False, state_dir=str(reg_dir), unregister=True)
    assert "managed-agent@1" in calls
    assert "managed-logstash@1" in calls
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
            agent_unit="managed-agent@1",
            logstash_unit="managed-logstash@1",
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

    assert "managed-agent@1" in stopped
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
            agent_unit="simulate-agent@3",
            logstash_unit="simulate-logstash@3",
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

    assert "simulate-agent@3" in stopped
    assert "simulate-3" not in reg.load_registry(str(reg_dir))["instances"]
    assert tree.exists()


# ---------- S1 upgrade tests ----------

def _write_legacy_registry(state_dir: Path, instance_id: int = 2) -> None:
    """Write a registry JSON with old-style unit names (pre-rename)."""
    import json
    reg_file = state_dir / "install-registry.json"
    reg_file.write_text(json.dumps({
        "package": {},
        "instances": {
            f"managed-{instance_id}": {
                "id": f"managed-{instance_id}",
                "role": "managed",
                "instance_id": instance_id,
                "agent_unit": f"logstash-agent@{instance_id}",
                "logstash_unit": f"logstash-managed@{instance_id}",
            },
            f"simulate-{instance_id}": {
                "id": f"simulate-{instance_id}",
                "role": "simulate",
                "instance_id": instance_id,
                "agent_unit": f"lsagent-simulate@{instance_id}",
                "logstash_unit": f"ls-simulate@{instance_id}",
            },
        },
    }))


def test_list_instances_rewrites_legacy_unit_names(tmp_path):
    """acceptance A1: list_instances() returns canonical names from stale registry."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    _write_legacy_registry(state_dir, instance_id=2)

    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]):
        instances = reg.list_instances(str(state_dir), include_discovered=False)

    by_id = {e["id"]: e for e in instances}
    assert by_id["managed-2"]["agent_unit"] == "managed-agent@2", by_id["managed-2"]
    assert by_id["managed-2"]["logstash_unit"] == "managed-logstash@2", by_id["managed-2"]
    assert by_id["simulate-2"]["agent_unit"] == "simulate-agent@2", by_id["simulate-2"]
    assert by_id["simulate-2"]["logstash_unit"] == "simulate-logstash@2", by_id["simulate-2"]


def test_registry_persists_canonical_unit_names(tmp_path):
    """acceptance A2: canonical names written back to JSON after rewrite."""
    import json
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    _write_legacy_registry(state_dir, instance_id=3)

    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]):
        reg.list_instances(str(state_dir), include_discovered=False)

    data = json.loads((state_dir / "install-registry.json").read_text())
    assert data["instances"]["managed-3"]["agent_unit"] == "managed-agent@3"
    assert data["instances"]["managed-3"]["logstash_unit"] == "managed-logstash@3"
    assert data["instances"]["simulate-3"]["agent_unit"] == "simulate-agent@3"
    assert data["instances"]["simulate-3"]["logstash_unit"] == "simulate-logstash@3"


def test_migrate_canonical_registry_noop(tmp_path):
    """acceptance A5: already-canonical entries are left untouched (idempotent)."""
    import json
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    # Write canonical registry from the start.
    reg_file = state_dir / "install-registry.json"
    reg_file.write_text(json.dumps({
        "package": {},
        "instances": {
            "managed-1": {
                "id": "managed-1",
                "role": "managed",
                "instance_id": 1,
                "agent_unit": "managed-agent@1",
                "logstash_unit": "managed-logstash@1",
            },
        },
    }))

    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]):
        instances1 = reg.list_instances(str(state_dir), include_discovered=False)
        instances2 = reg.list_instances(str(state_dir), include_discovered=False)

    assert instances1[0]["agent_unit"] == "managed-agent@1"
    assert instances2[0]["agent_unit"] == "managed-agent@1"

    # Bare logstash-agent (no @) must not be rewritten.
    reg_file.write_text(json.dumps({
        "package": {},
        "instances": {
            "packaged": {
                "id": "packaged",
                "role": "packaged",
                "agent_unit": "logstash-agent",
                "logstash_unit": "logstash",
            },
        },
    }))
    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]):
        packed = reg.list_instances(str(state_dir), include_discovered=False)
    assert packed[0]["agent_unit"] == "logstash-agent", "bare packaged unit was rewritten"


# ---------- S2 upgrade tests ----------

def _legacy_reg_json(state_dir: Path, instance_id: int = 2) -> None:
    """Write a registry with old-style unit names for the given instance_id."""
    import json
    reg_file = state_dir / "install-registry.json"
    reg_file.write_text(json.dumps({
        "package": {},
        "instances": {
            f"managed-{instance_id}": {
                "id": f"managed-{instance_id}",
                "role": "managed",
                "instance_id": instance_id,
                "agent_unit": f"logstash-agent@{instance_id}",
                "logstash_unit": f"logstash-managed@{instance_id}",
            },
        },
    }))


def test_migrate_enables_canonical_units(tmp_path, monkeypatch):
    """acceptance A3: migrate_legacy_systemd_units enables canonical units with systemctl."""
    from logstashagent import installer

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    _legacy_reg_json(state_dir, instance_id=2)

    # Track systemctl calls.
    systemctl_calls = []

    def fake_systemctl_cmd(*args, check=False):
        systemctl_calls.append(list(args))
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr(installer, "_systemctl_cmd", fake_systemctl_cmd)
    monkeypatch.setattr(installer, "_systemctl_bin", lambda: "/usr/bin/systemctl")

    # Suppress the print-path systemctl list-units (subprocess.run) and redirect to fake.
    monkeypatch.setattr(installer.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": ""})())

    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]):
        installer.migrate_legacy_systemd_units(state_dir=str(state_dir))

    # Must have called enable --now for managed-agent@2 AND managed-logstash@2.
    enable_units = [args[-1] for args in systemctl_calls if args and args[0] == "enable"]
    assert "managed-agent@2" in enable_units, f"enable calls: {systemctl_calls}"
    assert "managed-logstash@2" in enable_units, f"enable calls: {systemctl_calls}"

    # Must NOT enable bare packaged unit.
    assert "logstash-agent" not in enable_units
    assert "logstash" not in enable_units


def test_install_templates_invokes_unit_migrate(tmp_path, monkeypatch):
    """acceptance A4a: install_multi_instance_unit_templates calls migrate_legacy_systemd_units."""
    from logstashagent import installer

    # Stub template install mechanics so we don't need actual service files.
    monkeypatch.setattr(installer, "_read_unit_template", lambda n: f"[Unit]\nDescription={n}\n")

    dests = {
        "lsagent_simulate_unit": str(tmp_path / "simulate-agent@.service"),
        "ls_simulate_unit": str(tmp_path / "simulate-logstash@.service"),
        "logstash_agent_template_unit": str(tmp_path / "managed-agent@.service"),
        "logstash_managed_unit": str(tmp_path / "managed-logstash@.service"),
    }
    for k, v in dests.items():
        monkeypatch.setitem(installer.INSTALL_PATHS, k, v)

    migrate_calls = []
    monkeypatch.setattr(installer, "migrate_legacy_systemd_units", lambda **kw: migrate_calls.append(kw))

    with patch.object(installer.subprocess, "run", return_value=type("R", (), {"returncode": 0})()) as _run:
        installer.install_multi_instance_unit_templates()

    assert migrate_calls, "install_multi_instance_unit_templates did not call migrate_legacy_systemd_units"


def test_list_instances_invokes_unit_migrate(tmp_path, monkeypatch):
    """acceptance A4b: list_instances invokes migrate when it rewrites stale unit names."""
    from logstashagent import installer

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    _legacy_reg_json(state_dir, instance_id=5)

    migrate_calls = []
    monkeypatch.setattr(installer, "migrate_legacy_systemd_units", lambda **kw: migrate_calls.append(kw))

    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]):
        reg.list_instances(str(state_dir), include_discovered=False)

    assert migrate_calls, "list_instances did not invoke migrate_legacy_systemd_units after rewriting stale units"

    # Second call (already canonical): migrate must NOT be called again.
    migrate_calls.clear()
    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]):
        reg.list_instances(str(state_dir), include_discovered=False)

    assert not migrate_calls, "list_instances called migrate unnecessarily on already-canonical entries"


def test_rewrite_legacy_unit_logs_on_import_error(caplog, monkeypatch):
    """acceptance A1/A4/D1: ImportError from import is caught, logged, returns unchanged."""
    import types, sys, logging
    from logstashagent import install_registry

    # Replace installer in sys.modules with a stub that lacks _canonical_for_old_instance.
    # 'from logstashagent.installer import _canonical_for_old_instance' then raises ImportError.
    dummy = types.ModuleType("logstashagent.installer")
    monkeypatch.setitem(sys.modules, "logstashagent.installer", dummy)

    with caplog.at_level(logging.WARNING, logger="logstashagent.install_registry"):
        result = install_registry._rewrite_legacy_unit("logstash-managed@1")

    assert result == "logstash-managed@1"
    assert any("_rewrite_legacy_unit" in r.message for r in caplog.records), caplog.records


def test_rewrite_legacy_unit_propagates_non_import_error(monkeypatch):
    """acceptance A1: non-ImportError from mapping call propagates (not swallowed)."""
    import types, sys, pytest
    from logstashagent import install_registry

    def boom(unit):
        raise RuntimeError("mapping logic error")

    # Replace installer with a stub whose mapping function raises RuntimeError.
    # The except ImportError clause must NOT catch this.
    dummy = types.ModuleType("logstashagent.installer")
    dummy._canonical_for_old_instance = boom
    monkeypatch.setitem(sys.modules, "logstashagent.installer", dummy)

    with pytest.raises(RuntimeError, match="mapping logic error"):
        install_registry._rewrite_legacy_unit("logstash-managed@1")


def test_list_instances_migrate_failure_is_logged(tmp_path, caplog, monkeypatch):
    """acceptance A4/D2: list_instances logs (not silently ignores) migrate failure."""
    import json, logging
    from logstashagent import install_registry as reg_mod

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    # Write stale registry to trigger dirty path.
    (state_dir / "install-registry.json").write_text(json.dumps({
        "package": {},
        "instances": {
            "managed-1": {
                "id": "managed-1",
                "role": "managed",
                "instance_id": 1,
                "agent_unit": "logstash-agent@1",
                "logstash_unit": "logstash-managed@1",
            },
        },
    }))

    def bad_migrate(**kw):
        raise RuntimeError("migrate exploded")

    # Patch the name inside install_registry's import namespace.
    with patch("logstashagent.install_registry.discover_instances_from_disk", return_value=[]), \
         patch("logstashagent.installer.migrate_legacy_systemd_units", side_effect=bad_migrate):
        with caplog.at_level(logging.WARNING, logger="logstashagent.install_registry"):
            result = reg_mod.list_instances(str(state_dir), include_discovered=False)

    # The call must not raise; registry rewrite still applied.
    assert result[0]["agent_unit"] == "managed-agent@1"
    # And must have logged a warning about the migrate failure.
    assert any("migrate" in r.message.lower() for r in caplog.records), caplog.records
