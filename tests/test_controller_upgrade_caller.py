#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Controller upgrade caller record (acceptance #2)."""

import logging
import os
import sys
from unittest.mock import MagicMock

import pytest

from logstashagent import controller, installer
from logstashagent import install_registry

_VERSION = "9.9.9"
_INSTALLED = "/opt/logstash-agent/bin/logstash-agent"
_SPAWN_ARGV = [
    "sudo",
    _INSTALLED,
    "upgrade",
    "--version",
    _VERSION,
    "--yes",
    "--_self-upgrade",
]


def _caller_bytes(key):
    return ('{"instance_key":"%s"}\n' % key).encode()


def _stage(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / "logstash-agent"
    binary.write_bytes(b"old-binary")
    (bin_dir / "_internal").mkdir()
    (bin_dir / "_internal" / "dep").write_text("old")
    state = tmp_path / "state"
    state.mkdir()
    packaged = tmp_path / "logstash-agent.service"
    simulate = tmp_path / "simulate-agent@.service"
    managed = tmp_path / "managed-agent@.service"
    for unit in (packaged, simulate, managed):
        unit.write_text("[Unit]\n")
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    new_bin = new_dir / "logstash-agent"
    new_bin.write_bytes(b"new-binary")
    (tmp_path / "work").mkdir()
    calls = []

    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(binary))
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary_dir", str(bin_dir))
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemd_service", str(packaged))
    monkeypatch.setitem(installer.INSTALL_PATHS, "cache_dir", str(tmp_path / "cache"))
    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(state))
    monkeypatch.setitem(installer.INSTALL_PATHS, "lsagent_simulate_unit", str(simulate))
    monkeypatch.setitem(installer.INSTALL_PATHS, "logstash_agent_template_unit", str(managed))
    monkeypatch.setattr(installer, "verify_root", lambda: None)
    monkeypatch.setattr(installer, "verify_platform", lambda: None)
    monkeypatch.setattr(installer, "download_release", lambda version, dest: str(tmp_path / "x.tgz"))
    monkeypatch.setattr(installer, "extract_binary", lambda tarball, dest: str(new_bin))
    monkeypatch.setattr(installer, "install_multi_instance_unit_templates", lambda: None)
    monkeypatch.setattr(installer, "migrate_legacy_systemd_units", lambda **kw: None)
    monkeypatch.setattr(installer, "install_systemctl_ctl", lambda: None)
    monkeypatch.setattr(
        installer.subprocess,
        "run",
        lambda *a, **k: MagicMock(returncode=1, stdout=b"", stderr=b""),
    )
    monkeypatch.setattr("tempfile.mkdtemp", lambda prefix="": str(tmp_path / "work"))
    monkeypatch.setattr("time.sleep", lambda n: None)

    def systemctl(*args, check=False):
        calls.append(tuple(args))
        return MagicMock(returncode=0, stdout=b"active\n", stderr=b"")

    monkeypatch.setattr(installer, "_systemctl_cmd", systemctl)
    real_exists = os.path.exists

    def exists(path):
        if path == _INSTALLED:
            return True
        return real_exists(path)

    monkeypatch.setattr(os.path, "exists", exists)
    return {"state": state, "calls": calls}


def _units(calls):
    return [c[1] for c in calls if c and c[0] in ("restart", "stop", "start", "is-active")]


def test_acceptance_2_controller_spawn(tmp_path, monkeypatch, caplog):
    # acceptance #2
    staged = _stage(tmp_path, monkeypatch)
    install_registry.register_instance(
        role="simulate",
        instance_id=2,
        agent_unit="simulate-agent@2",
        logstash_unit="simulate-logstash@2",
        state_dir=str(staged["state"]),
    )
    install_registry.register_instance(
        role="managed",
        instance_id=1,
        agent_unit="managed-agent@1",
        logstash_unit="managed-logstash@1",
        state_dir=str(staged["state"]),
    )
    install_registry.register_instance(
        role="packaged",
        agent_unit="logstash-agent",
        logstash_unit="logstash",
        state_dir=str(staged["state"]),
    )
    caller = staged["state"] / "upgrade-caller.json"
    assert not caller.exists()

    spawned = []
    snapshots = []

    def fake_popen(argv, **kwargs):
        spawned.append(list(argv))
        snapshots.append(caller.read_bytes() if caller.is_file() else b"")
        os.environ.pop("LOGSTASH_AGENT_STATE_DIR", None)
        assert "LOGSTASH_AGENT_STATE_DIR" not in os.environ
        monkeypatch.setattr(
            sys,
            "argv",
            ["logstash-agent", "upgrade", "--version", _VERSION, "--yes", "--_self-upgrade"],
        )
        assert "--mode" not in sys.argv and "--instance" not in sys.argv
        installer.perform_upgrade(version=_VERSION)
        return MagicMock()

    monkeypatch.setattr(controller.subprocess, "Popen", fake_popen)

    binary_path = _INSTALLED if os.path.exists(_INSTALLED) else sys.executable
    assert binary_path == _INSTALLED

    assert controller._spawn_self_upgrade(
        binary_path, _VERSION, mode="simulate", instance_id=2
    ) is True
    assert snapshots[-1] == _caller_bytes("simulate-2")
    assert spawned[-1] == _SPAWN_ARGV
    assert set(_units(staged["calls"])) == {"simulate-agent@2"}
    assert not caller.exists()

    staged["calls"].clear()
    installer.perform_upgrade(version=_VERSION)
    assert set(_units(staged["calls"])) == {"logstash-agent"}

    staged["calls"].clear()
    assert controller._spawn_self_upgrade(
        binary_path, _VERSION, mode="managed", instance_id=1
    ) is True
    assert snapshots[-1] == _caller_bytes("managed-1")
    assert spawned[-1] == _SPAWN_ARGV
    assert set(_units(staged["calls"])) == {"managed-agent@1"}
    assert not caller.exists()

    staged["calls"].clear()
    assert controller._spawn_self_upgrade(
        binary_path, _VERSION, mode="packaged", instance_id=None
    ) is True
    assert snapshots[-1] == _caller_bytes("packaged")
    assert spawned[-1] == _SPAWN_ARGV
    assert set(_units(staged["calls"])) == {"logstash-agent"}
    assert not caller.exists()

    missing = tmp_path / "no-such-parent" / "state"
    assert not missing.parent.exists()
    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(missing))
    before = len(spawned)
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="logstashagent.controller"):
        assert controller._spawn_self_upgrade(
            binary_path, _VERSION, mode="simulate", instance_id=2
        ) is False
    assert len(spawned) == before
    assert any(
        r.getMessage() == "upgrade: cannot record caller instance" for r in caplog.records
    )
