#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Controller upgrade caller record (acceptance #2)."""

import logging
import os
import re
import sys
import time
from unittest.mock import MagicMock

import pytest

from logstashagent import controller, installer
from logstashagent import install_registry

_VERSION = "9.9.9"
_INSTALLED = "/opt/logstash-agent/bin/logstash-agent"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _expect_argv(caller_id):
    return [
        "sudo",
        _INSTALLED,
        "upgrade",
        "--version",
        _VERSION,
        "--yes",
        "--_self-upgrade",
        "--_caller-id",
        caller_id,
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
    shared = staged["state"] / "upgrade-caller.json"
    assert not shared.exists()

    spawned = []
    snapshots = []

    def fake_popen(argv, **kwargs):
        spawned.append(list(argv))
        # acceptance #4: the invocation file already exists when Popen starts
        at = argv.index("--_caller-id")
        caller_id = argv[at + 1]
        path = staged["state"] / f"upgrade-caller-{caller_id}.json"
        snapshots.append((caller_id, path.read_bytes() if path.is_file() else b""))
        os.environ.pop("LOGSTASH_AGENT_STATE_DIR", None)
        assert "LOGSTASH_AGENT_STATE_DIR" not in os.environ
        assert "--mode" not in argv and "--instance" not in argv
        return MagicMock()

    monkeypatch.setattr(controller.subprocess, "Popen", fake_popen)

    binary_path = _INSTALLED if os.path.exists(_INSTALLED) else sys.executable
    assert binary_path == _INSTALLED

    assert controller._spawn_self_upgrade(
        binary_path, _VERSION, mode="simulate", instance_id=2
    ) is True
    sim_id, sim_body = snapshots[-1]
    assert sim_body == _caller_bytes("simulate-2")
    assert spawned[-1] == _expect_argv(sim_id)
    sim_path = staged["state"] / f"upgrade-caller-{sim_id}.json"
    assert sim_path.name != "upgrade-caller.json"
    assert sim_path.read_bytes() == _caller_bytes("simulate-2")
    assert not shared.exists()

    staged["calls"].clear()
    monkeypatch.setattr(
        sys,
        "argv",
        ["logstash-agent", "upgrade", "--version", _VERSION, "--yes"],
    )
    installer.perform_upgrade(version=_VERSION)
    assert set(_units(staged["calls"])) == {"logstash-agent"}

    staged["calls"].clear()
    assert controller._spawn_self_upgrade(
        binary_path, _VERSION, mode="managed", instance_id=1
    ) is True
    man_id, man_body = snapshots[-1]
    assert man_body == _caller_bytes("managed-1")
    assert spawned[-1] == _expect_argv(man_id)
    man_path = staged["state"] / f"upgrade-caller-{man_id}.json"
    assert man_path.name != "upgrade-caller.json"
    # acceptance #3
    assert sim_id != man_id
    assert sim_path.is_file() and man_path.is_file()
    assert sim_path.read_bytes() == _caller_bytes("simulate-2")
    assert man_path.read_bytes() == _caller_bytes("managed-1")
    assert not shared.exists()

    staged["calls"].clear()
    child = [
        "logstash-agent",
        "upgrade",
        "--version",
        _VERSION,
        "--yes",
        "--_caller-id",
        sim_id,
        "--_detached",
    ]
    assert "--_self-upgrade" not in child
    monkeypatch.setattr(sys, "argv", child)
    installer.perform_upgrade(version=_VERSION)
    assert not sim_path.exists()
    assert man_path.read_bytes() == _caller_bytes("managed-1")
    assert set(_units(staged["calls"])) == {"simulate-agent@2"}

    staged["calls"].clear()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "logstash-agent",
            "upgrade",
            "--version",
            _VERSION,
            "--yes",
            "--_caller-id",
            man_id,
            "--_detached",
        ],
    )
    installer.perform_upgrade(version=_VERSION)
    assert set(_units(staged["calls"])) == {"managed-agent@1"}

    staged["calls"].clear()
    assert controller._spawn_self_upgrade(
        binary_path, _VERSION, mode="packaged", instance_id=None
    ) is True
    pkg_id, pkg_body = snapshots[-1]
    assert pkg_body == _caller_bytes("packaged")
    assert spawned[-1] == _expect_argv(pkg_id)
    pkg_path = staged["state"] / f"upgrade-caller-{pkg_id}.json"
    assert pkg_path.name != "upgrade-caller.json"
    assert pkg_path.read_bytes() == _caller_bytes("packaged")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "logstash-agent",
            "upgrade",
            "--version",
            _VERSION,
            "--yes",
            "--_caller-id",
            pkg_id,
            "--_detached",
        ],
    )
    installer.perform_upgrade(version=_VERSION)
    assert set(_units(staged["calls"])) == {"logstash-agent"}

    # acceptance #4
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


def test_r4_acceptance_4_same_second_ids(tmp_path, monkeypatch):
    # acceptance #4
    staged = _stage(tmp_path, monkeypatch)
    monkeypatch.setattr(time, "time", lambda: 1700000000.0)
    spawned = []

    def fake_popen(argv, **kwargs):
        spawned.append(list(argv))
        return MagicMock()

    monkeypatch.setattr(controller.subprocess, "Popen", fake_popen)
    binary_path = _INSTALLED if os.path.exists(_INSTALLED) else sys.executable
    assert binary_path == _INSTALLED
    for _ in range(2):
        assert controller._spawn_self_upgrade(
            binary_path, _VERSION, mode="simulate", instance_id=2
        ) is True
    ids = [argv[argv.index("--_caller-id") + 1] for argv in spawned]
    assert len(ids) == 2
    assert ids[0] != ids[1]
    assert _ID_RE.fullmatch(ids[0]) and _ID_RE.fullmatch(ids[1])
    paths = [staged["state"] / f"upgrade-caller-{caller_id}.json" for caller_id in ids]
    assert paths[0] != paths[1]
    assert paths[0].is_file() and paths[1].is_file()
    assert paths[0].read_bytes() == paths[1].read_bytes() == _caller_bytes("simulate-2")
    assert not (staged["state"] / "upgrade-caller.json").exists()


def test_r6_acceptance_1_spawn_log_caller_id(tmp_path, monkeypatch, caplog):
    # acceptance #1
    staged = _stage(tmp_path, monkeypatch)
    spawned = []
    snapshots = []

    def fake_popen(argv, **kwargs):
        spawned.append(list(argv))
        if "--_caller-id" in argv:
            at = argv.index("--_caller-id")
            if at + 1 < len(argv):
                caller_id = argv[at + 1]
                path = staged["state"] / f"upgrade-caller-{caller_id}.json"
                snapshots.append((caller_id, path.read_bytes() if path.is_file() else b""))
        return MagicMock()

    monkeypatch.setattr(controller.subprocess, "Popen", fake_popen)
    binary_path = _INSTALLED if os.path.exists(_INSTALLED) else sys.executable
    assert binary_path == _INSTALLED

    def _assert_single_spawn_log(records, argv):
        spawn_logs = [
            r for r in records if r.getMessage().startswith("Spawning upgrade process")
        ]
        assert len(spawn_logs) == 1
        msg = spawn_logs[0].getMessage()
        assert "--_caller-id" in msg
        tokens = msg.split()
        logged_id = tokens[tokens.index("--_caller-id") + 1]
        assert "--_caller-id" in argv
        argv_id = argv[argv.index("--_caller-id") + 1]
        assert logged_id == argv_id
        return argv_id

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="logstashagent.controller"):
        assert controller._spawn_self_upgrade(
            binary_path, _VERSION, mode="simulate", instance_id=2
        ) is True
    direct_id = _assert_single_spawn_log(caplog.records, spawned[-1])
    assert snapshots[-1] == (direct_id, _caller_bytes("simulate-2"))

    # Drive run_controller once so a duplicate spawn log in the caller fails.
    class _StopLoopEvent:
        def wait(self, timeout=None):
            raise KeyboardInterrupt()

        def clear(self):
            pass

    monkeypatch.setattr(controller, "_log_watcher", None)
    monkeypatch.setattr(
        controller.agent_state,
        "get_state",
        lambda: {
            "enrolled": True,
            "api_key": "k",
            "connection_id": "c",
            "mode": "simulate",
            "instance_id": 2,
        },
    )
    monkeypatch.setattr(controller, "recover_incomplete_runtime_upgrade", lambda: None)
    monkeypatch.setattr(controller, "heal_stale_logstash_launch", lambda state: None)
    monkeypatch.setattr(controller, "heal_legacy_systemd_units_on_checkin", lambda state: None)
    monkeypatch.setattr(controller, "check_in", lambda: {"desired_agent_version": _VERSION})
    monkeypatch.setattr(controller, "get_version", lambda name: "0.0.1")
    monkeypatch.setattr(controller.log_analyzer, "is_logstash_restarting", lambda log_dir="": False)
    monkeypatch.setattr(controller.threading, "Event", _StopLoopEvent)

    before = len(spawned)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="logstashagent.controller"):
        controller.run_controller()
    assert len(spawned) == before + 1
    rc_id = _assert_single_spawn_log(caplog.records, spawned[-1])
    assert snapshots[-1] == (rc_id, _caller_bytes("simulate-2"))