#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""perform_upgrade registry agent_unit selection (acceptance #1 #3 #4 #5)."""

import logging
import os
import subprocess
import sys
from unittest.mock import MagicMock

import pytest

from logstashagent import installer

_NO_ENTRY = "upgrade: no registry entry for this instance"
_FORBIDDEN = (
    "systemctl start logstash-agent",
    "systemctl stop logstash-agent",
    "systemctl restart logstash-agent",
    "systemctl status logstash-agent",
)
_ENTRIES = (
    {"id": "packaged", "agent_unit": "logstash-agent"},
    {"id": "managed-1", "agent_unit": "managed-agent@1"},
    {"id": "simulate-2", "agent_unit": "simulate-agent@2"},
)
_ACTIONS = ("restart", "stop", "start", "is-active")


def _caller_bytes(key):
    return ('{"instance_key":"%s"}\n' % key).encode()


def _stage(tmp_path, monkeypatch, *, instances=_ENTRIES):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    binary = bin_dir / "logstash-agent"
    binary.write_bytes(b"old-binary")
    (bin_dir / "_internal").mkdir()
    (bin_dir / "_internal" / "dep").write_text("old")
    state = tmp_path / "state"
    state.mkdir()
    packaged = tmp_path / "logstash-agent.service"
    simulate = tmp_path / "simulate-agent@.service"
    managed = tmp_path / "managed-agent@.service"
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    new_bin = new_dir / "logstash-agent"
    new_bin.write_bytes(b"new-binary")
    (tmp_path / "work").mkdir()

    calls = []
    downloads = []

    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(binary))
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary_dir", str(bin_dir))
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemd_service", str(packaged))
    monkeypatch.setitem(installer.INSTALL_PATHS, "cache_dir", str(tmp_path / "cache"))
    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(state))
    monkeypatch.setitem(installer.INSTALL_PATHS, "lsagent_simulate_unit", str(simulate))
    monkeypatch.setitem(installer.INSTALL_PATHS, "logstash_agent_template_unit", str(managed))
    monkeypatch.setattr(installer, "verify_root", lambda: None)
    monkeypatch.setattr(installer, "verify_platform", lambda: None)
    monkeypatch.setattr(
        installer,
        "download_release",
        lambda version, dest: downloads.append(version) or str(tmp_path / "x.tgz"),
    )
    monkeypatch.setattr(installer, "extract_binary", lambda tarball, dest: str(new_bin))
    monkeypatch.setattr(installer, "install_multi_instance_unit_templates", lambda: None)
    monkeypatch.setattr(installer, "migrate_legacy_systemd_units", lambda **kw: None)
    monkeypatch.setattr(installer, "install_systemctl_ctl", lambda: None)
    monkeypatch.setattr(
        "logstashagent.install_registry.list_instances",
        lambda *a, **k: [dict(entry) for entry in instances],
    )
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
    return {
        "binary": binary,
        "state": state,
        "packaged": packaged,
        "simulate": simulate,
        "managed": managed,
        "calls": calls,
        "downloads": downloads,
        "systemctl": systemctl,
    }


def _write_caller(staged, key):
    path = staged["state"] / "upgrade-caller.json"
    path.write_bytes(_caller_bytes(key))
    return path


def _argv(self_upgrade):
    argv = ["logstash-agent", "upgrade", "--version", "0.1.30", "--yes"]
    if self_upgrade:
        argv.append("--_self-upgrade")
    return argv


def _units(calls, action):
    return [c[1] for c in calls if c and c[0] == action]


def test_acceptance_1_selection(tmp_path, monkeypatch):
    # acceptance #1
    staged = _stage(tmp_path, monkeypatch)
    for unit_path in (staged["packaged"], staged["simulate"], staged["managed"]):
        unit_path.write_text("[Unit]\n")

    def fail_rename(*args, **kwargs):
        raise OSError(16, "Text file busy")

    original_rename = os.rename
    for key, unit in (
        ("packaged", "logstash-agent"),
        ("managed-1", "managed-agent@1"),
        ("simulate-2", "simulate-agent@2"),
    ):
        staged["calls"].clear()
        caller = _write_caller(staged, key)
        monkeypatch.setattr(sys, "argv", _argv(True))
        assert "--mode" not in sys.argv and "--instance" not in sys.argv
        monkeypatch.setattr(os, "rename", fail_rename)
        with pytest.raises(installer.InstallError):
            installer.perform_upgrade("0.1.30")
        monkeypatch.setattr(os, "rename", original_rename)
        assert not caller.exists()

        caller = _write_caller(staged, key)

        def systemctl(*args, check=False):
            staged["calls"].append(tuple(args))
            if args and args[0] == "restart":
                raise subprocess.CalledProcessError(1, "restart")
            return MagicMock(returncode=0, stdout=b"active\n", stderr=b"")

        monkeypatch.setattr(installer, "_systemctl_cmd", systemctl)
        with pytest.raises(installer.InstallError):
            installer.perform_upgrade("0.1.30")
        assert not caller.exists()
        for action in _ACTIONS:
            seen = _units(staged["calls"], action)
            assert seen, action
            assert set(seen) == {unit}, (key, action, seen)

    staged["calls"].clear()
    monkeypatch.setattr(sys, "argv", _argv(True))
    monkeypatch.setattr(installer, "_systemctl_cmd", staged["systemctl"])
    installer.perform_upgrade("0.1.30")
    assert _units(staged["calls"], "restart") == ["logstash-agent"]
    assert not (staged["state"] / "upgrade-caller.json").exists()

    staged["calls"].clear()
    caller = _write_caller(staged, "simulate-2")
    exact = caller.read_bytes()
    monkeypatch.setattr(sys, "argv", _argv(False))
    installer.perform_upgrade("0.1.30")
    assert caller.read_bytes() == exact
    assert _units(staged["calls"], "restart") == ["logstash-agent"]


def test_acceptance_3_existence_gate(tmp_path, monkeypatch, caplog):
    # acceptance #3
    cases = (
        ("simulate-2", "simulate-agent@2", "simulate", "managed"),
        ("managed-1", "managed-agent@1", "managed", "simulate"),
    )
    for key, unit, present_name, absent_name in cases:
        staged = _stage(tmp_path / key, monkeypatch)
        present = staged[present_name]
        absent = staged[absent_name]
        present.write_text("[Unit]\n")
        assert not staged["packaged"].exists()
        assert not absent.exists()
        _write_caller(staged, key)
        monkeypatch.setattr(sys, "argv", _argv(True))
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="logstashagent.installer"):
            installer.perform_upgrade("0.1.30")
        assert _units(staged["calls"], "restart") == [unit]
        skipped = f"{unit} systemd unit not found; skipping service restart"
        assert not any(r.getMessage() == skipped for r in caplog.records)

        present.unlink()
        _write_caller(staged, key)
        staged["calls"].clear()
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="logstashagent.installer"):
            installer.perform_upgrade("0.1.30")
        assert _units(staged["calls"], "restart") == []
        assert any(
            r.levelno == logging.WARNING and r.getMessage() == skipped
            for r in caplog.records
        )

    staged = _stage(tmp_path / "packaged", monkeypatch)
    monkeypatch.setattr(sys, "argv", _argv(False))
    caplog.clear()
    warning = "logstash-agent systemd unit not found; skipping service restart"
    with caplog.at_level(logging.WARNING, logger="logstashagent.installer"):
        installer.perform_upgrade("0.1.30")
    assert _units(staged["calls"], "restart") == []
    assert any(
        r.levelno == logging.WARNING and r.getMessage() == warning
        for r in caplog.records
    )


def _hint_messages(caplog, start):
    return [r.getMessage() for r in caplog.records[start:]]


def test_acceptance_4_operator_hints(tmp_path, monkeypatch, caplog):
    # acceptance #4
    caplog.set_level(logging.INFO, logger="logstashagent.installer")
    staged = _stage(tmp_path, monkeypatch)
    staged["simulate"].write_text("[Unit]\n")
    staged["packaged"].write_text("[Unit]\n")

    def fail_restart_and_start(*args, check=False):
        staged["calls"].append(tuple(args))
        if args and args[0] in ("restart", "start"):
            raise subprocess.CalledProcessError(1, args[0])
        return MagicMock(returncode=0, stdout=b"active\n", stderr=b"")

    monkeypatch.setattr(installer, "_systemctl_cmd", fail_restart_and_start)
    monkeypatch.setattr(sys, "argv", _argv(True))
    _write_caller(staged, "simulate-2")
    start = len(caplog.records)
    with pytest.raises(installer.InstallError):
        installer.perform_upgrade("0.1.30")
    hints = "\n".join(_hint_messages(caplog, start))
    assert "  4. Start service: sudo systemctl start simulate-agent@2" in hints
    assert "  5. Check status: sudo systemctl status simulate-agent@2" in hints
    for forbidden in _FORBIDDEN:
        assert forbidden not in hints

    def succeed(*args, check=False):
        staged["calls"].append(tuple(args))
        return MagicMock(returncode=0, stdout=b"active\n", stderr=b"")

    monkeypatch.setattr(installer, "_systemctl_cmd", succeed)
    _write_caller(staged, "simulate-2")
    start = len(caplog.records)
    installer.perform_upgrade("0.1.30")
    hints = "\n".join(_hint_messages(caplog, start))
    assert "  sudo systemctl status simulate-agent@2" in hints
    for forbidden in _FORBIDDEN:
        assert forbidden not in hints

    is_active_n = {"n": 0}

    def inactive_then_active(*args, check=False):
        staged["calls"].append(tuple(args))
        if args and args[0] == "is-active":
            is_active_n["n"] += 1
            rc = 3 if is_active_n["n"] == 1 else 0
            return MagicMock(returncode=rc, stdout=b"inactive\n", stderr=b"")
        return MagicMock(returncode=0, stdout=b"active\n", stderr=b"")

    monkeypatch.setattr(installer, "_systemctl_cmd", inactive_then_active)
    _write_caller(staged, "simulate-2")
    start = len(caplog.records)
    installer.perform_upgrade("0.1.30")
    hints = "\n".join(_hint_messages(caplog, start))
    assert "  sudo systemctl start simulate-agent@2" in hints
    for forbidden in _FORBIDDEN:
        assert forbidden not in hints

    monkeypatch.setattr(installer, "_systemctl_cmd", fail_restart_and_start)
    monkeypatch.setattr(sys, "argv", _argv(False))
    start = len(caplog.records)
    with pytest.raises(installer.InstallError):
        installer.perform_upgrade("0.1.30")
    hints = "\n".join(_hint_messages(caplog, start))
    assert "sudo systemctl start logstash-agent" in hints
    assert "sudo systemctl status logstash-agent" in hints


def test_acceptance_5_missing_entry(tmp_path, monkeypatch, caplog):
    # acceptance #5
    staged = _stage(tmp_path, monkeypatch)
    assert not (tmp_path / "simulate-9").exists()
    caller = _write_caller(staged, "simulate-9")
    before = staged["binary"].read_bytes()
    monkeypatch.setattr(sys, "argv", _argv(True))
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="logstashagent.installer"):
        with pytest.raises(installer.InstallError) as raised:
            installer.perform_upgrade("0.1.30")
    assert str(raised.value) == _NO_ENTRY
    assert any(
        r.levelno == logging.ERROR and r.getMessage() == _NO_ENTRY
        for r in caplog.records
    )
    assert staged["downloads"] == []
    assert staged["calls"] == []
    assert staged["binary"].read_bytes() == before
    assert not caller.exists()
