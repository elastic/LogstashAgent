#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""perform_upgrade unit guard, ctl regen, and ignore-errors (acceptance #1 #2 #3 #6 #10)."""

import logging
import os
import subprocess
import sys
import time
from unittest.mock import MagicMock

import pytest

from logstashagent import installer

_SKIP_WARNING = "logstash-agent systemd unit not found; skipping service restart"
_IGNORE_WARNING = "--ignore-errors: rollback skipped; backups retained"
_BANNER = "COMPLETED SUCCESSFULLY!"


def _stage(tmp_path, monkeypatch, *, unit_present, restart_error=None, ctl_error=None):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / "logstash-agent"
    binary.write_bytes(b"old-binary")
    internal = bin_dir / "_internal"
    internal.mkdir()
    (internal / "dep").write_text("old")
    unit = tmp_path / "logstash-agent.service"
    if unit_present:
        unit.write_text("[Unit]\n")
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    new_bin = new_dir / "logstash-agent"
    new_bin.write_bytes(b"new-binary")
    (new_dir / "_internal").mkdir()
    (new_dir / "_internal" / "dep").write_text("new")
    (tmp_path / "work").mkdir()

    order = []
    systemctl_calls = []
    verify_calls = []
    sleeps = []

    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(binary))
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary_dir", str(bin_dir))
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemd_service", str(unit))
    monkeypatch.setitem(installer.INSTALL_PATHS, "cache_dir", str(tmp_path / "cache"))
    monkeypatch.setattr(installer, "verify_root", lambda: None)
    monkeypatch.setattr(installer, "verify_platform", lambda: None)
    monkeypatch.setattr(installer, "download_release", lambda version, dest: str(tmp_path / "x.tgz"))
    monkeypatch.setattr(installer, "extract_binary", lambda tarball, dest: str(new_bin))
    monkeypatch.setattr(
        installer, "install_multi_instance_unit_templates", lambda: order.append("templates")
    )
    monkeypatch.setattr(
        installer, "migrate_legacy_systemd_units", lambda **kw: order.append("migrate")
    )

    def ctl():
        order.append("ctl")
        if ctl_error is not None:
            raise ctl_error
        return str(tmp_path / "ctl")

    monkeypatch.setattr(installer, "install_systemctl_ctl", ctl)

    def verify():
        verify_calls.append(1)
        return True

    monkeypatch.setattr(installer, "verify_service_running", verify)

    def systemctl(*args, check=False):
        systemctl_calls.append(args)
        order.append(args)
        if restart_error is not None and args and args[0] == "restart":
            raise restart_error
        return MagicMock(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(installer, "_systemctl_cmd", systemctl)
    monkeypatch.setattr(
        installer.subprocess,
        "run",
        lambda *a, **k: MagicMock(returncode=1, stdout=b"", stderr=b""),
    )
    monkeypatch.setattr("tempfile.mkdtemp", lambda prefix="": str(tmp_path / "work"))
    monkeypatch.setattr("time.sleep", lambda n: sleeps.append(n))
    return {
        "binary": binary,
        "backup": bin_dir / "logstash-agent.backup",
        "internal_backup": bin_dir / "_internal.backup",
        "order": order,
        "systemctl": systemctl_calls,
        "verify": verify_calls,
        "sleeps": sleeps,
    }


def _actions(calls):
    return [c[0] for c in calls if c]


@pytest.mark.parametrize("ignore_errors", [False, True])
def test_absent_unit_skips_restart_health_and_rollback(tmp_path, monkeypatch, ignore_errors):
    # acceptance #1
    staged = _stage(tmp_path, monkeypatch, unit_present=False)
    installer.perform_upgrade("0.1.30", ignore_errors=ignore_errors)
    assert "restart" not in _actions(staged["systemctl"])
    assert "stop" not in _actions(staged["systemctl"])
    assert "start" not in _actions(staged["systemctl"])
    assert staged["verify"] == [1]  # Step 5 only; Step 10 health check did not run
    assert staged["sleeps"] == []


def test_present_unit_restarts_and_verifies(tmp_path, monkeypatch):
    # acceptance #2
    staged = _stage(tmp_path, monkeypatch, unit_present=True)
    installer.perform_upgrade("0.1.30")
    assert "restart" in _actions(staged["systemctl"])
    assert staged["verify"] == [1, 1]  # Step 5 and Step 10
    assert staged["sleeps"] == [2]
    assert "ctl" not in staged["order"]  # replace_ctl defaults off


def test_absent_unit_warning_exact(tmp_path, monkeypatch, caplog):
    # acceptance #3
    _stage(tmp_path, monkeypatch, unit_present=False)
    with caplog.at_level(logging.WARNING, logger="logstashagent.installer"):
        installer.perform_upgrade("0.1.30")
    assert any(
        r.levelno == logging.WARNING and r.message == _SKIP_WARNING for r in caplog.records
    )


def test_replace_ctl_runs_after_step_8b_before_restart(tmp_path, monkeypatch):
    # acceptance #6
    staged = _stage(tmp_path, monkeypatch, unit_present=True)
    installer.perform_upgrade("0.1.30", replace_ctl=True)
    order = staged["order"]
    assert order.index("migrate") < order.index("ctl") < order.index(("restart", "logstash-agent"))


def test_replace_ctl_failure_is_nonfatal_warning(tmp_path, monkeypatch, caplog):
    # acceptance #6
    staged = _stage(tmp_path, monkeypatch, unit_present=True, ctl_error=OSError("disk full"))
    with caplog.at_level(logging.WARNING, logger="logstashagent.installer"):
        installer.perform_upgrade("0.1.30", replace_ctl=True)
    assert "restart" in _actions(staged["systemctl"])
    assert any(
        r.levelno == logging.WARNING
        and r.message == "Could not install systemctl helper: disk full"
        for r in caplog.records
    )


def test_ignore_errors_skips_rollback_retains_backups(tmp_path, monkeypatch, caplog):
    # acceptance #10
    err = subprocess.CalledProcessError(1, ["systemctl", "restart", "logstash-agent"])
    staged = _stage(tmp_path, monkeypatch, unit_present=True, restart_error=err)
    caplog.set_level(logging.INFO, logger="logstashagent.installer")
    with pytest.raises(installer.InstallError) as raised:
        installer.perform_upgrade("0.1.30", ignore_errors=True)
    assert str(raised.value) == f"--ignore-errors: upgrade failed: {err}"
    assert "Upgrade failed and was rolled back" not in str(raised.value)
    assert "stop" not in _actions(staged["systemctl"])
    assert "start" not in _actions(staged["systemctl"])
    assert staged["binary"].read_bytes() == b"new-binary"
    assert staged["backup"].read_bytes() == b"old-binary"
    assert (staged["internal_backup"] / "dep").read_text() == "old"
    assert _BANNER not in caplog.text
    assert "Performing rollback" not in caplog.text
    assert "ROLLBACK FAILED" not in caplog.text
    assert "Service failed to start" not in caplog.text
    assert any(
        r.levelno == logging.WARNING and r.message == _IGNORE_WARNING for r in caplog.records
    )


def test_detach_upgrade_systemd_run_contract(tmp_path, monkeypatch):
    # acceptance #3
    calls = []
    env = {"ENV_SENTINEL": "detach"}

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    monkeypatch.setattr(installer, "host_subprocess_env", lambda: env)
    monkeypatch.setattr(time, "time", lambda: 1700000000.4)

    installer.detach_upgrade("0.1.4")
    argv, kwargs = calls[0]
    assert argv == [
        "systemd-run",
        "--unit=logstash-agent-upgrade-0.1.4-1700000000",
        "--collect",
        "--property=Type=exec",
        sys.executable,
        "upgrade",
        "--version",
        "0.1.4",
        "--yes",
        "--_detached",
    ]
    assert "--_self-upgrade" not in argv
    assert "--yes" in argv
    assert kwargs == {
        "capture_output": True,
        "text": True,
        "timeout": 30,
        "check": False,
        "env": env,
    }

    binary = tmp_path / "logstash-agent"
    binary.write_bytes(b"x")
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(binary))
    calls.clear()
    installer.detach_upgrade("1.2.3", replace_ctl=True, ignore_errors=False)
    argv, kwargs = calls[0]
    assert argv[4] == str(binary)
    assert argv[-3:] == ["--yes", "--replace-ctl", "--_detached"]
    assert "--ignore-errors" not in argv
    assert "--_self-upgrade" not in argv
    assert os.path.exists(binary)

    calls.clear()
    installer.detach_upgrade("1.2.3", replace_ctl=False, ignore_errors=True)
    argv, _kwargs = calls[0]
    assert argv[-3:] == ["--yes", "--ignore-errors", "--_detached"]
    assert "--replace-ctl" not in argv
    assert len(calls) == 1

