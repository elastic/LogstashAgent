#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""upgrade CLI flags (acceptance #4 #9 #11 and #10 exit 1)."""

import logging
import os
import runpy
import subprocess
import sys
import time

import pytest

from logstashagent import installer

_CTL_FAIL = "Failed to regenerate logstash-agent-ctl"
_PROMPT_STEP = "2. Stop the logstash-agent service"


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("logstashagent.main", run_name="__main__")
    return exc.value.code


def _forbid(name):
    def _boom(*args, **kwargs):
        raise AssertionError(f"{name} called")
    return _boom


@pytest.mark.parametrize("extra", [[], ["--yes"], ["--force"], ["--yes", "--force"]])
def test_replace_ctl_only_writes_ctl_and_exits_0(tmp_path, monkeypatch, extra):
    # acceptance #4
    dest = tmp_path / "bin" / "logstash-agent-ctl"
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemctl_ctl", str(dest))
    monkeypatch.setattr(installer, "perform_upgrade", _forbid("perform_upgrade"))
    monkeypatch.setattr(installer, "download_release", _forbid("download_release"))
    monkeypatch.setattr(installer, "_systemctl_cmd", _forbid("_systemctl_cmd"))
    monkeypatch.setattr("builtins.input", _forbid("input"))
    code = _run(monkeypatch, ["logstash-agent", "upgrade", "--replace-ctl", *extra])
    assert code == 0
    assert dest.read_bytes() == installer._SYSTEMCTL_CTL_SCRIPT.encode()
    assert (dest.stat().st_mode & 0o777) == 0o755


@pytest.mark.parametrize("extra", [[], ["--ignore-errors"]])
def test_replace_ctl_write_failure_exits_1(monkeypatch, caplog, extra):
    # acceptance #4: --ignore-errors does not soften the fatal exit
    def fail():
        raise OSError("disk full")

    monkeypatch.setattr(installer, "install_systemctl_ctl", fail)
    monkeypatch.setattr(installer, "perform_upgrade", _forbid("perform_upgrade"))
    monkeypatch.setattr("builtins.input", _forbid("input"))
    caplog.set_level("ERROR")
    code = _run(monkeypatch, ["logstash-agent", "upgrade", "--replace-ctl", *extra])
    assert code == 1
    assert any(r.message == _CTL_FAIL for r in caplog.records)


def test_force_skips_prompt_only(monkeypatch):
    # acceptance #9
    seen = {}

    def perform_upgrade(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(installer, "perform_upgrade", perform_upgrade)
    monkeypatch.setattr("builtins.input", _forbid("input"))
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--force"],
    )
    assert code == 0
    assert seen == {
        "version": "0.1.4",
        "auto": False,
        "replace_ctl": False,
        "ignore_errors": False,
    }


def test_ignore_errors_does_not_skip_prompt(monkeypatch, capsys):
    # acceptance #9
    monkeypatch.setattr(installer, "perform_upgrade", _forbid("perform_upgrade"))
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--ignore-errors"],
    )
    assert code == 0
    assert _PROMPT_STEP in capsys.readouterr().out


def test_ignore_errors_forwarded_to_perform_upgrade(monkeypatch):
    # B1 mutant P: handler must forward --ignore-errors to perform_upgrade
    seen = {}

    def perform_upgrade(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(installer, "perform_upgrade", perform_upgrade)
    monkeypatch.setattr("builtins.input", _forbid("input"))
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--ignore-errors"],
    )
    assert code == 0
    assert seen["ignore_errors"] is True


def test_replace_ctl_forwarded_to_perform_upgrade(monkeypatch):
    # B1 mutant Q: handler must forward --replace-ctl to perform_upgrade
    seen = {}

    def perform_upgrade(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(installer, "perform_upgrade", perform_upgrade)
    monkeypatch.setattr("builtins.input", _forbid("input"))
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--replace-ctl"],
    )
    assert code == 0
    assert seen["replace_ctl"] is True


def test_ignore_errors_installerror_exits_1(monkeypatch, caplog):
    # acceptance #10: exit 1 via main's InstallError mapping, not the generic path
    seen = {}

    def perform_upgrade(**kwargs):
        seen.update(kwargs)
        raise installer.InstallError("--ignore-errors: upgrade failed: boom")

    monkeypatch.setattr(installer, "perform_upgrade", perform_upgrade)
    monkeypatch.setattr("builtins.input", _forbid("input"))
    caplog.set_level("ERROR")
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--ignore-errors"],
    )
    assert code == 1
    assert seen["ignore_errors"] is True
    # InstallError message surfaced via the InstallError mapping (main.py upgrade handler)
    assert any(
        r.message == "Upgrade failed: --ignore-errors: upgrade failed: boom"
        for r in caplog.records
    )
    # generic-Exception mapping did not run
    assert not any(
        r.message.startswith("Unexpected upgrade error") for r in caplog.records
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["logstash-agent", "upgrade"],
        ["logstash-agent", "upgrade", "--force"],
        ["logstash-agent", "upgrade", "--yes"],
        ["logstash-agent", "upgrade", "--ignore-errors"],
    ],
)
def test_upgrade_without_version_exits_2(monkeypatch, argv):
    # acceptance #11
    assert _run(monkeypatch, argv) == 2


# acceptance #1: base help under the same launcher (uv/python -m) at COLUMNS 80 and 40.
_HELP_80 = """\
usage: python -m logstashagent.main upgrade [-h] [--version VERSION] [--yes]
                                            [--replace-ctl] [--force]
                                            [--ignore-errors]

options:
  -h, --help         show this help message and exit
  --version VERSION  Version to upgrade to (e.g., 0.1.4)
  --yes              Skip the upgrade confirmation prompt
  --replace-ctl      Regenerate the on-disk logstash-agent-ctl
  --force            Force the upgrade; skip the confirmation prompt
  --ignore-errors    Ignore upgrade errors and proceed without rollback
"""

_HELP_40 = """\
usage: python -m logstashagent.main upgrade
       [-h] [--version VERSION]
       [--yes] [--replace-ctl]
       [--force] [--ignore-errors]

options:
  -h, --help      show this help
                  message and exit
  --version VERSION
                  Version to upgrade
                  to (e.g., 0.1.4)
  --yes           Skip the upgrade
                  confirmation prompt
  --replace-ctl   Regenerate the on-
                  disk logstash-agent-
                  ctl
  --force         Force the upgrade;
                  skip the
                  confirmation prompt
  --ignore-errors
                  Ignore upgrade
                  errors and proceed
                  without rollback
"""

_EPOCH = 1700000000


def _upgrade_help(columns):
    env = os.environ.copy()
    env["COLUMNS"] = str(columns)
    proc = subprocess.run(
        [sys.executable, "-m", "logstashagent.main", "upgrade", "--help"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return proc.returncode, proc.stdout


def _spy_run(monkeypatch, result):
    # Record outside the fake. Assertions happen after _run returns.
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    return calls


def _seen_upgrade(monkeypatch):
    seen = []

    def perform_upgrade(**kwargs):
        seen.append(kwargs)

    monkeypatch.setattr(installer, "perform_upgrade", perform_upgrade)
    return seen


def _arm(monkeypatch, euid):
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(time, "time", lambda: float(_EPOCH) + 0.9)
    monkeypatch.setattr("builtins.input", _forbid("input"))


def _expect_argv(flags=()):
    version = "0.1.4"
    return [
        "systemd-run",
        f"--unit=logstash-agent-upgrade-{version}-{_EPOCH}",
        "--collect",
        "--property=Type=exec",
        sys.executable,
        "upgrade",
        "--version",
        version,
        "--yes",
        *flags,
        "--_detached",
    ]


def _assert_run_contract(kwargs):
    assert kwargs == {
        "capture_output": True,
        "text": True,
        "timeout": 30,
        "check": False,
        "env": installer.host_subprocess_env(),
    }


def test_upgrade_help_hides_detach_flags():
    # acceptance #1
    for columns, expected in ((80, _HELP_80), (40, _HELP_40)):
        code, out = _upgrade_help(columns)
        assert code == 0, out
        assert out == expected
        assert out.count("--_self-upgrade") == 0
        assert out.count("--_detached") == 0


def test_hidden_flag_dests(monkeypatch):
    # acceptance #1
    from logstashagent.main import parse_arguments

    monkeypatch.setattr(
        sys,
        "argv",
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--_self-upgrade", "--_detached"],
    )
    args = None
    try:
        args = parse_arguments()
    except SystemExit as exc:
        pytest.fail(f"hidden flags not registered: {exc.code}")
    assert args is not None
    assert args._self_upgrade is True
    assert args._detached is True

    monkeypatch.setattr(
        sys, "argv", ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes"]
    )
    plain = parse_arguments()
    assert getattr(plain, "_self_upgrade", None) is False
    assert getattr(plain, "_detached", None) is False


def test_replace_ctl_only_exits_before_detach_guard(tmp_path, monkeypatch):
    # acceptance #2: ctl-only path exits 0 before the guard
    dest = tmp_path / "bin" / "logstash-agent-ctl"
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemctl_ctl", str(dest))
    _arm(monkeypatch, 0)
    calls = _spy_run(monkeypatch, subprocess.CompletedProcess([], 0, "", ""))
    seen = _seen_upgrade(monkeypatch)
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--replace-ctl", "--_self-upgrade"],
    )
    assert code == 0
    assert seen == []
    assert calls == []
    assert dest.read_bytes() == installer._SYSTEMCTL_CTL_SCRIPT.encode()


@pytest.mark.parametrize(
    "argv,euid",
    [
        (["logstash-agent", "upgrade", "--version", "0.1.4", "--yes"], 0),
        (["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--_detached"], 0),
        (
            [
                "logstash-agent",
                "upgrade",
                "--version",
                "0.1.4",
                "--yes",
                "--_self-upgrade",
                "--_detached",
            ],
            0,
        ),
        (["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--_self-upgrade"], 1),
    ],
)
def test_guard_not_called_when_predicate_false(monkeypatch, argv, euid):
    # acceptance #2 #5
    _arm(monkeypatch, euid)
    calls = _spy_run(monkeypatch, subprocess.CompletedProcess([], 0, "", ""))
    seen = _seen_upgrade(monkeypatch)
    code = _run(monkeypatch, argv)
    assert code == 0
    assert calls == []
    assert seen == [{
        "version": "0.1.4",
        "auto": False,
        "replace_ctl": False,
        "ignore_errors": False,
    }]


@pytest.mark.parametrize(
    "extra,flags",
    [
        ([], ()),
        (["--replace-ctl"], ("--replace-ctl",)),
        (["--ignore-errors"], ("--ignore-errors",)),
        (["--replace-ctl", "--ignore-errors"], ("--replace-ctl", "--ignore-errors")),
    ],
)
def test_guard_reexec_exact_argv_once(monkeypatch, caplog, extra, flags):
    # acceptance #3 #4 #5
    _arm(monkeypatch, 0)
    calls = _spy_run(monkeypatch, subprocess.CompletedProcess([], 0, "", ""))
    seen = _seen_upgrade(monkeypatch)
    caplog.set_level(logging.INFO)
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--_self-upgrade", *extra],
    )
    assert code == 0
    assert seen == []
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == _expect_argv(flags)
    assert "--_self-upgrade" not in argv
    assert "--yes" in argv
    _assert_run_contract(kwargs)
    assert any(
        r.levelno == logging.INFO and r.message == "Re-launched upgrade in transient unit"
        for r in caplog.records
    )


def test_guard_nonzero_rc_falls_back(monkeypatch, caplog):
    # acceptance #4
    _arm(monkeypatch, 0)
    calls = _spy_run(
        monkeypatch,
        subprocess.CompletedProcess([], 3, "", "detach-stderr-marker"),
    )
    seen = _seen_upgrade(monkeypatch)
    caplog.set_level(logging.INFO)
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--_self-upgrade"],
    )
    assert code == 0
    assert len(calls) == 1
    assert seen and seen[0]["version"] == "0.1.4"
    assert any(
        r.levelno == logging.WARNING and "detach-stderr-marker" in r.message
        for r in caplog.records
    )


def test_guard_oserror_falls_back(monkeypatch, caplog):
    # acceptance #4
    _arm(monkeypatch, 0)
    calls = _spy_run(monkeypatch, FileNotFoundError("systemd-run-missing"))
    seen = _seen_upgrade(monkeypatch)
    caplog.set_level(logging.INFO)
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--_self-upgrade"],
    )
    assert code == 0
    assert len(calls) == 1
    assert seen and seen[0]["version"] == "0.1.4"
    assert any(
        r.levelno == logging.WARNING and "systemd-run-missing" in r.message
        for r in caplog.records
    )


def test_guard_timeout_exits_1_without_fallback(monkeypatch, caplog):
    # acceptance #4
    _arm(monkeypatch, 0)
    calls = _spy_run(monkeypatch, subprocess.TimeoutExpired(["systemd-run"], 30))
    seen = _seen_upgrade(monkeypatch)
    caplog.set_level(logging.INFO)
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--_self-upgrade"],
    )
    assert code == 1
    assert len(calls) == 1
    assert seen == []
    assert any(
        r.levelno == logging.ERROR and r.message == "systemd-run timed out"
        for r in caplog.records
    )


def test_guard_other_exception_falls_back(monkeypatch, caplog):
    # acceptance #4
    _arm(monkeypatch, 0)
    calls = _spy_run(monkeypatch, RuntimeError("detach-boom"))
    seen = _seen_upgrade(monkeypatch)
    caplog.set_level(logging.INFO)
    code = _run(
        monkeypatch,
        ["logstash-agent", "upgrade", "--version", "0.1.4", "--yes", "--_self-upgrade"],
    )
    assert code == 0
    assert len(calls) == 1
    assert seen and seen[0]["version"] == "0.1.4"
    assert any(
        r.levelno == logging.WARNING and "detach-boom" in r.message
        for r in caplog.records
    )

