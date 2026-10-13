#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""upgrade CLI flags (acceptance #4 #9 #11 and #10 exit 1)."""

import runpy
import sys

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
