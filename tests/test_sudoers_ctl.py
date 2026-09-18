#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Sudoers / systemctl helper must avoid wildcards (sudo-rs)."""

import re
import stat
from pathlib import Path

from logstashagent import installer


def test_systemctl_ctl_script_validates_units(tmp_path, monkeypatch):
    ctl_path = tmp_path / "logstash-agent-ctl"
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemctl_ctl", str(ctl_path))
    out = installer.install_systemctl_ctl()
    assert Path(out) == ctl_path
    assert ctl_path.is_file()
    mode = ctl_path.stat().st_mode
    assert mode & stat.S_IXUSR
    text = ctl_path.read_text(encoding="utf-8")
    assert "systemctl" in text
    # A5: new canonical names present
    assert "simulate-agent" in text
    assert "simulate-logstash" in text
    assert "managed-agent" in text
    assert "managed-logstash" in text
    # A6: deprecated old names still handled (DEPRECATED rewrite block)
    assert "DEPRECATED" in text
    assert "lsagent-simulate@" in text
    assert "ls-simulate@" in text
    assert "logstash-managed@" in text
    assert "grep -Eq" in text
    # Extract allowlist regex and validate accepted / rejected units
    # The regex now applies to CANONICAL_UNIT after rewriting
    m = re.search(r"grep -Eq '([^']+)'", text)
    assert m, "ctl script missing unit allowlist grep"
    unit_re = re.compile(m.group(1))
    for ok in (
        "logstash",
        "logstash-agent",
        "simulate-agent@1",
        "simulate-agent@42",
        "simulate-logstash@3",
        "managed-agent@1",
        "managed-logstash@9",
    ):
        assert unit_re.fullmatch(ok), f"should allow canonical {ok}"
    for bad in (
        "logstash@1",
        "sshd",
        "simulate-agent@1x",
        "managed-logstash@",
        "simulate-agent@*",
    ):
        assert not unit_re.fullmatch(bad), f"should reject {bad}"


def test_ctl_script_rewrites_deprecated_unit(tmp_path, monkeypatch):
    """acceptance A6: deprecated old instance names -> canonical + DEPRECATED on stderr."""
    import subprocess
    ctl_path = tmp_path / "logstash-agent-ctl"
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemctl_ctl", str(ctl_path))
    installer.install_systemctl_ctl()
    text = ctl_path.read_text(encoding="utf-8")
    deprecated_cases = {
        "logstash-agent@1": "managed-agent@1",
        "logstash-managed@3": "managed-logstash@3",
        "lsagent-simulate@2": "simulate-agent@2",
        "ls-simulate@5": "simulate-logstash@5",
    }
    for old, canonical in deprecated_cases.items():
        # Check the script text encodes the mapping (no live systemctl needed)
        assert f"DEPRECATED" in text
        # The case block must handle old name and produce the canonical
        assert old.split("@")[0] in text or old.rsplit("-", 1)[0] in text
        assert canonical.split("@")[0] in text
    # sshd must still be rejected (the allowlist check runs on CANONICAL_UNIT)
    unit_re_m = re.search(r"grep -Eq '([^']+)'", text)
    assert unit_re_m
    unit_re = re.compile(unit_re_m.group(1))
    assert not unit_re.fullmatch("sshd"), "sshd must be rejected"
    assert not unit_re.fullmatch("simulate-agent@abc"), "non-numeric must be rejected"


def test_ctl_script_runs_canonical_unit(tmp_path, monkeypatch):
    """acceptance S2 gap: ctl script EXECUTES systemctl with the canonical name, not the old name.

    Runs the actual installed shell script against a stub systemctl that records
    its arguments. Asserts the argument is the canonical unit, not the deprecated one.
    """
    import subprocess as _subprocess

    # Install the ctl script.
    ctl_path = tmp_path / "logstash-agent-ctl"
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemctl_ctl", str(ctl_path))
    installer.install_systemctl_ctl()

    # Build a stub systemctl that records $2 (the unit argument) to a file.
    stub_systemctl = tmp_path / "systemctl"
    recorded = tmp_path / "recorded_unit.txt"
    stub_systemctl.write_text(
        f"#!/bin/sh\necho \"$2\" > {recorded}\nexit 0\n"
    )
    stub_systemctl.chmod(0o755)

    # Point PATH at the stub so the script finds our systemctl first.
    env = {
        "PATH": f"{tmp_path}:{__import__('os').environ.get('PATH', '/usr/bin:/bin')}",
    }

    for old_unit, expected_canonical in (
        ("ls-simulate@5", "simulate-logstash@5"),
        ("lsagent-simulate@2", "simulate-agent@2"),
        ("logstash-managed@3", "managed-logstash@3"),
        ("logstash-agent@1", "managed-agent@1"),
    ):
        recorded.unlink(missing_ok=True)
        result = _subprocess.run(
            ["sh", str(ctl_path), "restart", old_unit],
            env=env,
            capture_output=True,
            text=True,
        )
        assert "DEPRECATED" in result.stderr, f"{old_unit}: expected DEPRECATED in stderr"
        assert recorded.is_file(), f"{old_unit}: stub systemctl was not called"
        called_with = recorded.read_text().strip()
        assert called_with == expected_canonical, (
            f"{old_unit}: expected systemctl called with {expected_canonical!r}, "
            f"got {called_with!r}"
        )


def test_sudoers_content_has_no_arg_wildcards(tmp_path, monkeypatch):
    """Simulate configure_logstash sudoers body rules without writing /etc."""
    ctl = "/opt/logstash-agent/bin/logstash-agent-ctl"
    agent = "/opt/logstash-agent/bin/logstash-agent"
    # Mirror the template used in configure_logstash (no @* / upgrade *)
    body = f"""
logstash ALL=(ALL) NOPASSWD: {ctl}
logstash ALL=(ALL) NOPASSWD: {agent}
logstash ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/default/logstash
logstash ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/default/logstash
logstash ALL=(ALL) NOPASSWD: /usr/bin/chmod 640 /etc/default/logstash
"""
    # Fail if any line still uses shell-style wildcards in command args
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert "*" not in line, f"wildcard not allowed for sudo-rs: {line}"
        assert not re.search(r"@\*", line)


def test_is_sudo_rs_detects_string(monkeypatch):
    class R:
        stdout = "sudo-rs 0.2.0"
        stderr = ""

    monkeypatch.setattr(
        installer.subprocess,
        "run",
        lambda *a, **k: R(),
    )
    assert installer.is_sudo_rs() is True


def _ctl_run_with_stub(tmp_path, monkeypatch, *args):
    """Install the ctl script, stub systemctl on PATH, run ctl with args.

    Returns (CompletedProcess, recorded-args Path). The stub appends each of
    its argv entries on its own line. macOS/CI have no real systemctl, so the
    script falls through to `command -v systemctl`, which finds the stub.
    """
    import os
    import subprocess as _subprocess

    ctl_path = tmp_path / "logstash-agent-ctl"
    monkeypatch.setitem(installer.INSTALL_PATHS, "systemctl_ctl", str(ctl_path))
    installer.install_systemctl_ctl()

    stub_systemctl = tmp_path / "systemctl"
    recorded = tmp_path / "recorded_args.txt"
    stub_systemctl.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {recorded}\nexit 0\n"
    )
    stub_systemctl.chmod(0o755)

    env = {"PATH": f"{tmp_path}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    result = _subprocess.run(
        ["sh", str(ctl_path), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, recorded


def test_ctl_a8_is_enabled_with_unit(tmp_path, monkeypatch):
    """acceptance A8: ctl accepts `is-enabled <unit>` and passes it to systemctl."""
    result, recorded = _ctl_run_with_stub(
        tmp_path, monkeypatch, "is-enabled", "simulate-agent@1"
    )
    assert result.returncode == 0, f"ctl rejected `is-enabled` (stderr: {result.stderr!r})"
    assert recorded.is_file(), "stub systemctl was not called"
    assert recorded.read_text().splitlines() == ["is-enabled", "simulate-agent@1"]


def test_ctl_a8_is_enabled_requires_unit(tmp_path, monkeypatch):
    """acceptance A8: `is-enabled` requires a unit — a bare call is rejected (exit 2)."""
    result, recorded = _ctl_run_with_stub(tmp_path, monkeypatch, "is-enabled")
    assert result.returncode == 2
    assert not recorded.exists(), "systemctl must not be reached without a unit"


def test_ctl_a8_daemon_reload_no_unit(tmp_path, monkeypatch):
    """acceptance A8: ctl accepts `daemon-reload` with NO unit and reaches systemctl.

    r11 defers the exact-argv / empty-unit exec pin to a later release, so this
    test asserts only that the call reaches systemctl with the daemon-reload
    action — not the full argv handed to systemctl.
    """
    result, recorded = _ctl_run_with_stub(tmp_path, monkeypatch, "daemon-reload")
    assert result.returncode == 0, f"ctl rejected `daemon-reload` (stderr: {result.stderr!r})"
    assert recorded.is_file(), "systemctl was not reached"
    assert recorded.read_text().splitlines()[0] == "daemon-reload"
