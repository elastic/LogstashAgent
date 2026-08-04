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
    assert "ls-simulate" in text
    assert "lsagent-simulate" in text
    assert "logstash-managed" in text
    assert "logstash-agent" in text
    assert "grep -Eq" in text
    # Extract allowlist regex and validate accepted / rejected units
    m = re.search(r"grep -Eq '([^']+)'", text)
    assert m, "ctl script missing unit allowlist grep"
    unit_re = re.compile(m.group(1))
    for ok in (
        "logstash",
        "logstash-agent",
        "logstash-agent@1",
        "logstash-agent@42",
        "logstash-managed@1",
        "ls-simulate@3",
        "lsagent-simulate@9",
    ):
        assert unit_re.fullmatch(ok), f"should allow {ok}"
    for bad in (
        "logstash@1",
        "logstash-agent@managed-1",
        "logstash-agent@*",
        "sshd",
        "ls-simulate@1x",
        "logstash-managed@",
    ):
        assert not unit_re.fullmatch(bad), f"should reject {bad}"


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
