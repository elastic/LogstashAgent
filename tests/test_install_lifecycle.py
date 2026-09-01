#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Install lifecycle: enable+start agent; package logstash enable-only."""

from unittest.mock import MagicMock, patch

import pytest

from logstashagent import installer
from logstashagent.installer import InstallError


def test_enable_package_logstash_only_never_starts():
    with patch.object(installer.subprocess, "run") as run:
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        installer.enable_package_logstash_only()
    args_list = [c.args[0] for c in run.call_args_list]
    assert any(a[:3] == ["systemctl", "enable", "logstash"] for a in args_list)
    for a in args_list:
        assert "start" not in a
        assert "--now" not in a


def test_enable_and_start_default_agent_uses_enable_now():
    with patch.object(installer.subprocess, "run") as run:
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        installer.enable_and_start_default_agent()
    args_list = [c.args[0] for c in run.call_args_list]
    assert any(
        a[:3] == ["systemctl", "enable", "--now"]
        or a == ["systemctl", "enable", "--now", "logstash-agent"]
        for a in args_list
    ) or any(a[:4] == ["systemctl", "enable", "--now", "logstash-agent"] for a in args_list)


def _systemctl_side_effect(cmd, **kwargs):
    """Simulate successful enable / is-enabled / is-active for multi-instance units."""
    args = list(cmd)
    # cmd is ['systemctl', ...]
    action = args[1] if len(args) > 1 else ""
    unit = args[-1] if len(args) > 2 else ""
    r = MagicMock(returncode=0, stdout="enabled\n", stderr="")
    if action == "is-enabled":
        r.stdout = "enabled\n"
    elif action == "is-active":
        # Logstash unit is enable-only (not started)
        if unit.startswith("ls-simulate") or unit.startswith("logstash-managed"):
            r.returncode = 3
            r.stdout = "inactive\n"
        else:
            r.stdout = "active\n"
    return r


def test_enable_simulate_services_starts_agent_not_logstash():
    with patch.object(installer.subprocess, "run", side_effect=_systemctl_side_effect) as run:
        status = installer.enable_simulate_services(3)
    args_list = [tuple(c.args[0]) for c in run.call_args_list]
    assert ("systemctl", "enable", "ls-simulate@3") in args_list
    joined = [" ".join(a) for a in args_list]
    assert any("lsagent-simulate@3" in j and ("--now" in j or "start" in j) for j in joined)
    # Must not start ls-simulate@3 at install
    assert ("systemctl", "start", "ls-simulate@3") not in args_list
    assert not any(j == "systemctl enable --now ls-simulate@3" for j in joined)
    assert status["agent_enabled"] is True
    assert status["agent_active"] is True
    assert status["ls_enabled"] is True


def test_host_subprocess_env_strips_frozen_ld_library_path(monkeypatch):
    """PyInstaller LD_LIBRARY_PATH must not reach systemctl (OpenSSL clash)."""
    monkeypatch.setenv("LD_LIBRARY_PATH", "/root/logstash-agent/_internal")
    monkeypatch.setenv("DYLD_LIBRARY_PATH", "/root/logstash-agent/_internal")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/lib")
    env = installer.host_subprocess_env()
    assert env.get("LD_LIBRARY_PATH") == "/usr/lib"
    assert "DYLD_LIBRARY_PATH" not in env


def test_host_subprocess_env_clears_ld_when_no_orig(monkeypatch):
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_internal")
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
    env = installer.host_subprocess_env()
    assert "LD_LIBRARY_PATH" not in env


def test_systemctl_cmd_passes_clean_env(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/logstash-agent/bin/_internal")
    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    installer._systemctl_cmd("daemon-reload")
    assert captured["cmd"][0] in ("/usr/bin/systemctl", "/bin/systemctl", "systemctl")
    assert "daemon-reload" in captured["cmd"]
    assert captured["env"] is not None
    assert "/_internal" not in (captured["env"].get("LD_LIBRARY_PATH") or "")


def test_enable_simulate_services_raises_when_enable_fails():
    def _fail(cmd, **kwargs):
        args = list(cmd)
        r = MagicMock(returncode=1, stdout="", stderr="Failed to enable unit")
        action = args[1] if len(args) > 1 else ""
        if action in ("is-enabled", "is-active"):
            r.returncode = 1
            r.stdout = "disabled\n" if action == "is-enabled" else "inactive\n"
        if action == "daemon-reload":
            r.returncode = 0
            r.stderr = ""
        return r

    with patch.object(installer.subprocess, "run", side_effect=_fail):
        with pytest.raises(InstallError, match="Failed to enable/start"):
            installer.enable_simulate_services(1)
