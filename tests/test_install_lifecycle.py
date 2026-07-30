#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Install lifecycle: enable+start agent; package logstash enable-only."""

from unittest.mock import MagicMock, call, patch

from logstashagent import installer


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
        a[:3] == ["systemctl", "enable", "--now"] or a == ["systemctl", "enable", "--now", "logstash-agent"]
        for a in args_list
    ) or any(a[:4] == ["systemctl", "enable", "--now", "logstash-agent"] for a in args_list)


def test_enable_simulate_services_starts_agent_not_logstash():
    with patch.object(installer.subprocess, "run") as run:
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        installer.enable_simulate_services(3)
    args_list = [tuple(c.args[0]) for c in run.call_args_list]
    assert ("systemctl", "enable", "ls-simulate@3") in args_list
    # Agent enable --now or enable+start
    joined = [" ".join(a) for a in args_list]
    assert any("lsagent-simulate@3" in j and ("--now" in j or "start" in j) for j in joined)
    # Must not start ls-simulate@3 at install
    assert ("systemctl", "start", "ls-simulate@3") not in args_list
    assert not any(j == "systemctl enable --now ls-simulate@3" for j in joined)
