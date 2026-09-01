#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Managed multi-instance unit names, materialize, and template install."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from logstashagent import installer


def test_resolve_multi_instance_units_managed():
    agent, ls = installer.resolve_multi_instance_units(2, 'MANAGED')
    assert agent == 'logstash-agent@2'
    assert ls == 'logstash-managed@2'


def test_resolve_multi_instance_units_simulate():
    agent, ls = installer.resolve_multi_instance_units(3, 'SIMULATE')
    assert agent == 'lsagent-simulate@3'
    assert ls == 'ls-simulate@3'


def test_resolve_multi_instance_units_honors_explicit():
    agent, ls = installer.resolve_multi_instance_units(
        1,
        'MANAGED',
        agent_unit='logstash-agent@9',
        logstash_unit='logstash-managed@9',
    )
    assert agent == 'logstash-agent@9'
    assert ls == 'logstash-managed@9'


def test_materialize_managed_tree(tmp_path, monkeypatch):
    root = tmp_path / "managed-1"
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))

    policy = {
        "policy_type": "MANAGED",
        "instance_id": 1,
        "path_root": str(root),
        "settings_path": str(root / "settings"),
        "config_path": str(root / "config"),
        "logs_path": str(root / "logs"),
        "data_path": str(root / "data"),
        "keystore_env_file": str(root / "env"),
        "binary_path": "/usr/share/logstash/bin",
        "logstash_source": "SYSTEM",
        "agent_api_port": 9601,
        "logstash_api_port": 9701,
        "logstash_yml": "api.http.port: 9701\n",
        "jvm_options": "-Xms1g\n",
        "log4j2_properties": "status=error\n",
        "agent_unit": "logstash-agent@1",
        "logstash_unit": "logstash-managed@1",
    }

    with patch.object(installer, "get_logstash_uid_gid", return_value=(0, 0)), patch.object(
        installer.os, "chown", create=True
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ):
        result = installer.materialize_simulate_instance(policy)

    assert result["agent_unit"] == "logstash-agent@1"
    assert result["logstash_unit"] == "logstash-managed@1"
    assert result["mode"] == "managed"
    assert (root / "settings" / "logstash.yml").is_file()
    assert (root / "env").is_file()
    agent_env = (root / "agent.env").read_text()
    assert "AGENT_MODE=managed" in agent_env
    assert "AGENT_UNIT=logstash-agent@1" in agent_env
    # No simulate harness confs for managed
    assert not (root / "settings" / "conf.d" / "simulate-start.conf").exists()
    pipelines = (root / "settings" / "pipelines.yml").read_text()
    assert "agent-placeholder" in pipelines or "Managed by LogstashAgent" in pipelines


def test_unit_templates_exist_on_disk():
    d = installer._systemd_template_dir()
    for name in (
        "lsagent-simulate@.service",
        "ls-simulate@.service",
        "logstash-agent@.service",
        "logstash-managed@.service",
    ):
        p = d / name
        assert p.is_file(), f"missing template {p}"
    managed_agent = (d / "logstash-agent@.service").read_text()
    assert "--mode managed" in managed_agent
    assert "managed-%i" in managed_agent
    managed_ls = (d / "logstash-managed@.service").read_text()
    assert "managed-%i" in managed_ls


@pytest.mark.skipif(sys.platform == 'win32', reason='Uses POSIX pwd module for logstash user injection')
def test_install_multi_instance_templates(tmp_path, monkeypatch):
    dests = {
        "lsagent_simulate_unit": str(tmp_path / "lsagent-simulate@.service"),
        "ls_simulate_unit": str(tmp_path / "ls-simulate@.service"),
        "logstash_agent_template_unit": str(tmp_path / "logstash-agent@.service"),
        "logstash_managed_unit": str(tmp_path / "logstash-managed@.service"),
    }
    for k, v in dests.items():
        monkeypatch.setitem(installer.INSTALL_PATHS, k, v)

    with patch.object(installer.subprocess, "run", return_value=type("R", (), {"returncode": 0})()):
        installer.install_multi_instance_unit_templates()

    for path in dests.values():
        assert Path(path).is_file()
    assert "--mode managed" in Path(dests["logstash_agent_template_unit"]).read_text()
