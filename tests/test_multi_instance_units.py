#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Managed multi-instance unit names, materialize, and template install."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _instance_policy(root: Path, policy_type: str, **extra) -> dict:
    policy = {
        "policy_type": policy_type,
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
        "log4j2_properties": "status=error\n",
    }
    policy.update(extra)
    return policy


def _materialize(policy: dict) -> dict:
    with patch.object(installer, "get_logstash_uid_gid", return_value=(0, 0)), patch.object(
        installer.os, "chown", create=True
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ):
        return installer.materialize_simulate_instance(policy)


@pytest.mark.parametrize("policy_type", ["MANAGED", "SIMULATE"])
def test_env_file_exports_ls_jvm_opts(tmp_path, monkeypatch, policy_type):
    """The env file must name jvm.options outright, not rely on the argv scan."""
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    root = tmp_path / "inst"
    policy = _instance_policy(root, policy_type, jvm_options="-Xmx1234m\n")

    _materialize(policy)

    settings = root / "settings"
    assert f"LS_JVM_OPTS={settings}/jvm.options" in (root / "env").read_text()
    assert (settings / "jvm.options").read_text() == "-Xmx1234m\n"


def test_env_file_omits_ls_jvm_opts_when_no_jvm_options(tmp_path, monkeypatch):
    """
    LS_JVM_OPTS naming a missing file makes JvmOptionsParser fail and Logstash
    refuse to start, so a policy with no jvm_options must not get the line.
    """
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    root = tmp_path / "inst"

    _materialize(_instance_policy(root, "MANAGED"))

    assert not (root / "settings" / "jvm.options").exists()
    assert "LS_JVM_OPTS" not in (root / "env").read_text()


def test_materialize_makes_jvm_options_readable(tmp_path, monkeypatch):
    """
    logstash.lib.sh only honours jvm.options when `[ -r ... ]` passes for the
    logstash user; a restrictive umask would otherwise revert Logstash to stock
    JVM settings.
    """
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    root = tmp_path / "inst"
    old_umask = os.umask(0o077)
    try:
        _materialize(_instance_policy(root, "MANAGED", jvm_options="-Xmx1234m\n"))
    finally:
        os.umask(old_umask)

    mode = (root / "settings" / "jvm.options").stat().st_mode & 0o777
    assert mode == 0o644, oct(mode)


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


def test_no_template_uses_equals_form_path_settings():
    """
    Regression guard for the whole class of bug.

    logstash.lib.sh discovers jvm.options by scanning "$@" for an argv entry
    *equal to* "--path.settings" and reading the next one. With
    `--path.settings=<dir>` it never matches, LS_JVM_OPTS is never exported, and
    Logstash silently uses the stock jvm.options from LOGSTASH_HOME — so
    policy-pushed heap settings never reach the JVM and nothing is logged.
    """
    d = installer._systemd_template_dir()
    for path in sorted(d.glob("*.service")):
        # Comments are inert; only directives matter.
        directives = [
            ln for ln in path.read_text().splitlines()
            if not ln.lstrip().startswith("#")
        ]
        assert "--path.settings=" not in "\n".join(directives), (
            f"{path.name} uses the equals form; jvm.options will be ignored"
        )


def test_logstash_templates_pass_path_settings_as_two_args():
    d = installer._systemd_template_dir()
    for name in ("ls-simulate@.service", "logstash-managed@.service"):
        text = (d / name).read_text()
        assert '--path.settings "${LOGSTASH_PATH_SETTINGS}"' in text, name


def test_installed_templates_always_run_as_logstash(tmp_path, monkeypatch):
    """
    Every unit must declare User=logstash as shipped. These used to be written
    with `# User=logstash` commented out and uncommented only when the account
    happened to resolve, so a host without the Logstash DEB/RPM silently ran
    Logstash as root.
    """
    dests = {
        "lsagent_simulate_unit": str(tmp_path / "lsagent-simulate@.service"),
        "ls_simulate_unit": str(tmp_path / "ls-simulate@.service"),
        "logstash_agent_template_unit": str(tmp_path / "logstash-agent@.service"),
        "logstash_managed_unit": str(tmp_path / "logstash-managed@.service"),
    }
    for k, v in dests.items():
        monkeypatch.setitem(installer.INSTALL_PATHS, k, v)

    # No logstash account on this host — must make no difference.
    fake_pwd = MagicMock()
    fake_pwd.getpwnam.side_effect = KeyError("logstash")
    fake_grp = MagicMock()
    fake_grp.getgrnam.side_effect = KeyError("logstash")
    monkeypatch.setattr(installer, "pwd", fake_pwd)
    monkeypatch.setattr(installer, "grp", fake_grp)

    with patch.object(installer.subprocess, "run", return_value=type("R", (), {"returncode": 0})()):
        installer.install_multi_instance_unit_templates()

    for name, path in dests.items():
        text = Path(path).read_text()
        assert "\nUser=logstash" in text, f"{name} missing User=logstash"
        assert "\nGroup=logstash" in text, f"{name} missing Group=logstash"
        assert "# User=logstash" not in text, f"{name} still has User= commented out"
