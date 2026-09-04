#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

from logstashagent import installer
from logstashagent.main import parse_arguments, AGENT_VERSION, _is_lightweight_cli


def test_top_level_version_is_lightweight():
    assert _is_lightweight_cli(["--version"]) is True


def test_parse_arguments_version(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["logstash-agent", "--version"])
    try:
        parse_arguments()
    except SystemExit as e:
        assert e.code == 0
    else:
        raise AssertionError("expected SystemExit")
    assert AGENT_VERSION in capsys.readouterr().out


def test_upgrade_version_still_parses(monkeypatch):
    monkeypatch.setattr("sys.argv", ["logstash-agent", "upgrade", "--version", "0.1.4"])
    args = parse_arguments()
    assert args.command == "upgrade"
    assert args.version == "0.1.4"


def _isolate_install_paths(tmp_path, monkeypatch, *, binary=None):
    """Point package paths at tmp so tests never read/write /opt."""
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(state))
    dest = binary if binary is not None else tmp_path / "missing-bin"
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(dest))
    return state


def test_installed_agent_version_from_registry(tmp_path, monkeypatch):
    dest = tmp_path / "logstash-agent"
    dest.write_text("#!/bin/sh\necho 9.9.9\n")
    dest.chmod(0o755)
    _isolate_install_paths(tmp_path, monkeypatch, binary=dest)
    monkeypatch.setattr(
        "logstashagent.install_registry.load_registry",
        lambda state_dir=None: {"package": {"agent_version": "0.5.1"}, "instances": {}},
    )
    assert installer.installed_agent_version() == "0.5.1"


def test_installed_agent_version_probes_dest_when_registry_empty(tmp_path, monkeypatch):
    dest = tmp_path / "logstash-agent"
    dest.write_text("#!/bin/sh\necho 0.5.2\n")
    dest.chmod(0o755)
    _isolate_install_paths(tmp_path, monkeypatch, binary=dest)
    monkeypatch.setattr(
        "logstashagent.install_registry.load_registry",
        lambda state_dir=None: {"package": {"agent_version": ""}, "instances": {}},
    )
    assert installer.installed_agent_version() == "0.5.2"


def test_compare_agent_versions():
    assert installer.compare_agent_versions("0.5.1", "0.5.2") < 0
    assert installer.compare_agent_versions("0.5.2", "0.5.2") == 0
    assert installer.compare_agent_versions("0.5.3", "0.5.2") > 0


def test_installed_agent_version_none_when_missing_or_probe_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "logstashagent.install_registry.load_registry",
        lambda state_dir=None: {"package": None, "instances": {}},
    )
    _isolate_install_paths(tmp_path, monkeypatch)
    assert installer.installed_agent_version() is None

    dest = tmp_path / "bad-bin"
    dest.write_text("#!/bin/sh\necho not-a-version\nexit 1\n")
    dest.chmod(0o755)
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(dest))
    assert installer.installed_agent_version() is None
