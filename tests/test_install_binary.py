#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import logging
import os
import sys
from unittest.mock import MagicMock

import pytest

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


def test_installed_agent_version_probe_uses_host_subprocess_env(tmp_path, monkeypatch):
    dest = tmp_path / "logstash-agent"
    dest.write_text("#!/bin/sh\necho 0.5.2\n")
    dest.chmod(0o755)
    _isolate_install_paths(tmp_path, monkeypatch, binary=dest)
    monkeypatch.setattr(
        "logstashagent.install_registry.load_registry",
        lambda state_dir=None: {"package": None, "instances": {}},
    )
    expected_env = {"PATH": "/usr/bin", "SENTINEL": "1"}
    monkeypatch.setattr(installer, "host_subprocess_env", lambda: expected_env)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return MagicMock(returncode=0, stdout="0.5.2\n", stderr="")

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    assert installer.installed_agent_version() == "0.5.2"
    assert captured["cmd"] == [str(dest), "--version"]
    assert captured["kwargs"]["env"] == expected_env
    assert captured["kwargs"]["timeout"] == 10
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"].get("check") is False
    assert captured["kwargs"].get("stdin") is installer.subprocess.DEVNULL


def test_installed_agent_version_probe_oserror_logs_and_returns_none(
    tmp_path, monkeypatch, caplog
):
    dest = tmp_path / "logstash-agent"
    dest.write_text("#!/bin/sh\necho 0.5.2\n")
    dest.chmod(0o755)
    _isolate_install_paths(tmp_path, monkeypatch, binary=dest)
    monkeypatch.setattr(
        "logstashagent.install_registry.load_registry",
        lambda state_dir=None: {"package": None, "instances": {}},
    )

    def boom(*args, **kwargs):
        raise OSError("exec format error")

    monkeypatch.setattr(installer.subprocess, "run", boom)
    with caplog.at_level(logging.WARNING):
        assert installer.installed_agent_version() is None
    assert str(dest) in caplog.text


def test_installed_agent_version_probe_timeout_logs_and_returns_none(
    tmp_path, monkeypatch, caplog
):
    dest = tmp_path / "logstash-agent"
    dest.write_text("#!/bin/sh\necho 0.5.2\n")
    dest.chmod(0o755)
    _isolate_install_paths(tmp_path, monkeypatch, binary=dest)
    monkeypatch.setattr(
        "logstashagent.install_registry.load_registry",
        lambda state_dir=None: {"package": None, "instances": {}},
    )

    def boom(*args, **kwargs):
        raise installer.subprocess.TimeoutExpired(cmd=[str(dest), "--version"], timeout=10)

    monkeypatch.setattr(installer.subprocess, "run", boom)
    with caplog.at_level(logging.WARNING):
        assert installer.installed_agent_version() is None
    assert str(dest) in caplog.text


def _prepare_install_binary(
    tmp_path,
    monkeypatch,
    *,
    dest_bytes=b"DEST-BIN",
    src_bytes=b"SRC-BIN",
    frozen=True,
    create_dest=True,
    create_internal=False,
    same_file=False,
):
    """Point INSTALL_PATHS binary/binary_dir at tmp; set sys.executable/frozen."""
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    dest = binary_dir / "logstash-agent"
    if create_dest:
        dest.write_bytes(dest_bytes)
        dest.chmod(0o755)
        os.utime(dest, (1_000_000, 1_000_000))
    if same_file:
        src = dest
    else:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        src = src_dir / "logstash-agent"
        src.write_bytes(src_bytes)
        src.chmod(0o755)
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary_dir", str(binary_dir))
    monkeypatch.setitem(installer.INSTALL_PATHS, "binary", str(dest))
    monkeypatch.setattr(sys, "executable", str(src))
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    internal = None
    if create_internal:
        internal = binary_dir / "_internal"
        internal.mkdir()
        (internal / "marker").write_text("keep")
    return dest, src, binary_dir, internal


def test_install_binary_same_file_skips_copy(tmp_path, monkeypatch):
    dest, _src, _binary_dir, internal = _prepare_install_binary(
        tmp_path, monkeypatch, same_file=True, create_internal=True
    )
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns

    installer.install_binary()

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns
    assert (internal / "marker").read_text() == "keep"


def test_install_binary_same_version_skips_copy_and_internal(tmp_path, monkeypatch):
    dest, _src, _binary_dir, internal = _prepare_install_binary(
        tmp_path, monkeypatch, create_internal=True
    )
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.5.2")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns

    installer.install_binary()

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns
    assert (internal / "marker").read_text() == "keep"


def test_install_binary_unknown_version_raises_and_leaves_dest(tmp_path, monkeypatch):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(tmp_path, monkeypatch)
    monkeypatch.setattr(installer, "installed_agent_version", lambda: None)
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns

    with pytest.raises(installer.InstallError, match="version"):
        installer.install_binary()

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns


def test_install_binary_dest_newer_skips(tmp_path, monkeypatch, caplog):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(tmp_path, monkeypatch)
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.9.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns

    with caplog.at_level(logging.WARNING):
        installer.install_binary()

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns
    assert "0.9.0" in caplog.text


def test_install_binary_dest_older_leaves_dest_unchanged(tmp_path, monkeypatch):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(tmp_path, monkeypatch)
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns

    installer.install_binary()

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns


def test_install_binary_missing_dest_atomic_install(tmp_path, monkeypatch):
    dest, src, _binary_dir, _internal = _prepare_install_binary(
        tmp_path, monkeypatch, create_dest=False, frozen=False
    )
    copy_dests = []
    real_copy2 = installer.shutil.copy2

    def spy_copy2(src_path, dst_path, *args, **kwargs):
        copy_dests.append(os.path.abspath(str(dst_path)))
        return real_copy2(src_path, dst_path, *args, **kwargs)

    monkeypatch.setattr(installer.shutil, "copy2", spy_copy2)

    installer.install_binary()

    assert dest.is_file()
    assert dest.read_bytes() == src.read_bytes()
    assert not os.path.exists(f"{dest}.new")
    dest_abs = os.path.abspath(str(dest))
    assert dest_abs not in copy_dests
    assert os.access(dest, os.X_OK)
