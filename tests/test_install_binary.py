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


def _spy_copy2(monkeypatch):
    copy_dests = []
    real_copy2 = installer.shutil.copy2

    def spy_copy2(src_path, dst_path, *args, **kwargs):
        copy_dests.append(os.path.abspath(str(dst_path)))
        return real_copy2(src_path, dst_path, *args, **kwargs)

    monkeypatch.setattr(installer.shutil, "copy2", spy_copy2)
    return copy_dests


def _stub_binary_side_effects(monkeypatch):
    monkeypatch.setattr(installer, "_restorecon_binary", lambda _dest: None)
    restart = MagicMock()
    monkeypatch.setattr(installer, "_restart_running_agent_units", restart)
    return restart


def _stub_perform_installation_around_binary(monkeypatch, tmp_path):
    """Patch prereqs and post-binary steps so perform_installation reaches enroll."""

    def _noop(*_a, **_k):
        return None

    for name in (
        "verify_root",
        "verify_platform",
        "ensure_logstash_user",
        "create_directories",
        "create_symlink",
        "write_config_file",
        "install_multi_instance_unit_templates",
        "install_systemd_service",
        "enable_and_start_default_agent",
        "enable_package_logstash_only",
        "configure_logstash",
        "_restorecon_binary",
        "_restart_running_agent_units",
    ):
        monkeypatch.setattr(installer, name, _noop)
    monkeypatch.setattr(installer, "verify_logstash_installed", lambda: False)
    monkeypatch.setattr(
        installer, "get_logstash_uid_gid", lambda: (os.getuid(), os.getgid())
    )
    state = tmp_path / "state"
    logs = tmp_path / "logs"
    config = tmp_path / "config"
    opt = tmp_path / "opt"
    for d in (state, logs, config, opt):
        d.mkdir(exist_ok=True)
    monkeypatch.setitem(installer.INSTALL_PATHS, "state_dir", str(state))
    monkeypatch.setitem(installer.INSTALL_PATHS, "log_dir", str(logs))
    monkeypatch.setitem(installer.INSTALL_PATHS, "config_dir", str(config))
    monkeypatch.setitem(installer.INSTALL_PATHS, "opt_root", str(opt))
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(opt))
    monkeypatch.setitem(
        installer.INSTALL_PATHS,
        "systemd_service",
        str(tmp_path / "logstash-agent.service"),
    )


def test_install_binary_dest_older_assume_yes_replaces_atomic(tmp_path, monkeypatch):
    dest, src, _binary_dir, _internal = _prepare_install_binary(
        tmp_path, monkeypatch, frozen=False
    )
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    restart = _stub_binary_side_effects(monkeypatch)
    copy_dests = _spy_copy2(monkeypatch)

    def boom(_prompt=""):
        raise AssertionError("input must not be called when assume_yes=True")

    monkeypatch.setattr("builtins.input", boom)

    installer.install_binary(assume_yes=True)

    assert dest.read_bytes() == src.read_bytes()
    assert not os.path.exists(f"{dest}.new")
    assert not os.path.exists(f"{dest}.backup")
    dest_abs = os.path.abspath(str(dest))
    assert dest_abs not in copy_dests
    assert os.access(dest, os.X_OK)
    restart.assert_called_once()


def test_install_binary_dest_older_input_n_leaves_dest(tmp_path, monkeypatch):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(tmp_path, monkeypatch)
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns
    prompts = []

    def fake_input(prompt=""):
        prompts.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", fake_input)
    restart = MagicMock()
    monkeypatch.setattr(installer, "_restart_running_agent_units", restart)

    installer.install_binary()

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns
    assert prompts, "expected upgrade prompt"
    assert "0.4.0" in prompts[0]
    assert "0.5.2" in prompts[0]
    assert "[y/N]" in prompts[0]
    restart.assert_not_called()


def test_install_binary_dest_older_input_y_replaces(tmp_path, monkeypatch):
    dest, src, _binary_dir, _internal = _prepare_install_binary(
        tmp_path, monkeypatch, frozen=False
    )
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    restart = _stub_binary_side_effects(monkeypatch)
    prompts = []

    def fake_input(prompt=""):
        prompts.append(prompt)
        return "y"

    monkeypatch.setattr("builtins.input", fake_input)

    installer.install_binary()

    assert dest.read_bytes() == src.read_bytes()
    assert not os.path.exists(f"{dest}.new")
    assert not os.path.exists(f"{dest}.backup")
    assert prompts, "expected upgrade prompt"
    assert "0.4.0" in prompts[0]
    assert "0.5.2" in prompts[0]
    assert "[y/N]" in prompts[0]
    restart.assert_called_once()


def test_perform_installation_dest_older_assume_yes_still_enrolls(
    tmp_path, monkeypatch
):
    dest, src, _binary_dir, _internal = _prepare_install_binary(
        tmp_path, monkeypatch, frozen=False
    )
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    _stub_perform_installation_around_binary(monkeypatch, tmp_path)
    copy_dests = _spy_copy2(monkeypatch)
    order = []
    real_install = installer.install_binary

    def tracking_install(*, assume_yes=False):
        order.append("install_binary")
        return real_install(assume_yes=assume_yes)

    monkeypatch.setattr(installer, "install_binary", tracking_install)

    def enrollment_func(*_a, **_k):
        order.append("enrollment")
        return {}

    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt="": (_ for _ in ()).throw(
            AssertionError("input must not be called when assume_yes=True")
        ),
    )

    installer.perform_installation(
        enroll_token="tok",
        logstash_ui_url="http://example.test",
        agent_id="agent-1",
        enrollment_func=enrollment_func,
        assume_yes=True,
    )

    assert dest.read_bytes() == src.read_bytes()
    assert not os.path.exists(f"{dest}.new")
    assert not os.path.exists(f"{dest}.backup")
    dest_abs = os.path.abspath(str(dest))
    assert dest_abs not in copy_dests
    assert order == ["install_binary", "enrollment"]


def test_perform_installation_dest_older_input_n_still_enrolls(tmp_path, monkeypatch):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(
        tmp_path, monkeypatch, frozen=False
    )
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    _stub_perform_installation_around_binary(monkeypatch, tmp_path)
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    enrollment_func = MagicMock(return_value={})

    installer.perform_installation(
        enroll_token="tok",
        logstash_ui_url="http://example.test",
        agent_id="agent-1",
        enrollment_func=enrollment_func,
    )

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns
    enrollment_func.assert_called_once()


def test_install_binary_dest_older_input_eof_leaves_dest(tmp_path, monkeypatch):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(tmp_path, monkeypatch)
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns

    def eof(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    restart = MagicMock()
    monkeypatch.setattr(installer, "_restart_running_agent_units", restart)

    installer.install_binary()

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns
    restart.assert_not_called()


def test_install_binary_dest_older_input_empty_leaves_dest(tmp_path, monkeypatch):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(tmp_path, monkeypatch)
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    before = dest.read_bytes()
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    restart = MagicMock()
    monkeypatch.setattr(installer, "_restart_running_agent_units", restart)

    installer.install_binary()

    assert dest.read_bytes() == before
    restart.assert_not_called()


def test_perform_installation_dest_older_input_eof_still_enrolls(
    tmp_path, monkeypatch
):
    dest, _src, _binary_dir, _internal = _prepare_install_binary(
        tmp_path, monkeypatch, frozen=False
    )
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    _stub_perform_installation_around_binary(monkeypatch, tmp_path)
    before = dest.read_bytes()
    mtime_ns = dest.stat().st_mtime_ns

    def eof(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    enrollment_func = MagicMock(return_value={})

    installer.perform_installation(
        enroll_token="tok",
        logstash_ui_url="http://example.test",
        agent_id="agent-1",
        enrollment_func=enrollment_func,
    )

    assert dest.read_bytes() == before
    assert dest.stat().st_mtime_ns == mtime_ns
    enrollment_func.assert_called_once()


def test_install_binary_dest_older_assume_yes_replaces_internal(
    tmp_path, monkeypatch
):
    dest, src, binary_dir, dest_internal = _prepare_install_binary(
        tmp_path, monkeypatch, frozen=True, create_internal=True
    )
    src_internal = src.parent / "_internal"
    src_internal.mkdir()
    (src_internal / "marker").write_text("new")
    monkeypatch.setattr(installer, "installed_agent_version", lambda: "0.4.0")
    monkeypatch.setattr(installer, "source_agent_version", lambda: "0.5.2")
    restart = _stub_binary_side_effects(monkeypatch)

    installer.install_binary(assume_yes=True)

    assert dest.read_bytes() == src.read_bytes()
    assert (dest_internal / "marker").read_text() == "new"
    assert not os.path.exists(f"{dest}.backup")
    assert not os.path.exists(binary_dir / "_internal.backup")
    restart.assert_called_once()


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
    monkeypatch.setattr(installer, "_restorecon_binary", lambda _dest: None)

    installer.install_binary()

    assert dest.is_file()
    assert dest.read_bytes() == src.read_bytes()
    assert not os.path.exists(f"{dest}.new")
    dest_abs = os.path.abspath(str(dest))
    assert dest_abs not in copy_dests
    assert os.access(dest, os.X_OK)


def test_install_binary_atomic_cleans_dest_new_on_oserror(tmp_path, monkeypatch):
    dest, src, _binary_dir, _internal = _prepare_install_binary(
        tmp_path, monkeypatch, create_dest=False, frozen=False
    )
    real_copy2 = installer.shutil.copy2

    def copy2_then_fail(src_path, dst_path, *args, **kwargs):
        real_copy2(src_path, dst_path, *args, **kwargs)
        raise OSError("simulated failure after dest.new")

    monkeypatch.setattr(installer.shutil, "copy2", copy2_then_fail)

    with pytest.raises(OSError, match="simulated failure after dest.new"):
        installer._install_binary_atomic(str(src), str(dest))

    assert not dest.exists()
    assert not os.path.exists(f"{dest}.new")


def test_source_agent_version_returns_dotted_version():
    ver = installer.source_agent_version()
    assert ver == AGENT_VERSION
    assert installer._VERSION_TOKEN_RE.fullmatch(ver)
    assert ver != "0.0.0+unknown"


def test_source_agent_version_pyproject_when_metadata_missing(monkeypatch):
    from importlib.metadata import PackageNotFoundError

    def _missing(_name):
        raise PackageNotFoundError(_name)

    monkeypatch.setattr("importlib.metadata.version", _missing)
    ver = installer.source_agent_version()
    assert ver == AGENT_VERSION
    assert installer._VERSION_TOKEN_RE.fullmatch(ver)
    assert ver != "0.0.0+unknown"
