#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from logstashagent import agent_state, controller
from logstashagent.logstash_download import LogstashDownloadError


def _place_version_tree(root: Path, version: str = "9.5.0") -> Path:
    binary = Path(root) / f"logstash-{version}" / "bin" / "logstash"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    return binary


def _bind_state(state: dict):
    def get_state():
        return state

    def update_state(key, value):
        state[key] = value

    return get_state, update_state


def _join_version_downloads(timeout: float = 2.0) -> None:
    threads = getattr(controller, "_VERSION_DOWNLOAD_THREADS", None)
    if not threads:
        return
    for t in list(threads.values()):
        t.join(timeout=timeout)


@pytest.fixture(autouse=True)
def _cleanup_version_download_threads():
    yield
    _join_version_downloads()
    threads = getattr(controller, "_VERSION_DOWNLOAD_THREADS", None)
    if threads is not None:
        threads.clear()
    status = getattr(controller, "_VERSION_DOWNLOAD_STATUS", None)
    if status is not None:
        status.clear()


def _download_threads() -> dict:
    return getattr(controller, "_VERSION_DOWNLOAD_THREADS", {})


def _ensure_off_controller_thread(side_effect=None):
    """Fail fast if ensure runs on the controller/check-in thread."""

    def fake_ensure(version, download_dir, **kwargs):
        if threading.current_thread() is threading.main_thread():
            raise AssertionError("ensure_logstash_version called on controller thread")
        if side_effect is not None:
            return side_effect(version, download_dir, **kwargs)
        return Path(download_dir) / f"logstash-{version}" / "bin" / "logstash"

    return fake_ensure


def _managed_tree(tmp_path: Path) -> dict:
    root = tmp_path / "managed-1"
    settings = root / "config"
    pipes = settings / "pipelines"
    confd = settings / "conf.d"
    pipes.mkdir(parents=True)
    confd.mkdir(parents=True)
    (settings / "logstash.yml").write_text("old-yml\n", encoding="utf-8")
    (settings / "jvm.options").write_text("-Xms1g\n", encoding="utf-8")
    (settings / "log4j2.properties").write_text("status=error\n", encoding="utf-8")
    (settings / "pipelines.yml").write_text("[]\n", encoding="utf-8")
    (settings / "logstash.keystore").write_bytes(b"ks")
    (pipes / "main.conf").write_text("input{}\n", encoding="utf-8")
    (confd / "main.conf").write_text("input{}\n", encoding="utf-8")
    env = root / "env"
    env.write_text("LOGSTASH_BINARY=/old/bin/logstash\n", encoding="utf-8")
    new_bin = _place_version_tree(tmp_path / "versions", "9.5.0")
    state = {
        "mode": "managed",
        "instance_id": 1,
        "path_root": str(root),
        "settings_path": str(settings) + "/",
        "keystore_env_file": str(env),
        "logstash_api_port": 9601,
        "logstash_source": "VERSION",
        "logstash_version": "9.4.3",
        "logstash_binary": "/old/bin/logstash",
        "agent_id": "a1",
    }
    return {"root": root, "settings": settings, "env": env, "new_bin": new_bin, "state": state}


def test_prepare_snapshots_then_rollback_restores(tmp_path):
    tree = _managed_tree(tmp_path)
    runtime = {
        "source": "VERSION",
        "version": "9.5.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/usr/share/logstash/bin",
    }
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(runtime)

    assert prep["ok"] is True
    assert prep["changed"] is True
    assert prep["desired_binary"] == str(tree["new_bin"])
    snap = Path(prep["snapshot_dir"])
    assert (snap / "meta.json").is_file()
    assert (snap / "env").read_text(encoding="utf-8").startswith("LOGSTASH_BINARY=/old")
    assert (snap / "settings" / "logstash.yml").read_text(encoding="utf-8") == "old-yml\n"
    assert (snap / "settings" / "conf.d" / "main.conf").read_text(encoding="utf-8") == "input{}\n"

    (tree["settings"] / "logstash.yml").write_text("NEW\n", encoding="utf-8")
    (tree["settings"] / "conf.d" / "main.conf").write_text("NEW-CONF\n", encoding="utf-8")
    (tree["settings"] / "conf.d" / "extra.conf").write_text("extra\n", encoding="utf-8")
    tree["env"].write_text("LOGSTASH_BINARY=/new\n", encoding="utf-8")

    with patch.object(controller, "restart_logstash", return_value=True) as rst:
        ok = controller.rollback_runtime_upgrade(prep, restart=False)
    rst.assert_not_called()
    assert ok is True
    assert (tree["settings"] / "logstash.yml").read_text(encoding="utf-8") == "old-yml\n"
    assert (tree["settings"] / "conf.d" / "main.conf").read_text(encoding="utf-8") == "input{}\n"
    assert not (tree["settings"] / "conf.d" / "extra.conf").exists()
    assert "LOGSTASH_BINARY=/old/bin/logstash" in tree["env"].read_text(encoding="utf-8")
    assert not snap.exists()


_ABSENT_SETTINGS = ("missing", "", "  \t")


def _apply_settings_path(d: dict, value: str) -> None:
    if value == "missing":
        d.pop("settings_path", None)
    else:
        d["settings_path"] = value


@pytest.mark.parametrize("settings_value", _ABSENT_SETTINGS)
def test_write_runtime_snapshot_absent_settings_path_skips_cwd(
    tmp_path, monkeypatch, settings_value
):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    decoy = cwd / "logstash.yml"
    decoy.write_text("from-cwd\n", encoding="utf-8")
    monkeypatch.chdir(cwd)

    root = tmp_path / "instance"
    root.mkdir()
    env = root / "env"
    env.write_text("LOGSTASH_BINARY=/old\n", encoding="utf-8")
    state = {"path_root": str(root), "keystore_env_file": str(env)}
    _apply_settings_path(state, settings_value)
    previous = {"env_file": str(env)}
    _apply_settings_path(previous, settings_value)

    snap = controller._write_runtime_snapshot(state, previous, {"binary": "/new"})
    assert (snap / "meta.json").is_file()
    assert (snap / "env").read_text(encoding="utf-8") == "LOGSTASH_BINARY=/old\n"
    assert not (snap / "settings").exists()
    assert decoy.read_text(encoding="utf-8") == "from-cwd\n"


@pytest.mark.parametrize("settings_value", _ABSENT_SETTINGS)
def test_restore_runtime_snapshot_absent_settings_path_skips_cwd(
    tmp_path, monkeypatch, settings_value
):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    decoy = cwd / "logstash.yml"
    decoy.write_text("from-cwd\n", encoding="utf-8")
    monkeypatch.chdir(cwd)

    root = tmp_path / "instance"
    root.mkdir()
    snap = root / controller.RUNTIME_SNAPSHOT_NAME
    settings_src = snap / "settings"
    settings_src.mkdir(parents=True)
    (settings_src / "logstash.yml").write_text("from-snap\n", encoding="utf-8")
    (snap / "env").write_text("LOGSTASH_BINARY=/old\n", encoding="utf-8")
    env_dest = root / "env"
    env_dest.write_text("LOGSTASH_BINARY=/new\n", encoding="utf-8")
    previous = {"env_file": str(env_dest)}
    _apply_settings_path(previous, settings_value)
    (snap / "meta.json").write_text(
        json.dumps({"previous": previous, "desired": {}}) + "\n", encoding="utf-8"
    )

    ok = controller._restore_runtime_snapshot({"snapshot_dir": str(snap)})
    assert ok is True
    assert decoy.read_text(encoding="utf-8") == "from-cwd\n"
    assert not (cwd / "jvm.options").exists()
    assert env_dest.read_text(encoding="utf-8") == "LOGSTASH_BINARY=/old\n"


def test_commit_deletes_snapshot_and_stamps_state(tmp_path):
    tree = _managed_tree(tmp_path)
    runtime = {
        "source": "VERSION",
        "version": "9.5.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/usr/share/logstash/bin",
    }
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(runtime)

    snap = Path(prep["snapshot_dir"])
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ) as upd, patch("logstashagent.install_registry.load_registry", return_value={"instances": {}}), patch(
        "logstashagent.install_registry.save_registry"
    ), patch("logstashagent.install_registry.instance_key", return_value="managed-1"):
        controller.commit_runtime_upgrade(prep)

    assert not snap.exists()
    keys = [c[0][0] for c in upd.call_args_list]
    assert "logstash_source" in keys
    assert "logstash_version" in keys
    assert "logstash_binary" in keys


def test_prepare_noop_for_packaged_and_matching_pin(tmp_path):
    tree = _managed_tree(tmp_path)
    tree["state"]["mode"] = "packaged"
    runtime = _version_runtime(tmp_path)
    with patch.object(agent_state, "get_state", return_value=tree["state"]):
        prep = controller.prepare_runtime_upgrade(runtime)
    assert prep["ok"] is True
    assert prep["changed"] is False
    assert not (tree["root"] / ".runtime-snapshot").exists()

    tree["state"]["mode"] = "managed"
    tree["state"]["logstash_binary"] = str(tree["new_bin"])
    tree["state"]["logstash_version"] = "9.5.0"
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ):
        prep = controller.prepare_runtime_upgrade(runtime)
    assert prep["ok"] is True
    assert prep["changed"] is False


def test_prepare_missing_tree_holds_without_snapshot(tmp_path):
    tree = _managed_tree(tmp_path)
    runtime = {
        "source": "VERSION",
        "version": "9.6.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/x",
    }
    state = dict(tree["state"])
    get_state, update_state = _bind_state(state)
    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(),
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy"
    ) as resolve:
        prep = controller.prepare_runtime_upgrade(runtime)
        started = list(_download_threads().values())
        mem = dict(getattr(controller, "_VERSION_DOWNLOAD_STATUS", {}))
        _join_version_downloads()
    assert prep["ok"] is True
    assert prep["changed"] is False
    assert prep.get("held") is True
    assert not (tree["root"] / ".runtime-snapshot").exists()
    assert mem.get("9.6.0")
    if started:
        assert started[0].daemon is True
    resolve.assert_not_called()
    rd = state.get("runtime_download") or {}
    assert rd.get("status") in ("pending", "running", "ready")
    assert rd.get("version") == "9.6.0"


def test_recover_restores_leftover_snapshot(tmp_path):
    tree = _managed_tree(tmp_path)
    runtime = {
        "source": "VERSION",
        "version": "9.5.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/usr/share/logstash/bin",
    }
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(runtime)

    (tree["settings"] / "logstash.yml").write_text("partial\n", encoding="utf-8")
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        controller, "restart_logstash", return_value=True
    ) as rst:
        controller.recover_incomplete_runtime_upgrade()
    rst.assert_called_once()
    assert (tree["settings"] / "logstash.yml").read_text(encoding="utf-8") == "old-yml\n"
    assert not Path(prep["snapshot_dir"]).exists()


def _version_runtime(tmp_path: Path) -> dict:
    return {
        "source": "VERSION",
        "version": "9.5.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/usr/share/logstash/bin",
    }


def test_recover_discards_snapshot_when_state_matches_desired(tmp_path):
    tree = _managed_tree(tmp_path)
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(_version_runtime(tmp_path))

    (tree["settings"] / "logstash.yml").write_text("NEW\n", encoding="utf-8")
    tree["state"]["logstash_source"] = "VERSION"
    tree["state"]["logstash_version"] = "9.5.0"
    tree["state"]["logstash_binary"] = str(tree["new_bin"])
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        controller, "restart_logstash", return_value=True
    ) as rst:
        ok = controller.recover_incomplete_runtime_upgrade()
    rst.assert_not_called()
    assert ok is True
    assert not Path(prep["snapshot_dir"]).exists()
    assert (tree["settings"] / "logstash.yml").read_text(encoding="utf-8") == "NEW\n"


def test_restore_io_failure_keeps_snapshot(tmp_path):
    tree = _managed_tree(tmp_path)
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(_version_runtime(tmp_path))

    snap = Path(prep["snapshot_dir"])
    with patch.object(controller, "_copy_if_exists", side_effect=OSError("disk full")), patch.object(
        controller, "restart_logstash", return_value=True
    ) as rst:
        ok = controller.rollback_runtime_upgrade(prep, restart=False)
    rst.assert_not_called()
    assert ok is False
    assert snap.is_dir()
    assert (snap / "meta.json").is_file()


def test_prepare_does_not_clobber_existing_snapshot(tmp_path):
    tree = _managed_tree(tmp_path)
    snap = tree["root"] / ".runtime-snapshot"
    snap.mkdir()
    sentinel = snap / "sentinel"
    sentinel.write_text("keep-me\n", encoding="utf-8")
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(_version_runtime(tmp_path))
    assert prep["ok"] is False
    assert prep["changed"] is False
    assert sentinel.is_file()
    assert sentinel.read_text(encoding="utf-8") == "keep-me\n"
    assert (snap / "meta.json").exists() is False


def test_recover_discards_unreadable_snapshot(tmp_path):
    tree = _managed_tree(tmp_path)
    snap = tree["root"] / ".runtime-snapshot"
    snap.mkdir()
    (snap / "sentinel").write_text("keep-me\n", encoding="utf-8")
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        controller, "restart_logstash", return_value=True
    ) as rst:
        ok = controller.recover_incomplete_runtime_upgrade()
    rst.assert_not_called()
    assert ok is False
    assert not snap.exists()


def test_rollback_keeps_snapshot_when_restart_fails(tmp_path):
    tree = _managed_tree(tmp_path)
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(_version_runtime(tmp_path))

    snap = Path(prep["snapshot_dir"])
    (tree["settings"] / "logstash.yml").write_text("NEW\n", encoding="utf-8")
    with patch.object(controller, "restart_logstash", return_value=False):
        ok = controller.rollback_runtime_upgrade(prep, restart=True)
    assert ok is False
    assert snap.is_dir()
    assert (tree["settings"] / "logstash.yml").read_text(encoding="utf-8") == "old-yml\n"


def test_wait_for_logstash_api_succeeds_on_accessible():
    with patch.object(
        controller,
        "get_logstash_api_status",
        return_value={"accessible": True},
    ) as poll:
        assert controller.wait_for_logstash_api(9601, timeout=0.01) is True
    poll.assert_called()


def test_wait_for_logstash_api_times_out():
    with patch.object(
        controller,
        "get_logstash_api_status",
        return_value={"accessible": False},
    ), patch.object(controller, "RUNTIME_UPGRADE_HEALTH_POLL", 0):
        assert controller.wait_for_logstash_api(9601, timeout=0) is False


def test_finalize_commits_when_api_up(tmp_path):
    tree = _managed_tree(tmp_path)
    prep = {
        "ok": True,
        "changed": True,
        "desired_binary": str(tree["new_bin"]),
        "snapshot_dir": str(tree["root"] / ".runtime-snapshot"),
        "previous": {"api_port": 9601, "env_file": str(tree["env"])},
        "source": "VERSION",
        "version": "9.5.0",
        "download_dir": str(tmp_path),
    }
    (tree["root"] / ".runtime-snapshot").mkdir()
    (tree["root"] / ".runtime-snapshot" / "meta.json").write_text("{}", encoding="utf-8")
    with patch.object(controller, "wait_for_logstash_api", return_value=True), patch.object(
        controller, "commit_runtime_upgrade"
    ) as commit, patch.object(controller, "rollback_runtime_upgrade") as rb:
        assert controller.finalize_runtime_upgrade(prep, restart_ok=True) is True
    commit.assert_called_once_with(prep)
    rb.assert_not_called()


def test_finalize_waits_on_resolved_port_not_snapshot(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGSTASH_API_PORT", "9561")
    prep = {"changed": True, "previous": {"api_port": 9600}}
    with patch.object(controller, "wait_for_logstash_api", return_value=True) as wait:
        with patch.object(controller, "commit_runtime_upgrade"):
            controller.finalize_runtime_upgrade(prep, restart_ok=True)
    wait.assert_called_once_with(9561)


def test_finalize_rolls_back_when_unhealthy(tmp_path):
    tree = _managed_tree(tmp_path)
    prep = {
        "ok": True,
        "changed": True,
        "desired_binary": str(tree["new_bin"]),
        "snapshot_dir": str(tree["root"] / ".runtime-snapshot"),
        "previous": {"api_port": 9601},
        "source": "VERSION",
        "version": "9.5.0",
    }
    with patch.object(controller, "wait_for_logstash_api", return_value=False), patch.object(
        controller, "commit_runtime_upgrade"
    ) as commit, patch.object(controller, "rollback_runtime_upgrade", return_value=True) as rb:
        assert controller.finalize_runtime_upgrade(prep, restart_ok=True) is False
    commit.assert_not_called()
    rb.assert_called_once()
    assert rb.call_args.kwargs.get("restart", True) is True


def test_finalize_rolls_back_when_restart_fails():
    prep = {"changed": True, "previous": {"api_port": 9601}}
    with patch.object(controller, "wait_for_logstash_api") as wait, patch.object(
        controller, "rollback_runtime_upgrade", return_value=True
    ) as rb:
        assert controller.finalize_runtime_upgrade(prep, restart_ok=False) is False
    wait.assert_not_called()
    rb.assert_called_once()


def _gcc_state(tmp_path: Path) -> tuple[str, dict, Path]:
    settings = tmp_path / "config"
    settings.mkdir()
    yml = settings / "logstash.yml"
    yml.write_text("old\n", encoding="utf-8")
    base = str(settings).replace("\\", "/") + "/"
    root = tmp_path / "managed-1"
    root.mkdir(exist_ok=True)
    env = root / "env"
    env.write_text("LOGSTASH_BINARY=/old\n", encoding="utf-8")
    state = {
        "logstash_ui_url": "http://localhost:8000",
        "api_key": "k",
        "connection_id": "c",
        "settings_path": base,
        "mode": "managed",
        "path_root": str(root),
        "keystore_env_file": str(env),
        "logstash_source": "VERSION",
        "logstash_version": "9.4.3",
        "logstash_binary": "/old",
    }
    return base, state, yml


def test_prepare_runs_before_yml_write(tmp_path):
    base, state, yml = _gcc_state(tmp_path)
    order = []

    def prep(runtime):
        order.append("prep")
        return controller._empty_runtime_prep(ok=True, changed=False)

    def write_yml(settings_path, content):
        order.append("yml")
        return True

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "success": True,
        "changes": {
            "logstash_yml": "new\n",
            "logstash_runtime": {"source": "VERSION", "version": "9.5.0"},
        },
        "current_revision": 3,
    }
    with patch.object(agent_state, "get_state", return_value=state), patch.object(
        agent_state, "update_state"
    ), patch.object(controller, "prepare_runtime_upgrade", side_effect=prep), patch.object(
        controller, "update_logstash_yml", side_effect=write_yml
    ), patch.object(controller, "restart_logstash", return_value=True), patch.object(
        controller.requests, "post", return_value=resp
    ):
        controller.get_config_changes()
    assert order == ["prep", "yml"]


def test_prepare_failure_does_not_write_yml(tmp_path):
    base, state, yml = _gcc_state(tmp_path)
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "success": True,
        "changes": {
            "logstash_yml": "new\n",
            "logstash_runtime": {"source": "VERSION", "version": "9.5.0"},
        },
        "current_revision": 3,
    }
    failed = controller._empty_runtime_prep(ok=False, error="network down")
    with patch.object(agent_state, "get_state", return_value=state), patch.object(
        agent_state, "update_state"
    ) as upd, patch.object(
        controller, "prepare_runtime_upgrade", return_value=failed
    ), patch.object(controller, "restart_logstash") as rst, patch.object(
        controller.requests, "post", return_value=resp
    ):
        controller.get_config_changes()
    assert yml.read_text(encoding="utf-8") == "old\n"
    rst.assert_not_called()
    rev_calls = [c for c in upd.call_args_list if c[0] and c[0][0] == "revision_number"]
    assert rev_calls == []


def test_merged_plan_flips_env_then_finalizes_commit(tmp_path):
    tree = _managed_tree(tmp_path)
    prep = {
        "ok": True,
        "changed": True,
        "desired_binary": str(tree["new_bin"]),
        "snapshot_dir": str(tree["root"] / ".runtime-snapshot"),
        "previous": {
            "env_file": str(tree["env"]),
            "api_port": 9601,
            "settings_path": str(tree["settings"]) + "/",
        },
        "source": "VERSION",
        "version": "9.5.0",
        "download_dir": str(tmp_path),
    }
    policy_res = {
        "ran": True,
        "files_updated": True,
        "requires_restart": True,
        "failed_operations": [],
        "aborted": False,
        "current_revision": 9,
        "runtime_prep": prep,
    }
    plan = {"keystore": {"set": {}, "delete": []}, "pipelines": {"set": {}, "delete": []}}
    order = []

    def flip(p):
        order.append("flip")
        return True

    def rst():
        order.append("restart")
        return True

    def fin(p, restart_ok):
        order.append("final")
        assert restart_ok is True
        return True

    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ), patch.object(controller, "flip_runtime_env", side_effect=flip), patch.object(
        controller, "restart_logstash", side_effect=rst
    ), patch.object(controller, "finalize_runtime_upgrade", side_effect=fin):
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, None)
    assert order == ["flip", "restart", "final"]


def test_merged_plan_unhealthy_does_not_bump_revision(tmp_path):
    tree = _managed_tree(tmp_path)
    prep = {
        "ok": True,
        "changed": True,
        "desired_binary": str(tree["new_bin"]),
        "snapshot_dir": str(tree["root"] / ".runtime-snapshot"),
        "previous": {"env_file": str(tree["env"]), "api_port": 9601},
        "source": "VERSION",
        "version": "9.5.0",
    }
    policy_res = {
        "ran": True,
        "files_updated": True,
        "requires_restart": True,
        "failed_operations": [],
        "aborted": False,
        "current_revision": 9,
        "runtime_prep": prep,
    }
    plan = {"keystore": {"set": {}, "delete": []}, "pipelines": {"set": {}, "delete": []}}
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ) as upd, patch.object(controller, "flip_runtime_env", return_value=True), patch.object(
        controller, "restart_logstash", return_value=True
    ), patch.object(controller, "finalize_runtime_upgrade", return_value=False):
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, None)
    rev_calls = [c for c in upd.call_args_list if c[0] and c[0][0] == "revision_number"]
    assert rev_calls == []
    last = [c[0][1] for c in upd.call_args_list if c[0] and c[0][0] == "last_policy_apply"]
    assert last and last[-1]["success"] is False
    assert "logstash runtime upgrade rolled back" in last[-1]["failed_operations"]


def test_pipeline_only_skips_finalize(tmp_path):
    tree = _managed_tree(tmp_path)
    policy_res = {
        "ran": True,
        "files_updated": True,
        "requires_restart": False,
        "failed_operations": [],
        "aborted": False,
        "current_revision": 4,
        "runtime_prep": controller._empty_runtime_prep(),
    }
    plan = {
        "keystore": {"set": {}, "delete": []},
        "pipelines": {"set": {"p": "conf"}, "delete": []},
    }
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ), patch.object(controller, "update_pipelines", return_value=True), patch.object(
        controller, "flip_runtime_env"
    ) as flip, patch.object(controller, "finalize_runtime_upgrade") as fin, patch.object(
        controller, "restart_logstash"
    ) as rst:
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, None)
    flip.assert_not_called()
    fin.assert_not_called()
    rst.assert_not_called()


def test_merged_plan_aborted_does_not_flip_or_restart(tmp_path):
    tree = _managed_tree(tmp_path)
    prep = {
        "ok": True,
        "changed": True,
        "desired_binary": str(tree["new_bin"]),
        "snapshot_dir": str(tree["root"] / ".runtime-snapshot"),
        "previous": {"env_file": str(tree["env"]), "api_port": 9601},
        "source": "VERSION",
        "version": "9.5.0",
    }
    policy_res = {
        "ran": True,
        "files_updated": True,
        "requires_restart": True,
        "failed_operations": ["logstash.yml write failed"],
        "aborted": True,
        "current_revision": 9,
        "runtime_prep": prep,
    }
    plan = {"keystore": {"set": {}, "delete": []}, "pipelines": {"set": {}, "delete": []}}
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ) as upd, patch.object(controller, "flip_runtime_env") as flip, patch.object(
        controller, "restart_logstash"
    ) as rst, patch.object(controller, "rollback_runtime_upgrade", return_value=True) as rb, patch.object(
        controller, "update_keystore"
    ) as uks, patch.object(controller, "update_pipelines") as upl:
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, None)
    flip.assert_not_called()
    rst.assert_not_called()
    uks.assert_not_called()
    upl.assert_not_called()
    rb.assert_called_once()
    assert rb.call_args.kwargs.get("restart", True) is False
    rev_calls = [c for c in upd.call_args_list if c[0] and c[0][0] == "revision_number"]
    assert rev_calls == []


def test_merged_plan_aborted_without_runtime_change_does_not_restart(tmp_path):
    tree = _managed_tree(tmp_path)
    policy_res = {
        "ran": True,
        "files_updated": True,
        "requires_restart": True,
        "failed_operations": ["logstash.yml write failed"],
        "aborted": True,
        "current_revision": 9,
        "runtime_prep": controller._empty_runtime_prep(),
    }
    plan = {
        "keystore": {"set": {"k": "v"}, "delete": []},
        "pipelines": {"set": {"p": {"lscl": "input{}"}}, "delete": []},
    }
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ), patch.object(controller, "flip_runtime_env") as flip, patch.object(
        controller, "restart_logstash"
    ) as rst, patch.object(controller, "update_keystore") as uks, patch.object(
        controller, "update_pipelines"
    ) as upl:
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, None)
    flip.assert_not_called()
    rst.assert_not_called()
    uks.assert_not_called()
    upl.assert_not_called()


def test_merged_plan_aborted_does_not_apply_keystore_or_pipelines(tmp_path):
    tree = _managed_tree(tmp_path)
    prep = {
        "ok": True,
        "changed": True,
        "desired_binary": str(tree["new_bin"]),
        "snapshot_dir": str(tree["root"] / ".runtime-snapshot"),
        "previous": {"env_file": str(tree["env"]), "api_port": 9601},
        "source": "VERSION",
        "version": "9.5.0",
    }
    policy_res = {
        "ran": True,
        "files_updated": True,
        "requires_restart": True,
        "failed_operations": ["logstash.yml write failed"],
        "aborted": True,
        "current_revision": 9,
        "runtime_prep": prep,
    }
    plan = {
        "keystore": {"set": {"k": "v"}, "delete": []},
        "pipelines": {"set": {"p": {"lscl": "input{}"}}, "delete": []},
    }
    snmp_res = {
        "ran": True,
        "pipeline_set": {"p": "hash"},
        "pipeline_delete_names": [],
        "keystore_set_names": ["k"],
        "keystore_delete_names": [],
        "keystore_skipped": False,
    }
    tree["state"]["snmp_pipelines"] = {}
    tree["state"]["snmp_keystore"] = {}
    tree["state"]["keystore"] = {"k": "v"}
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ) as upd, patch.object(controller, "flip_runtime_env") as flip, patch.object(
        controller, "restart_logstash"
    ) as rst, patch.object(controller, "rollback_runtime_upgrade", return_value=True) as rb, patch.object(
        controller, "update_keystore"
    ) as uks, patch.object(controller, "update_pipelines") as upl:
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, snmp_res)
    uks.assert_not_called()
    upl.assert_not_called()
    flip.assert_not_called()
    rst.assert_not_called()
    rb.assert_called_once()
    snmp_calls = [c for c in upd.call_args_list if c[0] and c[0][0] in ("snmp_pipelines", "snmp_keystore")]
    assert snmp_calls == []


def test_system_to_version_uses_prepare_path(tmp_path):
    tree = _managed_tree(tmp_path)
    tree["state"]["logstash_source"] = "SYSTEM"
    tree["state"]["logstash_version"] = ""
    tree["state"]["logstash_binary"] = "/usr/share/logstash/bin/logstash"
    runtime = {
        "source": "VERSION",
        "version": "9.5.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/usr/share/logstash/bin",
    }
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ) as resolve, patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(runtime)
    assert prep["changed"] is True
    resolve.assert_called_once()
    assert resolve.call_args.kwargs["logstash_source"] == "VERSION"
    # Leftover snapshot would block the second prepare (helpers refuse overwrite).
    controller.rollback_runtime_upgrade(prep, restart=False)

    runtime_sys = {
        "source": "SYSTEM",
        "version": "",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/usr/share/logstash/bin",
    }
    sys_bin = tmp_path / "usr" / "share" / "logstash" / "bin" / "logstash"
    sys_bin.parent.mkdir(parents=True)
    sys_bin.write_text("x", encoding="utf-8")
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(sys_bin),
    ) as resolve2:
        prep2 = controller.prepare_runtime_upgrade(runtime_sys)
    assert prep2["changed"] is True
    assert resolve2.call_args.kwargs["logstash_source"] == "SYSTEM"


def test_check_in_recovers_before_work(tmp_path):
    tree = _managed_tree(tmp_path)
    tree["state"].update({
        "enrolled": True,
        "logstash_ui_url": "http://localhost:8000",
        "api_key": "k",
        "connection_id": "c",
        "settings_path": str(tree["settings"]) + "/",
        "logs_path": str(tmp_path / "logs") + "/",
        "binary_path": str(tmp_path / "bin"),
    })
    rec = MagicMock()
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        controller, "recover_incomplete_runtime_upgrade", rec
    ), patch.object(
        controller.requests, "post", side_effect=RuntimeError("stop-after-recover")
    ):
        try:
            controller.check_in()
        except RuntimeError:
            pass
    rec.assert_called()


def _gcc_runtime_changes(tmp_path: Path, *, version: str = "9.5.0", extra_changes=None) -> dict:
    changes = {
        "logstash_yml": "new\n",
        "logstash_runtime": {
            "source": "VERSION",
            "version": version,
            "download_dir": str(tmp_path / "versions"),
        },
    }
    if extra_changes:
        changes.update(extra_changes)
    return changes


def test_missing_tree_holds_gcc_yml_and_revision(tmp_path):
    base, state, yml = _gcc_state(tmp_path)
    get_state, update_state = _bind_state(state)
    block = threading.Event()

    def blocked_ensure(version, download_dir, **kwargs):
        block.wait(timeout=5)
        return Path(download_dir) / f"logstash-{version}" / "bin" / "logstash"

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "success": True,
        "changes": _gcc_runtime_changes(tmp_path),
        "current_revision": 3,
    }
    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(blocked_ensure),
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy"
    ) as resolve, patch.object(
        controller, "restart_logstash"
    ) as rst, patch.object(
        controller, "finalize_runtime_upgrade", return_value=True
    ), patch.object(controller.requests, "post", return_value=resp):
        try:
            controller.get_config_changes()
            started = list(_download_threads().values())

            assert yml.read_text(encoding="utf-8") == "old\n"
            assert state.get("revision_number") != 3
            assert "revision_number" not in state
            assert started and started[0].daemon is True
            assert started[0].is_alive() is True
            resolve.assert_not_called()
            rst.assert_not_called()
            rd = state.get("runtime_download") or {}
            assert rd.get("status") in ("pending", "running")
            assert rd.get("version") == "9.5.0"
            last = state.get("last_policy_apply") or {}
            assert last.get("failed_operations") == []
        finally:
            block.set()
            _join_version_downloads()


def test_inflight_does_not_start_second_thread(tmp_path):
    base, state, yml = _gcc_state(tmp_path)
    get_state, update_state = _bind_state(state)
    block = threading.Event()

    def blocked_ensure(version, download_dir, **kwargs):
        block.wait(timeout=5)
        return Path(download_dir) / f"logstash-{version}" / "bin" / "logstash"

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "success": True,
        "changes": _gcc_runtime_changes(tmp_path),
        "current_revision": 3,
    }
    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(blocked_ensure),
    ), patch.object(controller, "restart_logstash") as rst, patch.object(
        controller, "finalize_runtime_upgrade", return_value=True
    ), patch.object(controller.requests, "post", return_value=resp):
        try:
            controller.get_config_changes()
            first = dict(_download_threads())
            controller.get_config_changes()
            second = dict(_download_threads())

            assert list(first.keys()) == ["9.5.0"]
            assert second == first
            assert next(iter(first.values())).is_alive() is True
            assert yml.read_text(encoding="utf-8") == "old\n"
            rst.assert_not_called()
            assert state.get("revision_number") != 3
        finally:
            block.set()
            _join_version_downloads()


def test_prepare_snapshots_when_version_tree_present(tmp_path):
    tree = _managed_tree(tmp_path)
    runtime = _version_runtime(tmp_path)
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value=str(tree["new_bin"]),
    ), patch("logstashagent.install_registry.register_logstash_version", return_value={}):
        prep = controller.prepare_runtime_upgrade(runtime)
    assert prep["ok"] is True
    assert prep["changed"] is True
    assert not prep.get("held")
    assert Path(prep["snapshot_dir"]).is_dir()
    controller.rollback_runtime_upgrade(prep, restart=False)


def test_via_ui_download_failure_stamps_failed_no_config_apply(tmp_path):
    base, state, yml = _gcc_state(tmp_path)
    stamps = []

    def get_state():
        return state

    def update_state(key, value):
        state[key] = value
        if key == "runtime_download" and isinstance(value, dict):
            stamps.append(dict(value))

    def boom(version, download_dir, **kwargs):
        raise LogstashDownloadError("HTTP 404")

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "success": True,
        "changes": _gcc_runtime_changes(tmp_path),
        "current_revision": 3,
    }
    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(boom),
    ), patch.object(controller, "restart_logstash") as rst, patch.object(
        controller, "finalize_runtime_upgrade", return_value=True
    ), patch.object(controller.requests, "post", return_value=resp):
        controller.get_config_changes()
        _join_version_downloads()
        controller.get_config_changes()
        _join_version_downloads()
        assert yml.read_text(encoding="utf-8") == "old\n"
        rst.assert_not_called()
        assert state.get("revision_number") != 3
        failed = [s for s in stamps if s.get("status") == "failed"]
        assert failed
        assert "404" in (failed[-1].get("error") or "")


@pytest.mark.parametrize("mode", ["packaged", "embedded"])
def test_packaged_embedded_version_pin_does_not_download(tmp_path, mode):
    tree = _managed_tree(tmp_path)
    tree["state"]["mode"] = mode
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(),
    ) as ensure:
        prep = controller.prepare_runtime_upgrade(_version_runtime(tmp_path))
    assert prep["ok"] is True
    assert prep["changed"] is False
    assert not prep.get("held")
    ensure.assert_not_called()
    assert _download_threads() == {}


def test_held_merge_aborts_without_failed_ops_or_rollback(tmp_path):
    base, state, yml = _gcc_state(tmp_path)
    get_state, update_state = _bind_state(state)
    block = threading.Event()

    def blocked_ensure(version, download_dir, **kwargs):
        block.wait(timeout=5)
        return Path(download_dir) / f"logstash-{version}" / "bin" / "logstash"

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "success": True,
        "changes": _gcc_runtime_changes(tmp_path),
        "current_revision": 9,
    }
    plan = {"keystore": {"set": {"k": "v"}, "delete": []}, "pipelines": {"set": {}, "delete": []}}
    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(blocked_ensure),
    ), patch.object(controller.requests, "post", return_value=resp):
        try:
            res = controller.get_config_changes(plan=plan)

            assert res["aborted"] is True
            assert res["failed_operations"] == []
            assert res["runtime_prep"].get("held") is True
            assert res["runtime_prep"].get("changed") is False
            assert yml.read_text(encoding="utf-8") == "old\n"
            assert _download_threads()

            with patch.object(controller, "update_keystore") as uks, patch.object(
                controller, "update_pipelines"
            ) as upl, patch.object(controller, "restart_logstash") as rst, patch.object(
                controller, "rollback_runtime_upgrade"
            ) as rb, patch.object(controller, "flip_runtime_env") as flip:
                controller._apply_merged_plan(base, plan, res, None)
            uks.assert_not_called()
            upl.assert_not_called()
            rst.assert_not_called()
            rb.assert_not_called()
            flip.assert_not_called()
            assert state.get("revision_number") != 9
        finally:
            block.set()
            _join_version_downloads()


def test_pipeline_only_applies_while_download_in_flight(tmp_path):
    tree = _managed_tree(tmp_path)
    state = dict(tree["state"])
    state.update({
        "logstash_ui_url": "http://localhost:8000",
        "api_key": "k",
        "connection_id": "c",
        "settings_path": str(tree["settings"]).replace("\\", "/") + "/",
    })
    get_state, update_state = _bind_state(state)
    block = threading.Event()

    def blocked_ensure(version, download_dir, **kwargs):
        block.wait(timeout=5)
        return Path(download_dir) / f"logstash-{version}" / "bin" / "logstash"

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "success": True,
        "changes": {"pipelines": {"set": {"p": "input{}"}, "delete": []}},
        "current_revision": 4,
    }
    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(blocked_ensure),
    ), patch.object(
        controller, "update_pipelines", return_value=True
    ) as upl, patch.object(controller, "restart_logstash") as rst, patch.object(
        controller.requests, "post", return_value=resp
    ):
        try:
            prep = controller.prepare_runtime_upgrade(
                _version_runtime(tmp_path) | {"version": "9.6.0"}
            )
            assert prep.get("held") is True
            first = dict(_download_threads())
            assert first

            controller.get_config_changes()
            upl.assert_called_once()
            rst.assert_not_called()
            assert state.get("revision_number") == 4
            assert _download_threads() == first
        finally:
            block.set()
            _join_version_downloads()


def test_check_in_status_blob_includes_runtime_download(tmp_path):
    tree = _managed_tree(tmp_path)
    tree["state"].update({
        "enrolled": True,
        "logstash_ui_url": "http://localhost:8000",
        "api_key": "k",
        "connection_id": "c",
        "settings_path": str(tree["settings"]) + "/",
        "logs_path": str(tmp_path / "logs") + "/",
        "binary_path": str(tmp_path / "bin"),
        "runtime_download": {
            "status": "failed",
            "version": "9.5.0",
            "error": "HTTP 404",
            "dir": str(tmp_path / "versions"),
        },
    })
    captured = {}

    def post(*args, **kwargs):
        captured["json"] = kwargs.get("json")
        raise RuntimeError("stop-after-blob")

    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        controller, "recover_incomplete_runtime_upgrade"
    ), patch.object(controller.requests, "post", side_effect=post):
        try:
            controller.check_in()
        except RuntimeError:
            pass
    rd = (captured.get("json") or {}).get("status_blob", {}).get("runtime_download")
    assert rd["status"] == "failed"
    assert rd["version"] == "9.5.0"
    assert rd["error"] == "HTTP 404"


def test_check_in_flushes_finished_download_into_status_blob(tmp_path):
    tree = _managed_tree(tmp_path)
    state = dict(tree["state"])
    state.update({
        "enrolled": True,
        "logstash_ui_url": "http://localhost:8000",
        "api_key": "k",
        "connection_id": "c",
        "settings_path": str(tree["settings"]) + "/",
        "logs_path": str(tmp_path / "logs") + "/",
        "binary_path": str(tmp_path / "bin"),
    })
    get_state, update_state = _bind_state(state)
    captured = {}

    def post(*args, **kwargs):
        captured["json"] = kwargs.get("json")
        raise RuntimeError("stop-after-blob")

    def boom(version, download_dir, **kwargs):
        raise LogstashDownloadError("HTTP 503")

    runtime = {
        "source": "VERSION",
        "version": "9.6.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/x",
    }
    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(boom),
    ), patch.object(controller, "recover_incomplete_runtime_upgrade"), patch.object(
        controller.requests, "post", side_effect=post
    ):
        controller.prepare_runtime_upgrade(runtime)
        _join_version_downloads()
        try:
            controller.check_in()
        except RuntimeError:
            pass
    rd = (captured.get("json") or {}).get("status_blob", {}).get("runtime_download") or {}
    assert rd.get("status") == "failed"
    assert rd.get("version") == "9.6.0"
    assert "503" in (rd.get("error") or "")


def test_download_worker_does_not_call_update_state(tmp_path):
    tree = _managed_tree(tmp_path)
    state = dict(tree["state"])
    controller_ident = threading.get_ident()
    update_calls = []

    def get_state():
        return state

    def update_state(key, value):
        update_calls.append(
            (threading.get_ident(), key, dict(value) if isinstance(value, dict) else value)
        )
        state[key] = value

    runtime = {
        "source": "VERSION",
        "version": "9.6.0",
        "download_dir": str(tmp_path / "versions"),
        "binary_path": "/x",
    }
    def boom(version, download_dir, **kwargs):
        raise LogstashDownloadError("HTTP 503")

    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(boom),
    ):
        prep = controller.prepare_runtime_upgrade(runtime)
        assert prep.get("held") is True
        _join_version_downloads()
        worker_updates = [c for c in update_calls if c[0] != controller_ident]
        assert worker_updates == []
        assert any(
            ident == controller_ident
            and key == "runtime_download"
            and (val or {}).get("status") in ("pending", "running")
            for ident, key, val in update_calls
        )
        prep2 = controller.prepare_runtime_upgrade(runtime)
        assert prep2.get("held") is True
        failed = [
            val
            for ident, key, val in update_calls
            if ident == controller_ident
            and key == "runtime_download"
            and (val or {}).get("status") == "failed"
        ]
        assert failed
        assert "503" in (failed[-1].get("error") or "")
        _join_version_downloads()


def test_prepare_holds_while_inflight_even_if_tree_present(tmp_path):
    tree = _managed_tree(tmp_path)
    download_dir = tmp_path / "versions"
    version = "9.6.0"
    runtime = {
        "source": "VERSION",
        "version": version,
        "download_dir": str(download_dir),
        "binary_path": "/usr/share/logstash/bin",
    }
    state = dict(tree["state"])
    get_state, update_state = _bind_state(state)
    block = threading.Event()

    def blocked_ensure(ver, dest, **kwargs):
        block.wait(timeout=5)
        return Path(dest) / f"logstash-{ver}" / "bin" / "logstash"

    with patch.object(agent_state, "get_state", side_effect=get_state), patch.object(
        agent_state, "update_state", side_effect=update_state
    ), patch(
        "logstashagent.logstash_download.ensure_logstash_version",
        side_effect=_ensure_off_controller_thread(blocked_ensure),
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy"
    ) as resolve, patch(
        "logstashagent.install_registry.register_logstash_version", return_value={}
    ):
        try:
            prep = controller.prepare_runtime_upgrade(runtime)
            assert prep.get("held") is True
            new_bin = _place_version_tree(download_dir, version)
            from logstashagent.logstash_download import version_is_present

            assert version_is_present(version, str(download_dir)) is True
            prep2 = controller.prepare_runtime_upgrade(runtime)
            assert prep2.get("held") is True
            resolve.assert_not_called()
        finally:
            block.set()
            _join_version_downloads()

        resolve.return_value = str(new_bin)
        prep3 = controller.prepare_runtime_upgrade(runtime)
    assert prep3.get("held") is not True
    assert prep3["ok"] is True
    assert prep3["changed"] is True
    controller.rollback_runtime_upgrade(prep3, restart=False)
