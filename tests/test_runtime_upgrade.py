#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from logstashagent import agent_state, controller


def _managed_tree(tmp_path: Path) -> dict:
    root = tmp_path / "managed-1"
    settings = root / "config"
    pipes = settings / "pipelines"
    pipes.mkdir(parents=True)
    (settings / "logstash.yml").write_text("old-yml\n", encoding="utf-8")
    (settings / "jvm.options").write_text("-Xms1g\n", encoding="utf-8")
    (settings / "log4j2.properties").write_text("status=error\n", encoding="utf-8")
    (settings / "pipelines.yml").write_text("[]\n", encoding="utf-8")
    (settings / "logstash.keystore").write_bytes(b"ks")
    (pipes / "main.conf").write_text("input{}\n", encoding="utf-8")
    env = root / "env"
    env.write_text("LOGSTASH_BINARY=/old/bin/logstash\n", encoding="utf-8")
    new_bin = tmp_path / "logstash-9.5.0" / "bin" / "logstash"
    new_bin.parent.mkdir(parents=True)
    new_bin.write_text("#!/bin/sh\n", encoding="utf-8")
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

    (tree["settings"] / "logstash.yml").write_text("NEW\n", encoding="utf-8")
    tree["env"].write_text("LOGSTASH_BINARY=/new\n", encoding="utf-8")

    with patch.object(controller, "restart_logstash", return_value=True) as rst:
        ok = controller.rollback_runtime_upgrade(prep, restart=False)
    rst.assert_not_called()
    assert ok is True
    assert (tree["settings"] / "logstash.yml").read_text(encoding="utf-8") == "old-yml\n"
    assert "LOGSTASH_BINARY=/old/bin/logstash" in tree["env"].read_text(encoding="utf-8")
    assert not snap.exists()


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
    runtime = {"source": "VERSION", "version": "9.5.0", "download_dir": str(tmp_path), "binary_path": "/usr/share/logstash/bin"}
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


def test_prepare_download_failure_has_no_snapshot(tmp_path):
    from logstashagent.logstash_download import LogstashDownloadError

    tree = _managed_tree(tmp_path)
    runtime = {"source": "VERSION", "version": "9.5.0", "download_dir": str(tmp_path), "binary_path": "/x"}
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        side_effect=LogstashDownloadError("network down"),
    ):
        prep = controller.prepare_runtime_upgrade(runtime)
    assert prep["ok"] is False
    assert prep["changed"] is False
    assert "network down" in (prep.get("error") or "")
    assert not (tree["root"] / ".runtime-snapshot").exists()


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
    ) as rst, patch.object(controller, "rollback_runtime_upgrade", return_value=True) as rb:
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, None)
    flip.assert_not_called()
    rst.assert_not_called()
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
    plan = {"keystore": {"set": {}, "delete": []}, "pipelines": {"set": {}, "delete": []}}
    with patch.object(agent_state, "get_state", return_value=tree["state"]), patch.object(
        agent_state, "update_state"
    ), patch.object(controller, "flip_runtime_env") as flip, patch.object(
        controller, "restart_logstash"
    ) as rst:
        controller._apply_merged_plan(str(tree["settings"]) + "/", plan, policy_res, None)
    flip.assert_not_called()
    rst.assert_not_called()


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
