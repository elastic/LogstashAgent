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
