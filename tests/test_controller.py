#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.controller."""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from logstashagent import controller
from logstashagent.ls_keystore_utils.exceptions import (
    IncorrectPassword,
    LogstashKeystoreException,
    LogstashKeystoreModified,
)


class TestUpdateLogstashYml:
    def test_writes_file_and_returns_true(self, temp_dir):
        base = temp_dir.replace("\\", "/")
        if not base.endswith("/"):
            base = base + "/"
        content = "pipeline:\n  workers: 2\n"

        assert controller.update_logstash_yml(base, content) is True

        written = Path(base) / "logstash.yml"
        assert written.read_text(encoding="utf-8") == content

    def test_returns_false_on_error(self, temp_dir):
        base = temp_dir.replace("\\", "/") + "/"
        with patch("builtins.open", side_effect=OSError("denied")):
            assert controller.update_logstash_yml(base, "x") is False


class TestUpdateJvmOptions:
    def test_writes_file_and_returns_true(self, temp_dir):
        base = temp_dir.replace("\\", "/") + "/"
        content = "-Xmx1g\n"

        assert controller.update_jvm_options(base, content) is True

        assert (Path(base) / "jvm.options").read_text(encoding="utf-8") == content

    def test_returns_false_on_error(self, temp_dir):
        base = temp_dir.replace("\\", "/") + "/"
        with patch("builtins.open", side_effect=OSError("denied")):
            assert controller.update_jvm_options(base, "x") is False

    def test_appends_trailing_newline(self, temp_dir):
        base = temp_dir.replace("\\", "/") + "/"
        assert controller.update_jvm_options(base, "-Xmx1g") is True
        assert (Path(base) / "jvm.options").read_text(encoding="utf-8") == "-Xmx1g\n"

    def test_file_is_readable_under_restrictive_umask(self, temp_dir):
        """
        logstash.lib.sh only honours jvm.options when `[ -r ... ]` passes for the
        logstash user. A 0600 root-owned file silently reverts Logstash to the
        stock JVM settings.
        """
        base = temp_dir.replace("\\", "/") + "/"
        old_umask = os.umask(0o077)
        try:
            assert controller.update_jvm_options(base, "-Xmx1g\n") is True
        finally:
            os.umask(old_umask)
        mode = (Path(base) / "jvm.options").stat().st_mode & 0o777
        assert mode == 0o644, oct(mode)


class TestEnsureEnvJvmOpts:
    def test_adds_line_pointing_at_jvm_options(self, tmp_path):
        settings = tmp_path / "settings"
        settings.mkdir()
        (settings / "jvm.options").write_text("-Xmx1g\n")
        env_file = tmp_path / "env"
        env_file.write_text("LOGSTASH_BINARY=/usr/share/logstash/bin/logstash\n")

        assert controller.ensure_env_jvm_opts(str(env_file), str(settings)) is True

        text = env_file.read_text()
        assert f"LS_JVM_OPTS={settings / 'jvm.options'}" in text
        assert "LOGSTASH_BINARY=/usr/share/logstash/bin/logstash" in text

    def test_is_idempotent(self, tmp_path):
        settings = tmp_path / "settings"
        settings.mkdir()
        (settings / "jvm.options").write_text("-Xmx1g\n")
        env_file = tmp_path / "env"
        env_file.write_text("LOGSTASH_BINARY=/bin/logstash\n")

        controller.ensure_env_jvm_opts(str(env_file), str(settings))
        first = env_file.read_text()
        controller.ensure_env_jvm_opts(str(env_file), str(settings))

        assert env_file.read_text() == first
        assert first.count("LS_JVM_OPTS=") == 1

    def test_replaces_stale_value(self, tmp_path):
        settings = tmp_path / "settings"
        settings.mkdir()
        (settings / "jvm.options").write_text("-Xmx1g\n")
        env_file = tmp_path / "env"
        env_file.write_text("LS_JVM_OPTS=/old/path/jvm.options\n")

        controller.ensure_env_jvm_opts(str(env_file), str(settings))

        text = env_file.read_text()
        assert "/old/path/jvm.options" not in text
        assert text.count("LS_JVM_OPTS=") == 1

    def test_preserves_keystore_password(self, tmp_path):
        settings = tmp_path / "settings"
        settings.mkdir()
        (settings / "jvm.options").write_text("-Xmx1g\n")
        env_file = tmp_path / "env"
        env_file.write_text("LOGSTASH_KEYSTORE_PASS=s3cret\nLOGSTASH_PATH_DATA=/d\n")

        controller.ensure_env_jvm_opts(str(env_file), str(settings))

        text = env_file.read_text()
        assert "LOGSTASH_KEYSTORE_PASS=s3cret" in text
        assert "LOGSTASH_PATH_DATA=/d" in text

    def test_removes_line_when_jvm_options_absent(self, tmp_path):
        """A missing file would make JvmOptionsParser fail Logstash startup."""
        settings = tmp_path / "settings"
        settings.mkdir()
        env_file = tmp_path / "env"
        env_file.write_text("LOGSTASH_BINARY=/bin/logstash\nLS_JVM_OPTS=/gone/jvm.options\n")

        assert controller.ensure_env_jvm_opts(str(env_file), str(settings)) is True

        text = env_file.read_text()
        assert "LS_JVM_OPTS" not in text
        assert "LOGSTASH_BINARY=/bin/logstash" in text

    def test_no_env_file_is_a_noop(self, tmp_path):
        # Packaged mode has no per-instance env file in state.
        assert controller.ensure_env_jvm_opts(None, str(tmp_path)) is False


class TestHealStaleLogstashLaunch:
    def _state(self, tmp_path, mode="managed", **extra):
        settings = tmp_path / "settings"
        settings.mkdir(exist_ok=True)
        (settings / "jvm.options").write_text("-Xmx1g\n")
        state = {
            "mode": mode,
            "settings_path": str(settings),
            "keystore_env_file": str(tmp_path / "env"),
            "logstash_unit": "logstash-managed@1",
        }
        state.update(extra)
        return state

    def test_packaged_mode_is_skipped(self, tmp_path):
        state = self._state(tmp_path, mode="packaged")
        assert controller.heal_stale_logstash_launch(state) is False
        assert not (tmp_path / "env").exists()

    def test_adds_ls_jvm_opts_without_touching_units(self, tmp_path):
        state = self._state(tmp_path)
        unit = tmp_path / "logstash-managed@.service"
        unit.write_text('ExecStart=/bin/bash -c \'exec "${LOGSTASH_BINARY}" --path.settings "${LOGSTASH_PATH_SETTINGS}"\'\n')

        with patch.dict(
            controller_installer().INSTALL_PATHS,
            {"logstash_managed_unit": str(unit)},
        ), patch.object(
            controller_installer(), "install_multi_instance_unit_templates"
        ) as reinstall:
            assert controller.heal_stale_logstash_launch(state) is True

        reinstall.assert_not_called()
        assert "LS_JVM_OPTS=" in (tmp_path / "env").read_text()

    def test_stale_unit_triggers_template_reinstall_as_root(self, tmp_path):
        state = self._state(tmp_path)
        unit = tmp_path / "logstash-managed@.service"
        unit.write_text('ExecStart=/bin/bash -c \'exec "${LOGSTASH_BINARY}" --path.settings="${LOGSTASH_PATH_SETTINGS}"\'\n')

        with patch.dict(
            controller_installer().INSTALL_PATHS,
            {"logstash_managed_unit": str(unit)},
        ), patch.object(
            controller_installer(), "install_multi_instance_unit_templates"
        ) as reinstall, patch.object(controller.os, "geteuid", return_value=0, create=True):
            assert controller.heal_stale_logstash_launch(state) is True

        reinstall.assert_called_once()

    def test_stale_unit_escalates_via_sudo_when_not_root(self, tmp_path):
        state = self._state(tmp_path)
        unit = tmp_path / "logstash-managed@.service"
        unit.write_text('ExecStart=/bin/bash -c \'exec "${LOGSTASH_BINARY}" --path.settings="${LOGSTASH_PATH_SETTINGS}"\'\n')

        inst = controller_installer()
        with patch.dict(
            inst.INSTALL_PATHS, {"logstash_managed_unit": str(unit)}
        ), patch.object(inst, "policy_config_from_state", return_value={"policy_type": "MANAGED"}), patch.object(
            inst, "ensure_simulate_setup", return_value={"status": "complete", "via": "sudo"}
        ) as escalate, patch.object(
            controller.os, "geteuid", return_value=1000, create=True
        ):
            assert controller.heal_stale_logstash_launch(state) is True

        escalate.assert_called_once()

    def test_failed_escalation_still_leaves_env_fix(self, tmp_path):
        state = self._state(tmp_path)
        unit = tmp_path / "logstash-managed@.service"
        unit.write_text('ExecStart=/bin/bash -c \'exec "${LOGSTASH_BINARY}" --path.settings="${LOGSTASH_PATH_SETTINGS}"\'\n')

        inst = controller_installer()
        with patch.dict(
            inst.INSTALL_PATHS, {"logstash_managed_unit": str(unit)}
        ), patch.object(inst, "policy_config_from_state", return_value={}), patch.object(
            inst, "ensure_simulate_setup", side_effect=RuntimeError("no sudo")
        ), patch.object(controller.os, "geteuid", return_value=1000, create=True):
            controller.heal_stale_logstash_launch(state)

        # The env-file half alone is enough to fix the bug.
        assert "LS_JVM_OPTS=" in (tmp_path / "env").read_text()


def controller_installer():
    from logstashagent import installer

    return installer


class TestUpdateLog4j2Properties:
    def test_writes_file_and_returns_true(self, temp_dir):
        base = temp_dir.replace("\\", "/") + "/"
        content = "rootLogger.level = info\n"

        assert controller.update_log4j2_properties(base, content) is True

        assert (Path(base) / "log4j2.properties").read_text(encoding="utf-8") == content

    def test_returns_false_on_error(self, temp_dir):
        base = temp_dir.replace("\\", "/") + "/"
        with patch("builtins.open", side_effect=OSError("denied")):
            assert controller.update_log4j2_properties(base, "x") is False


class TestUpdateKeystore:
    def test_no_ops_returns_false(self):
        with patch.object(controller.agent_state, "get_state", return_value={}):
            assert controller.update_keystore("/cfg/", {"set": {}, "delete": []}) is False

    @patch.object(controller.LogstashKeystore, "load")
    def test_incorrect_password_returns_false(self, mock_load):
        mock_load.side_effect = IncorrectPassword("wrong")
        with patch.object(controller.agent_state, "get_state", return_value={}):
            assert (
                controller.update_keystore(
                    "/cfg/", {"set": {"K": "v"}, "delete": []}
                )
                is False
            )

    @patch.object(controller.LogstashKeystore, "create")
    @patch.object(controller.LogstashKeystore, "load")
    def test_creates_keystore_when_load_fails_with_logstash_exception(
        self, mock_load, mock_create
    ):
        mock_load.side_effect = LogstashKeystoreException("no file")
        ks = MagicMock()
        ks.keys = ["MYKEY"]
        ks.get_key.return_value = "secret"
        mock_create.return_value = ks

        with patch.object(controller.agent_state, "get_state", return_value={"api_key": "test_key"}):
            with patch.object(controller.agent_state, "update_state") as update_state:
                with patch.object(controller, "_decrypt_from_server", side_effect=lambda k, v: v):
                    ok = controller.update_keystore(
                        "/cfg", {"set": {"mykey": "secret"}, "delete": []}
                    )

        assert ok is True
        mock_create.assert_called_once()
        ks.add_key.assert_called_once_with({"mykey": "secret"})
        # Key names are normalised to lowercase before hashing
        expected_hash = hashlib.sha256(b"mykeysecret").hexdigest()
        update_state.assert_called_once()
        call_kw = update_state.call_args
        assert call_kw[0][0] == "keystore"
        assert call_kw[0][1] == {"mykey": expected_hash}

    @patch.object(controller.LogstashKeystore, "load")
    def test_deletes_then_sets(self, mock_load):
        ks = MagicMock()
        ks.keys = ["OLD", "OTHER"]
        mock_load.return_value = ks

        with patch.object(controller.agent_state, "get_state", return_value={"api_key": "test_key"}):
            with patch.object(controller.agent_state, "update_state"):
                with patch.object(controller, "_decrypt_from_server", side_effect=lambda k, v: v):
                    controller.update_keystore(
                        "/cfg/",
                        {"set": {"new": "1"}, "delete": ["old", "missing"]},
                    )

        ks.remove_key.assert_called_once_with(["old"])
        ks.add_key.assert_called_once_with({"new": "1"})

    @patch.object(controller.LogstashKeystore, "load")
    def test_logstash_modified_on_delete_returns_false(self, mock_load):
        ks = MagicMock()
        ks.keys = ["K"]
        mock_load.return_value = ks
        ks.remove_key.side_effect = LogstashKeystoreModified(["k"], 1.0)

        with patch.object(controller.agent_state, "get_state", return_value={}):
            assert (
                controller.update_keystore("/cfg/", {"set": {}, "delete": ["k"]})
                is False
            )

    @patch.object(controller.LogstashKeystore, "load")
    def test_create_failure_returns_false(self, mock_load):
        mock_load.side_effect = LogstashKeystoreException("missing")
        with patch.object(
            controller.LogstashKeystore,
            "create",
            side_effect=RuntimeError("cannot create"),
        ):
            with patch.object(controller.agent_state, "get_state", return_value={}):
                assert (
                    controller.update_keystore(
                        "/cfg/", {"set": {"a": "b"}, "delete": []}
                    )
                    is False
                )

    def test_unauthenticated_create_and_set(self, temp_dir):
        """No keystore_password in state: create unauth keystore and set keys."""
        settings = temp_dir.replace("\\", "/") + "/"
        with patch.object(
            controller.agent_state,
            "get_state",
            return_value={"api_key": "test_key"},
        ), patch.object(controller.agent_state, "update_state") as update_state, patch.object(
            controller, "_decrypt_from_server", side_effect=lambda k, v: v
        ):
            ok = controller.update_keystore(
                settings, {"set": {"alpha": "a1"}, "delete": []}
            )
        assert ok is True
        ks_path = Path(settings) / "logstash.keystore"
        assert ks_path.exists()
        # Load without password (unauthenticated trailer)
        from logstashagent.ls_keystore_utils import LogstashKeystore
        loaded = LogstashKeystore.load(settings, password=None, exepath=None)
        assert loaded.uses_embedded_password is True
        assert loaded.get_key("alpha") == "a1"
        # Hash state updated with lowercase key names
        assert update_state.called
        assert update_state.call_args[0][0] == "keystore"
        assert "alpha" in update_state.call_args[0][1]

    def test_snmp_merge_without_password_contributes_keystore(self):
        plan = {"keystore": {"set": {}, "delete": []}, "pipelines": {"set": {}, "delete": []}}
        with patch.object(controller.agent_state, "get_state", return_value={}):
            res = controller.apply_snmp_changes(
                "/cfg/",
                {
                    "keystore": {"set": {"k1": "enc"}, "delete": []},
                    "pipelines": {},
                },
                plan=plan,
            )
        assert res["ran"] is True
        assert res["keystore_skipped"] is False
        assert res["keystore_set_names"] == ["k1"]
        assert "k1" in plan["keystore"]["set"]



class TestLogstashUnitName:
    def test_explicit_unit_wins(self):
        with patch.object(
            controller.agent_state,
            "get_state",
            return_value={"logstash_unit": "ls-simulate@9", "mode": "host", "instance_id": 1},
        ):
            assert controller._logstash_unit_name() == "ls-simulate@9"

    def test_host_alias_maps_to_managed_unit(self):
        with patch.object(
            controller.agent_state,
            "get_state",
            return_value={"mode": "host", "instance_id": 3},
        ):
            assert controller._logstash_unit_name() == "logstash-managed@3"

    def test_default_and_agent_aliases_use_packaged_unit(self):
        for mode in ("default", "agent", "packaged", None):
            with patch.object(
                controller.agent_state,
                "get_state",
                return_value={"mode": mode, "instance_id": 1},
            ):
                assert controller._logstash_unit_name() == "logstash"


class TestRestartLogstash:
    @patch.object(controller.agent_state, "get_state", return_value={})
    @patch("logstashagent.installer.systemctl_via_sudo")
    def test_systemctl_success_returns_true(self, mock_ctl, _state):
        mock_ctl.return_value = MagicMock(returncode=0, stderr="")

        assert controller.restart_logstash() is True

        mock_ctl.assert_called_with("restart", "logstash", timeout=30)

    @patch.object(controller.agent_state, "get_state", return_value={})
    @patch.object(controller.subprocess, "run")
    @patch("logstashagent.installer.systemctl_via_sudo", side_effect=FileNotFoundError())
    def test_falls_back_to_service_command(self, _mock_ctl, mock_run, _state):
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        assert controller.restart_logstash() is True

        assert mock_run.call_args_list[0][0][0] == [
            "sudo",
            "service",
            "logstash",
            "restart",
        ]

    @patch.object(controller.agent_state, "get_state", return_value={})
    @patch.object(controller.subprocess, "run")
    @patch("logstashagent.installer.systemctl_via_sudo", side_effect=FileNotFoundError())
    def test_returns_false_when_no_manager_succeeds(self, _mock_ctl, mock_run, _state):
        mock_run.side_effect = FileNotFoundError()

        assert controller.restart_logstash() is False

    @patch.object(controller.agent_state, "get_state", return_value={})
    @patch("logstashagent.installer.systemctl_via_sudo")
    def test_timeout_returns_false(self, mock_ctl, _state):
        mock_ctl.side_effect = subprocess.TimeoutExpired("cmd", 30)

        assert controller.restart_logstash() is False


class TestGetConfigChanges:
    def test_missing_required_state_returns_none(self):
        with patch.object(
            controller.agent_state,
            "get_state",
            return_value={"logstash_ui_url": "http://x"},
        ):
            assert controller.get_config_changes() is None

    def test_no_config_files_found_returns_none(self, temp_dir):
        base = Path(temp_dir) / "empty_settings"
        base.mkdir()
        settings = str(base).replace("\\", "/") + "/"
        state = {
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "key",
            "connection_id": "conn-1",
            "settings_path": settings,
        }
        with patch.object(controller.agent_state, "get_state", return_value=state):
            assert controller.get_config_changes() is None

    def test_posts_hashes_and_returns_result(self, temp_dir):
        settings = Path(temp_dir) / "ls_settings"
        settings.mkdir()
        yml = settings / "logstash.yml"
        yml.write_text("http.host: 0.0.0.0\n", encoding="utf-8")

        base = str(settings).replace("\\", "/") + "/"
        state = {
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "secret-key",
            "connection_id": "conn-1",
            "settings_path": base,
            "keystore": {"FOO": "hash1"},
        }

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"success": True, "changes": {}}

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.requests, "post", return_value=resp) as post:
                out = controller.get_config_changes()

        assert out["success"] is True
        post.assert_called_once()
        url, kwargs = post.call_args[0][0], post.call_args[1]
        assert url.endswith("/ConnectionManager/GetConfigChanges/")
        assert kwargs["json"]["connection_id"] == "conn-1"
        assert kwargs["json"]["keystore"] == {"FOO": "hash1"}
        assert kwargs["headers"]["Authorization"] == "ApiKey secret-key"
        # Product-CA pin uses system∪product trust (not verify=False when pinned).
        # Unpinned / missing CA may still pass a path or True-ish verify object.
        assert "verify" in kwargs
        assert kwargs["verify"] is not None

    def test_http_error_returns_none(self, temp_dir):
        settings = Path(temp_dir) / "s"
        settings.mkdir()
        (settings / "logstash.yml").write_text("a", encoding="utf-8")
        base = str(settings).replace("\\", "/") + "/"
        state = {
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
            "settings_path": base,
        }
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "err"

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.requests, "post", return_value=resp):
                assert controller.get_config_changes() is None

    def test_invalid_json_returns_none(self, temp_dir):
        """JSON decode errors are caught by the outer handler and become None."""
        settings = Path(temp_dir) / "s2"
        settings.mkdir()
        (settings / "logstash.yml").write_text("a", encoding="utf-8")
        base = str(settings).replace("\\", "/") + "/"
        state = {
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
            "settings_path": base,
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
        resp.headers = {}
        resp.text = "not-json"

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.requests, "post", return_value=resp):
                assert controller.get_config_changes() is None

    def test_applies_changes_and_restarts(self, temp_dir):
        settings = Path(temp_dir) / "s3"
        settings.mkdir()
        (settings / "logstash.yml").write_text("old", encoding="utf-8")
        base = str(settings).replace("\\", "/") + "/"

        state = {
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
            "settings_path": base,
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "changes": {"logstash_yml": "new-content"},
            "current_revision": 7,
        }

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.agent_state, "update_state") as upd:
                with patch.object(
                    controller, "update_logstash_yml", return_value=True
                ) as mock_ylm:
                    with patch.object(
                        controller, "restart_logstash", return_value=True
                    ) as mock_restart:
                        with patch.object(controller.requests, "post", return_value=resp):
                            out = controller.get_config_changes()

        assert out["success"] is True
        mock_ylm.assert_called_once_with(base, "new-content")
        mock_restart.assert_called_once()
        # Check that update_state was called twice: revision_number and last_policy_apply
        assert upd.call_count == 2
        # First call: revision_number
        assert upd.call_args_list[0][0] == ("revision_number", 7)
        # Second call: last_policy_apply dict
        last_apply = upd.call_args_list[1][0]
        assert last_apply[0] == "last_policy_apply"
        assert last_apply[1]["success"] is True
        assert last_apply[1]["revision"] == 7
        assert last_apply[1]["failed_operations"] == []


class TestCheckIn:
    def test_not_enrolled_returns_none(self):
        with patch.object(controller.agent_state, "get_state", return_value={}):
            assert controller.check_in() is None

    def test_missing_fields_returns_none(self):
        with patch.object(
            controller.agent_state,
            "get_state",
            return_value={"enrolled": True, "logstash_ui_url": "http://x"},
        ):
            assert controller.check_in() is None

    def test_success_same_revision(self):
        state = {
            "enrolled": True,
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
            "revision_number": 5,
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "current_revision_number": 5,
        }

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller, "get_config_changes") as gcc:
                with patch.object(controller.requests, "post", return_value=resp):
                    out = controller.check_in()

        assert out["success"] is True
        gcc.assert_not_called()

    def test_success_new_revision_triggers_get_config_changes(self):
        from unittest.mock import ANY
        state = {
            "enrolled": True,
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
            "revision_number": 1,
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "current_revision_number": 2,
            "settings_path": "/a/",
            "logs_path": "/l/",
            "binary_path": "/b/",
        }

        gcc_result = {
            "ran": False, "files_updated": False, "requires_restart": False,
            "failed_operations": [], "aborted": False, "current_revision": 2,
            "snmp_changes": None,
        }

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.agent_state, "update_state"):
                with patch.object(controller, "get_config_changes", return_value=gcc_result) as gcc:
                    with patch.object(controller, "_apply_merged_plan"):
                        with patch.object(controller.requests, "post", return_value=resp):
                            controller.check_in()

        gcc.assert_called_once_with("/a/", "/l/", "/b/", plan=ANY)

    def test_request_failure_returns_none(self):
        state = {
            "enrolled": True,
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
        }
        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(
                controller.requests,
                "post",
                side_effect=requests.exceptions.ConnectionError("down"),
            ):
                assert controller.check_in() is None

    def test_success_false_returns_result(self):
        state = {
            "enrolled": True,
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"success": False, "message": "no"}

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.requests, "post", return_value=resp):
                out = controller.check_in()

        assert out["success"] is False

    def test_via_ui_flip_alone_triggers_get_config_changes(self):
        """
        Ticking the proxy checkbox does not move the revision number, so the
        via_ui comparison is the only thing that can trigger the fetch.
        """
        from unittest.mock import ANY

        state = {
            "enrolled": True,
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
            "revision_number": 5,
            "logstash_source": "VERSION",
            "logstash_version": "9.4.3",
            "logstash_via_ui": False,
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "current_revision_number": 5,  # unchanged
            "logstash_source": "VERSION",
            "logstash_version": "9.4.3",
            "logstash_via_ui": True,  # the only change
            "settings_path": "/a/",
            "logs_path": "/l/",
            "binary_path": "/b/",
        }
        gcc_result = {
            "ran": False, "files_updated": False, "requires_restart": False,
            "failed_operations": [], "aborted": False, "current_revision": 5,
            "snmp_changes": None,
        }

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.agent_state, "update_state"):
                with patch.object(
                    controller, "get_config_changes", return_value=gcc_result
                ) as gcc:
                    with patch.object(controller, "_apply_merged_plan"):
                        with patch.object(
                            controller.requests, "post", return_value=resp
                        ):
                            controller.check_in()

        gcc.assert_called_once_with("/a/", "/l/", "/b/", plan=ANY)

    def test_via_ui_unchanged_does_not_trigger_fetch(self):
        state = {
            "enrolled": True,
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": "c",
            "revision_number": 5,
            "logstash_source": "VERSION",
            "logstash_version": "9.4.3",
            "logstash_via_ui": True,
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "current_revision_number": 5,
            "logstash_source": "VERSION",
            "logstash_version": "9.4.3",
            "logstash_via_ui": True,
        }

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller.agent_state, "update_state"):
                with patch.object(controller, "get_config_changes") as gcc:
                    with patch.object(controller, "_apply_merged_plan"):
                        with patch.object(
                            controller.requests, "post", return_value=resp
                        ):
                            controller.check_in()

        gcc.assert_not_called()


class TestGetConfigChangesViaUiReporting:
    """
    The server compares the agent's reported logstash_via_ui against the policy
    to compute runtime_changed. Omitting the key defaults it to False, which
    silently prevents a checkbox-only change from ever being applied.
    """

    def _run(self, tmp_path, state, env=None, monkeypatch=None):
        settings = tmp_path / "settings"
        settings.mkdir()
        (settings / "logstash.yml").write_text("a: 1\n", encoding="utf-8")
        (settings / "jvm.options").write_text("-Xmx1g\n", encoding="utf-8")
        (settings / "log4j2.properties").write_text("x=y\n", encoding="utf-8")

        full_state = {
            "logstash_ui_url": "http://localhost:8000",
            "api_key": "k",
            "connection_id": 7,
            "settings_path": str(settings),
        }
        full_state.update(state)

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"success": True, "changes": {}}

        with patch.object(
            controller.agent_state, "get_state", return_value=full_state
        ):
            with patch.object(controller, "build_pipelines_state", return_value={}):
                with patch.object(
                    controller.requests, "post", return_value=resp
                ) as post:
                    controller.get_config_changes()
        return post.call_args.kwargs["json"]

    def test_sends_via_ui_true(self, tmp_path):
        body = self._run(tmp_path, {"logstash_via_ui": True})
        assert body["logstash_via_ui"] is True

    def test_sends_via_ui_false_when_absent(self, tmp_path):
        body = self._run(tmp_path, {})
        assert body["logstash_via_ui"] is False

    def test_reports_state_not_env_override(self, tmp_path, monkeypatch):
        """
        The env escape hatch must not be reported: it would disagree with policy
        permanently and re-trigger a runtime delta on every single check-in.
        """
        monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "1")
        body = self._run(tmp_path, {"logstash_via_ui": False})
        assert body["logstash_via_ui"] is False


class TestRunController:
    def test_not_enrolled_returns_after_wait(self):
        """Controller polls for enrollment then exits if still missing."""
        with patch.object(controller.agent_state, "get_state", return_value={}):
            with patch.object(controller.agent_state, "STATE_DIR", "/tmp/x"):
                with patch("time.sleep") as sleep:
                    with patch("time.monotonic", side_effect=[0, 0, 200, 200]):
                        controller.run_controller()
        # At least one sleep while waiting (poll interval)
        assert sleep.called


class TestDecryptFromServer:
    def test_decrypts_value_successfully(self):
        """Test that _decrypt_from_server correctly decrypts a value."""
        from cryptography.fernet import Fernet
        import base64
        import hashlib

        api_key = "test-api-key-123"
        plaintext = "secret-value"

        # Encrypt the value the same way the server would
        key = base64.urlsafe_b64encode(hashlib.sha256(api_key.encode('utf-8')).digest())
        fernet = Fernet(key)
        encrypted = fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')

        # Test decryption
        result = controller._decrypt_from_server(api_key, encrypted)
        assert result == plaintext


class TestUpdateLogstashEnvFile:
    @patch.object(controller, '_LOGSTASH_ENV_FILE')
    def test_raises_file_not_found_when_file_missing(self, mock_env_file):
        """Test that FileNotFoundError is raised when env file doesn't exist."""
        mock_env_file.exists.return_value = False

        with patch('pytest.raises', FileNotFoundError):
            try:
                controller.update_logstash_env_file("password123")
                assert False, "Should have raised FileNotFoundError"
            except FileNotFoundError as e:
                assert "not found" in str(e)

    @patch.object(controller, '_LOGSTASH_ENV_FILE')
    @patch('subprocess.run')
    def test_updates_password_successfully(self, mock_run, mock_env_file):
        """Test successful password update."""
        mock_env_file.exists.return_value = True
        mock_env_file.__str__.return_value = '/etc/default/logstash'

        # Mock successful read
        read_result = MagicMock()
        read_result.returncode = 0
        read_result.stdout = "# Existing content\nOTHER_VAR=value\n"

        # Mock successful write
        write_result = MagicMock()
        write_result.returncode = 0

        # Mock successful chmod
        chmod_result = MagicMock()
        chmod_result.returncode = 0

        mock_run.side_effect = [read_result, write_result, chmod_result]

        controller.update_logstash_env_file("newpass")

        # Verify write was called with correct content
        assert mock_run.call_count == 3
        write_call = mock_run.call_args_list[1]
        assert 'tee' in write_call[0][0]
        assert 'LOGSTASH_KEYSTORE_PASS=newpass' in write_call[1]['input']

    @patch.object(controller, '_LOGSTASH_ENV_FILE')
    @patch('subprocess.run')
    def test_handles_read_failure(self, mock_run, mock_env_file):
        """Test handling of read failure."""
        mock_env_file.exists.return_value = True
        mock_env_file.__str__.return_value = '/etc/default/logstash'

        read_result = MagicMock()
        read_result.returncode = 1
        read_result.stderr = "Permission denied"
        mock_run.return_value = read_result

        try:
            controller.update_logstash_env_file("pass")
            assert False, "Should have raised OSError"
        except OSError:
            pass

    @patch.object(controller, '_LOGSTASH_ENV_FILE')
    @patch('subprocess.run')
    def test_handles_timeout(self, mock_run, mock_env_file):
        """Test handling of subprocess timeout."""
        mock_env_file.exists.return_value = True
        mock_env_file.__str__.return_value = '/etc/default/logstash'

        mock_run.side_effect = subprocess.TimeoutExpired('sudo', 5)

        try:
            controller.update_logstash_env_file("pass")
            assert False, "Should have raised TimeoutExpired"
        except subprocess.TimeoutExpired:
            pass


class TestBuildPipelinesState:
    def test_returns_empty_when_conf_d_missing(self, temp_dir):
        """Test returns empty dict when conf.d doesn't exist."""
        settings = temp_dir.replace("\\", "/") + "/"

        with patch.object(controller.agent_state, "get_state", return_value={}):
            result = controller.build_pipelines_state(settings)

        assert result == {}

    def test_returns_empty_when_no_conf_files(self, temp_dir):
        """Test returns empty dict when no .conf files exist."""
        import os
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        with patch.object(controller.agent_state, "get_state", return_value={}):
            result = controller.build_pipelines_state(settings)

        assert result == {}

    def test_builds_state_from_conf_files(self, temp_dir):
        """Test building state from existing .conf files."""
        import yaml

        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        # Create a pipeline config file
        (conf_d / "pipeline1.conf").write_text("input { stdin {} }", encoding="utf-8")

        # Create pipelines.yml
        pipelines_yml = Path(temp_dir) / "pipelines.yml"
        pipelines_data = [
            {
                'pipeline.id': 'pipeline1',
                'pipeline.workers': 2,
                'pipeline.batch.size': 256
            }
        ]
        pipelines_yml.write_text(yaml.dump(pipelines_data), encoding="utf-8")

        # Mock agent state with stored hash
        state = {
            'pipelines': {
                'pipeline1': {
                    'config_hash': 'abc123',
                    'settings': {'pipeline_workers': 1}
                }
            }
        }

        with patch.object(controller.agent_state, "get_state", return_value=state):
            result = controller.build_pipelines_state(settings)

        assert 'pipeline1' in result
        assert result['pipeline1']['config_hash'] == 'abc123'
        assert result['pipeline1']['settings']['pipeline_workers'] == 2

    def test_includes_no_input_pipelines_from_state(self, temp_dir):
        """Test that no_input pipelines from state are included even without .conf files."""
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        # Create a regular pipeline .conf file
        (conf_d / "regular_pipeline.conf").write_text("input { stdin {} }", encoding="utf-8")

        state = {
            'pipelines': {
                'regular_pipeline': {
                    'config_hash': 'abc123',
                    'settings': {'pipeline_workers': 1}
                },
                'no_input_pipeline': {
                    'config_hash': 'xyz789',
                    'no_input': True,
                    'settings': {'pipeline_workers': 1}
                }
            }
        }

        with patch.object(controller.agent_state, "get_state", return_value=state):
            result = controller.build_pipelines_state(settings)

        # Both pipelines should be in the result
        assert 'regular_pipeline' in result
        assert 'no_input_pipeline' in result
        assert result['no_input_pipeline']['no_input'] is True
        assert result['no_input_pipeline']['config_hash'] == 'xyz789'


class TestUpdatePipelines:
    def test_returns_false_when_no_changes(self, temp_dir):
        """Test returns False when no changes to apply."""
        settings = temp_dir.replace("\\", "/") + "/"
        changes = {'set': {}, 'delete': []}

        result = controller.update_pipelines(settings, changes)
        assert result is False

    def test_creates_conf_d_directory(self, temp_dir):
        """Test that conf.d directory is created if missing."""
        import os
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"

        changes = {
            'set': {
                'test_pipeline': {
                    'lscl': 'input { stdin {} }',
                    'pipeline_hash': 'hash123',
                    'settings': {}
                }
            },
            'delete': []
        }

        with patch.object(controller.agent_state, "get_state", return_value={}):
            with patch.object(controller.agent_state, "update_state"):
                controller.update_pipelines(settings, changes)

        assert conf_d.exists()

    def test_writes_pipeline_config_file(self, temp_dir):
        """Test writing pipeline .conf file."""
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        lscl_content = "input { stdin {} }\nfilter { mutate { add_tag => ['test'] } }"
        changes = {
            'set': {
                'my_pipeline': {
                    'lscl': lscl_content,
                    'pipeline_hash': 'hash456',
                    'settings': {'pipeline_workers': 2}
                }
            },
            'delete': []
        }

        with patch.object(controller.agent_state, "get_state", return_value={}):
            with patch.object(controller.agent_state, "update_state"):
                result = controller.update_pipelines(settings, changes)

        assert result is True
        conf_file = conf_d / "my_pipeline.conf"
        assert conf_file.exists()
        assert conf_file.read_text(encoding="utf-8") == lscl_content

    def test_deletes_pipeline_config_file(self, temp_dir):
        """Test deleting pipeline .conf file."""
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        # Create a file to delete
        conf_file = conf_d / "old_pipeline.conf"
        conf_file.write_text("input { stdin {} }", encoding="utf-8")

        changes = {
            'set': {},
            'delete': ['old_pipeline']
        }

        with patch.object(controller.agent_state, "get_state", return_value={}):
            result = controller.update_pipelines(settings, changes)

        assert result is True
        assert not conf_file.exists()

    def test_skips_conf_write_for_no_input_pipeline(self, temp_dir):
        """Test that no_input pipelines don't get .conf files written."""
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        changes = {
            'set': {
                'no_input_pipe': {
                    'lscl': 'should not be written',
                    'pipeline_hash': 'hash789',
                    'no_input': True,
                    'settings': {}
                }
            },
            'delete': []
        }

        with patch.object(controller.agent_state, "get_state", return_value={}):
            with patch.object(controller.agent_state, "update_state"):
                result = controller.update_pipelines(settings, changes)

        assert result is True
        conf_file = conf_d / "no_input_pipe.conf"
        assert not conf_file.exists()

    def test_returns_false_on_delete_error(self, temp_dir):
        """Test returns False when delete operation fails."""
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        changes = {
            'set': {},
            'delete': ['test_pipeline']
        }

        with patch('os.remove', side_effect=PermissionError("Access denied")):
            with patch('os.path.isfile', return_value=True):
                result = controller.update_pipelines(settings, changes)

        assert result is False

    def test_returns_false_on_write_error(self, temp_dir):
        """Test returns False when write operation fails."""
        settings = temp_dir.replace("\\", "/") + "/"
        conf_d = Path(temp_dir) / "conf.d"
        conf_d.mkdir()

        changes = {
            'set': {
                'test': {
                    'lscl': 'content',
                    'pipeline_hash': 'hash',
                    'settings': {}
                }
            },
            'delete': []
        }

        with patch('builtins.open', side_effect=OSError("Write failed")):
            result = controller.update_pipelines(settings, changes)

        assert result is False


class TestSetKeystorePassword:
    def test_migrates_unauth_to_auth_preserving_secrets(self, temp_dir):
        settings = temp_dir.replace("\\", "/") + "/"
        from logstashagent.ls_keystore_utils import LogstashKeystore
        ks = LogstashKeystore.create(settings, password=None, exepath=None)
        ks.add_key("keep", "secret-value")

        with patch.object(controller.agent_state, "get_state", return_value={}), patch.object(
            controller.agent_state, "update_state"
        ) as update_state, patch.object(controller, "update_logstash_env_file") as env_upd:
            result = controller.set_keystore_password(settings, "NewAuthPass")

        assert result["success"] is True
        assert result["wiped"] is False
        assert result["action"] == "migrated"
        env_upd.assert_called_once_with("NewAuthPass")
        # Password stored in state
        keys = [c[0][0] for c in update_state.call_args_list]
        assert "keystore_password" in keys
        loaded = LogstashKeystore.load(settings, password="NewAuthPass", exepath=None)
        assert loaded.get_key("keep") == "secret-value"
        assert loaded.uses_embedded_password is False

    def test_creates_when_missing(self, temp_dir):
        settings = temp_dir.replace("\\", "/") + "/"
        with patch.object(controller.agent_state, "get_state", return_value={}), patch.object(
            controller.agent_state, "update_state"
        ), patch.object(controller, "update_logstash_env_file"):
            result = controller.set_keystore_password(settings, "pass123")
        assert result["success"] is True
        assert result["action"] == "created"
        from logstashagent.ls_keystore_utils import LogstashKeystore
        loaded = LogstashKeystore.load(settings, password="pass123", exepath=None)
        assert loaded.uses_embedded_password is False

    def test_clear_keystore_password_api(self, temp_dir):
        settings = temp_dir.replace("\\", "/") + "/"
        from logstashagent.ls_keystore_utils import LogstashKeystore
        LogstashKeystore.create(settings, password="authpass", exepath=None)
        with patch.object(
            controller.agent_state,
            "get_state",
            return_value={"keystore_password": "authpass"},
        ), patch.object(controller.agent_state, "update_state"), patch.object(
            controller, "update_logstash_env_file"
        ) as env_upd:
            result = controller.clear_keystore_password(settings)
        assert result["success"] is True
        assert result["action"] == "migrated_unauth"
        env_upd.assert_called_once_with(None)
        loaded = LogstashKeystore.load(settings, password=None, exepath=None)
        assert loaded.uses_embedded_password is True


class TestApplyKeystorePasswordChange:
    """Check-in protocol: false=no-op, null=clear, string=set."""

    def test_false_is_noop(self, temp_dir):
        settings = temp_dir.replace("\\", "/") + "/"
        with patch.object(controller, "clear_keystore_password") as clear, patch.object(
            controller, "set_keystore_password"
        ) as set_pw:
            out = controller.apply_keystore_password_change(settings, False, "api-key")
        assert out["applied"] is False
        assert out["success"] is True
        clear.assert_not_called()
        set_pw.assert_not_called()

    def test_null_clears_password(self, temp_dir):
        settings = temp_dir.replace("\\", "/") + "/"
        with patch.object(
            controller,
            "clear_keystore_password",
            return_value={"success": True, "action": "migrated_unauth"},
        ) as clear:
            out = controller.apply_keystore_password_change(settings, None, "api-key")
        assert out["applied"] is True
        assert out["success"] is True
        assert out["requires_restart"] is True
        assert out["action"] == "migrated_unauth"
        clear.assert_called_once_with(settings)

    def test_encrypted_string_sets_password(self, temp_dir):
        settings = temp_dir.replace("\\", "/") + "/"
        with patch.object(
            controller, "_decrypt_from_server", return_value="plain-pass"
        ), patch.object(
            controller,
            "set_keystore_password",
            return_value={"success": True, "action": "migrated", "wiped": False},
        ) as set_pw:
            out = controller.apply_keystore_password_change(
                settings, "encrypted-blob", "api-key"
            )
        assert out["applied"] is True
        assert out["success"] is True
        set_pw.assert_called_once_with(settings, "plain-pass")

    def test_clear_failure_reports_error(self, temp_dir):
        settings = temp_dir.replace("\\", "/") + "/"
        with patch.object(
            controller,
            "clear_keystore_password",
            return_value={"success": False, "action": "failed"},
        ):
            out = controller.apply_keystore_password_change(settings, None, "api-key")
        assert out["success"] is False
        assert "clear" in (out.get("error") or "")


class TestUpdateLogstashEnvFileClear:
    @patch.object(controller.subprocess, "run")
    def test_clears_password_line(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="FOO=1\nLOGSTASH_KEYSTORE_PASS=old\n", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]
        with patch.object(controller.Path, "exists", return_value=True):
            # Path.exists is used on _LOGSTASH_ENV_FILE via instance — patch the file
            with patch.object(controller, "_LOGSTASH_ENV_FILE", Path("/tmp/fake-default-logstash")):
                Path("/tmp/fake-default-logstash").write_text("x")
                controller.update_logstash_env_file(None)
        # Second call is sudo tee with content without LOGSTASH_KEYSTORE_PASS
        tee_call = mock_run.call_args_list[1]
        assert tee_call[1].get("input") is not None or (tee_call[0] and True)
        # input= content
        written = mock_run.call_args_list[1].kwargs.get("input") or ""
        assert "LOGSTASH_KEYSTORE_PASS" not in written
        assert "FOO=1" in written
