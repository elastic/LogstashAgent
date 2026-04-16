#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.controller."""

import hashlib
import json
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
        expected_hash = hashlib.sha256(b"MYKEYsecret").hexdigest()
        update_state.assert_called_once()
        call_kw = update_state.call_args
        assert call_kw[0][0] == "keystore"
        assert call_kw[0][1] == {"MYKEY": expected_hash}

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


class TestRestartLogstash:
    @patch.object(controller.subprocess, "run")
    def test_systemctl_success_returns_true(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        assert controller.restart_logstash() is True

        mock_run.assert_called_with(
            ["sudo", "systemctl", "restart", "logstash"],
            capture_output=True,
            text=True,
            timeout=30,
        )

    @patch.object(controller.subprocess, "run")
    def test_falls_back_to_service_command(self, mock_run):
        mock_run.side_effect = [
            FileNotFoundError(),
            MagicMock(returncode=0, stderr=""),
        ]

        assert controller.restart_logstash() is True

        assert mock_run.call_args_list[1][0][0] == [
            "sudo",
            "service",
            "logstash",
            "restart",
        ]

    @patch.object(controller.subprocess, "run")
    def test_returns_false_when_no_manager_succeeds(self, mock_run):
        mock_run.side_effect = [
            FileNotFoundError(),
            FileNotFoundError(),
        ]

        assert controller.restart_logstash() is False

    @patch.object(controller.subprocess, "run")
    def test_timeout_returns_false(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 30)

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
        assert kwargs["verify"] is False

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

        with patch.object(controller.agent_state, "get_state", return_value=state):
            with patch.object(controller, "get_config_changes") as gcc:
                with patch.object(controller.requests, "post", return_value=resp):
                    controller.check_in()

        gcc.assert_called_once_with("/a/", "/l/", "/b/")

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


class TestRunController:
    def test_not_enrolled_returns_without_loop(self):
        with patch.object(controller.agent_state, "get_state", return_value={}):
            with patch.object(controller.time, "sleep") as sleep:
                controller.run_controller()
        sleep.assert_not_called()


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
