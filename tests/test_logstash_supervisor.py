#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.logstash_supervisor."""

import os
import signal
import subprocess
import time

import pytest
from unittest.mock import patch, MagicMock

from logstashagent import logstash_supervisor
from logstashagent.logstash_supervisor import LogstashSupervisor


# ---- TestSupervisorInit ----

class TestSupervisorInit:
    def test_default_config(self):
        sup = LogstashSupervisor()
        assert sup.simulation_mode_type == "embedded"
        assert sup.logstash_binary == "/usr/share/logstash/bin/logstash"
        assert sup.logstash_settings.endswith("/")
        assert sup.simulation_mode is True
        assert sup.is_healthy is False
        assert sup.is_restarting is False
        assert sup.restart_count == 0

    def test_embedded_mode_config(self, supervisor_config_embedded):
        sup = LogstashSupervisor(config=supervisor_config_embedded)
        assert sup.simulation_mode_type == "embedded"

    def test_host_mode_config_collapses_to_embedded_process(self, supervisor_config_host):
        """Legacy simulation_mode=host still uses embedded process ownership."""
        sup = LogstashSupervisor(config=supervisor_config_host)
        assert sup.simulation_mode_type == "embedded"
        assert sup.legacy_host_layout is True
        assert sup.run_as_logstash_user is True

    def test_settings_path_trailing_slash_added(self):
        sup = LogstashSupervisor(config={"logstash_settings": "/etc/logstash"})
        assert sup.logstash_settings == "/etc/logstash/"

    def test_log_path_trailing_slash_stripped(self):
        sup = LogstashSupervisor(config={"logstash_log_path": "/var/log/logstash/"})
        assert sup.logstash_log_path == "/var/log/logstash"

    def test_memory_thresholds(self):
        sup = LogstashSupervisor()
        assert sup.heap_threshold_percent == 95.0
        assert sup.threshold_duration_seconds == 60.0
        assert sup.rss_critical_multiplier == 1.5
        assert sup.api_unresponsive_threshold == 6

    def test_initial_tracking_state(self):
        sup = LogstashSupervisor()
        assert sup.high_memory_start_time is None
        assert sup.api_unresponsive_count == 0
        assert sup.pipeline_mismatch_start_time is None
        assert sup.heap_max_gb is None
        assert sup.process is None
        assert sup.monitor_thread is None
        assert sup._healthy_since is None


# ---- TestStartLogstash ----

class TestStartLogstash:
    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.subprocess.Popen")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=True)
    @patch("logstashagent.logstash_supervisor.os.chmod")
    def test_start_spawns_process(self, _chmod, _exists, mock_popen, _getpgid,
                                   supervisor_instance, mock_logstash_process):
        mock_popen.return_value = mock_logstash_process
        supervisor_instance.start_logstash()
        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        assert supervisor_instance.logstash_binary in args
        assert "--path.settings" in args
        assert supervisor_instance.process is mock_logstash_process

    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.subprocess.Popen")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=True)
    @patch("logstashagent.logstash_supervisor.os.chmod")
    def test_start_sets_logstash_url_embedded(self, _c, _e, mock_popen, _getpgid,
                                               supervisor_instance, mock_logstash_process):
        mock_popen.return_value = mock_logstash_process
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOGSTASH_URL", None)
            supervisor_instance.start_logstash()
        env = mock_popen.call_args[1]["env"]
        assert env["LOGSTASH_URL"] == "https://logstashui:8443"

    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.subprocess.Popen")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=True)
    @patch("logstashagent.logstash_supervisor.os.chmod")
    def test_start_sets_logstash_url_host(self, _c, _e, mock_popen, _getpgid,
                                           supervisor_config_host, mock_logstash_process,
                                           reset_supervisor_global):
        mock_popen.return_value = mock_logstash_process
        sup = LogstashSupervisor(config=supervisor_config_host)
        with patch.object(sup, "ensure_sim_layout"), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOGSTASH_URL", None)
            sup.start_logstash()
        env = mock_popen.call_args[1]["env"]
        assert env["LOGSTASH_URL"] == "https://localhost:8443"

    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=False)
    def test_start_raises_binary_not_found(self, _e, supervisor_instance):
        with pytest.raises(FileNotFoundError, match="Logstash binary not found"):
            supervisor_instance.start_logstash()

    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.subprocess.Popen")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=True)
    @patch("logstashagent.logstash_supervisor.os.chmod")
    def test_start_cleans_lock_file(self, _c, mock_exists, mock_popen, _getpgid,
                                     supervisor_instance, mock_logstash_process):
        mock_popen.return_value = mock_logstash_process
        with patch("logstashagent.logstash_supervisor.os.remove") as mock_rm:
            mock_exists.return_value = True
            supervisor_instance.start_logstash()
            mock_rm.assert_any_call("/usr/share/logstash/data/.lock")

    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.subprocess.Popen")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=True)
    @patch("logstashagent.logstash_supervisor.os.chmod")
    def test_start_creates_monitor_thread(self, _c, _e, mock_popen, _getpgid,
                                           supervisor_instance, mock_logstash_process):
        mock_popen.return_value = mock_logstash_process
        supervisor_instance.start_logstash()
        assert supervisor_instance.monitor_thread is not None
        assert supervisor_instance.monitor_thread.daemon is True
        supervisor_instance.should_run = False

    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.subprocess.Popen")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=True)
    @patch("logstashagent.logstash_supervisor.os.chmod")
    def test_start_skips_if_already_running(self, _c, _e, mock_popen,
                                             supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = 0
        supervisor_instance.start_logstash()
        mock_popen.assert_not_called()

    @patch("logstashagent.logstash_supervisor.os.name", "posix")
    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.subprocess.Popen")
    @patch("logstashagent.logstash_supervisor.os.path.exists", return_value=True)
    @patch("logstashagent.logstash_supervisor.os.chmod")
    def test_start_calls_ensure_sim_layout(self, _c, _e, mock_popen, _getpgid,
                                          supervisor_config_host, mock_logstash_process,
                                          reset_supervisor_global):
        mock_popen.return_value = mock_logstash_process
        sup = LogstashSupervisor(config=supervisor_config_host)
        with patch.object(sup, "ensure_sim_layout") as mock_setup:
            sup.start_logstash()
            mock_setup.assert_called_once()


# ---- TestStopLogstash ----

class TestStopLogstash:
    def test_stop_no_process(self, supervisor_instance):
        supervisor_instance.process = None
        supervisor_instance.stop_logstash()
        assert supervisor_instance.process is None

    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.os.killpg")
    def test_stop_graceful(self, mock_killpg, _gpgid,
                            supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = None
        with patch.object(supervisor_instance, "_cleanup_orphaned_processes"):
            supervisor_instance.stop_logstash(graceful=True)
        mock_killpg.assert_called_with(12345, signal.SIGTERM)
        assert supervisor_instance.process is None

    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.os.killpg")
    def test_stop_force_after_timeout(self, mock_killpg, _gpgid,
                                       supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = None
        mock_logstash_process.wait.side_effect = [
            subprocess.TimeoutExpired("ls", 30), 0
        ]
        with patch.object(supervisor_instance, "_cleanup_orphaned_processes"):
            supervisor_instance.stop_logstash(graceful=True)
        assert mock_killpg.call_count == 2
        mock_killpg.assert_any_call(12345, signal.SIGKILL)

    @patch("logstashagent.logstash_supervisor.os.getpgid", return_value=12345)
    @patch("logstashagent.logstash_supervisor.os.killpg")
    def test_stop_force_directly(self, mock_killpg, _gpgid,
                                  supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = None
        with patch.object(supervisor_instance, "_cleanup_orphaned_processes"):
            supervisor_instance.stop_logstash(graceful=False)
        mock_killpg.assert_called_once_with(12345, signal.SIGKILL)

    def test_stop_already_terminated(self, supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = 0
        mock_logstash_process.returncode = 0
        with patch.object(supervisor_instance, "_cleanup_orphaned_processes"):
            supervisor_instance.stop_logstash()
        assert supervisor_instance.process is None

    @patch("logstashagent.logstash_supervisor.os.getpgid", side_effect=ProcessLookupError)
    def test_stop_process_lookup_error(self, _gpgid,
                                        supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = None
        with patch.object(supervisor_instance, "_cleanup_orphaned_processes"):
            supervisor_instance.stop_logstash(graceful=True)
        assert supervisor_instance.process is None


# ---- TestRestartLogstash ----

class TestRestartLogstash:
    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_restart_increments_count(self, _sleep, supervisor_instance):
        with patch.object(supervisor_instance, "stop_logstash"), \
             patch.object(supervisor_instance, "start_logstash"), \
             patch("logstashagent.slots") as ms:
            ms.evict_all_slots_and_cleanup.return_value = []
            supervisor_instance.restart_logstash("test")
        assert supervisor_instance.restart_count == 1

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_restart_flag_transitions(self, _sleep, supervisor_instance):
        flags = {}
        def capture(**kw):
            flags["restarting"] = supervisor_instance.is_restarting
            flags["healthy"] = supervisor_instance.is_healthy
        with patch.object(supervisor_instance, "stop_logstash", side_effect=capture), \
             patch.object(supervisor_instance, "start_logstash"), \
             patch("logstashagent.slots") as ms:
            ms.evict_all_slots_and_cleanup.return_value = []
            supervisor_instance.restart_logstash("test")
        assert flags["restarting"] is True
        assert flags["healthy"] is False
        assert supervisor_instance.is_restarting is False

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_restart_evicts_before_stop(self, _sleep, supervisor_instance):
        order = []
        with patch.object(supervisor_instance, "stop_logstash",
                          side_effect=lambda **kw: order.append("stop")), \
             patch.object(supervisor_instance, "start_logstash",
                          side_effect=lambda: order.append("start")), \
             patch("logstashagent.slots") as ms:
            ms.evict_all_slots_and_cleanup.side_effect = \
                lambda: (order.append("evict"), [])[1]
            supervisor_instance.restart_logstash("test")
        assert order == ["evict", "stop", "start"]

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_restart_resets_timers(self, _sleep, supervisor_instance):
        supervisor_instance.high_memory_start_time = time.time()
        supervisor_instance.pipeline_mismatch_start_time = time.time()
        with patch.object(supervisor_instance, "stop_logstash"), \
             patch.object(supervisor_instance, "start_logstash"), \
             patch("logstashagent.slots") as ms:
            ms.evict_all_slots_and_cleanup.return_value = []
            supervisor_instance.restart_logstash("test")
        assert supervisor_instance.high_memory_start_time is None
        assert supervisor_instance.pipeline_mismatch_start_time is None

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_restart_handles_eviction_error(self, _sleep, supervisor_instance):
        with patch.object(supervisor_instance, "stop_logstash"), \
             patch.object(supervisor_instance, "start_logstash"), \
             patch("logstashagent.slots") as ms:
            ms.evict_all_slots_and_cleanup.side_effect = RuntimeError("boom")
            supervisor_instance.restart_logstash("test")
        assert supervisor_instance.restart_count == 1


# ---- TestMemoryMonitoring ----

class TestMemoryMonitoring:
    def test_jvm_heap_returns_percent(self, supervisor_instance, mock_logstash_api):
        with patch("logstashagent.logstash_supervisor.LogstashAPI",
                   return_value=mock_logstash_api):
            assert supervisor_instance._get_jvm_heap_usage() == 50.0

    def test_jvm_heap_caches_max(self, supervisor_instance, mock_logstash_api):
        assert supervisor_instance.heap_max_gb is None
        with patch("logstashagent.logstash_supervisor.LogstashAPI",
                   return_value=mock_logstash_api):
            supervisor_instance._get_jvm_heap_usage()
        assert supervisor_instance.heap_max_gb == pytest.approx(4.0)

    def test_jvm_heap_none_on_error(self, supervisor_instance):
        api = MagicMock()
        api.__enter__ = MagicMock(return_value=api)
        api.__exit__ = MagicMock(return_value=False)
        api.get_node_stats.side_effect = Exception("down")
        with patch("logstashagent.logstash_supervisor.LogstashAPI", return_value=api):
            assert supervisor_instance._get_jvm_heap_usage() is None

    def test_rss_with_children(self, supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        parent = MagicMock()
        parent.memory_info.return_value = MagicMock(rss=2 * 1024**3)
        child = MagicMock()
        child.pid = 99
        child.memory_info.return_value = MagicMock(rss=1 * 1024**3)
        parent.children.return_value = [child]
        with patch("logstashagent.logstash_supervisor.psutil.Process",
                   return_value=parent):
            assert supervisor_instance._get_rss_memory_gb() == pytest.approx(3.0)

    def test_rss_none_no_process(self, supervisor_instance):
        supervisor_instance.process = None
        assert supervisor_instance._get_rss_memory_gb() is None

    def test_rss_none_dead_process(self, supervisor_instance, mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = 1
        assert supervisor_instance._get_rss_memory_gb() is None

    def test_heap_threshold_starts_timer(self, supervisor_instance):
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=96.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=3.0):
            assert supervisor_instance._check_memory_thresholds() is None
        assert supervisor_instance.high_memory_start_time is not None

    def test_heap_threshold_triggers_restart(self, supervisor_instance):
        supervisor_instance.high_memory_start_time = time.time() - 120
        supervisor_instance.heap_max_gb = 4.0
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=96.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=3.0):
            result = supervisor_instance._check_memory_thresholds()
        assert result is not None and "JVM heap" in result

    def test_heap_resets_on_recovery(self, supervisor_instance):
        supervisor_instance.high_memory_start_time = time.time()
        supervisor_instance.heap_max_gb = 4.0
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=80.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=3.0):
            assert supervisor_instance._check_memory_thresholds() is None
        assert supervisor_instance.high_memory_start_time is None

    def test_rss_critical_immediate_restart(self, supervisor_instance):
        supervisor_instance.heap_max_gb = 4.0
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=50.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=7.0):
            result = supervisor_instance._check_memory_thresholds()
        assert result is not None and "RSS memory" in result

    def test_rss_below_critical_ok(self, supervisor_instance):
        supervisor_instance.heap_max_gb = 4.0
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=50.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=5.0):
            assert supervisor_instance._check_memory_thresholds() is None

    def test_api_unresponsive_increments(self, supervisor_instance):
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=None), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=None):
            supervisor_instance._check_memory_thresholds()
        assert supervisor_instance.api_unresponsive_count == 1

    def test_api_unresponsive_triggers_restart(self, supervisor_instance):
        supervisor_instance.api_unresponsive_count = 5
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=None), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=None):
            result = supervisor_instance._check_memory_thresholds()
        assert result is not None and "unresponsive" in result

    def test_api_responsive_resets_counter(self, supervisor_instance):
        supervisor_instance.api_unresponsive_count = 5
        supervisor_instance.heap_max_gb = 4.0
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=50.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=3.0):
            supervisor_instance._check_memory_thresholds()
        assert supervisor_instance.api_unresponsive_count == 0
        assert supervisor_instance.is_healthy is True

    @pytest.mark.parametrize("heap_pct,sustained,expect", [
        (94.0, False, False),
        (95.0, False, False),
        (95.1, True, True),
    ])
    def test_heap_boundary(self, supervisor_instance, heap_pct, sustained, expect):
        supervisor_instance.heap_max_gb = 4.0
        if sustained:
            supervisor_instance.high_memory_start_time = time.time() - 120
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=heap_pct), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=3.0):
            result = supervisor_instance._check_memory_thresholds()
        assert (result is not None) == expect


# ---- TestPipelineMismatch ----

class TestPipelineMismatch:
    def test_get_expected_pipelines(self, supervisor_instance):
        state = {
            1: {"pipelines": [{"f": "a"}]},
            2: {"pipelines": [{"f": "b"}, {"f": "c"}]},
        }
        with patch("logstashagent.slots") as ms:
            ms.get_slot_state.return_value = state
            result = supervisor_instance._get_expected_slot_pipelines()
        assert result == {"slot1-filter1", "slot2-filter1", "slot2-filter2"}

    def test_get_expected_empty(self, supervisor_instance):
        with patch("logstashagent.slots") as ms:
            ms.get_slot_state.return_value = {}
            assert supervisor_instance._get_expected_slot_pipelines() == set()

    def test_get_expected_error(self, supervisor_instance):
        with patch("logstashagent.slots") as ms:
            ms.get_slot_state.side_effect = RuntimeError("x")
            assert supervisor_instance._get_expected_slot_pipelines() == set()

    def test_mismatch_starts_timer(self, supervisor_instance, mock_logstash_api):
        mock_logstash_api.get_running_pipelines_from_health.return_value = []
        with patch("logstashagent.logstash_supervisor.LogstashAPI",
                   return_value=mock_logstash_api), \
             patch.object(supervisor_instance, "_get_expected_slot_pipelines",
                          return_value={"slot1-filter1"}):
            assert supervisor_instance._check_pipeline_mismatch() is None
        assert supervisor_instance.pipeline_mismatch_start_time is not None

    def test_mismatch_triggers_after_threshold(self, supervisor_instance,
                                                mock_logstash_api):
        supervisor_instance.pipeline_mismatch_start_time = time.time() - 60
        mock_logstash_api.get_running_pipelines_from_health.return_value = []
        with patch("logstashagent.logstash_supervisor.LogstashAPI",
                   return_value=mock_logstash_api), \
             patch.object(supervisor_instance, "_get_expected_slot_pipelines",
                          return_value={"slot1-filter1"}):
            result = supervisor_instance._check_pipeline_mismatch()
        assert result is not None and "Pipeline mismatch" in result

    def test_mismatch_resets_on_match(self, supervisor_instance, mock_logstash_api):
        supervisor_instance.pipeline_mismatch_start_time = time.time()
        mock_logstash_api.get_running_pipelines_from_health.return_value = [
            "slot1-filter1", "simulate-start"
        ]
        with patch("logstashagent.logstash_supervisor.LogstashAPI",
                   return_value=mock_logstash_api), \
             patch.object(supervisor_instance, "_get_expected_slot_pipelines",
                          return_value={"slot1-filter1"}):
            assert supervisor_instance._check_pipeline_mismatch() is None
        assert supervisor_instance.pipeline_mismatch_start_time is None


# ---- TestMonitorLoop ----

class TestMonitorLoop:
    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_crash_detection(self, mock_sleep, supervisor_instance,
                              mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = 137
        mock_logstash_process.returncode = 137
        # Mock communicate to prevent blocking
        mock_logstash_process.communicate.return_value = (b"", b"")
        
        # Mock restart_logstash to stop the loop when called
        # (restart calls continue, skipping the sleep, causing infinite loop)
        def mock_restart(reason):
            supervisor_instance.should_run = False
        
        with patch.object(supervisor_instance, "restart_logstash", side_effect=mock_restart) as mr:
            supervisor_instance._monitor_loop()
            mr.assert_called_once()
            assert "crash" in mr.call_args[0][0].lower()

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_memory_threshold_restart(self, mock_sleep, supervisor_instance,
                                       mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = None
        
        # Mock restart_logstash to stop the loop when called
        # (restart calls continue, skipping the sleep, causing infinite loop)
        def mock_restart(reason):
            supervisor_instance.should_run = False
        
        with patch.object(supervisor_instance, "_check_memory_thresholds",
                          return_value="RSS critical"), \
             patch.object(supervisor_instance, "restart_logstash", side_effect=mock_restart) as mr:
            supervisor_instance._monitor_loop()
            mr.assert_called_once()
            assert "RSS critical" in mr.call_args[0][0]

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_stops_on_flag(self, mock_sleep, supervisor_instance,
                            mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.return_value = None
        
        # Stop loop immediately after first sleep
        def _sleep(s):
            supervisor_instance.should_run = False
        mock_sleep.side_effect = _sleep
        
        with patch.object(supervisor_instance, "_check_memory_thresholds",
                          return_value=None):
            supervisor_instance._monitor_loop()
            # Verify loop exited cleanly without calling restart
            assert supervisor_instance.should_run is False

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_handles_exception(self, mock_sleep, supervisor_instance,
                                mock_logstash_process):
        supervisor_instance.process = mock_logstash_process
        mock_logstash_process.poll.side_effect = [RuntimeError("x"), None]
        
        call_count = [0]
        def _sleep(s):
            call_count[0] += 1
            # Stop after startup sleep + one error iteration + one normal iteration
            if call_count[0] >= 3:
                supervisor_instance.should_run = False
        mock_sleep.side_effect = _sleep
        
        with patch.object(supervisor_instance, "_check_memory_thresholds",
                          return_value=None):
            supervisor_instance._monitor_loop()
            # Verify it handled the exception and continued
            assert call_count[0] >= 2


# ---- TestEnsureSimLayout ----

class TestEnsureSimLayout:
    def test_seeds_harness_and_dirs(self, supervisor_config_host, tmp_path):
        settings = str(tmp_path / "settings")
        cfg = dict(supervisor_config_host)
        cfg["logstash_settings"] = settings
        cfg["logstash_log_path"] = str(tmp_path / "logs")
        sup = LogstashSupervisor(config=cfg)
        sup.ensure_sim_layout()
        assert (tmp_path / "settings" / "conf.d").is_dir()
        assert (tmp_path / "settings" / "config" / "simulate_start.conf").is_file()
        assert (tmp_path / "settings" / "config" / "simulate_end.conf").is_file()
        assert (tmp_path / "settings" / "pipelines.yml").is_file()

    def test_setup_host_mode_alias(self, supervisor_config_host):
        sup = LogstashSupervisor(config=supervisor_config_host)
        with patch.object(sup, "ensure_sim_layout") as ensure:
            sup.setup_host_mode()
        ensure.assert_called_once()


# ---- TestCleanupOrphanedProcesses ----

class TestCleanupOrphanedProcesses:
    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_kills_logstash_java(self, _sleep, supervisor_instance):
        proc = MagicMock()
        proc.info = {"pid": 54321, "name": "java",
                     "cmdline": ["java", "logstash.runner"]}
        with patch("logstashagent.logstash_supervisor.psutil.process_iter",
                   return_value=[proc]):
            supervisor_instance._cleanup_orphaned_processes()
        proc.kill.assert_called_once()

    def test_no_orphans(self, supervisor_instance):
        proc = MagicMock()
        proc.info = {"pid": 1, "name": "python", "cmdline": ["python"]}
        with patch("logstashagent.logstash_supervisor.psutil.process_iter",
                   return_value=[proc]):
            supervisor_instance._cleanup_orphaned_processes()

    def test_access_denied(self, supervisor_instance):
        import psutil
        proc = MagicMock()
        proc.info = {"pid": 1, "name": "java", "cmdline": ["java", "logstash"]}
        proc.kill.side_effect = psutil.AccessDenied(pid=1)
        with patch("logstashagent.logstash_supervisor.psutil.process_iter",
                   return_value=[proc]):
            supervisor_instance._cleanup_orphaned_processes()


# ---- TestHealthState ----

class TestHealthState:
    def test_healthy_on_api_response(self, supervisor_instance):
        supervisor_instance.is_healthy = False
        supervisor_instance.heap_max_gb = 4.0
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=50.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=3.0):
            supervisor_instance._check_memory_thresholds()
        assert supervisor_instance.is_healthy is True

    def test_unhealthy_after_sustained_failures(self, supervisor_instance):
        supervisor_instance.api_unresponsive_count = 5
        with patch.object(supervisor_instance, "_get_jvm_heap_usage",
                          return_value=None), \
             patch.object(supervisor_instance, "_get_rss_memory_gb",
                          return_value=None):
            supervisor_instance._check_memory_thresholds()
        assert supervisor_instance.is_healthy is False

    def test_healthy_since_set_on_first_healthy_response(self, supervisor_instance):
        """_healthy_since is recorded on the False->True transition."""
        assert supervisor_instance._healthy_since is None
        supervisor_instance.is_healthy = False
        supervisor_instance.heap_max_gb = 4.0
        before = time.monotonic()
        with patch.object(supervisor_instance, "_get_jvm_heap_usage", return_value=50.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb", return_value=3.0):
            supervisor_instance._check_memory_thresholds()
        assert supervisor_instance._healthy_since is not None
        assert supervisor_instance._healthy_since >= before

    def test_healthy_since_not_overwritten_while_already_healthy(self, supervisor_instance):
        """_healthy_since stays fixed once set so warm-healthy duration keeps growing."""
        supervisor_instance.is_healthy = True
        supervisor_instance.heap_max_gb = 4.0
        first = time.monotonic() - 10.0
        supervisor_instance._healthy_since = first
        with patch.object(supervisor_instance, "_get_jvm_heap_usage", return_value=50.0), \
             patch.object(supervisor_instance, "_get_rss_memory_gb", return_value=3.0):
            supervisor_instance._check_memory_thresholds()
        assert supervisor_instance._healthy_since == first

    def test_healthy_since_reset_on_restart(self, supervisor_instance):
        """restart_logstash clears _healthy_since so the next start gets a fresh timestamp."""
        supervisor_instance._healthy_since = time.monotonic()
        with patch.object(supervisor_instance, "stop_logstash"), \
             patch.object(supervisor_instance, "start_logstash"), \
             patch("logstashagent.logstash_supervisor.time.sleep"), \
             patch("logstashagent.slots") as ms:
            ms.evict_all_slots_and_cleanup.return_value = []
            supervisor_instance.restart_logstash("reset test")
        assert supervisor_instance._healthy_since is None


# ---- TestGlobalFunctions ----

class TestGlobalFunctions:
    def test_singleton(self, reset_supervisor_global):
        s1 = logstash_supervisor.get_supervisor()
        s2 = logstash_supervisor.get_supervisor()
        assert s1 is s2

    def test_get_with_config(self, reset_supervisor_global,
                              supervisor_config_embedded):
        s = logstash_supervisor.get_supervisor(config=supervisor_config_embedded)
        assert s.simulation_mode_type == "embedded"

    @patch("logstashagent.logstash_supervisor.time.sleep")
    def test_trigger_restart(self, _sleep, reset_supervisor_global):
        s = logstash_supervisor.get_supervisor()
        with patch.object(s, "stop_logstash"), \
             patch.object(s, "start_logstash"), \
             patch("logstashagent.slots") as ms:
            ms.evict_all_slots_and_cleanup.return_value = []
            logstash_supervisor.trigger_restart("ext")
        assert s.restart_count == 1

    def test_shutdown_no_instance(self, reset_supervisor_global):
        logstash_supervisor.shutdown_supervisor()

    def test_shutdown_calls_stop(self, reset_supervisor_global):
        s = logstash_supervisor.get_supervisor()
        with patch.object(s, "stop_logstash") as ms:
            logstash_supervisor.shutdown_supervisor()
            ms.assert_called_once()


# ---- TestShutdown ----

class TestShutdown:
    def test_sets_should_run_false(self, supervisor_instance):
        with patch.object(supervisor_instance, "stop_logstash"):
            supervisor_instance.shutdown()
        assert supervisor_instance.should_run is False

    def test_joins_monitor_thread(self, supervisor_instance):
        mt = MagicMock()
        mt.is_alive.return_value = False
        supervisor_instance.monitor_thread = mt
        with patch.object(supervisor_instance, "stop_logstash"):
            supervisor_instance.shutdown()
        mt.join.assert_called_once_with(timeout=5)

    def test_calls_stop(self, supervisor_instance):
        with patch.object(supervisor_instance, "stop_logstash") as ms:
            supervisor_instance.shutdown()
        ms.assert_called_once_with(graceful=True)
