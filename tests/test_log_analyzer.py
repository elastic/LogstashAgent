#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.log_analyzer."""

import json
from unittest.mock import patch

from logstashagent import log_analyzer


def _line(obj: dict) -> str:
    return json.dumps(obj) + "\n"


class TestReadJsonLogs:
    """Tests for _read_json_logs using a temporary log directory."""

    def test_empty_directory_returns_empty_list(self, tmp_path):
        assert (
            log_analyzer._read_json_logs(log_dir=str(tmp_path), max_lines=10) == []
        )

    def test_reads_ndjson_lines_sequential(self, tmp_path):
        f = tmp_path / "logstash-json.log"
        f.write_text(
            _line({"a": 1})
            + "not json\n"
            + _line({"b": 2}),
            encoding="utf-8",
        )

        out = log_analyzer._read_json_logs(
            log_dir=str(tmp_path),
            pattern="logstash-json*.log",
            max_lines=None,
            reverse=False,
        )

        assert out == [{"a": 1}, {"b": 2}]

    def test_respects_max_lines_sequential(self, tmp_path):
        f = tmp_path / "logstash-json.log"
        f.write_text(
            "".join(_line({"n": i}) for i in range(5)),
            encoding="utf-8",
        )

        out = log_analyzer._read_json_logs(
            log_dir=str(tmp_path),
            pattern="logstash-json*.log",
            max_lines=2,
            reverse=False,
        )

        assert len(out) == 2
        assert out[0] == {"n": 0}
        assert out[1] == {"n": 1}

    def test_reverse_with_max_lines_reads_recent_first(self, tmp_path):
        f = tmp_path / "logstash-json.log"
        f.write_text(
            "".join(_line({"idx": i, "timeMillis": 1000 + i}) for i in range(5)),
            encoding="utf-8",
        )

        out = log_analyzer._read_json_logs(
            log_dir=str(tmp_path),
            pattern="logstash-json*.log",
            max_lines=3,
            reverse=True,
        )

        assert len(out) == 3
        # Newest lines last in file; reversed tail should surface highest idx first
        assert out[0]["idx"] >= out[-1]["idx"]

    def test_globs_multiple_files(self, tmp_path):
        (tmp_path / "logstash-json.log").write_text(_line({"file": 1}), encoding="utf-8")
        (tmp_path / "logstash-json-2.log").write_text(
            _line({"file": 2}), encoding="utf-8"
        )

        out = log_analyzer._read_json_logs(
            log_dir=str(tmp_path),
            pattern="logstash-json*.log",
            max_lines=None,
            reverse=False,
        )

        assert len(out) == 2


class TestGetRunningPipelines:
    def test_returns_none_when_no_status_entries(self):
        with patch.object(log_analyzer, "_read_json_logs", return_value=[{"x": 1}]):
            assert log_analyzer.get_running_pipelines(log_dir="/tmp") is None

    def test_picks_latest_by_timestamp(self):
        logs = [
            {
                "timeMillis": 100,
                "logEvent": {
                    "running_pipelines": ["old"],
                    "non_running_pipelines": [],
                    "count": 1,
                },
            },
            {
                "timeMillis": 200,
                "level": "INFO",
                "logEvent": {
                    "running_pipelines": ["new"],
                    "non_running_pipelines": [],
                    "count": 1,
                    "message": "status",
                },
            },
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs):
            out = log_analyzer.get_running_pipelines(log_dir="/tmp")

        assert out is not None
        assert out["timestamp"] == 200
        assert out["running_pipelines"] == ["new"]
        assert out["count"] == 1
        assert "raw_event" not in out

    def test_removes_running_pipelines_with_failed_action(self):
        ts = 500
        logs = [
            {
                "timeMillis": ts,
                "level": "INFO",
                "logEvent": {
                    "running_pipelines": ["good", "bad"],
                    "non_running_pipelines": [],
                    "count": 2,
                },
            },
            {
                "timeMillis": ts + 10,
                "level": "ERROR",
                "logEvent": {
                    "action_type": "FailedAction",
                    "id": "bad",
                },
            },
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs):
            out = log_analyzer.get_running_pipelines(log_dir="/tmp")

        assert out["running_pipelines"] == ["good"]


class TestIsPipelineRunning:
    def test_true_when_in_running_list(self):
        with patch.object(
            log_analyzer,
            "get_running_pipelines",
            return_value={"running_pipelines": ["a", "b"]},
        ):
            assert log_analyzer.is_pipeline_running("b") is True

    def test_false_when_status_missing(self):
        with patch.object(log_analyzer, "get_running_pipelines", return_value=None):
            assert log_analyzer.is_pipeline_running("x") is False

    def test_false_when_not_in_list(self):
        with patch.object(
            log_analyzer,
            "get_running_pipelines",
            return_value={"running_pipelines": ["a"]},
        ):
            assert log_analyzer.is_pipeline_running("z") is False


class TestFindRelatedLogs:
    """Test log analysis with mocked log data"""

    def test_find_logs_for_pipeline(self):
        """Test finding logs related to a specific pipeline"""
        mock_logs = [
            {
                "level": "ERROR",
                "pipeline.id": "test-pipeline",
                "logEvent": {
                    "message": "Pipeline error occurred",
                },
                "timeMillis": 1704110400000,
            },
            {
                "level": "WARN",
                "pipeline.id": "test-pipeline",
                "logEvent": {
                    "message": "Pipeline warning",
                },
                "timeMillis": 1704110460000,
            },
            {
                "level": "INFO",
                "pipeline.id": "other-pipeline",
                "logEvent": {
                    "message": "Other pipeline info",
                },
                "timeMillis": 1704110520000,
            },
        ]

        with patch.object(log_analyzer, "_read_json_logs", return_value=mock_logs):
            logs = log_analyzer.find_related_logs(
                pipeline_id="test-pipeline",
                max_entries=10,
                min_level="WARN",
            )

        assert len(logs) == 2
        assert all(log["pipeline.id"] == "test-pipeline" for log in logs)

    def test_match_by_thread_name(self):
        mock_logs = [
            {
                "level": "ERROR",
                "thread": "[slot1-filter1]>worker0",
                "timeMillis": 1,
            }
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=mock_logs):
            logs = log_analyzer.find_related_logs(
                "slot1-filter1",
                max_entries=10,
                min_level="WARN",
            )
        assert len(logs) == 1

    def test_match_by_snapshot_reference(self):
        mock_logs = [
            {
                "level": "ERROR",
                "timeMillis": 1,
                "logEvent": {
                    "event": {
                        "snapshots": {"s1": "pipeline slot2-filter99 state"},
                    }
                },
            }
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=mock_logs):
            logs = log_analyzer.find_related_logs(
                "slot2-filter99",
                max_entries=10,
                min_level="WARN",
            )
        assert len(logs) == 1

    def test_find_logs_with_min_level_filter(self):
        """Test log filtering by minimum level"""
        mock_logs = [
            {
                "level": "ERROR",
                "pipeline.id": "test-pipeline",
                "timeMillis": 1704110400000,
            },
            {
                "level": "WARN",
                "pipeline.id": "test-pipeline",
                "timeMillis": 1704110460000,
            },
            {
                "level": "INFO",
                "pipeline.id": "test-pipeline",
                "timeMillis": 1704110520000,
            },
            {
                "level": "DEBUG",
                "pipeline.id": "test-pipeline",
                "timeMillis": 1704110580000,
            },
        ]

        with patch.object(log_analyzer, "_read_json_logs", return_value=mock_logs):
            logs = log_analyzer.find_related_logs(
                pipeline_id="test-pipeline",
                max_entries=10,
                min_level="ERROR",
            )

        assert len(logs) == 1
        assert logs[0]["level"] == "ERROR"

    def test_find_logs_with_timestamp_filter(self):
        """Test log filtering by minimum timestamp"""
        base_time = 1704110400000
        mock_logs = [
            {"level": "ERROR", "pipeline.id": "test-pipeline", "timeMillis": base_time},
            {
                "level": "ERROR",
                "pipeline.id": "test-pipeline",
                "timeMillis": base_time + 300000,
            },
            {
                "level": "ERROR",
                "pipeline.id": "test-pipeline",
                "timeMillis": base_time + 600000,
            },
        ]

        min_timestamp = base_time + 300000

        with patch.object(log_analyzer, "_read_json_logs", return_value=mock_logs):
            logs = log_analyzer.find_related_logs(
                pipeline_id="test-pipeline",
                max_entries=10,
                min_level="DEBUG",
                min_timestamp=min_timestamp,
            )

        assert len(logs) == 2

    def test_find_logs_max_entries_limit(self):
        """Test that max_entries limit is respected"""
        mock_logs = [
            {
                "level": "ERROR",
                "pipeline.id": "test-pipeline",
                "timeMillis": 1704110400000 + (i * 1000),
            }
            for i in range(100)
        ]

        with patch.object(log_analyzer, "_read_json_logs", return_value=mock_logs):
            logs = log_analyzer.find_related_logs(
                pipeline_id="test-pipeline",
                max_entries=10,
                min_level="DEBUG",
            )

        assert len(logs) == 10

    def test_find_logs_no_matches(self):
        """Test when no logs match the criteria"""
        mock_logs = [
            {
                "level": "INFO",
                "pipeline.id": "other-pipeline",
                "timeMillis": 1704110400000,
            }
        ]

        with patch.object(log_analyzer, "_read_json_logs", return_value=mock_logs):
            logs = log_analyzer.find_related_logs(
                pipeline_id="test-pipeline",
                max_entries=10,
                min_level="WARN",
            )

        assert len(logs) == 0


# ---------------------------------------------------------------------------
# _read_agent_logs
# ---------------------------------------------------------------------------

class TestReadAgentLogs:
    def _write_agent_log(self, path, lines):
        """Write agent log lines (pre-formatted) to file."""
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _fmt(self, dt_str, level, module, func, message):
        return f"[{level}] {dt_str} {module} {func}: {message}"

    def test_returns_empty_when_no_files(self, tmp_path):
        result = log_analyzer._read_agent_logs(agent_log_dir=tmp_path)
        assert result == []

    def test_parses_restart_initiated(self, tmp_path):
        line = self._fmt(
            "2026-01-01 12:00:00",
            "INFO", "logstashagent.supervisor", "restart_logstash",
            "Restarting Logstash (restart #3): memory threshold exceeded",
        )
        log_file = tmp_path / "logstashagent.log"
        self._write_agent_log(log_file, [line])

        entries = log_analyzer._read_agent_logs(agent_log_dir=tmp_path)

        assert len(entries) == 1
        e = entries[0]
        assert e["event_type"] == "restart_initiated"
        assert e["restart_count"] == 3
        assert "memory" in e["reason"]

    def test_parses_process_died(self, tmp_path):
        line = self._fmt(
            "2026-01-01 12:01:00",
            "ERROR", "logstashagent.supervisor", "_monitor_loop",
            "Logstash process died (exit code: 137)",
        )
        log_file = tmp_path / "logstashagent.log"
        self._write_agent_log(log_file, [line])

        entries = log_analyzer._read_agent_logs(agent_log_dir=tmp_path)

        assert len(entries) == 1
        e = entries[0]
        assert e["event_type"] == "process_died"
        assert "137" in e["reason"]

    def test_parses_started(self, tmp_path):
        line = self._fmt(
            "2026-01-01 12:02:00",
            "INFO", "logstashagent.supervisor", "start",
            "Logstash started with PID 42",
        )
        log_file = tmp_path / "logstashagent.log"
        self._write_agent_log(log_file, [line])

        entries = log_analyzer._read_agent_logs(agent_log_dir=tmp_path)

        assert len(entries) == 1
        e = entries[0]
        assert e["event_type"] == "started"
        assert e["pid"] == 42

    def test_ignores_non_restart_lines(self, tmp_path):
        line = self._fmt(
            "2026-01-01 12:00:00",
            "INFO", "logstashagent.main", "run",
            "Agent started successfully",
        )
        log_file = tmp_path / "logstashagent.log"
        self._write_agent_log(log_file, [line])

        entries = log_analyzer._read_agent_logs(agent_log_dir=tmp_path)
        assert entries == []

    def test_since_timestamp_filters_old_entries(self, tmp_path):
        from datetime import datetime
        old_line = self._fmt(
            "2024-01-01 00:00:00",
            "INFO", "m", "f",
            "Restarting Logstash (restart #1): old",
        )
        new_line = self._fmt(
            "2026-06-01 12:00:00",
            "INFO", "m", "f",
            "Restarting Logstash (restart #2): new",
        )
        log_file = tmp_path / "logstashagent.log"
        self._write_agent_log(log_file, [old_line, new_line])

        cutoff = int(datetime(2025, 1, 1).timestamp() * 1000)
        entries = log_analyzer._read_agent_logs(
            agent_log_dir=tmp_path, since_timestamp=cutoff
        )

        # Only the 2026 entry should survive
        assert len(entries) == 1
        assert "new" in entries[0]["reason"]

    def test_returns_chronological_order(self, tmp_path):
        lines = [
            self._fmt("2026-01-01 12:00:00", "INFO", "m", "f", "Restarting Logstash (restart #1): first"),
            self._fmt("2026-01-01 12:01:00", "INFO", "m", "f", "Restarting Logstash (restart #2): second"),
        ]
        log_file = tmp_path / "logstashagent.log"
        self._write_agent_log(log_file, lines)

        entries = log_analyzer._read_agent_logs(agent_log_dir=tmp_path)

        assert len(entries) == 2
        assert entries[0]["timestamp_ms"] <= entries[1]["timestamp_ms"]


# ---------------------------------------------------------------------------
# _find_logstash_lifecycle_events
# ---------------------------------------------------------------------------

class TestFindLogstashLifecycleEvents:
    def _entry(self, ts, message):
        return {
            "timeMillis": ts,
            "logEvent": {"message": message},
        }

    def test_detects_shutdown(self):
        logs = [self._entry(1000, "Logstash shut down.")]
        events = log_analyzer._find_logstash_lifecycle_events(logs)
        assert len(events) == 1
        assert events[0]["event_type"] == "shutdown"
        assert events[0]["timestamp"] == 1000

    def test_detects_startup(self):
        logs = [self._entry(2000, "Successfully started Logstash API endpoint")]
        events = log_analyzer._find_logstash_lifecycle_events(logs)
        assert len(events) == 1
        assert events[0]["event_type"] == "startup"

    def test_ignores_unrelated_messages(self):
        logs = [self._entry(3000, "Just a regular log line")]
        events = log_analyzer._find_logstash_lifecycle_events(logs)
        assert events == []

    def test_returns_chronological_order(self):
        logs = [
            self._entry(3000, "Successfully started Logstash API endpoint"),
            self._entry(1000, "Logstash shut down."),
        ]
        events = log_analyzer._find_logstash_lifecycle_events(logs)
        assert events[0]["timestamp"] == 1000
        assert events[1]["timestamp"] == 3000

    def test_handles_missing_log_event(self):
        logs = [{"timeMillis": 100}]
        events = log_analyzer._find_logstash_lifecycle_events(logs)
        assert events == []

    def test_case_insensitive_matching(self):
        logs = [self._entry(1000, "LOGSTASH SHUT DOWN.")]
        events = log_analyzer._find_logstash_lifecycle_events(logs)
        assert len(events) == 1


# ---------------------------------------------------------------------------
# _check_for_shutdown_message
# ---------------------------------------------------------------------------

class TestCheckForShutdownMessage:
    def _entry(self, ts, message):
        return {
            "timeMillis": ts,
            "logEvent": {"message": message},
        }

    def test_returns_true_when_shutdown_message_in_window(self):
        logs = [self._entry(1000, "Logstash shut down.")]
        result = log_analyzer._check_for_shutdown_message(logs, near_timestamp=1000)
        assert result is True

    def test_returns_false_when_outside_window(self):
        logs = [self._entry(1000, "Logstash shut down.")]
        result = log_analyzer._check_for_shutdown_message(
            logs, near_timestamp=1000, window_ms=100
        )
        # 1000 is at the boundary (lo=900, hi=1100), so it should be True
        assert result is True

    def test_returns_false_when_no_matching_message(self):
        logs = [self._entry(1000, "Just a regular log")]
        result = log_analyzer._check_for_shutdown_message(logs, near_timestamp=1000)
        assert result is False

    def test_returns_false_for_empty_logs(self):
        result = log_analyzer._check_for_shutdown_message([], near_timestamp=1000)
        assert result is False


# ---------------------------------------------------------------------------
# detect_restart_events
# ---------------------------------------------------------------------------

class TestDetectRestartEvents:
    def test_returns_empty_when_no_logs(self, tmp_path):
        events = log_analyzer.detect_restart_events(
            log_dir=str(tmp_path),
            agent_log_dir=tmp_path,
        )
        assert events == []

    def test_detects_graceful_restart_from_lifecycle(self, tmp_path):
        sd_ts = 1_000_000
        su_ts = 1_010_000
        # Return newest-first so internal .reverse() makes them chronological
        logs = [
            {
                "timeMillis": su_ts,
                "logEvent": {"message": "Successfully started Logstash API endpoint"},
            },
            {
                "timeMillis": sd_ts,
                "logEvent": {"message": "Logstash shut down."},
            },
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs), \
             patch.object(log_analyzer, "_read_agent_logs", return_value=[]):
            events = log_analyzer.detect_restart_events(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )

        assert len(events) == 1
        evt = events[0]
        assert evt["is_complete"] is True
        assert evt["type"] == "graceful"
        assert evt["shutdown_timestamp"] == sd_ts
        assert evt["startup_timestamp"] == su_ts

    def test_detects_incomplete_restart(self, tmp_path):
        sd_ts = 1_000_000
        # Single entry — order doesn't matter for one item
        logs = [
            {"timeMillis": sd_ts, "logEvent": {"message": "Logstash shut down."}},
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs), \
             patch.object(log_analyzer, "_read_agent_logs", return_value=[]):
            events = log_analyzer.detect_restart_events(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )

        assert len(events) == 1
        assert events[0]["is_complete"] is False
        assert events[0]["startup_timestamp"] is None

    def test_detects_restart_from_agent_logs(self, tmp_path):
        from datetime import datetime
        sd_ts = int(datetime(2026, 1, 1, 12, 0, 0).timestamp() * 1000)
        agent_entries = [
            {
                "event_type": "restart_initiated",
                "timestamp_ms": sd_ts,
                "reason": "memory threshold",
                "restart_count": 1,
            }
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=[]), \
             patch.object(log_analyzer, "_read_agent_logs", return_value=agent_entries):
            events = log_analyzer.detect_restart_events(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )

        assert len(events) == 1
        assert events[0]["cause_hint"] == "agent: memory threshold"
        assert events[0]["restart_count"] == 1

    def test_deduplicates_signals_within_window(self, tmp_path):
        ts_base = 1_000_000
        # Newest first so internal .reverse() restores chronological order
        logs = [
            {"timeMillis": ts_base + 15_000, "logEvent": {"message": "Successfully started Logstash API endpoint"}},
            {"timeMillis": ts_base + 5_000, "logEvent": {"message": "Logstash shut down."}},
            {"timeMillis": ts_base, "logEvent": {"message": "Logstash shut down."}},
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs), \
             patch.object(log_analyzer, "_read_agent_logs", return_value=[]):
            events = log_analyzer.detect_restart_events(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )

        # Both shutdown signals should be deduplicated into one event
        assert len(events) == 1

    def test_respects_since_timestamp(self, tmp_path):
        sd_ts = 500_000
        # Single entry; order irrelevant
        logs = [
            {"timeMillis": sd_ts, "logEvent": {"message": "Logstash shut down."}},
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs), \
             patch.object(log_analyzer, "_read_agent_logs", return_value=[]):
            events = log_analyzer.detect_restart_events(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
                since_timestamp=1_000_000,  # filter out the old signal
            )

        assert events == []

    def test_pipeline_loop_detection(self, tmp_path):
        base = 1_000_000
        # detect_restart_events calls _read_json_logs(reverse=True) then
        # immediately reverses the list to get chronological order.  Our mock
        # must therefore return logs in NEWEST-FIRST order so that after the
        # internal .reverse() they end up chronological.
        logs_newest_first = [
            {"timeMillis": base + 20_000, "logEvent": {"running_pipelines": ["loop-pipe"], "count": 1}},
            {"timeMillis": base + 15_000, "logEvent": {"running_pipelines": [], "count": 0}},
            {"timeMillis": base + 10_000, "logEvent": {"running_pipelines": ["loop-pipe"], "count": 1}},
            {"timeMillis": base + 5_000,  "logEvent": {"running_pipelines": [], "count": 0}},
            {"timeMillis": base,           "logEvent": {"running_pipelines": ["loop-pipe"], "count": 1}},
        ]
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs_newest_first), \
             patch.object(log_analyzer, "_read_agent_logs", return_value=[]):
            events = log_analyzer.detect_restart_events(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )

        loop_events = [e for e in events if e["type"] == "pipeline_loop"]
        assert len(loop_events) >= 1

    def test_respects_max_events(self, tmp_path):
        base = 1_000_000
        # Build newest-first so internal .reverse() makes them chronological
        logs = []
        for i in range(19, -1, -1):
            logs.append({"timeMillis": base + i * 30_000, "logEvent": {"message": "Logstash shut down."}})
        with patch.object(log_analyzer, "_read_json_logs", return_value=logs), \
             patch.object(log_analyzer, "_read_agent_logs", return_value=[]):
            events = log_analyzer.detect_restart_events(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
                max_events=5,
            )

        assert len(events) <= 5


# ---------------------------------------------------------------------------
# is_logstash_restarting
# ---------------------------------------------------------------------------

class TestIsLogstashRestarting:
    def test_returns_false_when_no_events(self, tmp_path):
        with patch.object(log_analyzer, "detect_restart_events", return_value=[]):
            result = log_analyzer.is_logstash_restarting(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )
        assert result is False

    def test_returns_true_when_most_recent_is_incomplete(self, tmp_path):
        events = [{"is_complete": False, "shutdown_timestamp": 1000}]
        with patch.object(log_analyzer, "detect_restart_events", return_value=events):
            result = log_analyzer.is_logstash_restarting(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )
        assert result is True

    def test_returns_false_when_most_recent_is_complete(self, tmp_path):
        events = [{"is_complete": True, "shutdown_timestamp": 1000}]
        with patch.object(log_analyzer, "detect_restart_events", return_value=events):
            result = log_analyzer.is_logstash_restarting(
                log_dir=str(tmp_path),
                agent_log_dir=tmp_path,
            )
        assert result is False


# ---------------------------------------------------------------------------
# LogstashLogWatcher
# ---------------------------------------------------------------------------

class TestLogstashLogWatcher:
    def test_initial_state_is_unknown(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        state = watcher.get_state()
        assert state["logstash_state"] == "unknown"
        assert state["is_restarting"] is False
        assert state["warnings_since_last_checkin"] == []
        assert state["errors_since_last_checkin"] == []

    def test_process_entry_shutdown_message(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher._process_entry({
            "level": "INFO",
            "timeMillis": 1000,
            "logEvent": {"message": "Logstash shut down."},
        })
        state = watcher.get_state()
        assert state["logstash_state"] == "restarting"
        assert state["is_restarting"] is True
        assert state["last_shutdown_ts"] == 1000

    def test_process_entry_running_message(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher._process_entry({
            "level": "INFO",
            "timeMillis": 2000,
            "logEvent": {"message": "Successfully started Logstash API endpoint"},
        })
        state = watcher.get_state()
        assert state["logstash_state"] == "running"

    def test_process_entry_starting_message(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher._process_entry({
            "level": "INFO",
            "timeMillis": 1500,
            "logEvent": {"message": "Starting Logstash"},
        })
        assert watcher.get_state()["logstash_state"] == "started"

    def test_process_entry_warn_collected(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher._process_entry({
            "level": "WARN",
            "timeMillis": 100,
            "loggerName": "org.logstash.Pipeline",
            "logEvent": {"message": "Pipeline warning"},
        })
        state = watcher.get_state()
        assert len(state["warnings_since_last_checkin"]) == 1
        assert state["warnings_since_last_checkin"][0]["message"] == "Pipeline warning"

    def test_process_entry_error_collected(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher._process_entry({
            "level": "ERROR",
            "timeMillis": 200,
            "loggerName": "org.logstash.Pipeline",
            "logEvent": {"message": "Pipeline error"},
        })
        state = watcher.get_state()
        assert len(state["errors_since_last_checkin"]) == 1

    def test_process_entry_fatal_collected(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher._process_entry({
            "level": "FATAL",
            "timeMillis": 300,
            "loggerName": "org.logstash.Logstash",
            "logEvent": {"message": "Fatal error"},
        })
        state = watcher.get_state()
        assert len(state["fatals_since_last_checkin"]) == 1

    def test_consume_for_checkin_clears_warnings_and_errors(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher._process_entry({
            "level": "WARN",
            "timeMillis": 100,
            "logEvent": {"message": "A warning"},
        })
        watcher._process_entry({
            "level": "ERROR",
            "timeMillis": 200,
            "logEvent": {"message": "An error"},
        })

        state = watcher.consume_for_checkin()
        assert len(state["warnings_since_last_checkin"]) == 1
        assert len(state["errors_since_last_checkin"]) == 1

        # After consuming, lists should be empty
        state2 = watcher.get_state()
        assert state2["warnings_since_last_checkin"] == []
        assert state2["errors_since_last_checkin"] == []

    def test_process_bytes_returns_partial_line(self, tmp_path):
        import json as _json
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        data = _json.dumps({"level": "INFO", "timeMillis": 1, "logEvent": {"message": "x"}}).encode()
        partial_before = b""
        result = watcher._process_bytes(partial_before + data + b"\nINPARTIAL")
        assert result == b"INPARTIAL"

    def test_process_bytes_handles_invalid_json(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        # Should not raise
        watcher._process_bytes(b"not json\n")

    def test_stop_event_stops_thread(self, tmp_path):
        watcher = log_analyzer.LogstashLogWatcher(log_dir=str(tmp_path))
        watcher.start()
        watcher.stop()
        assert not watcher._thread.is_alive()

    def test_checkin_event_set_on_shutdown(self, tmp_path):
        import threading
        event = threading.Event()
        watcher = log_analyzer.LogstashLogWatcher(
            log_dir=str(tmp_path), checkin_event=event
        )
        watcher._process_entry({
            "level": "INFO",
            "timeMillis": 1,
            "logEvent": {"message": "Logstash shut down."},
        })
        assert event.is_set()

    def test_fmt_ts_returns_none_for_none(self, tmp_path):
        assert log_analyzer.LogstashLogWatcher._fmt_ts(None) is None

    def test_fmt_ts_returns_utc_string(self, tmp_path):
        result = log_analyzer.LogstashLogWatcher._fmt_ts(0)
        assert "UTC" in result
