#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""P0: enrolled simulate uses systemctl for Logstash, not supervisor Popen."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from logstashagent import main


class TestIsSystemctlManagedSimulate:
    def test_true_with_ls_simulate_unit(self):
        with patch.object(
            main.agent_state,
            "get_state",
            return_value={"logstash_unit": "ls-simulate@3", "mode": "simulate"},
        ):
            assert main.is_systemctl_managed_simulate() is True

    def test_true_with_mode_and_instance(self):
        with patch.object(
            main.agent_state,
            "get_state",
            return_value={"mode": "simulate", "instance_id": 2},
        ):
            assert main.is_systemctl_managed_simulate() is True

    def test_true_enrolled_simulate_policy(self):
        with patch.object(
            main.agent_state,
            "get_state",
            return_value={
                "enrolled": True,
                "policy_type": "SIMULATE",
                "instance_id": 1,
            },
        ):
            assert main.is_systemctl_managed_simulate() is True

    def test_false_legacy_host_sim_without_instance(self):
        """Legacy UI host path maps to mode=simulate but has no instance_id."""
        with patch.object(
            main.agent_state,
            "get_state",
            return_value={"mode": "simulate"},
        ), patch.dict(main.AGENT_CONFIG, {"mode": "simulate"}, clear=False):
            # Ensure config instance_id is not set either
            cfg = dict(main.AGENT_CONFIG or {})
            cfg.pop("instance_id", None)
            cfg["mode"] = "simulate"
            with patch.object(main, "AGENT_CONFIG", cfg):
                assert main.is_systemctl_managed_simulate() is False

    def test_false_embedded(self):
        with patch.object(
            main.agent_state,
            "get_state",
            return_value={"mode": "embedded"},
        ), patch.object(main, "AGENT_CONFIG", {"mode": "embedded"}):
            assert main.is_systemctl_managed_simulate() is False


class TestSimLogstashApiPort:
    def test_from_state(self):
        with patch.object(
            main.agent_state,
            "get_state",
            return_value={"logstash_api_port": 9567},
        ):
            assert main.sim_logstash_api_port() == 9567

    def test_from_instance_id(self):
        with patch.object(
            main.agent_state,
            "get_state",
            return_value={"instance_id": 4},
        ):
            assert main.sim_logstash_api_port() == 9564

    def test_env_wins(self, monkeypatch, tmp_path):
        from logstashagent import agent_state

        monkeypatch.setenv("LOGSTASH_API_PORT", "9561")
        agent_state.configure_state_dir(tmp_path)
        try:
            agent_state.update_state("logstash_api_port", 9600)
            assert main.sim_logstash_api_port() == 9561
        finally:
            agent_state.configure_state_dir(None)


class TestCheckSimLogstashHealth:
    def test_systemctl_path_probes_api(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(main, "is_systemctl_managed_simulate", return_value=True), patch.object(
            main, "sim_logstash_api_port", return_value=9563
        ), patch.object(main.requests, "get", return_value=mock_resp) as get:
            out = main.check_sim_logstash_health()
        assert out["healthy"] is True
        assert out["via"] == "systemctl"
        assert out["logstash_api_port"] == 9563
        get.assert_called()
        assert "9563" in get.call_args[0][0]

    def test_systemctl_unhealthy_on_connection_error(self):
        with patch.object(main, "is_systemctl_managed_simulate", return_value=True), patch.object(
            main, "sim_logstash_api_port", return_value=9563
        ), patch.object(
            main.requests, "get", side_effect=ConnectionError("down")
        ):
            out = main.check_sim_logstash_health()
        assert out["healthy"] is False
        assert out["via"] == "systemctl"

    def test_supervisor_path(self):
        sup = MagicMock()
        sup.is_healthy = True
        sup.is_restarting = False
        sup.restart_count = 2
        with patch.object(main, "is_systemctl_managed_simulate", return_value=False), patch.object(
            main.logstash_supervisor, "get_supervisor", return_value=sup
        ):
            out = main.check_sim_logstash_health()
        assert out["healthy"] is True
        assert out["via"] == "supervisor"
        assert out["restart_count"] == 2


class TestTriggerSimLogstashRestart:
    def test_systemctl_uses_bare_recovery(self):
        with patch.object(main, "is_systemctl_managed_simulate", return_value=True), patch(
            "logstashagent.simulate_recovery.recover_simulate_logstash",
            return_value={"success": True, "restarted": True},
        ) as recover, patch.object(
            main.logstash_supervisor, "trigger_restart"
        ) as trig:
            main._sim_systemctl_restart_count = 0
            assert main.trigger_sim_logstash_restart("oom") is True
            recover.assert_called_once()
            assert recover.call_args.kwargs.get("restart") is True
            trig.assert_not_called()
            assert main._sim_systemctl_restart_count == 1

    def test_embedded_uses_supervisor(self):
        with patch.object(main, "is_systemctl_managed_simulate", return_value=False), patch.object(
            main.controller, "restart_logstash"
        ) as restart, patch.object(
            main.logstash_supervisor, "trigger_restart"
        ) as trig:
            assert main.trigger_sim_logstash_restart("oom") is True
            restart.assert_not_called()
            trig.assert_called_once()


class TestStartupSkipsSupervisor:
    def test_startup_skips_supervisor_for_enrolled_simulate(self):
        async def _run():
            with patch.object(
                main, "is_systemctl_managed_simulate", return_value=True
            ), patch.object(
                main, "sim_logstash_api_port", return_value=9561
            ), patch.object(
                main.logstash_supervisor, "start_supervised_logstash"
            ) as start, patch.object(
                main.asyncio, "create_task", return_value=MagicMock()
            ):
                await main.startup_event()
                return start

        start = asyncio.run(_run())
        start.assert_not_called()

    def test_startup_starts_supervisor_for_embedded(self):
        async def _sleep(_n):
            return None

        async def _run():
            with patch.object(
                main, "is_systemctl_managed_simulate", return_value=False
            ), patch.object(
                main.logstash_supervisor, "start_supervised_logstash"
            ) as start, patch.object(
                main.asyncio, "sleep", side_effect=_sleep
            ), patch.object(
                main.asyncio, "create_task", return_value=MagicMock()
            ):
                await main.startup_event()
                return start

        start = asyncio.run(_run())
        start.assert_called_once()

    def test_shutdown_leaves_systemctl_logstash(self):
        main._queue_processor_task = None

        async def _run():
            with patch.object(
                main, "is_systemctl_managed_simulate", return_value=True
            ), patch.object(
                main.logstash_supervisor, "shutdown_supervisor"
            ) as shut:
                await main.shutdown_event()
                return shut

        shut = asyncio.run(_run())
        shut.assert_not_called()


class TestPipelineBusRetryStormRecovery:
    """Stuck send_to retries leave API healthy; simulate instance may restart."""

    STORM = {
        "destination": "slot1-filter1",
        "count": 15,
        "span_seconds": 14.0,
        "source_pipeline": "simulate-start",
    }

    def _mock_api(self, listed):
        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.list_pipelines.return_value = listed
        return mock_api

    def test_escalates_only_after_configured_confirmations(self):
        """Default policy: 3 confirmations then hard-restart this sim Logstash."""
        hits: dict = {}
        mock_api = self._mock_api([])
        with patch.object(
            main.log_analyzer,
            "detect_pipeline_bus_retry_storms",
            return_value=[self.STORM],
        ), patch.object(main, "LogstashAPI", return_value=mock_api), patch.object(
            main, "trigger_sim_logstash_hard_restart", return_value=True
        ) as hard_restart, patch.object(
            main, "_is_simulate_instance_for_bus_recovery", return_value=True
        ), patch.object(
            main.slots, "get_slot_state", return_value={}
        ), patch.object(main.slots, "release_slot", return_value=False):
            # Confirmations 1 and 2: detect only, no restart
            for expected in (1, 2):
                assert (
                    main.handle_pipeline_bus_retry_storms(
                        _hits=hits, min_consecutive=3
                    )
                    is False
                )
                assert hits.get("slot1-filter1") == expected
                hard_restart.assert_not_called()

            # Confirmation 3: course of correction = kill -9 + systemctl restart
            assert (
                main.handle_pipeline_bus_retry_storms(
                    _hits=hits, min_consecutive=3
                )
                is True
            )
            hard_restart.assert_called_once()
            assert "pipeline bus retry storm" in hard_restart.call_args[0][0]
            assert hits == {}

    def test_listed_destination_still_actionable_workers_never_drain(self):
        """list_pipelines membership must NOT hold forever — stuck send_to never drains."""
        hits: dict = {}
        mock_api = self._mock_api(["slot1-filter1"])  # listed but bus unavailable
        with patch.object(
            main.log_analyzer,
            "detect_pipeline_bus_retry_storms",
            return_value=[self.STORM],
        ), patch.object(main, "LogstashAPI", return_value=mock_api), patch.object(
            main, "trigger_sim_logstash_hard_restart", return_value=True
        ) as hard_restart, patch.object(
            main, "_is_simulate_instance_for_bus_recovery", return_value=True
        ), patch.object(
            main.slots, "get_slot_state", return_value={}
        ), patch.object(main.slots, "release_slot", return_value=False):
            assert (
                main.handle_pipeline_bus_retry_storms(
                    _hits=hits, min_consecutive=1
                )
                is True
            )
            hard_restart.assert_called_once()

    def test_grace_for_young_booked_slot(self):
        from datetime import datetime, timezone

        hits: dict = {}
        mock_api = self._mock_api(["slot1-filter1"])
        young = {
            1: {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "content_hash": "abc",
            }
        }
        with patch.object(
            main.log_analyzer,
            "detect_pipeline_bus_retry_storms",
            return_value=[self.STORM],
        ), patch.object(main, "LogstashAPI", return_value=mock_api), patch.object(
            main, "trigger_sim_logstash_hard_restart", return_value=True
        ) as hard_restart, patch.object(
            main, "_is_simulate_instance_for_bus_recovery", return_value=True
        ), patch.object(
            main.slots, "get_slot_state", return_value=young
        ):
            assert (
                main.handle_pipeline_bus_retry_storms(
                    _hits=hits, min_consecutive=1
                )
                is False
            )
            hard_restart.assert_not_called()

    def test_withholds_restart_when_not_simulate_instance(self):
        hits: dict = {}
        mock_api = self._mock_api([])
        with patch.object(
            main.log_analyzer,
            "detect_pipeline_bus_retry_storms",
            return_value=[self.STORM],
        ), patch.object(main, "LogstashAPI", return_value=mock_api), patch.object(
            main, "trigger_sim_logstash_hard_restart", return_value=True
        ) as hard_restart, patch.object(
            main, "_is_simulate_instance_for_bus_recovery", return_value=False
        ), patch.object(
            main.slots, "get_slot_state", return_value={}
        ):
            # Even after confirmations, non-simulate must not hard-restart
            for _ in range(3):
                main.handle_pipeline_bus_retry_storms(
                    _hits=hits, min_consecutive=2
                )
            hard_restart.assert_not_called()

    def test_force_kill_uses_mainpid_and_kill_9(self):
        with patch.object(
            main.controller, "_logstash_unit_name", return_value="ls-simulate@1"
        ), patch("subprocess.run") as run_mock:
            # show MainPID, then kill -9
            show = MagicMock()
            show.returncode = 0
            show.stdout = "12345\n"
            show.stderr = ""
            kill = MagicMock()
            kill.returncode = 0
            kill.stdout = ""
            kill.stderr = ""
            run_mock.side_effect = [show, kill]

            out = main.force_kill_simulate_logstash_jvm(reason="test")

        assert out["unit"] == "ls-simulate@1"
        assert out["pids_killed"] == [12345]
        assert run_mock.call_count == 2
        kill_cmd = run_mock.call_args_list[1][0][0]
        assert kill_cmd[:3] == ["sudo", "kill", "-9"]
        assert kill_cmd[3] == "12345"


class TestAllocateStartupGate:
    """Fix A: allocate/slots returns 503 while Logstash pipeline bus is initializing."""

    def _post_allocate(self, healthy_duration):
        """Call allocate_simulation_slot with a mocked healthy duration."""
        body = {"pipeline_name": "test-pipe", "pipelines": [{"filter_config": "filter{}", "index": 1}]}

        with patch.object(main, "_get_logstash_healthy_duration", return_value=healthy_duration):
            return asyncio.run(main.allocate_simulation_slot(body))

    def test_rejects_when_never_healthy(self):
        """healthy_duration=None (Logstash never became healthy) → 503."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            self._post_allocate(healthy_duration=None)
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail["error"] == "logstash_initializing"
        assert "Retry-After" in exc_info.value.headers

    def test_rejects_within_warmup_window(self):
        """healthy_duration < PIPELINE_BUS_WARMUP_SECONDS → 503."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            self._post_allocate(healthy_duration=main.PIPELINE_BUS_WARMUP_SECONDS - 1)
        assert exc_info.value.status_code == 503

    def test_retry_after_header_is_positive(self):
        """Retry-After value is at least 1 second."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            self._post_allocate(healthy_duration=5.0)
        retry_after = int(exc_info.value.headers["Retry-After"])
        assert retry_after >= 1

    def test_passes_after_warmup_window(self):
        """healthy_duration >= PIPELINE_BUS_WARMUP_SECONDS → gate does not block."""
        mock_api = MagicMock()
        mock_api.__enter__ = MagicMock(return_value=mock_api)
        mock_api.__exit__ = MagicMock(return_value=False)
        mock_api.list_pipelines.return_value = []
        mock_api.detect_pipeline_state.return_value = "running"

        with patch.object(main, "_get_logstash_healthy_duration",
                          return_value=main.PIPELINE_BUS_WARMUP_SECONDS + 5), \
             patch.object(main, "LogstashAPI", return_value=mock_api), \
             patch.object(main, "_create_slot_pipelines",
                          new_callable=AsyncMock,
                          return_value={"create_ms": 0, "verify_ms": 0}), \
             patch.object(main, "_adaptive_bus_settle", new_callable=AsyncMock):
            result = asyncio.run(main.allocate_simulation_slot(
                {"pipeline_name": "test-pipe",
                 "pipelines": [{"filter_config": "filter{}", "index": 1}]}
            ))
        assert result["slot_id"] is not None

    def test_systemctl_path_reads_module_var_not_supervisor(self):
        """_get_logstash_healthy_duration uses _sim_systemctl_healthy_since for systemctl mode."""
        with patch.object(main, "is_systemctl_managed_simulate", return_value=True):
            # Never healthy
            main._sim_systemctl_healthy_since = None
            assert main._get_logstash_healthy_duration() is None

            # Healthy for ~5s
            main._sim_systemctl_healthy_since = time.monotonic() - 5.0
            duration = main._get_logstash_healthy_duration()
            assert duration is not None and 4.0 < duration < 10.0

    def test_restart_rearms_gate_for_systemctl(self):
        """trigger_sim_logstash_restart clears _sim_systemctl_healthy_since."""
        main._sim_systemctl_healthy_since = time.monotonic() - 60.0
        with patch.object(main, "is_systemctl_managed_simulate", return_value=True), \
             patch("logstashagent.simulate_recovery.recover_simulate_logstash",
                   return_value={"success": True, "restarted": True}):
            main.trigger_sim_logstash_restart("test")
        assert main._sim_systemctl_healthy_since is None

    def test_hard_restart_rearms_gate_for_systemctl(self):
        """trigger_sim_logstash_hard_restart clears _sim_systemctl_healthy_since."""
        main._sim_systemctl_healthy_since = time.monotonic() - 60.0
        with patch.object(main, "is_systemctl_managed_simulate", return_value=True), \
             patch.object(main, "force_kill_simulate_logstash_jvm",
                          return_value={"unit": "ls-simulate@1", "pids_killed": [], "errors": []}), \
             patch("logstashagent.simulate_recovery.recover_simulate_logstash",
                   return_value={"success": True, "restarted": True}):
            main.trigger_sim_logstash_hard_restart("test")
        assert main._sim_systemctl_healthy_since is None


class TestAllocateBusReadyCheck:
    """Fix B: pure_reuse is skipped when the listed pipeline is not bus-ready."""

    def _run_impl(self, pipeline_state, *, reused=True):
        """
        Run _allocate_simulation_slot_impl with a pipeline that appears listed
        but has the given detect_pipeline_state result.
        """
        from logstashagent import slots as slots_mod

        slots_mod.clear_all_slots()
        pipelines = [{"filter_config": "filter{drop{}}", "index": 1}]
        pipeline_name = "test-pipe"

        if reused:
            # Pre-book the slot so reused=True
            slots_mod.allocate_slot(pipeline_name, pipelines)

        mock_api = MagicMock()
        mock_api.__enter__ = MagicMock(return_value=mock_api)
        mock_api.__exit__ = MagicMock(return_value=False)
        mock_api.list_pipelines.return_value = ["slot1-filter1"]
        mock_api.detect_pipeline_state.return_value = pipeline_state

        created = []

        async def fake_create(slot_id, pipelines):
            created.append(slot_id)
            return {"create_ms": 1, "verify_ms": 1}

        with patch.object(main, "LogstashAPI", return_value=mock_api), \
             patch.object(main, "_create_slot_pipelines", side_effect=fake_create), \
             patch.object(main, "_adaptive_bus_settle", new_callable=AsyncMock), \
             patch.object(main, "delete_pipeline_internal", return_value=True):
            content_hash = slots_mod._compute_pipeline_hash(pipelines)
            asyncio.run(main._allocate_simulation_slot_impl(
                pipeline_name=pipeline_name,
                pipelines=pipelines,
                content_hash=content_hash,
            ))

        return created

    def test_listed_and_running_takes_pure_reuse_path(self):
        """Listed pipeline that is genuinely running → no recreate (warm reuse still fast)."""
        created = self._run_impl(pipeline_state="running")
        assert created == [], "should not recreate a healthy pipeline"

    def test_listed_and_idle_takes_pure_reuse_path(self):
        """Idle is also bus-ready → pure_reuse."""
        created = self._run_impl(pipeline_state="idle")
        assert created == []

    def test_listed_but_not_found_forces_recreate(self):
        """not_found = silent 172ms termination after cold-start race → must recreate."""
        created = self._run_impl(pipeline_state="not_found")
        assert created == [1], "should force-delete and recreate dead pipeline"

    def test_listed_but_unknown_state_forces_recreate(self):
        """Unknown state (API error) is treated conservatively: recreate."""
        created = self._run_impl(pipeline_state="unknown")
        assert created == [1]

    def test_fresh_slot_not_listed_creates_normally(self):
        """Fresh allocation (not listed at all) still goes through create."""
        from logstashagent import slots as slots_mod

        slots_mod.clear_all_slots()
        pipelines = [{"filter_config": "filter{drop{}}", "index": 1}]

        mock_api = MagicMock()
        mock_api.__enter__ = MagicMock(return_value=mock_api)
        mock_api.__exit__ = MagicMock(return_value=False)
        mock_api.list_pipelines.return_value = []

        created = []

        async def fake_create(slot_id, pipelines):
            created.append(slot_id)
            return {"create_ms": 1, "verify_ms": 1}

        with patch.object(main, "LogstashAPI", return_value=mock_api), \
             patch.object(main, "_create_slot_pipelines", side_effect=fake_create), \
             patch.object(main, "_adaptive_bus_settle", new_callable=AsyncMock):
            content_hash = slots_mod._compute_pipeline_hash(pipelines)
            asyncio.run(main._allocate_simulation_slot_impl(
                pipeline_name="test-pipe",
                pipelines=pipelines,
                content_hash=content_hash,
            ))

        assert created == [1]
