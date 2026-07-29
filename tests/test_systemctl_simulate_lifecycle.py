#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""P0: enrolled simulate uses systemctl for Logstash, not supervisor Popen."""

import asyncio
from unittest.mock import MagicMock, patch

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
    def test_systemctl_uses_controller(self):
        with patch.object(main, "is_systemctl_managed_simulate", return_value=True), patch.object(
            main.controller, "restart_logstash", return_value=True
        ) as restart, patch.object(
            main.logstash_supervisor, "trigger_restart"
        ) as trig:
            main._sim_systemctl_restart_count = 0
            assert main.trigger_sim_logstash_restart("oom") is True
            restart.assert_called_once()
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
