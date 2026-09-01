#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.slots."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from logstashagent import slots


@pytest.fixture(autouse=True)
def clear_slots():
    slots.clear_all_slots()
    slots.clear_allocate_flights()
    yield
    slots.clear_all_slots()
    slots.clear_allocate_flights()


def _pipelines(filter_config: str, index: int = 1, output_config: str = "ignored-output"):
    return [{"filter_config": filter_config, "index": index, "output_config": output_config}]


class TestPipelineHash:
    def test_hash_ignores_output_config(self):
        p1 = _pipelines("filter { mutate { add_tag => ['a'] } }", output_config="stdout {}")
        p2 = _pipelines("filter { mutate { add_tag => ['a'] } }", output_config="null {}")
        assert slots._compute_pipeline_hash(p1) == slots._compute_pipeline_hash(p2)

    def test_hash_changes_with_filter_config_or_index(self):
        base = _pipelines("filter { mutate { add_tag => ['a'] } }", index=1)
        changed_filter = _pipelines("filter { mutate { add_tag => ['b'] } }", index=1)
        changed_index = _pipelines("filter { mutate { add_tag => ['a'] } }", index=2)
        assert slots._compute_pipeline_hash(base) != slots._compute_pipeline_hash(changed_filter)
        assert slots._compute_pipeline_hash(base) != slots._compute_pipeline_hash(changed_index)


class TestReleaseSlotIfHash:
    def test_releases_only_matching_hash(self):
        pipelines = _pipelines("filter { drop {} }")
        sid = slots.allocate_slot("p", pipelines)
        h = slots._compute_pipeline_hash(pipelines)
        assert slots.release_slot_if_hash(sid, "deadbeef" * 8) is False
        assert sid in slots.get_slot_state()
        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            assert slots.release_slot_if_hash(sid, h) is True
        assert sid not in slots.get_slot_state()
        # Named Logstash pipelines must be torn down with the slot
        cleanup.assert_called_once()
        assert cleanup.call_args[0][0] == sid

    def test_noop_missing_slot(self):
        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            assert slots.release_slot_if_hash(99, "abc") is False
        cleanup.assert_not_called()


class TestAllocateSingleFlight:
    def test_followers_join_leader_result(self):
        async def _run():
            h = "a" * 64
            fut1, lead1 = await slots.begin_allocate_flight(h)
            assert lead1 is True
            fut2, lead2 = await slots.begin_allocate_flight(h)
            assert lead2 is False
            assert fut2 is fut1

            result = {"slot_id": 3, "reused": False}
            await slots.complete_allocate_flight(h, fut1, result=result)
            assert await fut2 == result

            # New flight can start after complete
            fut3, lead3 = await slots.begin_allocate_flight(h)
            assert lead3 is True
            await slots.complete_allocate_flight(h, fut3, result={"slot_id": 1})

        asyncio.run(_run())

    def test_followers_see_leader_error(self):
        async def _run():
            h = "b" * 64
            fut1, lead1 = await slots.begin_allocate_flight(h)
            assert lead1 is True
            fut2, lead2 = await slots.begin_allocate_flight(h)
            assert lead2 is False

            err = RuntimeError("boom")
            await slots.complete_allocate_flight(h, fut1, error=err)
            with pytest.raises(RuntimeError, match="boom"):
                await fut2

        asyncio.run(_run())


class TestAllocateSlot:
    def test_allocates_new_slot(self):
        slot_id = slots.allocate_slot("pipeline-a", _pipelines("filter { drop {} }"))
        state = slots.get_slot_state()
        assert slot_id == 1
        assert state[slot_id]["pipeline_name"] == "pipeline-a"

    def test_reuses_slot_for_same_hash_and_keeps_created_at(self):
        pipelines = _pipelines("filter { drop {} }")
        slot_1 = slots.allocate_slot("pipeline-a", pipelines)
        created_at_1 = slots.get_slot_state()[slot_1]["created_at"]
        last_accessed_1 = slots.get_slot_state()[slot_1]["last_accessed"]

        slot_2 = slots.allocate_slot("pipeline-b", pipelines)
        state = slots.get_slot_state()[slot_2]

        assert slot_1 == slot_2
        assert state["created_at"] == created_at_1
        assert state["last_accessed"] >= last_accessed_1
        assert len(slots.get_slot_state()) == 1

    def test_different_hash_gets_different_slot(self):
        slot_1 = slots.allocate_slot("pipeline-a", _pipelines("filter { drop {} }"))
        slot_2 = slots.allocate_slot("pipeline-b", _pipelines("filter { mutate { add_tag => ['x'] } }"))
        assert slot_1 != slot_2
        assert len(slots.get_slot_state()) == 2

    def test_evicts_oldest_slot_when_full_and_cleans_old_slot(self):
        first_slot = None
        for i in range(slots.NUM_SLOTS):
            slot_id = slots.allocate_slot(f"pipeline-{i}", _pipelines(f"filter {{ mutate {{ add_tag => ['{i}'] }} }}"))
            if i == 0:
                first_slot = slot_id

        old_snapshot = slots.get_slot_state()[first_slot].copy()
        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            new_slot = slots.allocate_slot("new-pipeline", _pipelines("filter { json {} }"))

        assert new_slot == first_slot
        cleanup.assert_called_once_with(first_slot, old_snapshot)
        assert len(slots.get_slot_state()) == slots.NUM_SLOTS
        assert slots.get_slot_state()[new_slot]["pipeline_name"] == "new-pipeline"


class TestSlotLifecycle:
    def test_release_slot_clears_named_pipelines(self):
        """Clearing a slot must delete slotN-filter* from Logstash (yml + conf.d).

        Otherwise simulate-start keeps send_to'ing a bus address that is gone
        or half-dead after memory-only release.
        """
        pipelines = _pipelines("filter { drop {} }")
        slot_id = slots.allocate_slot("pipeline-a", pipelines)
        snapshot = slots.get_slot_state()[slot_id].copy()

        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            assert slots.release_slot(slot_id) is True

        assert slot_id not in slots.get_slot_state()
        cleanup.assert_called_once_with(slot_id, snapshot)

    def test_release_missing_slot_still_attempts_orphan_pipeline_cleanup(self):
        """DELETE /slots/{id} for an unknown slot should still purge leftovers."""
        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            assert slots.release_slot(3) is False
        cleanup.assert_called_once()
        assert cleanup.call_args[0][0] == 3
        # Synthetic slot_data with at least filter1 so filter1 is always targeted
        assert cleanup.call_args[0][1] == {"pipelines": [{"index": 1}]}

    def test_release_slot_can_skip_pipeline_cleanup(self):
        slot_id = slots.allocate_slot("pipeline-a", _pipelines("filter { drop {} }"))
        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            assert slots.release_slot(slot_id, cleanup_pipelines=False) is True
        cleanup.assert_not_called()
        assert slot_id not in slots.get_slot_state()


class TestDeleteSlotPipelines:
    def test_deletes_each_filter_pipeline_for_slot(self):
        slot_data = {
            "pipelines": [
                {"filter_config": "filter { drop {} }", "index": 1},
                {"filter_config": "filter { json {} }", "index": 2},
            ]
        }
        with patch("logstashagent.main.delete_pipeline_internal", return_value=True) as delete:
            with patch("logstashagent.main.PIPELINES_DIR", "/nonexistent"):
                slots._delete_slot_pipelines(2, slot_data)

        assert [c.args[0] for c in delete.call_args_list] == [
            "slot2-filter1",
            "slot2-filter2",
        ]

    def test_always_targets_filter1_when_slot_data_empty(self):
        with patch("logstashagent.main.delete_pipeline_internal", return_value=False) as delete:
            with patch("logstashagent.main.PIPELINES_DIR", "/nonexistent"):
                slots._delete_slot_pipelines(1, None)

        delete.assert_called_once_with("slot1-filter1")


class TestEvictExpiredSlots:
    def test_evicts_old_and_invalid_slots(self):
        old_slot = slots.allocate_slot("old", _pipelines("filter { drop {} }"))
        bad_ts_slot = slots.allocate_slot("bad-ts", _pipelines("filter { json {} }"))
        active_slot = slots.allocate_slot("active", _pipelines("filter { mutate { add_tag => ['ok'] } }"))

        old_time = datetime.now(timezone.utc) - timedelta(seconds=slots.SLOT_TTL_SECONDS + 10)
        with slots._slots_lock:
            slots._slots[old_slot]["last_accessed"] = old_time.isoformat()
            slots._slots[bad_ts_slot]["last_accessed"] = "not-a-timestamp"

        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            evicted = slots.evict_expired_slots()

        assert set(evicted) == {old_slot, bad_ts_slot}
        assert active_slot in slots.get_slot_state()
        assert cleanup.call_count == 2

    def test_does_not_evict_recent_slot(self):
        slots.allocate_slot("recent", _pipelines("filter { drop {} }"))
        with patch.object(slots, "_delete_slot_pipelines") as cleanup:
            evicted = slots.evict_expired_slots()
        assert evicted == []
        cleanup.assert_not_called()


class TestEvictFailedSlots:
    def _age_slot(self, slot_id: int, age_seconds: int = 60, access_seconds: int | None = None):
        ts = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        access = (
            datetime.now(timezone.utc) - timedelta(seconds=access_seconds)
            if access_seconds is not None
            else ts
        )
        with slots._slots_lock:
            slots._slots[slot_id]["created_at"] = ts.isoformat()
            slots._slots[slot_id]["last_accessed"] = access.isoformat()

    def test_does_not_evict_new_slot_before_min_age(self):
        slot_id = slots.allocate_slot("new-slot", _pipelines("filter { drop {} }"))

        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.list_pipelines.return_value = []

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            evicted = slots.evict_failed_slots()

        assert evicted == []
        assert slot_id in slots.get_slot_state()

    def test_does_not_evict_missing_pipeline_within_not_found_grace(self):
        """Cold allocate can exceed 30s; 60s-old missing slots stay until 90s grace."""
        slot_id = slots.allocate_slot("mid-age", _pipelines("filter { drop {} }"))
        self._age_slot(slot_id, age_seconds=60, access_seconds=60)

        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.list_pipelines.return_value = []

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            with patch.object(slots, "_delete_slot_pipelines") as cleanup:
                evicted = slots.evict_failed_slots()

        assert evicted == []
        cleanup.assert_not_called()
        assert slot_id in slots.get_slot_state()

    def test_evicts_when_pipeline_missing_after_min_age(self):
        slot_id = slots.allocate_slot("missing", _pipelines("filter { drop {} }"))
        # Past not_found grace and last_access grace
        self._age_slot(slot_id, age_seconds=120, access_seconds=120)

        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.list_pipelines.return_value = []

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            with patch.object(slots, "_delete_slot_pipelines") as cleanup:
                evicted = slots.evict_failed_slots()

        assert evicted == [slot_id]
        cleanup.assert_called_once()
        assert len(slots.get_slot_state()) == 0

    def test_does_not_evict_listed_pipeline_with_detect_not_found(self):
        """list_pipelines membership wins over detect_pipeline_state==not_found glitches."""
        slot_id = slots.allocate_slot("glitch", _pipelines("filter { drop {} }"))
        self._age_slot(slot_id, age_seconds=120, access_seconds=120)
        pipeline_name = f"slot{slot_id}-filter1"

        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.list_pipelines.return_value = [pipeline_name]
        mock_api.detect_pipeline_state.return_value = "not_found"

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            with patch.object(slots, "_delete_slot_pipelines") as cleanup:
                evicted = slots.evict_failed_slots()

        assert evicted == []
        cleanup.assert_not_called()
        assert slot_id in slots.get_slot_state()

    def test_skips_eviction_during_in_flight_allocate(self):
        pipelines = _pipelines("filter { drop {} }")
        slot_id = slots.allocate_slot("inflight", pipelines)
        self._age_slot(slot_id, age_seconds=120, access_seconds=120)
        h = slots._compute_pipeline_hash(pipelines)

        async def _prime_flight():
            fut, lead = await slots.begin_allocate_flight(h)
            assert lead is True
            return fut

        fut = asyncio.run(_prime_flight())

        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.list_pipelines.return_value = []

        try:
            with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
                with patch.object(slots, "_delete_slot_pipelines") as cleanup:
                    evicted = slots.evict_failed_slots()
            assert evicted == []
            cleanup.assert_not_called()
            assert slot_id in slots.get_slot_state()
        finally:
            asyncio.run(slots.complete_allocate_flight(h, fut, result={"slot_id": slot_id}))

    def test_evicts_when_pipeline_state_failed(self):
        slot_id = slots.allocate_slot("failed", _pipelines("filter { drop {} }"))
        self._age_slot(slot_id, age_seconds=30, access_seconds=30)

        pipeline_name = f"slot{slot_id}-filter1"
        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.list_pipelines.return_value = [pipeline_name]
        mock_api.detect_pipeline_state.return_value = "failed"

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            with patch.object(slots, "_delete_slot_pipelines"):
                evicted = slots.evict_failed_slots()

        assert evicted == [slot_id]
        assert len(slots.get_slot_state()) == 0

    def test_falls_back_when_api_raises(self):
        with patch("logstashagent.slots.LogstashAPI", side_effect=Exception("api down")):
            with patch("logstashagent.slots._evict_failed_slots_fallback", return_value=[2]) as fallback:
                assert slots.evict_failed_slots() == [2]
                fallback.assert_called_once()


class TestVerifySlotPipelinesLoaded:
    def test_returns_true_when_running(self):
        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.get_pipeline_stats.return_value = {
            "pipelines": {
                "slot1-filter1": {"reloads": {"failures": 0, "successes": 1}}
            }
        }
        mock_api.detect_pipeline_state.return_value = "running"

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            result = asyncio.run(
                slots.verify_slot_pipelines_loaded(
                    slot_id=1, expected_count=1, max_wait_seconds=0.2, poll_interval=0
                )
            )

        assert result is True
        mock_api.detect_pipeline_state.assert_called_once_with("slot1-filter1")

    def test_idle_accepts_after_short_stability(self):
        """Idle pipelines succeed after idle_stability_seconds (not a multi-second hold)."""
        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.get_pipeline_stats.return_value = {
            "pipelines": {
                "slot1-filter1": {"reloads": {"failures": 0, "successes": 1}}
            }
        }
        mock_api.detect_pipeline_state.return_value = "idle"

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            result = asyncio.run(
                slots.verify_slot_pipelines_loaded(
                    slot_id=1,
                    expected_count=1,
                    max_wait_seconds=2.0,
                    poll_interval=0.05,
                    idle_stability_seconds=0.15,
                )
            )

        assert result is True

    def test_returns_false_on_new_reload_failures(self):
        mock_api = MagicMock()
        mock_api.__enter__.return_value = mock_api
        mock_api.__exit__.return_value = False
        mock_api.get_pipeline_stats.side_effect = [
            {"pipelines": {"slot1-filter1": {"reloads": {"failures": 0, "successes": 0}}}},
            {"pipelines": {"slot1-filter1": {"reloads": {"failures": 1, "successes": 0}}}},
        ]
        mock_api.detect_pipeline_state.return_value = "not_found"

        with patch("logstashagent.slots.LogstashAPI", return_value=mock_api):
            result = asyncio.run(
                slots.verify_slot_pipelines_loaded(
                    slot_id=1, expected_count=1, max_wait_seconds=0.5, poll_interval=0
                )
            )

        assert result is False

    def test_falls_back_when_api_unavailable(self):
        with patch("logstashagent.slots.LogstashAPI", side_effect=Exception("api down")):
            with patch(
                "logstashagent.slots._verify_slot_pipelines_loaded_fallback",
                return_value=True,
            ) as fallback:
                result = asyncio.run(
                    slots.verify_slot_pipelines_loaded(
                        slot_id=3, expected_count=2, max_wait_seconds=0.1, poll_interval=0
                    )
                )

        assert result is True
        fallback.assert_called_once_with(3, 2)
