#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from threading import Lock, Thread
import time
import yaml
import os
from . import log_analyzer
from . import main
import logging
from .logstash_api import LogstashAPI

# Configure logging
logger = logging.getLogger(__name__)

# Number of simulation slots available
NUM_SLOTS = 6

# Slot TTL in seconds (2 minutes)
SLOT_TTL_SECONDS = 120

# Global slot state - thread-safe
_slots_lock = Lock()
_slots: Dict[int, Dict[str, Any]] = {}

# Async single-flight for concurrent allocate of the same content hash.
# Keyed by content_hash → Future of the full allocate result dict.
# Lazily created on first use so import stays sync-safe.
_allocate_flight_lock: Optional[Any] = None  # asyncio.Lock
_allocate_flights: Dict[str, Any] = {}  # content_hash → asyncio.Future
_slot_create_locks: Dict[int, Any] = {}  # slot_id → asyncio.Lock


def _ensure_asyncio_lock(lock_holder_name: str):
    """Create an asyncio.Lock on the running loop if needed."""
    import asyncio

    global _allocate_flight_lock
    if lock_holder_name == "flight":
        if _allocate_flight_lock is None:
            _allocate_flight_lock = asyncio.Lock()
        return _allocate_flight_lock
    raise ValueError(lock_holder_name)


async def begin_allocate_flight(content_hash: str):
    """
    Join or start a single-flight for this pipeline content hash.

    Returns:
        (future, is_leader):
          - is_leader True: caller must run allocate and complete_allocate_flight
          - is_leader False: caller should await future for the leader's result
    """
    import asyncio

    lock = _ensure_asyncio_lock("flight")
    async with lock:
        existing = _allocate_flights.get(content_hash)
        if existing is not None and not existing.done():
            logger.info(
                "allocate single-flight JOIN hash=%s… (wait for in-flight leader)",
                content_hash[:8],
            )
            return existing, False
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        _allocate_flights[content_hash] = fut
        logger.debug("allocate single-flight LEAD hash=%s…", content_hash[:8])
        return fut, True


async def complete_allocate_flight(
    content_hash: str,
    fut,
    *,
    result: Optional[Dict[str, Any]] = None,
    error: Optional[BaseException] = None,
) -> None:
    """Publish leader result/error and clear the flight entry."""
    lock = _ensure_asyncio_lock("flight")
    async with lock:
        if not fut.done():
            if error is not None:
                fut.set_exception(error)
            else:
                fut.set_result(result)
        if _allocate_flights.get(content_hash) is fut:
            del _allocate_flights[content_hash]


async def get_slot_create_lock(slot_id: int):
    """Per-slot asyncio lock so concurrent creates for one slot serialize."""
    import asyncio

    lock = _ensure_asyncio_lock("flight")
    async with lock:
        if slot_id not in _slot_create_locks:
            _slot_create_locks[slot_id] = asyncio.Lock()
        return _slot_create_locks[slot_id]


def clear_allocate_flights() -> None:
    """Test helper: drop in-flight allocate futures (does not cancel tasks)."""
    _allocate_flights.clear()
    _slot_create_locks.clear()


def allocate_flight_in_progress(content_hash: str) -> bool:
    """True if a single-flight allocate leader is still running for this hash."""
    if not content_hash:
        return False
    fut = _allocate_flights.get(content_hash)
    return fut is not None and not fut.done()


def _compute_pipeline_hash(pipelines: List[Dict[str, Any]]) -> str:
    """
    Compute a hash of the pipeline list to detect changes.

    Only hashes fields that actually affect the created pipeline:
    - filter_config: The filter configuration content
    - index: The pipeline index/order

    Args:
        pipelines: List of pipeline configurations

    Returns:
        SHA256 hash string
    """
    # Extract only the fields that affect the actual pipeline
    # (output_config is sent by UI but ignored by agent, so exclude it from hash)
    normalized_pipelines = []
    for pipeline in pipelines:
        filter_config = pipeline.get('filter_config', '')
        normalized_pipelines.append({
            'filter_config': filter_config,
            'index': pipeline.get('index', 1)
        })

    # Convert to JSON string with sorted keys for consistent hashing
    pipeline_str = json.dumps(normalized_pipelines, sort_keys=True)
    computed_hash = hashlib.sha256(pipeline_str.encode()).hexdigest()

    # Debug: Write full filter_config to temp file for comparison
    # if normalized_pipelines:
    #     import tempfile
    #     filter_config = normalized_pipelines[0]['filter_config']
    #     debug_file = os.path.join(tempfile.gettempdir(), f"filter_config_{computed_hash[:8]}.txt")
    #     try:
    #         with open(debug_file, 'w', encoding='utf-8') as f:
    #             f.write(filter_config)
    #         logger.info(f"Hash {computed_hash[:8]}: Wrote filter_config to {debug_file} ({len(filter_config)} bytes)")
    #     except Exception as e:
    #         logger.error(f"Failed to write debug file: {e}")
    
    return computed_hash


def get_slot_state() -> Dict[int, Dict[str, Any]]:
    """
    Get a copy of the current slot state.

    Returns:
        Dictionary mapping slot IDs to their state
    """
    with _slots_lock:
        return _slots.copy()


def allocate_slot(pipeline_name: str, pipelines: List[Dict[str, Any]]) -> Optional[int]:
    """
    Allocate a slot for the given pipeline configuration.

    If a slot already exists with the same content hash, reuse it.
    Otherwise, find an empty slot or evict the oldest one.

    Args:
        pipeline_name: Name of the pipeline
        pipelines: List of pipeline configurations

    Returns:
        Slot ID (1-10) or None if allocation failed
    """
    content_hash = _compute_pipeline_hash(pipelines)
    old_slot_data_to_cleanup = None
    slot_id_to_cleanup = None

    logger.info(f"allocate_slot: Looking for hash {content_hash[:8]}... in {len(_slots)} existing slots")

    with _slots_lock:
        # Check if we already have a slot with this exact configuration
        for slot_id, slot_data in _slots.items():
            existing_hash = slot_data.get('content_hash', '')
            logger.debug(f"  Slot {slot_id} hash: {existing_hash[:8]}...")
            if existing_hash == content_hash:
                # Update last_accessed to prevent TTL eviction
                # DO NOT update created_at - keep original creation time to prevent race conditions
                # with eviction logic during active simulations
                now = datetime.now(timezone.utc)
                slot_data['last_accessed'] = now.isoformat()
                logger.info(f"+ Reusing slot {slot_id} with matching hash")
                return slot_id
            else:
                # Debug: Compare configs to see what's different
                if pipelines and slot_data.get('pipelines'):
                    new_config = pipelines[0].get('filter_config', '')
                    old_config = slot_data['pipelines'][0].get('filter_config', '')
                    if len(new_config) == len(old_config):
                        # Same length but different hash - find first difference
                        for i, (c1, c2) in enumerate(zip(new_config, old_config)):
                            if c1 != c2:
                                start = max(0, i - 50)
                                end = min(len(new_config), i + 50)
                                logger.warning(f"Hash mismatch at position {i}:")
                                logger.warning(f"  Old (slot {slot_id}): ...{old_config[start:end]}...")
                                logger.warning(f"  New: ...{new_config[start:end]}...")
                                break

        # Find an empty slot
        logger.info(f"No matching hash found, allocating new slot")
        for slot_id in range(1, NUM_SLOTS + 1):
            if slot_id not in _slots:
                now = datetime.now(timezone.utc)
                _slots[slot_id] = {
                    'content_hash': content_hash,
                    'created_at': now.isoformat(),
                    'created_at_millis': int(now.timestamp() * 1000),
                    'last_accessed': now.isoformat(),
                    'pipeline_name': pipeline_name,
                    'pipelines': pipelines
                }
                logger.info(f"+ Allocated new empty slot {slot_id}")
                return slot_id

        # No empty slots - evict the oldest one (by created_at)
        oldest_slot_id = min(
            _slots.keys(),
            key=lambda sid: _slots[sid]['created_at']
        )

        # Save old slot data before overwriting so we can clean up its pipelines
        old_slot_data_to_cleanup = _slots[oldest_slot_id].copy()
        slot_id_to_cleanup = oldest_slot_id

        now = datetime.now(timezone.utc)
        _slots[oldest_slot_id] = {
            'content_hash': content_hash,
            'created_at': now.isoformat(),
            'created_at_millis': int(now.timestamp() * 1000),
            'last_accessed': now.isoformat(),
            'pipeline_name': pipeline_name,
            'pipelines': pipelines
        }

    # Delete old pipelines OUTSIDE the lock to avoid blocking other allocations
    if old_slot_data_to_cleanup is not None:
        logger.info(f"Evicting slot {slot_id_to_cleanup}, cleaning up old pipelines")
        _delete_slot_pipelines(slot_id_to_cleanup, old_slot_data_to_cleanup)

    return oldest_slot_id


def release_slot(slot_id: int, cleanup_pipelines: bool = True) -> bool:
    """
    Release a slot, making it available for reuse.

    Always tears down named Logstash pipelines (``slotN-filter*``) when
    ``cleanup_pipelines`` is True so simulate-start does not keep retrying
    send_to against a dead bus address.

    Args:
        slot_id: Slot ID (1-10)
        cleanup_pipelines: Delete corresponding pipelines from pipelines.yml / conf.d

    Returns:
        True if the slot was in the table (and is now gone), False if it did not exist.
        Orphan pipeline cleanup still runs when the slot was missing so leftover
        conf/yml entries cannot linger.
    """
    slot_data: Optional[Dict[str, Any]] = None
    existed = False
    with _slots_lock:
        if slot_id in _slots:
            slot_data = _slots[slot_id].copy()
            del _slots[slot_id]
            existed = True

    if cleanup_pipelines:
        # Always attempt cleanup — even if the slot dict was already gone (orphans)
        _delete_slot_pipelines(slot_id, slot_data or {"pipelines": [{"index": 1}]})

    if existed:
        logger.info("Released slot %s (pipelines cleaned=%s)", slot_id, cleanup_pipelines)
    return existed


def release_slot_if_hash(slot_id: int, content_hash: str) -> bool:
    """
    Release a slot only if it still holds ``content_hash``.

    Prevents a failed concurrent allocate from wiping a slot that another
    request has already re-booked or finished successfully with the same hash.
    When released, named Logstash pipelines for the slot are deleted.
    """
    slot_data: Optional[Dict[str, Any]] = None
    with _slots_lock:
        data = _slots.get(slot_id)
        if not data:
            return False
        if data.get("content_hash") != content_hash:
            logger.info(
                "Skip release slot %s — hash changed (wanted %s… have %s…)",
                slot_id,
                (content_hash or "")[:8],
                (data.get("content_hash") or "")[:8],
            )
            return False
        slot_data = data.copy()
        del _slots[slot_id]
        logger.info("Released slot %s (hash %s…)", slot_id, content_hash[:8])

    _delete_slot_pipelines(slot_id, slot_data or {"pipelines": [{"index": 1}]})
    return True


def clear_all_slots():
    """Clear all slots - useful for testing or reset."""
    with _slots_lock:
        _slots.clear()
    clear_allocate_flights()


def evict_all_slots_and_cleanup():
    """
    Evict all slots and clean up all pipeline files from conf.d.
    This should be called before Logstash restart to prevent mismatch
    between slots state and Logstash's loaded pipelines.
    
    Returns:
        List of evicted slot IDs
    """
    logger.info("Evicting all slots and cleaning up conf.d folder for Logstash restart")
    evicted_slots = []
    
    with _slots_lock:
        # Get all current slots before clearing
        slots_to_cleanup = list(_slots.items())
        
        # Clear the slots dictionary
        _slots.clear()
        evicted_slots = [slot_id for slot_id, _ in slots_to_cleanup]
    
    # Delete all pipeline files outside the lock
    for slot_id, slot_data in slots_to_cleanup:
        try:
            _delete_slot_pipelines(slot_id, slot_data)
        except Exception as e:
            logger.error(f"Error cleaning up slot {slot_id} during evict_all: {e}")
    
    # Also clean up any orphaned pipeline files in conf.d
    try:
        conf_d_path = main.PIPELINES_DIR
        if os.path.exists(conf_d_path):
            orphaned_files = []
            for filename in os.listdir(conf_d_path):
                if filename.startswith('slot') and filename.endswith('.conf'):
                    file_path = os.path.join(conf_d_path, filename)
                    try:
                        os.remove(file_path)
                        orphaned_files.append(filename)
                        logger.debug(f"Removed orphaned pipeline file: {filename}")
                    except Exception as e:
                        logger.error(f"Error removing orphaned file {filename}: {e}")
            
            if orphaned_files:
                logger.info(f"Cleaned up {len(orphaned_files)} orphaned pipeline files from conf.d")
    except Exception as e:
        logger.error(f"Error cleaning up orphaned files: {e}")
    
    logger.info(f"Evicted all {len(evicted_slots)} slots and cleaned up conf.d folder")
    return evicted_slots


def evict_expired_slots() -> List[int]:
    """
    Evict slots that haven't been accessed within the TTL period.

    Returns:
        List of evicted slot IDs
    """
    evicted_slots = []
    current_time = datetime.now(timezone.utc)

    with _slots_lock:
        slots_to_evict = []

        for slot_id, slot_data in _slots.items():
            last_accessed_str = slot_data.get('last_accessed')
            if last_accessed_str:
                try:
                    last_accessed = datetime.fromisoformat(last_accessed_str.replace('Z', '+00:00'))
                    time_since_access = (current_time - last_accessed).total_seconds()

                    if time_since_access > SLOT_TTL_SECONDS:
                        slots_to_evict.append((slot_id, slot_data))
                except (ValueError, AttributeError):
                    # If we can't parse the timestamp, evict the slot to be safe
                    slots_to_evict.append((slot_id, slot_data))
            else:
                # No last_accessed timestamp, evict to be safe
                slots_to_evict.append((slot_id, slot_data))

        # Evict the expired slots
        for slot_id, slot_data in slots_to_evict:
            del _slots[slot_id]
            evicted_slots.append(slot_id)

    # Delete Logstash pipelines for evicted slots (outside the lock)
    for slot_id, slot_data in slots_to_evict:
        _delete_slot_pipelines(slot_id, slot_data)

    if evicted_slots:
        logger.info(f"Evicted {len(evicted_slots)} expired slots: {evicted_slots}")

    return evicted_slots


# Grace periods for failed-slot cleanup (background worker).
# Cold allocate can take 30–60s+; single-flight create must not be evicted mid-flight.
MIN_SLOT_AGE_NOT_FOUND_SECONDS = 90  # missing pipeline — was 30s (too aggressive)
MIN_SLOT_AGE_FAILED_SECONDS = 20     # explicit reload failures can be faster
MIN_LAST_ACCESS_GRACE_SECONDS = 60   # recently used → do not treat as dead


def _slot_age_seconds(slot_data: Dict[str, Any], current_time: datetime) -> Optional[float]:
    """Age since created_at, or None if unparseable/missing."""
    created_at_str = slot_data.get("created_at")
    if not created_at_str:
        return None
    try:
        created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        return (current_time - created_at).total_seconds()
    except (ValueError, AttributeError):
        return None


def _seconds_since_last_access(slot_data: Dict[str, Any], current_time: datetime) -> Optional[float]:
    last_accessed_str = slot_data.get("last_accessed")
    if not last_accessed_str:
        return None
    try:
        last_accessed = datetime.fromisoformat(last_accessed_str.replace("Z", "+00:00"))
        return (current_time - last_accessed).total_seconds()
    except (ValueError, AttributeError):
        return None


def _has_active_allocate_flight(content_hash: str) -> bool:
    """True if a single-flight allocate is still running for this hash."""
    if not content_hash:
        return False
    fut = _allocate_flights.get(content_hash)
    return fut is not None and not fut.done()


def evict_failed_slots() -> List[int]:
    """
    Evict slots whose pipelines have failed to load or are not running.

    Uses the Logstash API to directly query pipeline state instead of parsing logs.
    This is more reliable and faster than log-based detection.

    Careful with races:
      - Do not evict slots still covered by an in-flight allocate (single-flight).
      - Do not treat transient not_found during cold create as failure (long grace).
      - Prefer ``failed`` (reload errors) over not_found for quick eviction.
      - list_pipelines membership trumps detect_pipeline_state==not_found glitches.

    Returns:
        List of evicted slot IDs
    """
    evicted_slots = []
    current_time = datetime.now(timezone.utc)

    try:
        with LogstashAPI(timeout=5.0) as api:
            # Get all currently loaded pipelines from Logstash
            all_pipelines = api.list_pipelines()

            with _slots_lock:
                slots_to_evict = []

                for slot_id, slot_data in _slots.items():
                    content_hash = slot_data.get("content_hash") or ""
                    if _has_active_allocate_flight(content_hash):
                        logger.debug(
                            "Slot %s hash %s… has in-flight allocate — skip failed eviction",
                            slot_id,
                            content_hash[:8],
                        )
                        continue

                    slot_age = _slot_age_seconds(slot_data, current_time)
                    since_access = _seconds_since_last_access(slot_data, current_time)

                    pipelines = slot_data.get('pipelines', [])

                    # Check if any pipeline in this slot is missing or hard-failed
                    for idx in range(1, len(pipelines) + 1):
                        pipeline_name = f"slot{slot_id}-filter{idx}"

                        in_list = pipeline_name in all_pipelines
                        state = None
                        if in_list:
                            try:
                                state = api.detect_pipeline_state(pipeline_name)
                            except Exception as e:
                                logger.debug(
                                    "detect_pipeline_state(%s) error: %s",
                                    pipeline_name,
                                    e,
                                )
                                state = None

                        # Explicit reload failure — faster path, still respect young slots
                        if state == "failed":
                            if slot_age is not None and slot_age < MIN_SLOT_AGE_FAILED_SECONDS:
                                logger.debug(
                                    "Slot %s failed but only %.1fs old — skip eviction",
                                    slot_id,
                                    slot_age,
                                )
                                break
                            logger.warning(
                                "Slot %s pipeline %s has failed (reload failures) — marking for eviction",
                                slot_id,
                                pipeline_name,
                            )
                            slots_to_evict.append((slot_id, slot_data))
                            break

                        # Missing from Logstash: only after long grace, and not if recently used
                        missing = (not in_list) or (state == "not_found" and not in_list)
                        # If still listed, ignore detect_pipeline_state==not_found (API quirk)
                        if state == "not_found" and in_list:
                            logger.debug(
                                "Slot %s pipeline %s listed but detect=not_found — treating as present",
                                slot_id,
                                pipeline_name,
                            )
                            continue

                        if not in_list or missing:
                            if slot_age is not None and slot_age < MIN_SLOT_AGE_NOT_FOUND_SECONDS:
                                logger.debug(
                                    "Slot %s pipeline %s missing but only %.1fs old "
                                    "(grace %ss) — skip eviction",
                                    slot_id,
                                    pipeline_name,
                                    slot_age,
                                    MIN_SLOT_AGE_NOT_FOUND_SECONDS,
                                )
                                break
                            if (
                                since_access is not None
                                and since_access < MIN_LAST_ACCESS_GRACE_SECONDS
                            ):
                                logger.debug(
                                    "Slot %s pipeline %s missing but last_accessed %.1fs ago "
                                    "(grace %ss) — skip eviction",
                                    slot_id,
                                    pipeline_name,
                                    since_access,
                                    MIN_LAST_ACCESS_GRACE_SECONDS,
                                )
                                break
                            logger.warning(
                                "Slot %s pipeline %s not found in Logstash "
                                "(age=%s last_access=%s) — marking for eviction",
                                slot_id,
                                pipeline_name,
                                f"{slot_age:.1f}s" if slot_age is not None else "?",
                                f"{since_access:.1f}s" if since_access is not None else "?",
                            )
                            slots_to_evict.append((slot_id, slot_data))
                            break

                # Evict the failed slots
                for slot_id, slot_data in slots_to_evict:
                    del _slots[slot_id]
                    evicted_slots.append(slot_id)

            # Delete Logstash pipelines for evicted slots (outside the lock)
            for slot_id, slot_data in slots_to_evict:
                _delete_slot_pipelines(slot_id, slot_data)

            if evicted_slots:
                logger.info(f"Evicted {len(evicted_slots)} failed slots: {evicted_slots}")

    except Exception as e:
        logger.error(f"Error during API-based slot eviction: {e}")
        # Fall back to log-based detection if API fails
        logger.warning("Falling back to log-based detection")
        return _evict_failed_slots_fallback()

    return evicted_slots


def _evict_failed_slots_fallback() -> List[int]:
    """
    Fallback to log-based eviction if API is unavailable.
    This is the old implementation kept as a safety net.
    """
    evicted_slots = []

    try:
        logs = log_analyzer._read_json_logs(max_lines=1000, reverse=True)
    except Exception as e:
        logger.error(f"Error reading logs for failed slot detection: {e}")
        return evicted_slots

    failed_pipeline_ids = set()

    for log_entry in logs:
        if log_entry.get('level') == 'ERROR':
            log_event = log_entry.get('logEvent', {})
            action_type = log_event.get('action_type', '')
            if 'FailedAction' in action_type:
                pipeline_id = log_event.get('id')
                if pipeline_id and pipeline_id.startswith('slot'):
                    failed_pipeline_ids.add(pipeline_id)

    if not failed_pipeline_ids:
        return evicted_slots

    with _slots_lock:
        slots_to_evict = []
        for slot_id, slot_data in _slots.items():
            pipelines = slot_data.get('pipelines', [])
            for idx in range(1, len(pipelines) + 1):
                pipeline_name = f"slot{slot_id}-filter{idx}"
                if pipeline_name in failed_pipeline_ids:
                    slots_to_evict.append((slot_id, slot_data))
                    break

        for slot_id, slot_data in slots_to_evict:
            del _slots[slot_id]
            evicted_slots.append(slot_id)

    for slot_id, slot_data in slots_to_evict:
        _delete_slot_pipelines(slot_id, slot_data)

    return evicted_slots


# Idle pipelines are "ready" after this much continuous observation (was 2.0s —
# dominate cold allocate when Logstash reports idle quickly). Running state is
# accepted immediately.
IDLE_STABILITY_SECONDS = 0.5


async def verify_slot_pipelines_loaded(
    slot_id: int,
    expected_count: int,
    max_wait_seconds: float = 15.0,
    poll_interval: float = 0.25,
    idle_stability_seconds: float = IDLE_STABILITY_SECONDS,
) -> bool:
    """
    Verify that all pipelines for a slot have been successfully loaded by Logstash.

    Uses continuous polling of the Logstash API to detect pipeline state changes immediately.
    This provides instant feedback when pipelines fail or succeed.

    Args:
        slot_id: Slot ID (1-10)
        expected_count: Number of pipelines expected for this slot
        max_wait_seconds: Maximum time to wait for pipelines to load (default: 15 seconds)
        poll_interval: How often to poll the API in seconds (default: 0.25s)
        idle_stability_seconds: Require idle pipelines to stay idle this long before success

    Returns:
        True if all slot pipelines are running, False otherwise
    """
    import asyncio
    import time

    logger.info(
        f"Verifying slot {slot_id} pipelines (polling every {poll_interval}s, "
        f"max wait: {max_wait_seconds}s, idle_stability: {idle_stability_seconds}s)..."
    )
    start_time = time.time()
    attempt = 0
    
    # Track when we first see each pipeline to detect initialization vs. actual failures
    first_seen = {}
    
    # Grace period for pipelines to appear in Logstash API (config reload detection time)
    # Logstash config.reload.automatic is typically 1-3 seconds
    GRACE_PERIOD_SECONDS = 5.0

    # Track baseline reload counters for each pipeline to detect NEW failures
    # Logstash reload counters are cumulative and persist across pipeline deletions
    baseline_reload_counters = {}
    
    try:
        with LogstashAPI(timeout=5.0) as api:
            while True:
                attempt += 1
                elapsed = time.time() - start_time

                try:
                    # Check if all slot pipelines are loaded
                    slot_pipelines = [f"slot{slot_id}-filter{i}" for i in range(1, expected_count + 1)]
                    not_found_pipelines = []
                    failed_pipelines = []
                    loaded_pipelines = []

                    for pipeline_name in slot_pipelines:
                        # Get detailed pipeline stats to check reload counters
                        try:
                            stats = api.get_pipeline_stats(pipeline_name)
                            pipeline_data = stats.get('pipelines', {}).get(pipeline_name, {})
                            reloads = pipeline_data.get('reloads', {})
                            current_failures = reloads.get('failures', 0)
                            current_successes = reloads.get('successes', 0)
                            
                            # Set baseline on first check of this pipeline
                            if pipeline_name not in baseline_reload_counters:
                                baseline_reload_counters[pipeline_name] = {
                                    'failures': current_failures,
                                    'successes': current_successes
                                }
                                logger.debug(f"Pipeline {pipeline_name} - baseline: failures={current_failures}, successes={current_successes}")
                            
                            # Calculate NEW failures/successes since baseline
                            baseline = baseline_reload_counters[pipeline_name]
                            new_failures = current_failures - baseline['failures']
                            new_successes = current_successes - baseline['successes']
                            
                            # Check if there are NEW failures (not historical ones)
                            if new_failures > 0 and new_failures >= new_successes:
                                failed_pipelines.append(pipeline_name)
                                logger.error(f"Pipeline {pipeline_name} has NEW failures (new_failures={new_failures}, new_successes={new_successes}, baseline_failures={baseline['failures']})")
                                continue
                                
                        except Exception as e:
                            logger.debug(f"Could not get detailed stats for {pipeline_name}: {e}")
                        
                        # Use standard state detection
                        state = api.detect_pipeline_state(pipeline_name)
                        
                        # Track when we first see this pipeline
                        if pipeline_name not in first_seen and state != 'not_found':
                            first_seen[pipeline_name] = time.time()

                        if state == 'not_found':
                            not_found_pipelines.append(pipeline_name)
                        elif state == 'idle':
                            # Pipeline exists and loaded successfully - but check if it's truly ready
                            # Logstash can report a pipeline as 'idle' while it's still initializing.
                            # Require a short stability window (default 0.5s) with fast polling.
                            if pipeline_name in first_seen:
                                time_since_first_seen = time.time() - first_seen[pipeline_name]
                                if time_since_first_seen >= idle_stability_seconds:
                                    loaded_pipelines.append(pipeline_name)
                                    logger.debug(
                                        f"Pipeline {pipeline_name} is idle "
                                        f"(stable for {time_since_first_seen:.1f}s)"
                                    )
                                else:
                                    # Pipeline just appeared, wait a bit longer to ensure it's truly ready
                                    logger.debug(
                                        f"Pipeline {pipeline_name} is idle but only seen for "
                                        f"{time_since_first_seen:.1f}s, waiting for stability"
                                    )
                                    not_found_pipelines.append(pipeline_name)
                            else:
                                # First time seeing this pipeline as idle, wait for next check
                                logger.debug(f"Pipeline {pipeline_name} is idle (first detection, waiting for stability)")
                                not_found_pipelines.append(pipeline_name)
                        elif state == 'running':
                            # Pipeline is actively processing - it's definitely ready!
                            loaded_pipelines.append(pipeline_name)
                            logger.debug(f"Pipeline {pipeline_name} is running")

                    # Check for failed pipelines first - FAIL IMMEDIATELY for fast feedback
                    if failed_pipelines:
                        logger.error(f"✗ Pipelines failed to load (NEW failures detected): {failed_pipelines}")
                        return False

                    # All pipelines found and loaded (either idle or running) - SUCCESS IMMEDIATELY
                    if len(loaded_pipelines) == expected_count:
                        logger.info(
                            f"+ All {expected_count} pipelines for slot {slot_id} are loaded "
                            f"(took {elapsed:.2f}s, {attempt} checks)"
                        )
                        return True

                    # Check if we've exceeded max wait time
                    if elapsed >= max_wait_seconds:
                        logger.error(
                            f"✗ Pipelines still not loaded after {elapsed:.2f}s ({attempt} checks): "
                            f"not_found={not_found_pipelines}, loaded={len(loaded_pipelines)}/{expected_count}"
                        )
                        return False

                    # Some pipelines are still not found - wait and retry
                    if elapsed > 5.0:
                        # Log at INFO level if taking longer than 5 seconds to help debug slow loads
                        logger.info(
                            f"Check {attempt} ({elapsed:.2f}s): Waiting for pipelines - "
                            f"loaded: {len(loaded_pipelines)}/{expected_count}, not_found: {not_found_pipelines}"
                        )
                    else:
                        logger.debug(
                            f"Check {attempt} ({elapsed:.2f}s): Loaded {len(loaded_pipelines)}/{expected_count}, "
                            f"waiting for: {not_found_pipelines}"
                        )
                    if poll_interval > 0:
                        await asyncio.sleep(poll_interval)

                except Exception as e:
                    logger.error(f"Error checking pipeline status (check {attempt}, {elapsed:.2f}s): {e}")
                    # On error, wait and retry (unless we've exceeded max wait time)
                    if elapsed >= max_wait_seconds:
                        logger.error(f"✗ Failed to verify pipelines after {elapsed:.2f}s due to errors")
                        return False
                    if poll_interval > 0:
                        await asyncio.sleep(poll_interval)

    except Exception as e:
        logger.error(f"Failed to verify slot {slot_id} pipelines via API: {e}")
        # Fallback to log-based verification
        logger.warning("Falling back to log-based verification")
        return await _verify_slot_pipelines_loaded_fallback(slot_id, expected_count)


async def _verify_slot_pipelines_loaded_fallback(slot_id: int, expected_count: int, max_retries: int = 3,
                                                 retry_delay: float = 1.0) -> bool:
    """
    Fallback to log-based verification if API is unavailable.
    This is the old implementation kept as a safety net.
    """
    import asyncio

    log_dir = log_analyzer.resolve_logstash_log_dir(
        logstash_log_path=_config.get("logstash_log_path") if isinstance(_config, dict) else None,
    )
    for attempt in range(max_retries):
        try:
            pipeline_status = log_analyzer.get_running_pipelines(log_dir=log_dir)

            if not pipeline_status:
                logger.warning(
                    f"Attempt {attempt + 1}/{max_retries}: No pipeline status found in logs yet "
                    f"(log_dir={log_dir})"
                )
                await asyncio.sleep(retry_delay)
                continue

            running_pipelines = pipeline_status.get('running_pipelines', [])
            slot_pipelines = [f"slot{slot_id}-filter{i}" for i in range(1, expected_count + 1)]
            missing_pipelines = [p for p in slot_pipelines if p not in running_pipelines]

            if not missing_pipelines:
                logger.info(f"+ All {expected_count} pipelines for slot {slot_id} are running (fallback)")
                return True

            logger.warning(f"Attempt {attempt + 1}/{max_retries}: Waiting for pipelines: {missing_pipelines}")
            await asyncio.sleep(retry_delay)

        except Exception as e:
            logger.error(f"Error checking pipeline status (attempt {attempt + 1}/{max_retries}): {e}")
            await asyncio.sleep(retry_delay)

    logger.error(f"X Failed to verify slot {slot_id} pipelines after {max_retries} attempts")
    return False


def _delete_slot_pipelines(slot_id: int, slot_data: Optional[Dict[str, Any]] = None):
    """
    Delete all Logstash pipelines associated with a slot.

    Removes entries from pipelines.yml + conf.d (via delete_pipeline_internal) so
    Logstash config reload drops the named bus address (slotN-filterM). Without
    this, simulate-start keeps retrying send_to against a dead address.

    Args:
        slot_id: Slot ID
        slot_data: Optional slot data; when missing, still deletes slot{id}-filter1
            and any extra conf files matching the slot pattern.
    """
    try:
        pipelines = (slot_data or {}).get("pipelines") or []
        # At least filter1; also cover multi-filter slots from slot_data
        max_idx = max(1, len(pipelines))
        names = [f"slot{slot_id}-filter{idx}" for idx in range(1, max_idx + 1)]

        # Orphan conf files for this slot (e.g. slot1-filter2 left after partial create)
        try:
            conf_d = main.PIPELINES_DIR
            if conf_d and os.path.isdir(conf_d):
                prefix = f"slot{slot_id}-filter"
                for filename in os.listdir(conf_d):
                    if filename.startswith(prefix) and filename.endswith(".conf"):
                        pipe_id = filename[: -len(".conf")]
                        if pipe_id not in names:
                            names.append(pipe_id)
        except Exception as e:
            logger.debug("Could not scan conf.d for slot %s orphans: %s", slot_id, e)

        deleted_count = 0
        for pipeline_name in names:
            try:
                success = main.delete_pipeline_internal(pipeline_name)
                if success:
                    deleted_count += 1
                    logger.info(f"Deleted pipeline {pipeline_name}")
                else:
                    # Still try removing a stray conf if yml entry was already gone
                    try:
                        stray = os.path.join(main.PIPELINES_DIR, f"{pipeline_name}.conf")
                        if os.path.isfile(stray):
                            os.remove(stray)
                            deleted_count += 1
                            logger.info("Removed orphan conf %s", stray)
                        else:
                            logger.debug(
                                "Pipeline %s not in pipelines.yml (already cleared)",
                                pipeline_name,
                            )
                    except Exception as e2:
                        logger.warning(
                            "Pipeline %s not found or already deleted (%s)",
                            pipeline_name,
                            e2,
                        )
            except Exception as e:
                logger.error(f"Error deleting pipeline {pipeline_name}: {e}")

        logger.info(
            "Deleted %s/%s pipeline artifacts for slot %s",
            deleted_count,
            len(names),
            slot_id,
        )
    except Exception as e:
        logger.error(f"Error cleaning up pipelines for slot {slot_id}: {e}")


def _background_cleanup_worker():
    """
    Background worker thread that periodically evicts expired and failed slots.
    Runs every 60 seconds to clean up expired and failed pipelines.

    Also scans Logstash logs for pipeline-bus ``send_to`` retry storms
    (destination address unavailable). Those loops do not fail the HTTP health
    probe; stuck workers need a Logstash restart (handled via main).
    """
    while True:
        try:
            time.sleep(60)

            # Evict slots that have exceeded TTL
            expired_slots = evict_expired_slots()
            if expired_slots:
                logger.info(f"Background cleanup evicted expired slots: {expired_slots}")

            # Evict slots with failed pipelines
            failed_slots = evict_failed_slots()
            if failed_slots:
                logger.info(f"Background cleanup evicted failed slots: {failed_slots}")

            # Bus retry storms: simulate-start send_to with missing dest retries forever.
            # Detection + confirmation + simulate-only restart live in main (with logging).
            try:
                log_dir = log_analyzer.resolve_logstash_log_dir(
                    logs_path=os.environ.get("LOGSTASH_PATH_LOGS"),
                )
                from logstashagent import main as main_mod

                if hasattr(main_mod, "handle_pipeline_bus_retry_storms"):
                    main_mod.handle_pipeline_bus_retry_storms(log_dir=log_dir)
            except Exception as e:
                logger.debug("Bus storm scan during slot cleanup failed: %s", e)

        except Exception as e:
            logger.error(f"Error during background cleanup: {e}")


def _load_config() -> Dict[str, Any]:
    """
    Load agent configuration (prefer LOGSTASH_AGENT_CONFIG / instance yml).

    Falls back to AGENT_MODE env or simulate defaults so multi-instance
    units still enable the slot cleanup worker.
    """
    candidates: list[str] = []
    env_cfg = (os.environ.get("LOGSTASH_AGENT_CONFIG") or "").strip()
    if env_cfg:
        candidates.append(env_cfg)
    candidates.append(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "logstashagent.yml")
    )
    candidates.append("/opt/logstash-agent/config/logstashagent.yml")

    for config_path in candidates:
        if not config_path or not os.path.exists(config_path):
            continue
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            if config:
                return config
        except Exception as e:
            logger.error(f"[Slots] Error loading config {config_path}: {e}")

    env_mode = (os.environ.get("AGENT_MODE") or "").strip().lower()
    if env_mode:
        return {"mode": env_mode}
    logger.warning("[Slots] Config file not found; using simulate defaults")
    return {"mode": "simulate"}


# Conditionally start the background cleanup thread based on config / env
_config = _load_config()
_mode = (_config.get("mode") or os.environ.get("AGENT_MODE") or "").lower()
# Legacy "simulation" plus multi-instance FastAPI roles that allocate slots
_SLOT_CLEANUP_MODES = frozenset({"simulation", "simulate", "managed", "embedded"})

if _mode in _SLOT_CLEANUP_MODES:
    _cleanup_thread = Thread(target=_background_cleanup_worker, daemon=True, name="SlotCleanupThread")
    _cleanup_thread.start()
    logger.info("[Slots] Started background cleanup thread (mode: %s)", _mode or "simulation")
else:
    logger.info(
        "[Slots] Background cleanup thread not started (mode: %s)",
        _mode or "not set",
    )
