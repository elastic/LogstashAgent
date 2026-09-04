#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import warnings

# Suppress FastAPI deprecation warnings before importing FastAPI
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys

FIRST_CLASS_MODES = ('packaged', 'managed', 'simulate', 'embedded')
MODE_ALIASES = {
    'default': 'packaged',
    'agent': 'packaged',
    'host': 'managed',
}


def canonical_agent_mode(value: str | None) -> str | None:
    """Map CLI/config aliases to a first-class mode. Unknown values returned lowercased."""
    if value is None:
        return None
    raw = str(value).strip().lower()
    if not raw:
        return None
    return MODE_ALIASES.get(raw, raw)


# slots starts a cleanup thread on import when mode looks like simulation.
# Skip for enroll/install/admin and for packaged --run (controller only).
# Do NOT skip for --run --mode simulate|managed|embedded — those serve FastAPI
# slot allocate/release endpoints and need the slots module.
def _argv_mode_hint() -> str | None:
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == '--mode' and i + 1 < len(argv):
            return canonical_agent_mode(argv[i + 1])
        if a.startswith('--mode='):
            return canonical_agent_mode(a.split('=', 1)[1])
    return None


_CLI_MODE_HINT = _argv_mode_hint()
_SIM_FASTAPI_MODES = frozenset({
    'simulate', 'managed', 'simulation', 'embedded',
})
_ADMIN_CLI = (
    '--enroll' in sys.argv
    or 'install' in sys.argv
    or 'upgrade' in sys.argv
    or 'uninstall' in sys.argv
    or 'configure' in sys.argv
    or 'setup-simulate' in sys.argv
    or 'recover-simulate' in sys.argv
    or 'list-instances' in sys.argv
    or 'list-versions' in sys.argv
    or 'ensure-version' in sys.argv
    or 'prune-versions' in sys.argv
)
_ADMIN_COMMANDS = (
    'install', 'uninstall', 'list-instances', 'list-versions',
    'ensure-version', 'prune-versions', 'configure', 'setup-simulate',
    'recover-simulate', 'upgrade',
)


def _is_lightweight_cli(argv: list[str] | None = None) -> bool:
    """True when we must not load yml, create agent_id, or makedirs pipeline dirs."""
    argv = list(argv if argv is not None else sys.argv[1:])
    if '-h' in argv or '--help' in argv or '--version' in argv or '-V' in argv:
        return True
    if '--run' in argv:
        return False
    for a in argv:
        if a in _ADMIN_COMMANDS:
            return True
        if a == '--enroll' or a.startswith('--enroll='):
            return True
    return False


_LIGHTWEIGHT_CLI = _is_lightweight_cli()
_SKIP_SIMULATION_IMPORTS = bool(
    _ADMIN_CLI
    or _LIGHTWEIGHT_CLI
    or (
        '--run' in sys.argv
        and (_CLI_MODE_HINT is None or _CLI_MODE_HINT not in _SIM_FASTAPI_MODES)
    )
)

import glob
import json
import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Path as FastAPIPath
from fastapi.responses import JSONResponse

from logstashagent import (
    agent_state,
    controller,
    enrollment,
    installer,
    log_analyzer,
    logstash_supervisor,
)

if not _SKIP_SIMULATION_IMPORTS:
    from logstashagent import slots
import argparse
import asyncio


def cli_mode_type(value: str) -> str:
    """argparse type=: accept first-class modes plus aliases; store canonical name."""
    mapped = canonical_agent_mode(value)
    if mapped not in FIRST_CLASS_MODES:
        raise argparse.ArgumentTypeError(
            f"invalid mode {value!r} (choose from {', '.join(FIRST_CLASS_MODES)}; "
            "aliases: default|agent→packaged, host→managed)"
        )
    return mapped


import atexit
import base64
import threading
import time
from collections import deque
from importlib.metadata import PackageNotFoundError, version
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests
import uvicorn

from logstashagent.logstash_api import LogstashAPI

# Configure basic console logging first
# File logging will be added later based on the command mode
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s %(name)s %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Reduce httpx logging noise - only show warnings and errors
logging.getLogger("httpx").setLevel(logging.WARNING)


def setup_file_logging():
    """
    Setup file logging for normal operation (not install/uninstall/upgrade).
    This is called after we know we're running as the service.
    """
    # Prefer /opt layout, then legacy /var/log, then local dev data/
    if os.path.isdir('/opt/logstash-agent/logs'):
        logs_dir = Path('/opt/logstash-agent/logs')
    elif os.path.isdir('/var/log/logstash-agent'):
        logs_dir = Path('/var/log/logstash-agent')
    else:
        logs_dir = Path(__file__).parent / 'data' / 'logs'
        logs_dir.mkdir(parents=True, exist_ok=True)

    # Add file handler to root logger
    file_handler = RotatingFileHandler(
        logs_dir / 'logstashagent.log',
        maxBytes=1024 * 1024 * 10,  # 10 MB
        backupCount=5,
    )
    file_handler.setFormatter(logging.Formatter(
        '[%(levelname)s] %(asctime)s %(name)s %(funcName)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logging.getLogger().addHandler(file_handler)

    logger.info(f"File logging initialized - logs directory: {logs_dir}")
    return logs_dir

# Get agent version from pyproject.toml
def _get_version():
    """Get version from installed package metadata or pyproject.toml"""
    try:
        return version("LogstashAgent")
    except PackageNotFoundError:
        try:
            import tomllib
            # Navigate to LogstashAgent root directory (2 levels up from main.py)
            agent_root = Path(__file__).resolve().parent.parent.parent
            pyproject_path = agent_root / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                    return pyproject_data.get("project", {}).get("version", "0.0.0+unknown")
        except Exception:
            pass
        return "0.0.0+unknown"

AGENT_VERSION = _get_version()

# Placeholders so FastAPI routes can close over names; filled by ensure_runtime_init.
AGENT_ID: str | None = None
AGENT_CONFIG: dict = {}
LOGSTASH_PATHS: dict = {}
PIPELINES_YML_PATH = ''
PIPELINES_DIR = ''
METADATA_DIR = ''
_RUNTIME_READY = False

# Load agent configuration
# Check for config in current directory first (native mode)
def get_config_path() -> str:
    """
    Resolve logstash-agent.yml for this process.

    Priority: LOGSTASH_AGENT_CONFIG env → multi-instance path from --mode/--instance
    → packaged /etc path → local dev config.
    """
    env_cfg = (os.environ.get('LOGSTASH_AGENT_CONFIG') or '').strip()
    if env_cfg:
        return env_cfg
    mode, instance = agent_state._peek_mode_and_instance_from_argv()
    if mode in ('managed', 'simulate') and instance is not None:
        try:
            return str(agent_state.instance_config_path(mode, instance))
        except ValueError:
            pass
    packaged = "/opt/logstash-agent/config/logstash-agent.yml"
    if os.path.exists(packaged):
        return packaged
    legacy = "/etc/logstash-agent/logstash-agent.yml"
    if os.path.exists(legacy):
        return legacy
    return os.path.join(os.path.dirname(__file__), "config/logstashagent.yml")

CONFIG_PATH = get_config_path()

def load_agent_config() -> dict:
    """Load logstashagent.yml configuration, with fallback to logstashui.yml or logstashui.example.yml if mounted"""
    # Prefer process-specific config (instance or packaged), then legacy paths
    for candidate in (
        get_config_path(),
        os.environ.get('LOGSTASH_AGENT_CONFIG') or '',
        "/opt/logstash-agent/config/logstash-agent.yml",
        "/etc/logstash-agent/logstash-agent.yml",
    ):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            with open(candidate, 'r') as f:
                config = yaml.safe_load(f) or {}
                logger.info(f"Loaded agent config from {candidate}")
                return config
        except Exception as e:
            logger.warning(f"Failed to load config from {candidate}: {e}")

    # Next, try to load from mounted logstashui.yml (preferred), then logstashui.example.yml
    # Check /app first (docker-compose mounts), then /etc (legacy)
    config_paths = [
        "/app/logstashui.yml",
        "/app/logstashui.example.yml",
        "/etc/logstashui.yml",
        "/etc/logstashui.example.yml"
    ]

    for logstashui_config_path in config_paths:
        if os.path.exists(logstashui_config_path):
            try:
                with open(logstashui_config_path, 'r') as f:
                    full_config = yaml.safe_load(f)
                    # logstash_agent is nested under simulation section
                    if full_config and 'simulation' in full_config:
                        simulation_config = full_config['simulation']
                        if 'logstash_agent' in simulation_config:
                            agent_config = simulation_config['logstash_agent'].copy()
                            # Add simulation mode from parent config
                            if 'mode' in simulation_config:
                                agent_config['simulation_mode'] = simulation_config['mode']
                            if 'mode' not in agent_config:
                                agent_config['mode'] = 'simulation'

                            # FORCE embedded mode to use container paths (ignore config file paths)
                            if agent_config.get('simulation_mode') == 'embedded':
                                agent_config['logstash_binary'] = '/usr/share/logstash/bin/logstash'
                                agent_config['logstash_settings'] = '/etc/logstash'
                                agent_config['logstash_log_path'] = '/var/log/logstash'

                            # Only log simulation_mode details when in simulation mode
                            mode = agent_config.get('mode', 'simulation')
                            if mode == 'simulation':
                                sim_mode = agent_config.get('simulation_mode', 'embedded')
                                if sim_mode == 'embedded':
                                    logger.info(f"Loaded agent config from {logstashui_config_path}: simulation_mode=embedded (forced Linux paths)")
                                else:
                                    logger.info(f"Loaded agent config from {logstashui_config_path}: simulation_mode={sim_mode}")
                            else:
                                logger.info(f"Loaded agent config from {logstashui_config_path}")
                            return agent_config
            except Exception as e:
                logger.warning(f"Failed to load config from {logstashui_config_path}: {e}, trying next path")

    # Fallback to logstashagent.yml
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = yaml.safe_load(f)
            mode = config.get('mode', 'simulation')
            if mode == 'simulation':
                logger.info(f"Loaded agent config from {CONFIG_PATH}: simulation_mode={config.get('simulation_mode', 'embedded')}")
            else:
                logger.info(f"Loaded agent config from {CONFIG_PATH}")
            return config
    except FileNotFoundError:
        logger.warning(f"Config file {CONFIG_PATH} not found, using embedded mode defaults")
        return {
            'mode': 'simulation',
            'simulation_mode': 'embedded',
            'logstash_binary': '/usr/share/logstash/bin/logstash',
            'logstash_settings': '/etc/logstash/'
        }
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        raise

def normalize_agent_mode(config: dict) -> dict:
    """
    Normalize legacy mode/simulation_mode into mode:
      packaged | managed | simulate | embedded

    Aliases:
      default | agent -> packaged
      host            -> managed

    Mapping:
      packaged|managed|simulate|embedded          -> first-class
      default|agent                               -> packaged
      host                                        -> managed
      simulation + embedded (or missing)          -> embedded
      simulation + host                           -> simulate
    """
    if not config:
        return {'mode': 'embedded', '_mode_legacy': '(empty config)'}
    config.pop('_mode_legacy', None)

    mode = str(config.get('mode', '') or '').lower()
    sim_mode = str(config.get('simulation_mode', '') or '').lower()

    if mode in FIRST_CLASS_MODES:
        config['mode'] = mode
        return config
    if mode in MODE_ALIASES:
        config['_mode_legacy'] = mode
        config['mode'] = MODE_ALIASES[mode]
        return config
    if mode == 'simulation' or mode == '':
        if sim_mode == 'host':
            config['_mode_legacy'] = 'simulation/host' if mode == 'simulation' else 'host (via simulation_mode)'
            config['mode'] = 'simulate'
        else:
            legacy = 'simulation/embedded' if mode == 'simulation' else (
                f'simulation/{sim_mode}' if sim_mode else 'simulation (defaulted)'
            )
            if mode == '':
                legacy = f'(empty mode; simulation_mode={sim_mode or "embedded"})'
            config['_mode_legacy'] = legacy
            config['mode'] = 'embedded'
        return config
    config['_mode_legacy'] = mode or '(unknown)'
    config['mode'] = 'embedded'
    return config


def log_resolved_agent_mode(mode: str, *, legacy: str | None = None, source: str = 'config') -> None:
    """
    Emit a clear startup line so operators can confirm upgraded default agents
    without re-enrolling. Example:
      mode=default (legacy 'agent' mapped) [config]
    """
    if legacy:
        logger.info(f"mode={mode} (legacy '{legacy}' mapped) [{source}]")
    else:
        logger.info(f"mode={mode} [{source}]")


def is_systemctl_managed_simulate() -> bool:
    """
    True when this process is an enrolled multi-instance agent whose Logstash
    is managed by systemd (``ls-simulate@N`` or ``logstash-managed@N``), not
    by LogstashSupervisor.

    Distinguishes from legacy UI "host mode" which maps to mode=simulate via
    normalize_agent_mode but has no instance_id / unit and still uses supervisor
    Popen.
    """
    state = agent_state.get_state() or {}
    unit = (state.get('logstash_unit') or '') or ''
    if str(unit).startswith('ls-simulate@') or str(unit).startswith('logstash-managed@'):
        return True

    mode = (state.get('mode') or (AGENT_CONFIG or {}).get('mode') or '').lower()
    instance_id = state.get('instance_id')
    if instance_id is None:
        instance_id = (AGENT_CONFIG or {}).get('instance_id')

    if mode in ('simulate', 'managed') and instance_id is not None:
        return True

    policy_type = (state.get('policy_type') or '').upper()
    if policy_type == 'DEFAULT':
        policy_type = 'PACKAGED'
    if state.get('enrolled') and policy_type in ('SIMULATE', 'MANAGED') and instance_id is not None:
        return True

    return False


# Alias preferred name (simulate + managed)
is_systemctl_managed_logstash = is_systemctl_managed_simulate


def sim_logstash_api_port() -> int:
    """HTTP API port for the Logstash instance this agent manages."""
    state = agent_state.get_state() or {}
    for key in ('logstash_api_port', 'api_port'):
        if state.get(key) is not None:
            try:
                return int(state[key])
            except (TypeError, ValueError):
                pass
    instance_id = state.get('instance_id')
    if instance_id is None:
        instance_id = (AGENT_CONFIG or {}).get('instance_id')
    mode = (state.get('mode') or (AGENT_CONFIG or {}).get('mode') or '').lower()
    if instance_id is not None:
        try:
            n = int(instance_id)
            if mode == 'managed':
                return 9700 + n
            return 9560 + n
        except (TypeError, ValueError):
            pass
    return int((AGENT_CONFIG or {}).get('logstash_api_port') or 9560)


# Restart counter for systemctl-managed simulate (supervisor has its own)
_sim_systemctl_restart_count = 0

# Monotonic timestamp of when the systemctl-managed simulate Logstash last became
# healthy (None until the first healthy probe after start/restart).  The supervisor
# tracks the equivalent value for embedded mode via _healthy_since.
_sim_systemctl_healthy_since: float | None = None


def check_sim_logstash_health() -> dict:
    """
    Health for simulation endpoints.

    - Systemctl-managed simulate: probe Logstash HTTP API (and fall back to :9449).
    - Embedded / legacy host supervisor: use supervisor process flags.
    """
    if is_systemctl_managed_simulate():
        port = sim_logstash_api_port()
        healthy = False
        try:
            resp = requests.get(f'http://127.0.0.1:{port}/', timeout=2)
            healthy = resp.status_code < 500
        except Exception:
            try:
                # Input plugin may answer even if node API is slow
                requests.get('http://127.0.0.1:9449', timeout=1)
                healthy = True
            except Exception:
                healthy = False
        return {
            'healthy': healthy,
            'restarting': False,
            'restart_count': _sim_systemctl_restart_count,
            'via': 'systemctl',
            'logstash_api_port': port,
        }

    supervisor = logstash_supervisor.get_supervisor()
    if supervisor:
        return {
            'healthy': bool(supervisor.is_healthy),
            'restarting': bool(supervisor.is_restarting),
            'restart_count': supervisor.restart_count,
            'via': 'supervisor',
        }
    return {
        'healthy': False,
        'restarting': False,
        'restart_count': 0,
        'via': 'none',
    }


# How long after Logstash first becomes healthy we wait before accepting slot
# allocations.  The Logstash pipeline bus can lag several seconds behind the
# HTTP API becoming responsive; allocations during this window produce pipelines
# that start and silently terminate in ~172ms, leaving a dead bus address.
PIPELINE_BUS_WARMUP_SECONDS = 15.0


def _get_logstash_healthy_duration() -> float | None:
    """
    Return how many seconds Logstash has been continuously healthy since its
    last start or restart, or None if it has never been healthy in this session.

    For embedded mode: reads from the supervisor's ``_healthy_since`` timestamp.
    For systemctl-managed simulate: reads the module-level ``_sim_systemctl_healthy_since``.

    NOTE: intentionally does NOT call get_supervisor() — that lazily creates a
    supervisor even for systemctl-managed instances, which would always return None
    and prevent the systemctl path from ever being reached.
    """
    # Systemctl-managed simulate has no in-process supervisor; use module-level var.
    if is_systemctl_managed_simulate():
        if _sim_systemctl_healthy_since is None:
            return None
        return time.monotonic() - _sim_systemctl_healthy_since

    # Embedded / legacy host: read directly from the existing supervisor instance
    # without creating one (get_supervisor() would lazily instantiate a fresh one).
    supervisor = logstash_supervisor._supervisor
    if supervisor is None or supervisor._healthy_since is None:
        return None
    return time.monotonic() - supervisor._healthy_since


def trigger_sim_logstash_restart(reason: str = 'Manual restart') -> bool:
    """
    Restart Logstash for sim failure recovery.

    Systemctl-managed simulate: bare recovery (quarantine slot pipelines,
    re-seed simulate-start/end harness, bare pipelines.yml) then
    ``systemctl restart ls-simulate@N``.

    Embedded / legacy host: in-process supervisor restart (still clears slots).
    """
    global _sim_systemctl_restart_count, _sim_systemctl_healthy_since
    if is_systemctl_managed_simulate():
        logger.warning(
            "Simulate recovery restart (bare pipelines + systemctl): %s", reason
        )
        # Clear healthy timestamp so the warmup gate rearms after the restart.
        _sim_systemctl_healthy_since = None
        from logstashagent import simulate_recovery

        result = simulate_recovery.recover_simulate_logstash(
            reason=reason,
            restart=True,
            agent_config=AGENT_CONFIG,
        )
        ok = bool(result.get('success') and result.get('restarted'))
        if ok:
            _sim_systemctl_restart_count += 1
        elif result.get('denied'):
            logger.error("Simulate recovery denied: %s", result.get('error'))
        return ok

    # Embedded / legacy host supervisor path — clear slots before process restart
    try:
        if not _SKIP_SIMULATION_IMPORTS:
            slots.evict_all_slots_and_cleanup()
    except Exception as e:
        logger.warning("Slot cleanup before supervisor restart failed: %s", e)
    logstash_supervisor.trigger_restart(reason)
    return True


def force_kill_simulate_logstash_jvm(*, reason: str = "") -> dict:
    """
    SIGKILL the Logstash JVM for this simulate unit (stuck bus workers never drain).

    Uses ``systemctl show -p MainPID`` for ``ls-simulate@N`` / managed unit, then
    ``kill -9``. Graceful stop is useless once AbstractPipelineBus is retrying
    forever on simulate-start.

    Returns:
        dict with unit, pid(s) killed, and any errors (best-effort).
    """
    import subprocess

    out: dict[str, Any] = {
        "unit": None,
        "pids_killed": [],
        "errors": [],
        "reason": reason,
    }
    try:
        unit = controller._logstash_unit_name()
        out["unit"] = unit
    except Exception as e:
        out["errors"].append(f"unit name: {e}")
        logger.error("force_kill: cannot resolve logstash unit: %s", e)
        return out

    try:
        from logstashagent.installer import host_subprocess_env, _systemctl_bin

        env = host_subprocess_env()
        systemctl = _systemctl_bin()
    except Exception:
        env = os.environ.copy()
        systemctl = "systemctl"

    pid = 0
    try:
        show = subprocess.run(
            ["sudo", systemctl, "show", unit, "-p", "MainPID", "--value"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=env,
        )
        raw = (show.stdout or "").strip()
        if show.returncode != 0:
            out["errors"].append(
                f"systemctl show MainPID failed: {(show.stderr or show.stdout or '')[:200]}"
            )
        elif raw.isdigit():
            pid = int(raw)
    except Exception as e:
        out["errors"].append(f"MainPID lookup: {e}")
        logger.error("force_kill: MainPID lookup failed for %s: %s", unit, e)

    if pid > 1:
        logger.error(
            "Bus storm CORRECTION: kill -9 Logstash JVM pid=%s unit=%s reason=%s",
            pid,
            unit,
            reason or "unspecified",
        )
        try:
            kill = subprocess.run(
                ["sudo", "kill", "-9", str(pid)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env=env,
            )
            if kill.returncode == 0:
                out["pids_killed"].append(pid)
            else:
                # Process may already be gone
                err = (kill.stderr or kill.stdout or "").strip()
                out["errors"].append(f"kill -9 {pid}: rc={kill.returncode} {err[:120]}")
                logger.warning(
                    "kill -9 %s returned rc=%s (%s)", pid, kill.returncode, err[:120]
                )
                # Still record as attempted
                out["pids_killed"].append(pid)
        except Exception as e:
            out["errors"].append(f"kill -9 {pid}: {e}")
            logger.error("force_kill: kill -9 %s failed: %s", pid, e)
    else:
        msg = f"no live MainPID for {unit} (got {pid!r})"
        out["errors"].append(msg)
        logger.warning("force_kill: %s — will still systemctl restart", msg)

    return out


def trigger_sim_logstash_hard_restart(reason: str = "bus storm hard restart") -> bool:
    """
    Clear stuck simulate-start send_to workers: kill -9 JVM, then bare recovery
    + systemctl restart (or supervisor restart for embedded).

    Stuck AbstractPipelineBus retries do not drain even when the destination
    pipeline is listed — only killing the process clears them.
    """
    global _sim_systemctl_restart_count, _sim_systemctl_healthy_since

    logger.error(
        "Simulate HARD restart (kill -9 JVM + recovery/restart): %s", reason
    )

    if is_systemctl_managed_simulate():
        # Clear healthy timestamp so the warmup gate rearms after the hard restart.
        _sim_systemctl_healthy_since = None
        kill_info = force_kill_simulate_logstash_jvm(reason=reason)
        logger.error(
            "force_kill result: unit=%s pids=%s errors=%s",
            kill_info.get("unit"),
            kill_info.get("pids_killed"),
            kill_info.get("errors"),
        )
        # Brief pause so systemd notices the dead MainPID before restart
        time.sleep(1.0)
        from logstashagent import simulate_recovery

        result = simulate_recovery.recover_simulate_logstash(
            reason=reason,
            restart=True,
            agent_config=AGENT_CONFIG,
        )
        ok = bool(result.get("success") and result.get("restarted"))
        if ok:
            _sim_systemctl_restart_count += 1
            logger.error(
                "Simulate HARD restart complete (unit=%s killed=%s)",
                kill_info.get("unit"),
                kill_info.get("pids_killed"),
            )
        elif result.get("denied"):
            logger.error(
                "Simulate HARD restart recovery denied: %s", result.get("error")
            )
        else:
            logger.error(
                "Simulate HARD restart incomplete: %s",
                result.get("error") or result,
            )
        return ok

    # Embedded supervisor: force-kill process group if we have a live process
    try:
        supervisor = logstash_supervisor.get_supervisor()
        if supervisor and getattr(supervisor, "process", None):
            proc = supervisor.process
            if proc.poll() is None:
                pid = proc.pid
                logger.error(
                    "Embedded HARD restart: kill -9 supervisor Logstash pid=%s", pid
                )
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
                except Exception as e:
                    logger.warning("Embedded kill -9 %s failed: %s", pid, e)
    except Exception as e:
        logger.warning("Embedded hard-kill path failed: %s", e)

    try:
        if not _SKIP_SIMULATION_IMPORTS:
            slots.evict_all_slots_and_cleanup()
    except Exception as e:
        logger.warning("Slot cleanup before embedded hard restart failed: %s", e)
    logstash_supervisor.trigger_restart(reason)
    return True


# ---------------------------------------------------------------------------
# Pipeline-bus retry storm policy (simulate instances only)
#
# simulate-start send_to => slotN-filterM. When the bus address is unavailable,
# Logstash WARNs ~1/s and retries *forever* — even if list_pipelines() still
# shows the dest. Stuck workers do NOT drain. For simulate instances we
# kill -9 the Logstash JVM + systemctl restart after deliberate confirmation.
# ---------------------------------------------------------------------------
# How many identical "address was unavailable" WARNs in the lookback window
# count as a storm (not a brief cold-start blip).
BUS_STORM_MIN_WARN_COUNT = 15
# Lookback window for those WARNs (seconds).
BUS_STORM_WINDOW_SECONDS = 30.0
# How many successive watchdog/cleanup scans must still see an *actionable*
# storm before we hard-restart (~3 × 10s watchdog ≈ 30s of confirmed stuck).
BUS_STORM_CONFIRMATIONS = 3
# Do not hard-restart while a slot is mid cold-allocate (brief bus WARNs expected).
BUS_STORM_ALLOCATE_GRACE_SECONDS = 90.0
# Post-restart cool-down inside the watchdog loop.
BUS_STORM_POST_RESTART_COOLDOWN_SECONDS = 60.0

# consecutive actionable confirmations per destination
_bus_storm_hits: dict[str, int] = {}


def _sim_log_dir() -> str:
    """Logstash JSON log directory for this agent instance."""
    try:
        st = agent_state.get_state() or {}
    except Exception:
        st = {}
    return log_analyzer.resolve_logstash_log_dir(
        logstash_log_path=(AGENT_CONFIG or {}).get("logstash_log_path"),
        logs_path=st.get("logs_path"),
    )


def _is_simulate_instance_for_bus_recovery() -> bool:
    """
    True when hard-restarting *this* Logstash for a bus storm is acceptable.

    Simulate (and embedded sim) instances are disposable for this purpose.
    Packaged / managed production units are not restarted for bus storms.
    """
    if is_systemctl_managed_simulate():
        return True
    mode = str((AGENT_CONFIG or {}).get("mode") or "").lower()
    if mode in ("simulate", "simulation", "embedded"):
        return True
    try:
        st = agent_state.get_state() or {}
        if str(st.get("mode") or "").lower() in ("simulate", "simulation", "embedded"):
            return True
        if str(st.get("policy_type") or "").upper() == "SIMULATE":
            return True
    except Exception:
        pass
    return False


def _bus_storm_actionable(storm: dict) -> tuple[bool, str]:
    """
    Decide whether a detected storm should escalate toward hard restart.

    IMPORTANT: Do **not** hold because the destination is ``list_pipelines()``
    membership. Stuck simulate-start workers retry forever even when the dest
    appears listed (bus address unavailable). Holding "until drain" never ends.

    Only hold for cold-allocate races:
    - young booked slot (allocate grace)
    - allocate single-flight still in progress for that slot
    """
    dest = storm.get("destination") or ""
    if not dest:
        return False, "empty destination"

    listed = False
    try:
        with LogstashAPI(timeout=2.0) as api:
            listed = dest in api.list_pipelines()
    except Exception as e:
        logger.debug("bus storm list_pipelines failed: %s", e)
        listed = False

    # slotN-filterM → slot id for grace against mid-allocate races only
    m = re.match(r"^slot(\d+)-filter", dest)
    if not m:
        return True, (
            f"non-slot destination {dest} bus unavailable "
            f"(listed={listed}; workers never drain — hard restart)"
        )

    slot_id = int(m.group(1))
    state = None
    if not _SKIP_SIMULATION_IMPORTS:
        try:
            state = slots.get_slot_state().get(slot_id)
        except Exception:
            state = None

    if state:
        age_s: float | None = None
        created = state.get("created_at")
        if created:
            try:
                created_dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                age_s = (datetime.now(UTC) - created_dt).total_seconds()
            except Exception:
                age_s = None

        content_hash = state.get("content_hash") or ""
        if content_hash and slots.allocate_flight_in_progress(content_hash):
            return False, f"allocate in flight for slot {slot_id}"

        if age_s is not None and age_s < BUS_STORM_ALLOCATE_GRACE_SECONDS:
            return (
                False,
                f"slot {slot_id} still in allocate grace "
                f"(age={age_s:.0f}s < {BUS_STORM_ALLOCATE_GRACE_SECONDS:.0f}s)",
            )

        return True, (
            f"stuck send_to {dest} (listed={listed}, slot {slot_id} booked"
            + (f", age={age_s:.0f}s" if age_s is not None else "")
            + "; workers never drain — hard restart)"
        )

    return True, (
        f"stuck send_to {dest} (listed={listed}, slot not booked; "
        "workers never drain — hard restart)"
    )


def handle_pipeline_bus_retry_storms(
    *,
    log_dir: str | None = None,
    min_consecutive: int | None = None,
    min_warn_count: int | None = None,
    window_seconds: float | None = None,
    _hits: dict | None = None,
) -> bool:
    """
    Detect pipeline-bus retry storms and, on a *simulate* instance, hard-restart
    this Logstash after enough consecutive confirmations.

    Policy (deliberate, not hair-trigger):
      1. DETECT — ≥ BUS_STORM_MIN_WARN_COUNT identical "address was unavailable"
         WARNs in BUS_STORM_WINDOW_SECONDS (default 15 in 30s).
      2. CONFIRM — same dest still storming / not mid-allocate for
         BUS_STORM_CONFIRMATIONS successive scans (default 3 ≈ 30s watchdog).
         Destination being ``list_pipelines()``-listed does **not** clear the
         storm (stuck workers never drain).
      3. CORRECT — release orphan slots, ``kill -9`` Logstash JVM, bare recovery
         + ``systemctl restart`` of *this* simulate unit.

    Logs each step: detection, confirmation progress, and course of correction.

    Returns:
        True if hard restart was triggered.
    """
    confirmations_needed = (
        BUS_STORM_CONFIRMATIONS if min_consecutive is None else min_consecutive
    )
    warn_threshold = (
        BUS_STORM_MIN_WARN_COUNT if min_warn_count is None else min_warn_count
    )
    lookback_s = (
        BUS_STORM_WINDOW_SECONDS if window_seconds is None else window_seconds
    )

    if _hits is None:
        global _bus_storm_hits
        hits_map = _bus_storm_hits
    else:
        hits_map = _hits

    directory = log_dir or _sim_log_dir()
    try:
        storms = log_analyzer.detect_pipeline_bus_retry_storms(
            log_dir=directory,
            window_seconds=lookback_s,
            min_count=warn_threshold,
        )
    except Exception as e:
        logger.debug("bus storm scan failed: %s", e)
        return False

    if not storms:
        if hits_map:
            logger.info(
                "Bus storm: cleared — no sustained 'address was unavailable' "
                "loop in last %.0fs (was tracking %s)",
                lookback_s,
                ", ".join(sorted(hits_map.keys())),
            )
        hits_map.clear()
        return False

    simulate_ok = _is_simulate_instance_for_bus_recovery()
    actionable: list[tuple[dict, str]] = []
    seen_dests: set[str] = set()

    for storm in storms:
        dest = storm.get("destination") or ""
        seen_dests.add(dest)
        count = storm.get("count") or 0
        span = float(storm.get("span_seconds") or 0.0)
        source = storm.get("source_pipeline") or "?"

        # --- DETECTION (always log; this is the signal we watch for) ---
        logger.warning(
            "Bus storm DETECTED: dest=%s warn_count=%s (threshold=%s) "
            "span=%.1fs window=%.0fs source=%s — AbstractPipelineBus is "
            "retrying send_to forever while destination is unavailable",
            dest,
            count,
            warn_threshold,
            span,
            lookback_s,
            source,
        )

        ok, why = _bus_storm_actionable(storm)
        if not ok:
            hits_map.pop(dest, None)
            logger.info(
                "Bus storm HOLD (no restart yet): dest=%s — %s",
                dest,
                why,
            )
            continue

        hits_map[dest] = hits_map.get(dest, 0) + 1
        conf = hits_map[dest]
        actionable.append((storm, why))

        if conf < confirmations_needed:
            logger.warning(
                "Bus storm CONFIRMING: dest=%s confirmation=%s/%s reason=%s — "
                "will kill -9 + systemctl restart this simulate Logstash after "
                "%s consecutive confirmations (avoids thrash on allocate races)",
                dest,
                conf,
                confirmations_needed,
                why,
                confirmations_needed,
            )
        else:
            logger.error(
                "Bus storm CONFIRMED stuck: dest=%s confirmation=%s/%s reason=%s",
                dest,
                conf,
                confirmations_needed,
                why,
            )

    # Drop counters for destinations no longer storming
    for dest in list(hits_map.keys()):
        if dest not in seen_dests:
            logger.info(
                "Bus storm cleared for dest=%s (no longer in log window)", dest
            )
            del hits_map[dest]

    ready = [
        (storm, why)
        for storm, why in actionable
        if hits_map.get(storm.get("destination") or "", 0) >= confirmations_needed
    ]
    if not ready:
        return False

    summary = "; ".join(
        f"{s.get('destination')}×{s.get('count')} warns ({why})" for s, why in ready
    )

    if not simulate_ok:
        logger.error(
            "Bus storm CORRECTION withheld: not a simulate instance — "
            "manual intervention required for: %s",
            summary,
        )
        # Do not keep ratcheting forever on non-sim
        for storm, _ in ready:
            hits_map.pop(storm.get("destination") or "", None)
        return False

    # --- CORRECTION: kill -9 JVM (workers never drain) + bare recovery + restart ---
    logger.error(
        "Bus storm CORRECTION: kill -9 Logstash JVM + systemctl restart on *this* "
        "simulate instance (stuck send_to workers never drain, listed or not). "
        "detail=%s confirmations_required=%s warn_threshold=%s/%.0fs",
        summary,
        confirmations_needed,
        warn_threshold,
        lookback_s,
    )

    if not _SKIP_SIMULATION_IMPORTS:
        for storm, _why in ready:
            dest = storm.get("destination") or ""
            m = re.match(r"^slot(\d+)-filter", dest)
            if not m:
                continue
            try:
                released = slots.release_slot(int(m.group(1)), cleanup_pipelines=True)
                logger.info(
                    "Bus storm CORRECTION: released slot %s for dest=%s (existed=%s)",
                    m.group(1),
                    dest,
                    released,
                )
            except Exception as e:
                logger.warning(
                    "Bus storm CORRECTION: could not release slot for %s: %s",
                    dest,
                    e,
                )

    ok = trigger_sim_logstash_hard_restart(f"pipeline bus retry storm: {summary}")
    if ok:
        logger.error(
            "Bus storm CORRECTION complete: hard-restarted simulate Logstash "
            "for stuck send_to loop (%s)",
            summary,
        )
    else:
        logger.error(
            "Bus storm CORRECTION failed: hard restart did not complete for "
            "stuck send_to loop (%s) — will re-detect on next scan "
            "(recovery may be rate-limited)",
            summary,
        )
    hits_map.clear()
    return ok


def _simulate_watchdog_loop():
    """
    Background probe for simulate Logstash.

    1. Pipeline-bus retry storms (API can stay healthy while send_to loops)
    2. Systemctl-managed: consecutive HTTP unhealthy → bare recovery + restart
    """
    failures = 0
    while True:
        try:
            time.sleep(10)

            # Stuck send_to loops do not fail HTTP health — scan logs and, after
            # deliberate confirmations, restart *this* simulate Logstash unit.
            try:
                if handle_pipeline_bus_retry_storms():
                    failures = 0
                    time.sleep(BUS_STORM_POST_RESTART_COOLDOWN_SECONDS)
                    continue
            except Exception as e:
                logger.error("Bus storm watchdog check failed: %s", e, exc_info=True)

            if not is_systemctl_managed_simulate():
                failures = 0
                continue
            health = check_sim_logstash_health()
            if health.get('healthy'):
                global _sim_systemctl_healthy_since
                if _sim_systemctl_healthy_since is None:
                    _sim_systemctl_healthy_since = time.monotonic()
                failures = 0
                continue
            # Logstash became unhealthy — reset so the next healthy probe records a fresh timestamp
            _sim_systemctl_healthy_since = None
            failures += 1
            logger.warning(
                "Simulate watchdog: Logstash unhealthy (failures=%s via=%s)",
                failures,
                health.get('via'),
            )
            if failures >= 3:
                logger.error(
                    "Simulate watchdog CORRECTION: bare recovery after %s "
                    "consecutive unhealthy checks",
                    failures,
                )
                trigger_sim_logstash_restart(
                    f"watchdog: unhealthy {failures} consecutive checks"
                )
                failures = 0
                time.sleep(60)  # post-recovery cool-down
        except Exception as e:
            logger.error("Simulate watchdog error: %s", e, exc_info=True)
            time.sleep(15)


def _atexit_shutdown_supervisor():
    """Do not stop systemctl-managed Logstash on agent exit."""
    if is_systemctl_managed_simulate():
        return
    logstash_supervisor.shutdown_supervisor()


app = FastAPI(title="logstashagent API", version="0.0.1")

# Request queue for simulation requests during Logstash restarts
_simulation_queue: deque = deque(maxlen=100)  # Max 100 queued requests
_queue_lock = threading.Lock()
_queue_processor_task: asyncio.Task | None = None

@app.on_event("startup")
async def startup_event():
    """Start Logstash under supervision when FastAPI starts (embedded / legacy host).

    Enrolled simulate agents leave Logstash to systemd (``ls-simulate@N``).
    """
    global _queue_processor_task
    # Process supervisor is embedded-only (Popen). Enrolled simulate uses systemctl + watchdog.
    if is_systemctl_managed_simulate():
        port = sim_logstash_api_port()
        logger.info(
            "FastAPI startup - enrolled simulate; Logstash managed by systemctl "
            "(ls-simulate@) + watchdog; skip embedded supervisor (API port %s)",
            port,
        )
        # Ensure static harness + LOGSTASH_URL for StreamSimulate HTTP outputs
        try:
            from logstashagent import simulate_recovery
            from pathlib import Path as _Path

            settings = simulate_recovery.resolve_settings_path(
                agent_config=AGENT_CONFIG
            )
            simulate_recovery.seed_static_harness(settings, force=False)
            yml = settings / 'pipelines.yml'
            if not yml.is_file():
                simulate_recovery.write_bare_pipelines_yml(settings)
                logger.info("Wrote initial bare pipelines.yml for simulate instance")

            # ls-simulate@N EnvironmentFile must carry LOGSTASH_URL (UI base).
            # Without it, harness confs default to host.docker.internal:8080.
            env_path = None
            try:
                st = agent_state.get_state() or {}
                root = st.get('path_root') or (
                    f"/opt/logstash-agent/simulate-{st.get('instance_id')}"
                    if st.get('instance_id') is not None
                    else None
                )
                if root:
                    env_path = _Path(str(root)) / 'env'
                else:
                    # settings is .../simulate-N/settings → parent/env
                    env_path = settings.parent / 'env'
            except Exception:
                env_path = settings.parent / 'env'
            url_result = simulate_recovery.ensure_logstash_url_in_env(
                env_path, agent_config=AGENT_CONFIG
            )
            if url_result.get('changed'):
                logger.info(
                    "Updated LOGSTASH_URL in %s — restarting Logstash unit to apply",
                    env_path,
                )
                try:
                    _restart_logstash_for_sim()
                except Exception as re:
                    logger.warning(
                        "Could not restart Logstash after LOGSTASH_URL update: %s", re
                    )
            elif url_result.get('ok'):
                logger.info("LOGSTASH_URL for StreamSimulate: %s", url_result.get('url'))
            else:
                logger.warning(
                    "LOGSTASH_URL missing — simulate HTTP outputs will fail to reach UI"
                )
        except Exception as e:
            logger.warning("Could not seed simulate harness on startup: %s", e)
        # Watchdog: bare recovery if Logstash stays unhealthy
        threading.Thread(
            target=_simulate_watchdog_loop,
            name='simulate-watchdog',
            daemon=True,
        ).start()
        logger.info("Simulate watchdog thread started")
    else:
        logger.info("FastAPI startup - initializing Logstash supervisor")
        logstash_supervisor.start_supervised_logstash(config=AGENT_CONFIG)
        # Wait for Logstash to initialize
        await asyncio.sleep(5)
        logger.info("Logstash supervision started")
        # Embedded (and other non-systemctl) agents: retry-fetch product CA until UI is up.
        # Bootstrap GET uses verify=False once; all later UI calls use the pinned CA.
        try:
            from logstashagent import tls_trust

            tls_trust.start_ui_ca_bootstrap_loop(agent_config=AGENT_CONFIG)
        except Exception as e:
            logger.warning("Could not start UI CA bootstrap loop: %s", e)

    # Start queue processor
    _queue_processor_task = asyncio.create_task(_process_simulation_queue())
    logger.info("Simulation queue processor started")

@app.on_event("shutdown")
async def shutdown_event():
    """Stop queue processor; stop supervisor only when we own the Logstash process."""
    global _queue_processor_task
    logger.info("FastAPI shutdown - stopping queue processor")
    if _queue_processor_task:
        _queue_processor_task.cancel()
        try:
            await _queue_processor_task
        except asyncio.CancelledError:
            pass
    if is_systemctl_managed_simulate():
        logger.info(
            "FastAPI shutdown - enrolled simulate; leaving systemctl Logstash running"
        )
    else:
        logger.info("FastAPI shutdown - stopping Logstash supervisor")
        logstash_supervisor.shutdown_supervisor()

# Also register atexit handler for clean shutdown (supervisor-owned Logstash only)
atexit.register(_atexit_shutdown_supervisor)

# Configuration paths - dynamically set based on mode
def get_logstash_paths():
    """Get Logstash paths based on configuration (Docker vs native)"""
    logstash_settings = AGENT_CONFIG.get('logstash_settings', '/etc/logstash/')

    # Ensure settings path ends with /
    if not logstash_settings.endswith('/') and not logstash_settings.endswith('\\'):
        logstash_settings += '/'

    # Normalize to forward slashes for consistency
    logstash_settings = logstash_settings.replace('\\', '/')

    return {
        'pipelines_yml': f"{logstash_settings}pipelines.yml",
        'conf_d': f"{logstash_settings}conf.d",
        'metadata': f"{logstash_settings}pipeline-metadata"
    }


def get_logstash_log_dir() -> str:
    """
    Directory with logstash-json*.log for this agent process.

    Packaged/embedded: usually /var/log/logstash.
    simulate-N / managed-N: /opt/logstash-agent/{role}-N/logs (from yml/state/env).
    """
    logs_path = None
    try:
        from logstashagent import agent_state

        logs_path = agent_state.get_state().get("logs_path")
    except Exception:
        pass
    log_dir = log_analyzer.resolve_logstash_log_dir(
        logstash_log_path=AGENT_CONFIG.get("logstash_log_path"),
        logs_path=logs_path,
    )
    return log_dir


def ensure_runtime_init(*, create_pipeline_dirs: bool = True) -> None:
    """Load config, agent_id, and pipeline dirs. No-op if already initialized."""
    global AGENT_ID, AGENT_CONFIG, LOGSTASH_PATHS
    global PIPELINES_YML_PATH, PIPELINES_DIR, METADATA_DIR, _RUNTIME_READY
    if _RUNTIME_READY:
        return
    agent_state.refresh_state_paths()
    AGENT_ID = agent_state.get_or_create_agent_id()
    agent_state.update_state('agent_version', AGENT_VERSION)
    logger.info(f"LogstashAgent version: {AGENT_VERSION}")
    logger.info(f"Agent state dir: {agent_state.STATE_DIR}")
    AGENT_CONFIG = normalize_agent_mode(load_agent_config())
    if AGENT_CONFIG.get('_mode_legacy'):
        log_resolved_agent_mode(
            AGENT_CONFIG.get('mode', 'embedded'),
            legacy=AGENT_CONFIG.get('_mode_legacy'),
            source='config',
        )
    else:
        log_resolved_agent_mode(AGENT_CONFIG.get('mode', 'embedded'), source='config')
    LOGSTASH_PATHS = get_logstash_paths()
    PIPELINES_YML_PATH = LOGSTASH_PATHS['pipelines_yml']
    PIPELINES_DIR = LOGSTASH_PATHS['conf_d']
    METADATA_DIR = LOGSTASH_PATHS['metadata']
    if create_pipeline_dirs:
        os.makedirs(PIPELINES_DIR, exist_ok=True)
        os.makedirs(METADATA_DIR, exist_ok=True)
    _RUNTIME_READY = True


if not _LIGHTWEIGHT_CLI:
    ensure_runtime_init(create_pipeline_dirs=True)


def _validate_pipeline_id(pipeline_id: str) -> None:
    """
    Validate pipeline_id to prevent path traversal attacks.

    Args:
        pipeline_id: The pipeline ID to validate

    Raises:
        HTTPException: If pipeline_id contains unsafe characters
    """
    # Allow only alphanumeric, hyphens, underscores, and dots
    # This prevents path traversal with ../ or absolute paths
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', pipeline_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid pipeline_id: must contain only alphanumeric characters, hyphens, underscores, and dots"
        )

    # Additional check: prevent .. sequences even if they pass regex
    if '..' in pipeline_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid pipeline_id: cannot contain '..' sequences"
        )

    # Prevent starting with dot (hidden files) or hyphen
    if pipeline_id.startswith('.') or pipeline_id.startswith('-'):
        raise HTTPException(
            status_code=400,
            detail="Invalid pipeline_id: cannot start with '.' or '-'"
        )


def _load_pipelines_yml() -> list:
    """Load the pipelines.yml file"""
    if not os.path.exists(PIPELINES_YML_PATH):
        return []

    try:
        with open(PIPELINES_YML_PATH, 'r') as f:
            content = f.read()
            # Handle empty or comment-only files
            if not content.strip() or all(line.strip().startswith('#') for line in content.split('\n') if line.strip()):
                return []
            pipelines = yaml.safe_load(content)
            return pipelines if pipelines else []
    except Exception as e:
        logger.error(f"Error loading pipelines.yml: {e}")
        return []


def _save_pipelines_yml(pipelines: list):
    """Save the pipelines.yml file atomically, ensuring static pipelines are preserved"""
    # Get logstash settings path from config
    logstash_settings = AGENT_CONFIG.get('logstash_settings', '/etc/logstash/')

    # Detect OS and handle path separators appropriately
    is_windows = os.name == 'nt'

    if is_windows:
        # Windows: Ensure path ends with backslash, then escape for YAML
        if not logstash_settings.endswith('/') and not logstash_settings.endswith('\\'):
            logstash_settings += '\\'
        # YAML requires backslashes to be escaped, so C:\path becomes C:\\path
        yaml_path = logstash_settings.replace('\\', '\\\\')
        path_sep = '\\\\'
    else:
        # Linux/Docker: Use forward slashes (no escaping needed)
        if not logstash_settings.endswith('/'):
            logstash_settings += '/'
        yaml_path = logstash_settings
        path_sep = '/'

    # Define static pipelines that must always be present
    # Static pipeline .conf files are in config/config/ subdirectory
    static_pipelines = [
        {
            'pipeline.id': 'simulate-start',
            'pipeline.workers': 1,
            'path.config': f'{yaml_path}config{path_sep}simulate_start.conf'
        },
        {
            'pipeline.id': 'simulate-end',
            'pipeline.workers': 1,
            'path.config': f'{yaml_path}config{path_sep}simulate_end.conf'
        }
    ]

    # Remove any existing static pipeline entries from the input list
    static_ids = {'simulate-start', 'simulate-end'}
    dynamic_pipelines = [p for p in pipelines if p.get('pipeline.id') not in static_ids]

    # Combine static pipelines (first) with dynamic pipelines
    final_pipelines = static_pipelines + dynamic_pipelines

    temp_path = f"{PIPELINES_YML_PATH}.tmp"
    try:
        with open(temp_path, 'w') as f:
            yaml.dump(final_pipelines, f, default_flow_style=False, sort_keys=False)
        os.replace(temp_path, PIPELINES_YML_PATH)
        logger.debug(f"Saved pipelines.yml with {len(static_pipelines)} static + {len(dynamic_pipelines)} dynamic pipelines")
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e


def delete_pipeline_internal(pipeline_id: str) -> bool:
    """
    Delete a pipeline directly without going through the HTTP API.
    This is used by slots.py to avoid HTTP overhead during cleanup.

    Args:
        pipeline_id: The pipeline ID to delete

    Returns:
        True if deleted successfully, False if not found or error occurred
    """
    try:
        _validate_pipeline_id(pipeline_id)

        # Load existing pipelines
        pipelines = _load_pipelines_yml()

        # Find and remove the pipeline
        pipeline_found = False
        config_path = None
        new_pipelines = []

        for pipeline in pipelines:
            if pipeline.get('pipeline.id') == pipeline_id:
                pipeline_found = True
                config_path = pipeline.get('path.config')
            else:
                new_pipelines.append(pipeline)

        if not pipeline_found:
            return False

        # Delete pipeline config file
        if config_path and os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception as e:
                logger.error(f"Failed to delete pipeline config {config_path}: {e}")
                return False

        # Delete metadata file
        metadata_path = os.path.join(METADATA_DIR, f"{pipeline_id}.json")
        if os.path.exists(metadata_path):
            try:
                os.remove(metadata_path)
            except Exception:
                pass  # Non-critical if metadata deletion fails

        # Save updated pipelines.yml
        try:
            _save_pipelines_yml(new_pipelines)
        except Exception as e:
            logger.error(f"Failed to update pipelines.yml: {e}")
            return False

        return True
    except Exception as e:
        logger.error(f"Error deleting pipeline {pipeline_id}: {e}")
        return False


def _load_pipeline_config(pipeline_id: str) -> str | None:
    """Load the pipeline configuration file(s) - supports wildcards"""
    pipelines = _load_pipelines_yml()

    for pipeline in pipelines:
        if pipeline.get('pipeline.id') == pipeline_id:
            config_path = pipeline.get('path.config')
            if not config_path:
                continue

            # Check if path contains wildcards
            if '*' in config_path or '?' in config_path:
                # Expand wildcards and read all matching files
                matching_files = sorted(glob.glob(config_path))
                if not matching_files:
                    return None

                # Concatenate all matching files
                config_parts = []
                for file_path in matching_files:
                    try:
                        with open(file_path, 'r') as f:
                            config_parts.append(f.read())
                    except Exception as e:
                        logger.error(f"Error reading {file_path}: {e}")
                        continue

                return '\n'.join(config_parts) if config_parts else None
            else:
                # Single file path
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        return f.read()
    return None


def _load_pipeline_metadata(pipeline_id: str) -> dict[str, Any]:
    """Load pipeline metadata (description, settings, etc.)"""
    _validate_pipeline_id(pipeline_id)
    metadata_path = os.path.join(METADATA_DIR, f"{pipeline_id}.json")

    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading metadata for pipeline '{pipeline_id}': {e}")

    # Return default metadata if file doesn't exist or failed to load
    return {
        "description": "",
        "last_modified": datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "pipeline_metadata": {
            "type": "logstash_pipeline",
            "version": 1
        },
        "username": "logstashagent",
        "pipeline_settings": {
            "pipeline.workers": 1,
            "pipeline.batch.size": 125,
            "pipeline.batch.delay": 50,
            "queue.type": "memory",
            "queue.max_bytes": "1gb",
            "queue.checkpoint.writes": 1024
        }
    }


def _save_pipeline_metadata(pipeline_id: str, metadata: dict[str, Any]):
    """Save pipeline metadata"""
    _validate_pipeline_id(pipeline_id)
    metadata_path = os.path.join(METADATA_DIR, f"{pipeline_id}.json")
    temp_path = f"{metadata_path}.tmp"

    try:
        with open(temp_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        os.replace(temp_path, metadata_path)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e


def _get_pipeline_settings_from_yml(pipeline_id: str) -> dict[str, Any]:
    """Extract pipeline settings from pipelines.yml"""
    _validate_pipeline_id(pipeline_id)
    pipelines = _load_pipelines_yml()
    settings = {}

    for pipeline in pipelines:
        if pipeline.get('pipeline.id') == pipeline_id:
            # Extract all pipeline.* and queue.* settings
            for key, value in pipeline.items():
                if key.startswith('pipeline.') or key.startswith('queue.'):
                    settings[key] = value
            break

    return settings


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "name": "logstashagent",
        "version": AGENT_VERSION,
        "status": "running"
    }


async def _process_simulation_queue():
    """
    Background task that processes queued simulation requests when Logstash becomes healthy.
    """
    logger.info("Queue processor started")
    last_healthy_time = None

    while True:
        try:
            await asyncio.sleep(2)  # Check every 2 seconds

            health = check_sim_logstash_health()
            if not health.get('healthy'):
                last_healthy_time = None
                continue

            # Track when Logstash became healthy
            if last_healthy_time is None:
                last_healthy_time = time.time()
                logger.info(
                    "Logstash became healthy (via=%s), waiting 10s for full "
                    "initialization before processing queue",
                    health.get('via'),
                )
                continue

            # Wait at least 10 seconds after Logstash becomes healthy before processing
            time_since_healthy = time.time() - last_healthy_time
            if time_since_healthy < 10:
                continue

            # Verify Logstash port 9449 is actually ready before processing queue
            try:
                test_response = requests.get("http://127.0.0.1:9449", timeout=2)
            except Exception:
                logger.debug("Logstash port 9449 not ready yet, waiting...")
                continue

            # Process all queued requests
            while True:
                queued_item = None
                with _queue_lock:
                    if _simulation_queue:
                        queued_item = _simulation_queue.popleft()
                    else:
                        break

                if queued_item:
                    log_data = queued_item['log_data']
                    slot_config = queued_item.get('slot_config')

                    logger.info(f"Processing queued simulation: slot={log_data.get('slot')}, run_id={log_data.get('run_id')}")

                    # Restore slot configuration if needed
                    if slot_config:
                        slot_id = slot_config['slot_id']
                        pipeline_name = slot_config['pipeline_name']
                        pipelines = slot_config['pipelines']

                        # Re-allocate slot (will reuse if hash matches)
                        try:
                            # Check if slot already exists
                            existing_slots = slots.get_slot_state()
                            slot_exists = slot_id in existing_slots

                            if not slot_exists:
                                # Allocate slot and create pipelines
                                slots.allocate_slot(pipeline_name, pipelines)
                                await _create_slot_pipelines(slot_id, pipelines)
                                logger.info(f"Restored slot {slot_id} configuration")
                            else:
                                logger.info(f"Slot {slot_id} already exists, skipping restoration")
                        except Exception as e:
                            logger.error(f"Failed to restore slot {slot_id}: {e}")
                            continue

                    # Forward the simulation request with retries
                    max_retries = 3
                    success = False
                    for attempt in range(max_retries):
                        try:
                            timeout = 2 + attempt  # 2s, 3s, 4s
                            response = requests.post(
                                "http://127.0.0.1:9449",
                                json=log_data,
                                timeout=timeout
                            )
                            response.raise_for_status()
                            logger.info(f"Queued simulation processed successfully: slot={log_data.get('slot')}")
                            success = True
                            break
                        except Exception as e:
                            if attempt < max_retries - 1:
                                logger.warning(f"Queued simulation attempt {attempt + 1} failed, retrying: {e}")
                                await asyncio.sleep(1)
                            else:
                                logger.error(f"Failed to process queued simulation after {max_retries} attempts: {e}")

                    if not success:
                        # Re-queue the failed item at the front for retry later
                        with _queue_lock:
                            _simulation_queue.appendleft(queued_item)
                        logger.warning("Re-queued failed simulation for retry later")
                        break  # Stop processing queue, will retry on next iteration

        except asyncio.CancelledError:
            logger.info("Queue processor cancelled")
            break
        except Exception as e:
            logger.error(f"Error in queue processor: {e}", exc_info=True)
            await asyncio.sleep(5)


@app.get("/_logstash/health")
async def logstash_health():
    """
    Check if Logstash is healthy and ready to accept simulation requests.

    Enrolled simulate: Logstash HTTP API (systemctl-managed).
    Embedded / legacy host: in-process supervisor flags.

    Also includes TLS trust indicators (product CA pin / bootstrap) for the UI.
    """
    health = check_sim_logstash_health()
    with _queue_lock:
        queue_size = len(_simulation_queue)

    content = {
        "healthy": health.get("healthy", False),
        "restarting": health.get("restarting", False),
        "restart_count": health.get("restart_count", 0),
        "queued_requests": queue_size,
        "via": health.get("via", "none"),
    }
    if health.get("logstash_api_port") is not None:
        content["logstash_api_port"] = health["logstash_api_port"]

    try:
        from logstashagent import tls_trust

        content["tls"] = tls_trust.get_tls_status()
    except Exception as e:
        content["tls"] = {"secure": False, "error": str(e)}

    return JSONResponse(
        status_code=200 if content["healthy"] else 503,
        content=content,
    )


@app.get("/_logstash/tls-status")
async def tls_status():
    """
    Product CA pin / bootstrap status for UI online+secure indicators.

    Does not require Logstash to be healthy.
    """
    try:
        from logstashagent import tls_trust

        return tls_trust.get_tls_status()
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"secure": False, "ca_pinned": False, "error": str(e)},
        )


@app.post("/_logstash/simulate")
async def simulate_log(request: Request):
    """
    Proxy endpoint for simulation log input.
    Accepts HTTPS requests from logstashui and forwards them to the local HTTP port 9449.

    Queues requests when Logstash is unhealthy and processes them when it recovers.
    """
    try:
        # Get the JSON body from the request
        log_data = await request.json()
        slot_id = log_data.get('slot')

        # Check if Logstash is healthy (supervisor or systemctl-managed simulate)
        is_healthy = bool(check_sim_logstash_health().get('healthy'))

        if not is_healthy:
            # Queue the request with slot configuration for restoration
            slot_config = None
            if slot_id:
                # Get current slot configuration to restore later
                slot_state = slots.get_slot_state()
                if slot_id in slot_state:
                    slot_data = slot_state[slot_id]
                    slot_config = {
                        'slot_id': slot_id,
                        'pipeline_name': slot_data.get('pipeline_name'),
                        'pipelines': slot_data.get('pipelines')
                    }

            with _queue_lock:
                _simulation_queue.append({
                    'log_data': log_data,
                    'slot_config': slot_config,
                    'queued_at': time.time()
                })
                queue_size = len(_simulation_queue)

            logger.warning(f"Logstash unhealthy - queued simulation request (queue size: {queue_size})")
            return JSONResponse(
                status_code=202,
                content={
                    "status": "queued",
                    "message": "Logstash is restarting, request queued for processing",
                    "queue_position": queue_size
                }
            )

        # If a slot is specified, ensure the filter pipeline is on the pipeline bus
        # before forwarding. list_pipelines() alone is not enough — simulate-start
        # send_to fails with "address was unavailable" until the bus registers it.
        if slot_id is not None:
            target = f"slot{slot_id}-filter1"
            ready = False
            last_state = "unknown"
            ready_since: float | None = None
            bus_hold_s = 1.0  # continuous idle/running before we forward
            for _ in range(40):  # up to ~20s
                try:
                    with LogstashAPI(timeout=2.0) as api:
                        if target not in api.list_pipelines():
                            last_state = "not_listed"
                            ready_since = None
                        else:
                            try:
                                last_state = api.detect_pipeline_state(target)
                            except Exception:
                                last_state = "listed"
                            if last_state in ("idle", "running"):
                                if ready_since is None:
                                    ready_since = time.time()
                                elif time.time() - ready_since >= bus_hold_s:
                                    ready = True
                                    break
                            else:
                                # listed but not idle/running yet
                                ready_since = None
                except Exception:
                    ready_since = None
                await asyncio.sleep(0.5)
            if not ready:
                logger.warning(
                    "Slot pipeline %s not bus-ready (last_state=%s); "
                    "forwarding anyway (may log address unavailable / empty snapshots)",
                    target,
                    last_state,
                )
            else:
                logger.info(
                    "Slot pipeline %s ready for simulate (state=%s)",
                    target,
                    last_state,
                )

        # Logstash is healthy - forward immediately with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                timeout = 1 + attempt  # 1s, 2s, 3s - aggressive timeouts to detect hung Logstash
                logger.debug(f"Simulation attempt {attempt + 1}/{max_retries}, timeout={timeout}s")

                # Forward to local Logstash HTTP input on port 9449
                response = requests.post(
                    "http://127.0.0.1:9449",
                    json=log_data,
                    timeout=timeout
                )
                response.raise_for_status()

                logger.info(
                    f"Forwarded simulation log to Logstash: slot={slot_id}, run_id={log_data.get('run_id')}")

                return JSONResponse(
                    status_code=200,
                    content={"status": "success", "message": "Log forwarded to Logstash"}
                )

            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    logger.warning(f"Simulation timeout on attempt {attempt + 1}, retrying...")
                    await asyncio.sleep(1)
                    continue
                else:
                    # All retries failed - Logstash is likely stunned/OOM
                    logger.error(f"Simulation failed after {max_retries} attempts due to timeout - triggering restart")

                    # Queue the request for retry after restart
                    slot_config = None
                    if slot_id:
                        slot_state = slots.get_slot_state()
                        if slot_id in slot_state:
                            slot_data = slot_state[slot_id]
                            slot_config = {
                                'slot_id': slot_id,
                                'pipeline_name': slot_data.get('pipeline_name'),
                                'pipelines': slot_data.get('pipelines')
                            }

                    with _queue_lock:
                        _simulation_queue.append({
                            'log_data': log_data,
                            'slot_config': slot_config,
                            'queued_at': time.time()
                        })
                        queue_size = len(_simulation_queue)

                    # Trigger restart (systemctl for enrolled simulate, else supervisor)
                    trigger_sim_logstash_restart(
                        "Simulation POST failed - Logstash stunned/OOM"
                    )

                    logger.warning(f"Queued failed simulation for retry after restart (queue size: {queue_size})")
                    return JSONResponse(
                        status_code=202,
                        content={
                            "status": "queued",
                            "message": "Logstash unresponsive, triggering restart and queuing request",
                            "queue_position": queue_size
                        }
                    )

            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Simulation request failed on attempt {attempt + 1}, retrying: {e}")
                    await asyncio.sleep(1)
                    continue
                else:
                    # All retries failed - Logstash is likely stunned/OOM
                    logger.error(f"Simulation failed after {max_retries} attempts: {e} - triggering restart")

                    # Queue the request for retry after restart
                    slot_config = None
                    if slot_id:
                        slot_state = slots.get_slot_state()
                        if slot_id in slot_state:
                            slot_data = slot_state[slot_id]
                            slot_config = {
                                'slot_id': slot_id,
                                'pipeline_name': slot_data.get('pipeline_name'),
                                'pipelines': slot_data.get('pipelines')
                            }

                    with _queue_lock:
                        _simulation_queue.append({
                            'log_data': log_data,
                            'slot_config': slot_config,
                            'queued_at': time.time()
                        })
                        queue_size = len(_simulation_queue)

                    trigger_sim_logstash_restart(
                        f"Simulation POST failed: {e!s}"
                    )

                    logger.warning(f"Queued failed simulation for retry after restart (queue size: {queue_size})")
                    return JSONResponse(
                        status_code=202,
                        content={
                            "status": "queued",
                            "message": "Logstash unresponsive, triggering restart and queuing request",
                            "queue_position": queue_size
                        }
                    )

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to forward log to Logstash: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to forward log to Logstash: {e!s}"
        )
    except Exception as e:
        logger.error(f"Error in simulate_log endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error processing simulation log: {e!s}"
        )


@app.get("/_logstash/pipeline")
async def list_pipelines():
    """List all pipelines (mimics Elasticsearch API)"""
    pipelines = _load_pipelines_yml()
    result = {}

    for pipeline in pipelines:
        pipeline_id = pipeline.get('pipeline.id')
        if pipeline_id:
            # Load pipeline config
            config = _load_pipeline_config(pipeline_id)
            if config is None:
                continue

            # Load metadata
            metadata = _load_pipeline_metadata(pipeline_id)

            # Get settings from pipelines.yml
            yml_settings = _get_pipeline_settings_from_yml(pipeline_id)

            # Merge settings (yml takes precedence)
            pipeline_settings = metadata.get('pipeline_settings', {})
            pipeline_settings.update(yml_settings)

            result[pipeline_id] = {
                "description": metadata.get('description', ''),
                "last_modified": metadata.get('last_modified'),
                "pipeline_metadata": metadata.get('pipeline_metadata', {
                    "type": "logstash_pipeline",
                    "version": 1
                }),
                "username": metadata.get('username', 'logstashagent'),
                "pipeline": config,
                "pipeline_settings": pipeline_settings
            }

    return result


@app.get("/_logstash/pipeline/{pipeline_id}")
async def get_pipeline(pipeline_id: str = FastAPIPath(..., description="Pipeline ID")):
    """Get a specific pipeline (mimics Elasticsearch API)"""
    _validate_pipeline_id(pipeline_id)

    # Load pipeline config
    config = _load_pipeline_config(pipeline_id)
    if config is None:
        raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_id}' not found")

    # Load metadata
    metadata = _load_pipeline_metadata(pipeline_id)

    # Get settings from pipelines.yml
    yml_settings = _get_pipeline_settings_from_yml(pipeline_id)

    # Merge settings (yml takes precedence)
    pipeline_settings = metadata.get('pipeline_settings', {})
    pipeline_settings.update(yml_settings)

    result = {
        pipeline_id: {
            "description": metadata.get('description', ''),
            "last_modified": metadata.get('last_modified'),
            "pipeline_metadata": metadata.get('pipeline_metadata', {
                "type": "logstash_pipeline",
                "version": 1
            }),
            "username": metadata.get('username', 'logstashagent'),
            "pipeline": config,
            "pipeline_settings": pipeline_settings
        }
    }

    return result


@app.put("/_logstash/pipeline/{pipeline_id}")
async def put_pipeline(pipeline_id: str, body: dict[str, Any]):
    """Create or update a pipeline (mimics Elasticsearch API)"""
    _validate_pipeline_id(pipeline_id)

    pipeline_config = body.get('pipeline')
    if not pipeline_config:
        raise HTTPException(status_code=400, detail="Missing 'pipeline' field in request body")

    # Prepare pipeline settings for pipelines.yml
    pipeline_settings = body.get('pipeline_settings', {})

    # Load existing pipelines
    pipelines = _load_pipelines_yml()

    # Check if pipeline exists
    pipeline_exists = False
    for i, pipeline in enumerate(pipelines):
        if pipeline.get('pipeline.id') == pipeline_id:
            pipeline_exists = True
            # Update existing pipeline entry
            config_path = pipeline.get('path.config', f"{PIPELINES_DIR}/{pipeline_id}.conf")
            pipelines[i] = {
                'pipeline.id': pipeline_id,
                'path.config': config_path,
                **{k: v for k, v in pipeline_settings.items() if k.startswith(('pipeline.', 'queue.'))}
            }
            break

    if not pipeline_exists:
        # Add new pipeline entry
        # Handle path separators based on OS
        if os.name == 'nt':
            # Windows: Convert to backslashes and escape for YAML
            config_path = f"{PIPELINES_DIR}/{pipeline_id}.conf".replace('/', '\\').replace('\\', '\\\\')
        else:
            # Linux/Docker: Use forward slashes (no escaping needed)
            config_path = f"{PIPELINES_DIR}/{pipeline_id}.conf"
        new_pipeline = {
            'pipeline.id': pipeline_id,
            'path.config': config_path,
            **{k: v for k, v in pipeline_settings.items() if k.startswith(('pipeline.', 'queue.'))}
        }
        pipelines.append(new_pipeline)

    # Save pipeline configuration file
    config_path = f"{PIPELINES_DIR}/{pipeline_id}.conf"
    temp_config_path = f"{config_path}.tmp"
    try:
        with open(temp_config_path, 'w') as f:
            f.write(pipeline_config)
        os.replace(temp_config_path, config_path)
    except Exception as e:
        if os.path.exists(temp_config_path):
            os.remove(temp_config_path)
        raise HTTPException(status_code=500, detail=f"Failed to write pipeline config: {e!s}")

    # Save pipelines.yml
    try:
        _save_pipelines_yml(pipelines)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update pipelines.yml: {e!s}")

    # Save metadata
    metadata = {
        "description": body.get('description', ''),
        "last_modified": datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "pipeline_metadata": body.get('pipeline_metadata', {
            "type": "logstash_pipeline",
            "version": 1
        }),
        "username": body.get('username', 'logstashagent'),
        "pipeline_settings": pipeline_settings
    }

    try:
        _save_pipeline_metadata(pipeline_id, metadata)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save metadata: {e!s}")

    return {"acknowledged": True}


@app.delete("/_logstash/pipeline/{pipeline_id}")
async def delete_pipeline(pipeline_id: str = FastAPIPath(..., description="Pipeline ID")):
    """Delete a pipeline (mimics Elasticsearch API)"""
    _validate_pipeline_id(pipeline_id)

    # Load existing pipelines
    pipelines = _load_pipelines_yml()

    # Find and remove the pipeline
    pipeline_found = False
    config_path = None
    new_pipelines = []

    for pipeline in pipelines:
        if pipeline.get('pipeline.id') == pipeline_id:
            pipeline_found = True
            config_path = pipeline.get('path.config')
        else:
            new_pipelines.append(pipeline)

    if not pipeline_found:
        raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_id}' not found")

    # Delete pipeline config file
    if config_path and os.path.exists(config_path):
        try:
            os.remove(config_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete pipeline config: {e!s}")

    # Delete metadata file
    metadata_path = os.path.join(METADATA_DIR, f"{pipeline_id}.json")
    if os.path.exists(metadata_path):
        try:
            os.remove(metadata_path)
        except Exception as e:
            logger.warning(f"Failed to delete metadata: {e!s}")  # Non-critical if metadata deletion fails

    # Save updated pipelines.yml
    try:
        _save_pipelines_yml(new_pipelines)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update pipelines.yml: {e!s}")

    return {"acknowledged": True}


def _ms_since(start: float) -> int:
    """Elapsed milliseconds since ``start`` (from time.perf_counter())."""
    return int(round((time.perf_counter() - start) * 1000))


async def _adaptive_bus_settle(
    pipeline_name: str,
    min_seconds: float = 1.25,
    max_seconds: float = 3.0,
    poll_seconds: float = 0.25,
) -> None:
    """
    Post-verify settle until the pipeline-to-pipeline bus address is usable.

    Logstash can list a pipeline as loaded/idle before ``pipeline { send_to => … }``
    destinations are registered on the bus. simulate-start then logs:
      Attempted to send event to 'slotN-filter1' but that address was unavailable

    Require the pipeline to be present and in idle/running for at least
    ``min_seconds`` continuously (reset if it drops), up to ``max_seconds``.
    """
    t0 = time.perf_counter()
    ready_since: float | None = None
    last_state = "unknown"

    while True:
        elapsed = time.perf_counter() - t0
        present = False
        state = "unknown"
        try:
            with LogstashAPI(timeout=2.0) as api:
                present = pipeline_name in api.list_pipelines()
                if present:
                    try:
                        state = api.detect_pipeline_state(pipeline_name)
                    except Exception as e:
                        logger.debug("bus settle detect_pipeline_state: %s", e)
                        state = "unknown"
        except Exception as e:
            logger.debug("bus settle list_pipelines: %s", e)
            present = False
            state = "unknown"

        last_state = state
        bus_ready = present and state in ("idle", "running")
        if bus_ready:
            if ready_since is None:
                ready_since = time.perf_counter()
            ready_for = time.perf_counter() - ready_since
            if ready_for >= min_seconds:
                logger.info(
                    "bus settle OK for %s after %.0fms (state=%s, stable=%.0fms)",
                    pipeline_name,
                    elapsed * 1000,
                    state,
                    ready_for * 1000,
                )
                return
        else:
            ready_since = None

        if elapsed >= max_seconds:
            logger.warning(
                "bus settle max %.0fms for %s (present=%s state=%s) — "
                "simulate may retry send_to until address is up",
                max_seconds * 1000,
                pipeline_name,
                present,
                last_state,
            )
            return
        await asyncio.sleep(poll_seconds)


@app.post("/_logstash/slots/allocate")
async def allocate_simulation_slot(body: dict[str, Any]):
    """
    Allocate a slot for simulation pipelines.

    Concurrent requests for the same pipeline content hash are single-flighted:
    followers await the leader and receive the same slot (avoids double-create 500s
    when the UI aborts/retries or warm-on-hover races with select).

    Request body:
    {
        "pipeline_name": "name of the pipeline being simulated",
        "pipelines": [
            {"config": "filter config 1", "index": 1},
            {"config": "filter config 2", "index": 2},
            ...
        ]
    }

    Returns:
    {
        "slot_id": 1-10,
        "reused": true/false (whether an existing slot was reused),
        "pipeline_count": N,
        "coalesced": true if this response joined an in-flight allocate,
        "timings_ms": { ... }
    }
    """
    pipeline_name = body.get('pipeline_name')
    pipelines = body.get('pipelines', [])

    if not pipeline_name:
        raise HTTPException(status_code=400, detail="Missing 'pipeline_name' field")

    if not pipelines:
        raise HTTPException(status_code=400, detail="Missing 'pipelines' field or empty pipeline list")

    # Startup warmup gate: reject allocations while the pipeline bus is still
    # initializing.  Logstash's HTTP API becomes responsive before the
    # pipeline-to-pipeline bus is ready; a pipeline created in this window
    # starts and silently terminates in ~172ms, leaving a dead bus address.
    healthy_for = _get_logstash_healthy_duration()
    if healthy_for is None or healthy_for < PIPELINE_BUS_WARMUP_SECONDS:
        remaining = (
            int(PIPELINE_BUS_WARMUP_SECONDS - healthy_for) + 1
            if healthy_for is not None
            else int(PIPELINE_BUS_WARMUP_SECONDS)
        )
        logger.info(
            "allocate rejected: Logstash pipeline bus still initializing "
            "(healthy_for=%s retry_after=%ss)",
            f"{healthy_for:.1f}s" if healthy_for is not None else "never",
            remaining,
        )
        raise HTTPException(
            status_code=503,
            headers={"Retry-After": str(remaining)},
            detail={
                "error": "logstash_initializing",
                "message": "Logstash pipeline bus is still initializing, retry shortly",
                "retry_after_seconds": remaining,
            },
        )

    content_hash = slots._compute_pipeline_hash(pipelines)

    # Single-flight: one leader create/verify per content hash; others join.
    # If the leader fails, followers retry as leaders (up to 2 more attempts).
    last_error: Exception | None = None
    for flight_attempt in range(3):
        fut, is_leader = await slots.begin_allocate_flight(content_hash)
        if not is_leader:
            try:
                result = await fut
                if isinstance(result, dict):
                    out = dict(result)
                    out["coalesced"] = True
                    # Joiner always "reuses" the leader's work from the client's POV
                    out["reused"] = True
                    if isinstance(out.get("timings_ms"), dict):
                        out["timings_ms"] = dict(out["timings_ms"])
                        out["timings_ms"]["path"] = out["timings_ms"].get("path", "pure_reuse")
                        out["timings_ms"]["coalesced"] = True
                    logger.info(
                        "allocate_slot COALESCED slot=%s hash=%s… (joined in-flight)",
                        out.get("slot_id"),
                        content_hash[:8],
                    )
                    return out
            except Exception as e:
                last_error = e if isinstance(e, Exception) else Exception(str(e))
                logger.warning(
                    "allocate single-flight leader failed (attempt %s): %s — retrying as leader",
                    flight_attempt + 1,
                    e,
                )
                continue

        # Leader path
        try:
            result = await _allocate_simulation_slot_impl(
                pipeline_name=pipeline_name,
                pipelines=pipelines,
                content_hash=content_hash,
            )
            await slots.complete_allocate_flight(content_hash, fut, result=result)
            return result
        except Exception as e:
            last_error = e if isinstance(e, Exception) else Exception(str(e))
            await slots.complete_allocate_flight(content_hash, fut, error=e)
            # Only re-raise immediately for client errors; transient 500s may be
            # retried by the next loop iteration if we re-enter as leader.
            if isinstance(e, HTTPException) and e.status_code < 500:
                raise
            if flight_attempt >= 2:
                raise
            logger.warning(
                "allocate leader failed attempt %s for hash %s…: %s",
                flight_attempt + 1,
                content_hash[:8],
                e,
            )
            await asyncio.sleep(0.25 * (flight_attempt + 1))
            continue

    if last_error:
        raise last_error
    raise HTTPException(status_code=500, detail="Failed to allocate slot")


async def _allocate_simulation_slot_impl(
    *,
    pipeline_name: str,
    pipelines: list[dict[str, Any]],
    content_hash: str,
) -> dict[str, Any]:
    """Core allocate/create/verify path (runs under single-flight leadership)."""
    t_total = time.perf_counter()
    timings_ms: dict[str, Any] = {
        "total": 0,
        "hash_lookup": 0,
        "slot_book": 0,
        "reuse_probe": 0,
        "evict_wait": 0,
        "create": 0,
        "verify": 0,
        "settle": 0,
        "path": "unknown",
    }

    # Check if a slot with this exact configuration already exists
    t0 = time.perf_counter()
    existing_slots = slots.get_slot_state()
    slot_existed_before = any(
        slot_data.get('content_hash') == content_hash
        for slot_data in existing_slots.values()
    )
    timings_ms["hash_lookup"] = _ms_since(t0)

    # Allocate or reuse slot (allocate_slot handles hash checking internally)
    t0 = time.perf_counter()
    slot_id = slots.allocate_slot(pipeline_name, pipelines)
    timings_ms["slot_book"] = _ms_since(t0)

    if slot_id is None:
        raise HTTPException(status_code=500, detail="Failed to allocate slot")

    # If the slot existed before with the same hash, it's reused
    reused = slot_existed_before

    logger.info(f"Slot {slot_id} - reused: {reused}, hash: {content_hash[:8]}...")

    # Serialize pipeline create/verify per slot (guards hash-mismatch eviction races)
    create_lock = await slots.get_slot_create_lock(slot_id)
    async with create_lock:
        # Re-probe under the lock: a coalesced peer may have finished create
        pipelines_exist = False
        first_pipeline_name = f"slot{slot_id}-filter1"
        t0 = time.perf_counter()
        try:
            with LogstashAPI(timeout=3.0) as api:
                all_pipelines = api.list_pipelines()
                pipelines_exist = first_pipeline_name in all_pipelines
        except Exception as e:
            logger.warning(
                "Failed to check pipeline existence via API: %s. Assuming pipelines don't exist.",
                e,
            )
            pipelines_exist = False
        timings_ms["reuse_probe"] = _ms_since(t0)
        if reused:
            logger.info(
                "Slot %s reused - pipelines exist: %s",
                slot_id,
                pipelines_exist,
            )

        # If this is a new (evicted) slot, wait for old pipeline to disappear from Logstash
        # before creating the new one. Empty slots: first check usually finds nothing.
        if not reused and not pipelines_exist:
            t0 = time.perf_counter()
            max_wait = 15.0
            poll_s = 0.25
            start_wait = time.time()
            logger.info(
                "Waiting for old pipeline %s to be removed before creating new one...",
                first_pipeline_name,
            )
            while time.time() - start_wait < max_wait:
                try:
                    with LogstashAPI(timeout=3.0) as api:
                        all_pipelines = api.list_pipelines()
                        if first_pipeline_name not in all_pipelines:
                            logger.info(
                                "Old pipeline %s is gone (%.2fs), proceeding with create",
                                first_pipeline_name,
                                time.time() - start_wait,
                            )
                            break
                except Exception as e:
                    logger.warning(f"Error checking pipeline removal: {e}")
                await asyncio.sleep(poll_s)
            else:
                logger.warning(
                    "Old pipeline %s still present after %.0fs — forcing delete",
                    first_pipeline_name,
                    max_wait,
                )
                try:
                    delete_pipeline_internal(first_pipeline_name)
                    await asyncio.sleep(0.5)
                except Exception as e:
                    logger.warning("Force-delete %s failed: %s", first_pipeline_name, e)
            timings_ms["evict_wait"] = _ms_since(t0)

        # When the pipeline appears listed but was created during a cold-start race
        # it may have already terminated (Logstash bus not ready → 172ms silent exit).
        # Trust detect_pipeline_state over mere listing: if the pipeline isn't
        # idle/running it isn't bus-ready, so force-delete and recreate.
        if pipelines_exist:
            try:
                with LogstashAPI(timeout=3.0) as api:
                    bus_state = api.detect_pipeline_state(first_pipeline_name)
            except Exception as _e:
                bus_state = "unknown"
                logger.debug("bus-ready check for %s failed: %s", first_pipeline_name, _e)
            if bus_state not in ("idle", "running"):
                logger.warning(
                    "Slot %s pipeline %s is listed but not bus-ready (state=%s) — "
                    "forcing delete and recreate",
                    slot_id,
                    first_pipeline_name,
                    bus_state,
                )
                try:
                    delete_pipeline_internal(first_pipeline_name)
                    await asyncio.sleep(0.5)
                except Exception as _e:
                    logger.warning("Force-delete before recreate failed: %s", _e)
                pipelines_exist = False

        # Create pipelines if they don't exist (new slot or reused slot with deleted pipelines)
        created_or_rebuilt = False
        if not pipelines_exist:
            created_or_rebuilt = True
            try:
                create_timings = await _create_slot_pipelines(slot_id, pipelines)
                timings_ms["create"] = int(create_timings.get("create_ms", 0))
                timings_ms["verify"] = int(create_timings.get("verify_ms", 0))
            except HTTPException:
                # Only release if we still own this hash (don't wipe a peer's success)
                slots.release_slot_if_hash(slot_id, content_hash)
                timings_ms["total"] = _ms_since(t_total)
                logger.error(
                    "allocate_slot FAILED slot=%s reused=%s hash=%s timings_ms=%s",
                    slot_id,
                    reused,
                    content_hash[:8],
                    timings_ms,
                )
                raise
            except Exception as e:
                slots.release_slot_if_hash(slot_id, content_hash)
                timings_ms["total"] = _ms_since(t_total)
                logger.error(
                    "allocate_slot FAILED slot=%s reused=%s hash=%s timings_ms=%s err=%s",
                    slot_id,
                    reused,
                    content_hash[:8],
                    timings_ms,
                    e,
                )
                raise HTTPException(
                    status_code=500,
                    detail={
                        "message": f"Failed to create slot pipelines: {e!s}",
                        "slot_id": slot_id,
                        "timings_ms": timings_ms,
                    }
                )
        else:
            # Another request (or prior run) already has pipelines loaded
            if reused:
                logger.info(
                    "Slot %s pipelines already present under create lock — skip create",
                    slot_id,
                )

    # After create+verify the pipeline is loaded; pipeline-to-pipeline bus can lag
    # briefly. Adaptive settle: short min hold while pipeline remains listed, cap
    # max (was fixed 1.5s). Pure reuse skips settle entirely.
    if created_or_rebuilt:
        timings_ms["path"] = "rebuild" if reused else "new"
        t0 = time.perf_counter()
        first_pipeline_name = f"slot{slot_id}-filter1"
        await _adaptive_bus_settle(first_pipeline_name)
        timings_ms["settle"] = _ms_since(t0)
    else:
        timings_ms["path"] = "pure_reuse"
        logger.info(
            "Slot %s pure reuse (pipelines already running) — skip bus settle wait",
            slot_id,
        )

    timings_ms["total"] = _ms_since(t_total)
    logger.info(
        "allocate_slot OK slot=%s reused=%s path=%s hash=%s pipelines=%s timings_ms=%s",
        slot_id,
        reused,
        timings_ms["path"],
        content_hash[:8],
        len(pipelines),
        timings_ms,
    )
    return {
        "slot_id": slot_id,
        "reused": reused,
        "pipeline_count": len(pipelines),
        "coalesced": False,
        "timings_ms": timings_ms,
        "content_hash_prefix": content_hash[:8],
    }


async def _create_slot_pipelines(slot_id: int, pipelines: list[dict[str, Any]]) -> dict[str, int]:
    """
    Create the filter pipelines for a specific slot.

    Args:
        slot_id: Slot ID (1-10)
        pipelines: List of pipeline configurations

    Returns:
        Timing breakdown in ms: create_ms (put_pipeline writes), verify_ms (load poll).
    """
    t_create = time.perf_counter()
    for pipeline_data in pipelines:
        idx = pipeline_data.get('index', 1)
        filter_config = pipeline_data.get('filter_config', '')

        if not filter_config:
            continue

        # Determine next filter address
        if idx < len(pipelines):
            _ = f"slot{slot_id}-filter{idx + 1}"
        else:
            _ = "filter-final"

        # Generate pipeline config with both pipeline and HTTP outputs
        pipeline_config = f"""input {{
  pipeline {{ address => "slot{slot_id}-filter{idx}" }}
}}

filter {{
{filter_config}
}}

output {{
  pipeline {{ send_to => "simulate-end" }}
}}
"""

        # Create the pipeline
        pipeline_name = f"slot{slot_id}-filter{idx}"
        pipeline_body = {
            "pipeline": pipeline_config,
            "last_modified": datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "pipeline_metadata": {
                "version": 1,
                "type": "logstash_pipeline"
            },
            "username": "logstashagent",
            "pipeline_settings": {
                "pipeline.workers": 1
            }
        }

        # Use the existing put_pipeline logic
        await put_pipeline(pipeline_name, pipeline_body)

    create_ms = _ms_since(t_create)

    # Verify all slot pipelines loaded successfully (fast poll + short idle stability)
    t_verify = time.perf_counter()
    verification_success = await slots.verify_slot_pipelines_loaded(
        slot_id,
        len(pipelines),
        max_wait_seconds=15.0,
        poll_interval=0.25,
    )
    verify_ms = _ms_since(t_verify)
    logger.info(
        "Slot %s create+verify: create_ms=%s verify_ms=%s success=%s",
        slot_id,
        create_ms,
        verify_ms,
        verification_success,
    )

    if not verification_success:
        # Delete the failed pipelines from Logstash to prevent log pollution
        logger.warning(f"Verification failed for slot {slot_id}, cleaning up pipelines")
        for idx in range(1, len(pipelines) + 1):
            pipeline_name = f"slot{slot_id}-filter{idx}"
            try:
                await delete_pipeline(pipeline_name)
                logger.info(f"Deleted failed pipeline {pipeline_name}")
            except Exception as cleanup_error:
                logger.error(f"Error deleting failed pipeline {pipeline_name}: {cleanup_error}")

        # Wait for pipelines to actually disappear from Logstash API
        # This prevents stale failure state when slot is reused
        import asyncio
        logger.info(f"Waiting for slot {slot_id} pipelines to be removed from Logstash...")
        max_wait = 5.0
        start_wait = time.time()
        while time.time() - start_wait < max_wait:
            try:
                with LogstashAPI(timeout=3.0) as api:
                    all_pipelines = api.list_pipelines()
                    slot_pipelines_still_exist = any(
                        f"slot{slot_id}-filter{idx}" in all_pipelines
                        for idx in range(1, len(pipelines) + 1)
                    )
                    if not slot_pipelines_still_exist:
                        logger.info(f"Slot {slot_id} pipelines successfully removed from Logstash")
                        break
            except Exception as e:
                logger.warning(f"Error checking pipeline removal: {e}")
            await asyncio.sleep(0.5)

        raise HTTPException(
            status_code=500,
            detail={
                "message": f"Slot {slot_id} pipelines created but failed to load in Logstash. Check logs for errors.",
                "slot_id": slot_id,
                "timings_ms": {"create_ms": create_ms, "verify_ms": verify_ms},
            }
        )

    return {"create_ms": create_ms, "verify_ms": verify_ms}


@app.get("/_logstash/slots")
async def get_slots():
    """Get the current state of all slots."""
    return slots.get_slot_state()


@app.delete("/_logstash/slots/{slot_id}")
async def release_slot(slot_id: int = FastAPIPath(..., description="Slot ID", ge=1, le=10)):
    """
    Release a specific slot and remove its named Logstash pipelines
    (``slotN-filter*`` from pipelines.yml / conf.d so the bus address goes away).
    """
    # Always attempt pipeline cleanup; 404 only if slot was unknown *and* nothing to clean
    existed = slots.release_slot(slot_id, cleanup_pipelines=True)
    if not existed:
        # Orphan cleanup still ran inside release_slot; report soft success so callers
        # that retry delete do not error — bus address should be cleared either way.
        logger.info(
            "DELETE slot %s: not in slot table; orphan pipeline cleanup still attempted",
            slot_id,
        )

    return {"acknowledged": True, "slot_id": slot_id, "existed": existed}


@app.get("/_logstash/pipeline/{pipeline_id}/logs")
async def get_pipeline_logs(
        pipeline_id: str = FastAPIPath(..., description="Pipeline ID"),
        max_entries: int = Query(50, description="Maximum number of log entries to return", ge=1, le=500),
        min_level: str = Query("WARN", description="Minimum log level (DEBUG, INFO, WARN, ERROR)"),
        min_timestamp: int = Query(None,
                                   description="Minimum timestamp in milliseconds. Only logs at or after this time will be included.")
):
    """
    Get log entries related to a specific pipeline.

    This endpoint searches Logstash JSON logs for entries related to the given pipeline,
    including errors, warnings, and other diagnostic information.

    Args:
        pipeline_id: The pipeline ID to search for (e.g., "slot4-filter1")
        max_entries: Maximum number of log entries to return (default: 50, max: 500)
        min_level: Minimum log level to include (default: WARN)
        min_timestamp: Optional minimum timestamp in milliseconds. Only logs at or after this time will be included.

    Returns:
        JSON response with:
        - pipeline_id: The pipeline ID searched
        - log_count: Number of log entries found
        - logs: List of log entries with full context
    """
    _validate_pipeline_id(pipeline_id)

    try:
        # Use instance log dir (simulate-N is not /var/log/logstash)
        log_dir = get_logstash_log_dir()
        logger.debug(
            "get_pipeline_logs: pipeline_id=%s log_dir=%s min_level=%s",
            pipeline_id,
            log_dir,
            min_level,
        )
        logs = log_analyzer.find_related_logs(
            pipeline_id=pipeline_id,
            log_dir=log_dir,
            max_entries=max_entries,
            min_level=min_level.upper(),
            min_timestamp=min_timestamp,
        )

        return {
            "pipeline_id": pipeline_id,
            "log_dir": log_dir,
            "log_count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching logs for pipeline {pipeline_id}: {e!s}"
        )


@app.get("/_logstash/pipelines/status")
async def get_pipelines_status():
    """
    Get the current status of all running pipelines from Logstash API.

    Returns:
        - running_pipelines: List of pipeline IDs currently loaded in Logstash
        - count: Total count of pipelines
        - timestamp: When this status was retrieved
        - states: Dictionary mapping pipeline names to their states (running/idle/failed/unknown)
    """
    try:
        with LogstashAPI(timeout=5.0) as api:
            # Get all pipelines
            all_pipelines = api.list_pipelines()

            # Get state for each pipeline
            # Use defensive error handling - if one pipeline fails, don't crash the whole endpoint
            pipeline_states = {}
            for pipeline_name in all_pipelines:
                try:
                    state = api.detect_pipeline_state(pipeline_name)
                    pipeline_states[pipeline_name] = state
                except Exception as e:
                    logger.error(f"Error detecting state for pipeline '{pipeline_name}': {e}")
                    pipeline_states[pipeline_name] = 'unknown'

            return {
                "running_pipelines": all_pipelines,
                "count": len(all_pipelines),
                "timestamp": datetime.now(UTC).isoformat(),
                "states": pipeline_states
            }
    except Exception as e:
        logger.error(f"Error in get_pipelines_status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching pipeline status from Logstash API: {e!s}"
        )


def _sim_settings_path() -> str:
    state = agent_state.get_state()
    settings_path = (
        state.get("settings_path")
        or AGENT_CONFIG.get("logstash_settings")
        or "/etc/logstash"
    )
    settings_path = str(settings_path).replace("\\", "/")
    if not settings_path.endswith("/"):
        settings_path = settings_path + "/"
    return settings_path


def _normalize_secrets_map(secrets: dict) -> dict:
    """Lowercase keys for Logstash keystore comparison (keystore stores lowercase)."""
    return {
        str(k).lower(): str(v)
        for k, v in (secrets or {}).items()
        if v is not None and str(k).lower() != "keystore.seed"
    }


def _read_instance_keystore_secrets(password: str | None = None) -> tuple[dict, bool]:
    """
    Read user secrets from the local Logstash keystore.

    Returns (secrets_map lowercase keys, exists).
    """
    from logstashagent.ls_keystore_utils.keystore_write import (
        _load_existing_secrets,
        extract_embedded_password,
        resolve_keystore_password,
    )

    settings_path = _sim_settings_path()
    keystore_path = Path(settings_path) / "logstash.keystore"
    if not keystore_path.is_file():
        return {}, False

    state = agent_state.get_state()
    try_passwords = []
    if password:
        try_passwords.append(password)
    if state.get("keystore_password"):
        try_passwords.append(state.get("keystore_password"))
    # Unauthenticated trailer
    try:
        emb = extract_embedded_password(keystore_path)
        if emb:
            try_passwords.append(emb)
    except Exception as e:
        logger.warning(f"Failed to extract embedded password: {e!s}")

    last_err = None
    for pwd in try_passwords:
        try:
            secrets = _load_existing_secrets(keystore_path, pwd)
            # Drop seed
            secrets = {k: v for k, v in secrets.items() if k != "keystore.seed"}
            return secrets, True
        except Exception as e:
            last_err = e
            continue

    # Last attempt: resolve_keystore_password
    try:
        pwd, _emb = resolve_keystore_password(keystore_path, password)
        secrets = _load_existing_secrets(keystore_path, pwd)
        secrets = {k: v for k, v in secrets.items() if k != "keystore.seed"}
        return secrets, True
    except Exception as e:
        logger.debug("Could not read instance keystore: %s (last=%s)", e, last_err)
        return {}, True  # exists but unreadable → treat as different on compare


def _restart_logstash_for_sim() -> bool:
    from logstashagent import controller as _controller

    state = agent_state.get_state()
    mode = canonical_agent_mode(state.get("mode") or AGENT_CONFIG.get("mode") or "") or ""
    # packaged: system logstash unit; simulate/managed: instance unit
    if mode in ("simulate", "packaged", "managed") or state.get("logstash_unit"):
        return bool(_controller.restart_logstash())
    try:
        sup = logstash_supervisor.get_supervisor()
        if sup is not None:
            sup.restart_logstash(reason="keystore sync")
            return True
    except Exception as sup_err:
        logger.warning("Supervisor restart after keystore sync failed: %s", sup_err)
    return False


@app.get("/_logstash/keystore")
async def keystore_get():
    """
    Return the current simulate-instance keystore user secrets (for comparison).

    Does not include keystore.seed. Values are returned so LogstashUI can compare
    against the source policy before deciding to sync.
    """
    state = agent_state.get_state()
    secrets, exists = _read_instance_keystore_secrets(
        password=state.get("keystore_password")
    )
    return JSONResponse(
        status_code=200,
        content={
            "exists": exists,
            "secrets": secrets,
            "secrets_count": len(secrets),
            "keys": sorted(secrets.keys()),
        },
    )


@app.post("/_logstash/keystore/sync")
async def keystore_sync(request: Request):
    """
    Replace the simulate instance Logstash keystore with the provided secrets
    only when contents differ from the current keystore.

    Used by LogstashUI before pipeline simulation when the pipeline references
    ${keystore} variables. Pure-Python write (no logstash-keystore CLI).
    No Logstash restart when the keystore already matches.

    Request body (JSON):
      {
        "secrets": {"KEY": "value", ...},   # full user secret map
        "password": "optional",             # omit/null => unauthenticated (embedded trailer)
        "restart": true                     # restart only if a write occurs (default true)
      }
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    secrets = body.get("secrets") or {}
    if not isinstance(secrets, dict):
        raise HTTPException(status_code=400, detail="'secrets' must be an object")

    password = body.get("password") or None
    do_restart = body.get("restart", True)

    state = agent_state.get_state()
    settings_path = _sim_settings_path()
    keystore_path = Path(settings_path) / "logstash.keystore"

    try:
        from logstashagent import controller as _controller
        from logstashagent.ls_keystore_utils.keystore_write import (
            create_keystore_file,
            generate_default_keystore_password,
            write_keystore_secrets,
        )

        secrets_map = _normalize_secrets_map(secrets)

        # Compare to current on-disk keystore (no write / no restart if equal)
        current, exists = _read_instance_keystore_secrets(password=password)
        if exists and current == secrets_map:
            # Also require auth mode compatibility: if password expected vs embedded
            # When both empty and both unauthenticated, equal is enough.
            logger.info(
                "Keystore sync: no changes (%d secret(s) already match) — skip write/restart",
                len(secrets_map),
            )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "success",
                    "unchanged": True,
                    "secrets_count": len(secrets_map),
                    "keystore_path": str(keystore_path),
                    "restarted": False,
                    "authenticated": bool(password),
                },
            )

        os.makedirs(settings_path, exist_ok=True)

        if password:
            write_keystore_secrets(
                keystore_path, password, secrets_map, embed_password=False
            )
            agent_state.update_state("keystore_password", password)
            env_file = state.get("keystore_env_file")
            try:
                _controller.update_logstash_env_file(password, env_file=env_file)
            except Exception as env_err:
                logger.warning("Keystore written but env file update failed: %s", env_err)
        else:
            # Unauthenticated keystore with embedded default-password trailer
            gen = generate_default_keystore_password()
            if not keystore_path.exists():
                create_keystore_file(keystore_path, password=gen, embed_password=True)
            write_keystore_secrets(
                keystore_path, gen, secrets_map, embed_password=True
            )
            agent_state.update_state("keystore_password", None)
            env_file = state.get("keystore_env_file")
            try:
                _controller.update_logstash_env_file(None, env_file=env_file)
            except Exception as env_err:
                logger.debug("Env clear skipped/failed: %s", env_err)

        restarted = False
        if do_restart:
            restarted = _restart_logstash_for_sim()

        logger.info(
            "Keystore sync: wrote %d secret(s) to %s (restarted=%s, was_unchanged=false)",
            len(secrets_map),
            keystore_path,
            restarted,
        )
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "unchanged": False,
                "secrets_count": len(secrets_map),
                "keystore_path": str(keystore_path),
                "restarted": restarted,
                "authenticated": bool(password),
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Keystore sync failed")
        raise HTTPException(status_code=500, detail=f"Keystore sync failed: {e}")


@app.post("/_logstash/write-file")
async def write_file(request: Request):
    """
    Write a file to the uploaded directory for simulation use.
    Only enabled when SIMULATION_MODE environment variable is set to true.

    Request body:
    {
        "filename": "filter_translate_10_dictionary_path.json",
        "content": "<base64 encoded file content>"
    }
    """
    # Check if simulation mode is enabled (defaults to true for development)
    # Set SIMULATION_MODE=false to explicitly disable file uploads
    simulation_mode = os.getenv("SIMULATION_MODE", "true").lower() == "true"
    if not simulation_mode:
        raise HTTPException(
            status_code=403,
            detail="File upload is only allowed in simulation mode"
        )

    try:
        body = await request.json()
        filename = body.get("filename")
        content = body.get("content")

        if not filename or not content:
            raise HTTPException(
                status_code=400,
                detail="Both 'filename' and 'content' are required"
            )

        # Create uploaded directory in /tmp if it doesn't exist
        uploaded_dir = "/tmp/uploaded"
        os.makedirs(uploaded_dir, exist_ok=True)

        # Sanitize filename to prevent path traversal
        safe_filename = os.path.basename(filename)
        file_path = os.path.join(uploaded_dir, safe_filename)

        # Decode base64 content and write file
        logger.info(f"Received content length: {len(content)} characters")
        file_content = base64.b64decode(content)
        logger.info(f"Decoded to {len(file_content)} bytes")

        with open(file_path, 'wb') as f:
            bytes_written = f.write(file_content)
            logger.info(f"Wrote {bytes_written} bytes to {file_path}")

        logger.info(f"File written successfully: {file_path}")

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": f"File written to {file_path}",
                "path": file_path
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error writing file: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error writing file: {e!s}"
        )


@app.post("/_logstash/validate")
async def validate_logstash_config(request: Request):
    """
    Validate a Logstash pipeline configuration using logstash --config.test_and_exit.

    Request body:
        - pipeline_name: Name of the pipeline (used for temp file naming)
        - config: The Logstash configuration to validate

    Returns:
        - status: "OK" or "ERROR"
        - notifications: List of warning/deprecation messages
        - error: Error message if validation failed
    """
    import subprocess

    try:
        body = await request.json()
        pipeline_name = body.get("pipeline_name", "pipeline")
        config = body.get("config")

        if not config:
            raise HTTPException(
                status_code=400,
                detail="No configuration provided"
            )

        # Create temporary config file
        temp_file_path = f"/tmp/{pipeline_name}.conf"

        try:
            # Replace keystore variables without defaults to avoid validation failures
            # Pattern: ${variable_name} -> ${variable_name:test}
            # Don't replace if already has a default: ${variable_name:existing_default}
            import re
            config_with_defaults = re.sub(
                r'\$\{([^}:]+)\}',  # Match ${variable_name} without colon
                r'${\1:test}',       # Replace with ${variable_name:test}
                config
            )

            # Write config to temp file
            with open(temp_file_path, 'w') as f:
                f.write(config_with_defaults)

            logger.info(f"Validating config for pipeline '{pipeline_name}' at {temp_file_path}")

            # Get logstash binary path from config
            logstash_binary = AGENT_CONFIG.get('logstash_binary', '/usr/share/logstash/bin/logstash')
            logger.info(f"Using Logstash binary: {logstash_binary}")

            # Run logstash validation
            result = subprocess.run(
                [logstash_binary, "--config.test_and_exit", "-f", temp_file_path, "--log.format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Parse output to extract notifications by log level
            notifications_by_level = {}
            output_lines = result.stdout.strip().split('\n')

            for line in output_lines:
                try:
                    log_entry = json.loads(line)
                    # Extract log entries with logEvent
                    if "logEvent" in log_entry:
                        message = log_entry["logEvent"].get("message", "")
                        logger_name = log_entry.get("loggerName", "")
                        level = log_entry.get("level", "INFO")

                        # Filter out noise
                        if "Reflections took" in message or "pipelines.yml" in message:
                            continue

                        # Only include relevant log levels
                        if level in ["FATAL", "ERROR", "WARN", "INFO"]:
                            # Skip generic INFO messages unless they're important
                            if level == "INFO":
                                # Filter out logstash.runner INFO logs - not useful to users
                                if logger_name == "logstash.runner":
                                    continue
                                # Only include specific INFO messages
                                if not any(keyword in message.lower() for keyword in ["deprecated", "warning", "error"]):
                                    continue

                            # Initialize level list if not exists
                            if level not in notifications_by_level:
                                notifications_by_level[level] = []

                            # Remove discussion forum text if present
                            cleaned_message = message.replace(
                                "If you have any questions about this, please ask it on the https://discuss.elastic.co/c/logstash discussion forum",
                                ""
                            ).strip()

                            # Add entry with plugin and message
                            notifications_by_level[level].append({
                                "plugin": logger_name,
                                "message": cleaned_message
                            })
                except json.JSONDecodeError:
                    # Skip non-JSON lines (like "Configuration OK")
                    if "Configuration OK" in line:
                        logger.info("Configuration validation passed")
                    continue

            # Determine overall status based on log levels present
            if "FATAL" in notifications_by_level or "ERROR" in notifications_by_level:
                status = "ERROR"
            elif "WARN" in notifications_by_level:
                status = "WARN"
            elif result.returncode == 0:
                status = "OK"
            else:
                status = "ERROR"

            logger.info(f"Validation result for pipeline '{pipeline_name}': {status}, levels: {list(notifications_by_level.keys())}")

            return JSONResponse(
                status_code=200,
                content={
                    "status": status,
                    "notifications": notifications_by_level
                }
            )

        finally:
            # Clean up temp file
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
                logger.debug(f"Removed temp file: {temp_file_path}")

    except subprocess.TimeoutExpired:
        logger.error(f"Validation timeout for pipeline '{pipeline_name}'")
        raise HTTPException(
            status_code=500,
            detail="Validation timeout - configuration took too long to validate"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating config: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error validating configuration: {e!s}"
        )


def parse_arguments():
    """
    Parse command-line arguments for enrollment and other modes
    """
    # Top-level --version / -V only; do not steal `upgrade --version VERSION`.
    if sys.argv[1:] in (['--version'], ['-V']):
        print(AGENT_VERSION)
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description='logstashagent - Control plane agent for logstashui',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Install and enroll agent with logstashui
  logstash-agent install --enroll TOKEN --logstash-ui-url http://localhost:8080

  # Apply Logstash-specific setup after installing Logstash post-agent-install
  sudo logstash-agent configure

  # Finish simulate materialization after non-root --enroll
  sudo logstash-agent setup-simulate

  # Bare recovery: quarantine slot pipelines, re-seed harness, restart ls-simulate@N
  sudo logstash-agent recover-simulate --yes

  # Upgrade agent to a new version
  logstash-agent upgrade --version 0.1.4

  # Uninstall agent (preserves state and logs)
  logstash-agent uninstall

  # Uninstall agent and remove all data
  logstash-agent uninstall --purge
        """
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Install command
    install_parser = subparsers.add_parser(
        'install',
        help='Install and enroll the agent with logstashui'
    )
    install_parser.add_argument(
        '--enroll',
        type=str,
        metavar='TOKEN',
        required=True,
        help='Enrollment token for registering with logstashui'
    )
    install_parser.add_argument(
        '--logstash-ui-url',
        type=str,
        metavar='URL',
        required=True,
        help='logstashui URL (e.g., http://localhost:8080 or https://logstashui.example.com)'
    )
    install_parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip the enrollment confirmation prompt'
    )

    # Uninstall command
    uninstall_parser = subparsers.add_parser(
        'uninstall',
        help='Uninstall the agent from the system (uses install registry)'
    )
    uninstall_parser.add_argument(
        '--purge',
        action='store_true',
        help='Full wipe: remove /opt/logstash-agent entirely and the CLI symlink'
    )
    uninstall_parser.add_argument(
        '--instance',
        metavar='ID',
        default=None,
        help=(
            'Remove only one multi-instance role (e.g. simulate-1, managed-2). '
            'Stops units and deletes that path tree; package and other instances stay. '
            'See also: list-instances'
        ),
    )
    uninstall_parser.add_argument(
        '--keep-data',
        action='store_true',
        help='With --instance: stop/disable units but keep the instance path tree'
    )
    uninstall_parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip the uninstallation confirmation prompt'
    )

    list_inst_parser = subparsers.add_parser(
        'list-instances',
        help='List package + multi-instance installs from the host registry'
    )
    list_inst_parser.add_argument(
        '--json',
        action='store_true',
        dest='list_json',
        help='Emit JSON instead of a table'
    )

    # VERSION binary lifecycle
    list_ver_parser = subparsers.add_parser(
        'list-versions',
        help='List Logstash versions under the download root (VERSION source cache)'
    )
    list_ver_parser.add_argument(
        '--download-dir',
        default=None,
        help='Override download root (default: /opt/logstash-agent/logstash-versions)'
    )
    list_ver_parser.add_argument(
        '--json',
        action='store_true',
        dest='list_versions_json',
        help='Emit JSON instead of a table'
    )

    ensure_ver_parser = subparsers.add_parser(
        'ensure-version',
        help='Download/extract a Logstash VERSION for multi-instance agents'
    )
    ensure_ver_parser.add_argument(
        'version',
        help='Logstash version to ensure (e.g. 9.4.3)'
    )
    ensure_ver_parser.add_argument(
        '--download-dir',
        default=None,
        help='Override download root'
    )
    ensure_ver_parser.add_argument(
        '--force',
        action='store_true',
        help='Re-download even if already present'
    )

    prune_ver_parser = subparsers.add_parser(
        'prune-versions',
        help='Remove unused Logstash VERSION trees from the download root'
    )
    prune_ver_parser.add_argument(
        '--download-dir',
        default=None,
        help='Override download root'
    )
    prune_ver_parser.add_argument(
        '--keep',
        action='append',
        default=[],
        help='Version to keep (repeatable); always keeps in-use versions'
    )
    prune_ver_parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be removed without deleting'
    )
    prune_ver_parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )

    # Configure command
    configure_parser = subparsers.add_parser(
        'configure',
        help='Apply Logstash-specific setup after Logstash is installed'
    )
    configure_parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )

    # setup-simulate: finish privileged materialization after non-root enroll
    setup_sim_parser = subparsers.add_parser(
        'setup-simulate',
        help='Materialize simulate-N dirs/units (run as root after non-root --enroll)'
    )
    setup_sim_parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )

    # recover-simulate: bare pipeline recovery after crash / bad slot config
    recover_sim_parser = subparsers.add_parser(
        'recover-simulate',
        help='Quarantine slot pipelines, re-seed simulate harness, restart ls-simulate@N'
    )
    recover_sim_parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )
    recover_sim_parser.add_argument(
        '--no-restart',
        action='store_true',
        help='Sanitize pipelines only (do not systemctl restart)'
    )
    recover_sim_parser.add_argument(
        '--force',
        action='store_true',
        help='Bypass recovery rate limits'
    )

    # Upgrade command
    upgrade_parser = subparsers.add_parser(
        'upgrade',
        help='Upgrade the agent to a new version'
    )
    upgrade_parser.add_argument(
        '--version',
        type=str,
        metavar='VERSION',
        required=True,
        help='Version to upgrade to (e.g., 0.1.4)'
    )
    upgrade_parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip the upgrade confirmation prompt'
    )

    # Legacy arguments for backward compatibility
    parser.add_argument(
        '--enroll',
        type=str,
        metavar='TOKEN',
        help='Enroll this agent with logstashui using the provided base64-encoded enrollment token'
    )

    parser.add_argument(
        '--logstash-ui-url',
        type=str,
        metavar='URL',
        help='logstashui URL for enrollment (required with --enroll, e.g., http://localhost:8080 or https://logstashui.example.com)'
    )

    parser.add_argument(
        '--run',
        action='store_true',
        help='Run the agent controller (enrolled default or simulate agents)'
    )

    parser.add_argument(
        '--mode',
        type=cli_mode_type,
        choices=list(FIRST_CLASS_MODES),
        default=None,
        help=(
            'Agent role: packaged (production), managed (enrolled instance N), '
            'simulate (enrolled sim N), embedded (docker sim). '
            'Aliases: default|agent→packaged, host→managed'
        ),
    )

    parser.add_argument(
        '--instance',
        type=int,
        metavar='N',
        default=None,
        help='Instance number N for --mode managed|simulate (logstash-agent@N / lsagent-simulate@N)',
    )

    parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip the enrollment confirmation prompt'
    )

    return parser.parse_args()


if __name__ == "__main__":
    """
    Main entry point for logstashagent

    Supports multiple modes:
    - Install mode: install command to perform enrollment and setup
    - Enrollment mode: --enroll flag to register with logstashui
    - Agent mode: mode=agent in config, checks in with logstashui
    - Simulation mode: mode=simulation in config, runs as simulation node
    - Host mode: mode=host in config, manages local Logstash instance
    """
    args = parse_arguments()

    # Check if we're in install mode
    if args.command == 'install':
        if not args.yes:
            print("\nThis will install LogstashAgent as a system service.")
            print("\nThe agent will be enrolled into LogstashUI managed mode.")
            print("\nFuture policy applies may overwrite manual changes made directly on the host, including:")
            print("  - logstash.yml")
            print("  - jvm.options")
            print("  - log4j2.properties")
            print("  - pipelines")
            print("  - keystore contents")
            print()
            answer = input("Continue? [y/N]: ").strip().lower()
            if answer != 'y':
                print("Installation cancelled.")
                sys.exit(0)

        try:
            ensure_runtime_init(create_pipeline_dirs=False)
            installer.perform_installation(
                enroll_token=args.enroll,
                logstash_ui_url=args.logstash_ui_url,
                agent_id=AGENT_ID,
                enrollment_func=enrollment.perform_enrollment,
                assume_yes=args.yes,
            )
            sys.exit(0)
        except installer.InstallError as e:
            logger.error(f"Installation failed: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected installation error: {e}", exc_info=True)
            sys.exit(1)

    # Check if we're in configure mode
    if args.command == 'configure':
        if not args.yes:
            print("\nThis will configure Logstash for agent management.")
            print("\nThe following will be applied:")
            print("  - Ownership of /etc/logstash, /var/log/logstash, /usr/share/logstash/data")
            print("    will be set to logstash:logstash")
            print("  - /etc/sudoers.d/logstash-agent will be written (passwordless sudo grants)")
            print("  - The logstash-agent systemd service will be updated to run as the logstash user")
            print()
            answer = input("Continue? [y/N]: ").strip().lower()
            if answer != 'y':
                print("Configure cancelled.")
                sys.exit(0)

        try:
            installer.perform_configure()
            sys.exit(0)
        except installer.InstallError as e:
            logger.error(f"Configure failed: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected configure error: {e}", exc_info=True)
            sys.exit(1)

    # Finish simulate host setup after non-root --enroll
    if args.command == 'setup-simulate':
        try:
            installer.perform_setup_simulate(yes=getattr(args, 'yes', False))
            sys.exit(0)
        except installer.InstallError as e:
            logger.error(f"setup-simulate failed: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected setup-simulate error: {e}", exc_info=True)
            sys.exit(1)

    # Bare recovery for simulate instance (quarantine slots + harness + restart)
    if args.command == 'recover-simulate':
        try:
            from logstashagent import simulate_recovery

            if not getattr(args, 'yes', False):
                print(
                    "\nThis will quarantine dynamic slot*-filter* pipelines, "
                    "re-seed simulate-start/end, write a bare pipelines.yml, "
                    "and restart ls-simulate@N (unless --no-restart)."
                )
                answer = input("Continue? [y/N]: ").strip().lower()
                if answer != 'y':
                    print("recover-simulate cancelled.")
                    sys.exit(0)
            result = simulate_recovery.recover_simulate_logstash(
                reason='cli recover-simulate',
                restart=not getattr(args, 'no_restart', False),
                force=getattr(args, 'force', False),
                agent_config=AGENT_CONFIG,
            )
            if not result.get('success'):
                logger.error("recover-simulate failed: %s", result.get('error'))
                sys.exit(1)
            logger.info(
                "recover-simulate ok layout=%s restarted=%s quarantine=%s",
                result.get('layout'),
                result.get('restarted'),
                (result.get('quarantine') or {}).get('quarantine_dir'),
            )
            sys.exit(0)
        except Exception as e:
            logger.error(f"Unexpected recover-simulate error: {e}", exc_info=True)
            sys.exit(1)

    # List install registry (no root required)
    if args.command == 'list-instances':
        try:
            from logstashagent import install_registry as _reg

            instances = _reg.list_instances(include_discovered=True)
            reg = _reg.load_registry()
            if getattr(args, 'list_json', False):
                print(json.dumps({
                    'package': reg.get('package'),
                    'instances': instances,
                    'registry_path': str(_reg.registry_path()),
                }, indent=2))
            else:
                pkg = reg.get('package')
                print(f"Registry: {_reg.registry_path()}")
                if pkg:
                    print(
                        f"Package: agent_version={pkg.get('agent_version') or '?'} "
                        f"updated={pkg.get('updated_at') or '?'}"
                    )
                else:
                    print("Package: (not registered)")
                print()
                print(_reg.format_instances_table(instances))
            sys.exit(0)
        except Exception as e:
            logger.error(f"list-instances failed: {e}", exc_info=True)
            sys.exit(1)

    # VERSION cache management
    if args.command == 'list-versions':
        try:
            from logstashagent import logstash_download as _ld

            root = args.download_dir or _ld.DEFAULT_DOWNLOAD_ROOT
            versions = _ld.list_installed_versions(root)
            used = _ld.collect_in_use_versions(root)
            if getattr(args, 'list_versions_json', False):
                print(json.dumps({
                    'download_root': root,
                    'versions': versions,
                    'in_use': sorted(used),
                }, indent=2))
            else:
                print(f"Download root: {root}")
                if used:
                    print(f"In use: {', '.join(sorted(used))}")
                print()
                print(_ld.format_versions_table(versions))
            sys.exit(0)
        except Exception as e:
            logger.error(f"list-versions failed: {e}", exc_info=True)
            sys.exit(1)

    if args.command == 'ensure-version':
        try:
            from logstashagent import install_registry as _reg
            from logstashagent import logstash_download as _ld

            root = args.download_dir or _ld.DEFAULT_DOWNLOAD_ROOT
            binary = _ld.ensure_logstash_version(
                args.version,
                root,
                force=bool(args.force),
            )
            try:
                _reg.register_logstash_version(
                    version=args.version,
                    binary=str(binary),
                    download_dir=root,
                )
            except Exception as reg_err:
                logger.warning("Registry update failed (version still on disk): %s", reg_err)
            print(f"Logstash {args.version} ready: {binary}")
            sys.exit(0)
        except Exception as e:
            logger.error(f"ensure-version failed: {e}", exc_info=True)
            sys.exit(1)

    if args.command == 'prune-versions':
        try:
            from logstashagent import logstash_download as _ld

            root = args.download_dir or _ld.DEFAULT_DOWNLOAD_ROOT
            keep = set(args.keep or [])
            preview = _ld.prune_versions(
                root, keep=keep, keep_used=True, dry_run=True
            )
            if not preview['removed']:
                print(f"Nothing to prune under {root}")
                if preview['kept']:
                    print(f"Kept: {', '.join(preview['kept'])}")
                sys.exit(0)
            print(f"Would remove: {', '.join(preview['removed'])}")
            print(f"Would keep:   {', '.join(preview['kept']) or '(none)'}")
            if args.dry_run:
                sys.exit(0)
            if not args.yes:
                answer = input("Continue prune? [y/N]: ").strip().lower()
                if answer != 'y':
                    print("Prune cancelled.")
                    sys.exit(0)
            result = _ld.prune_versions(
                root, keep=keep, keep_used=True, dry_run=False
            )
            print(f"Removed: {', '.join(result['removed']) or '(none)'}")
            if result['errors']:
                for err in result['errors']:
                    logger.warning("prune error: %s", err)
                sys.exit(1)
            sys.exit(0)
        except Exception as e:
            logger.error(f"prune-versions failed: {e}", exc_info=True)
            sys.exit(1)

    # Check if we're in uninstall mode
    if args.command == 'uninstall':
        instance = getattr(args, 'instance', None)
        keep_data = getattr(args, 'keep_data', False)
        if instance and args.purge:
            print(
                "Note: --purge with --instance is ignored; "
                "instance uninstall removes the path tree unless --keep-data."
            )
        if not args.yes:
            if instance:
                print(f"\nThis will uninstall multi-instance role: {instance}")
                print("  - Stop/disable its agent + Logstash systemd units")
                if keep_data:
                    print("  - Keep path tree under /opt/logstash-agent/ (--keep-data)")
                else:
                    print("  - Delete its path tree under /opt/logstash-agent/")
                print("  - Leave the package binary and other instances installed")
            else:
                print("\nThis will uninstall LogstashAgent from the system.")
                print("\nRemoved:")
                print("  - Binary: /opt/logstash-agent/bin")
                print("  - Config: /opt/logstash-agent/config")
                print("  - Systemd units (packaged + multi-instance templates)")
                print("  - Multi-instance units (stopped/disabled)")
                try:
                    from logstashagent import install_registry as _reg

                    insts = _reg.list_instances(include_discovered=True)
                    multi = [i for i in insts if (i.get('role') or '') in ('managed', 'simulate')]
                    if multi:
                        print("\nRegistered / discovered instances (stopped; trees kept unless --purge):")
                        for i in multi:
                            print(
                                f"  - {i.get('id')}: {i.get('agent_unit')}  "
                                f"{i.get('path_root') or ''}"
                            )
                        print(
                            "\nTip: remove one role only with:\n"
                            "  sudo logstash-agent uninstall --instance <id>"
                        )
                except Exception as e:
                    logger.warning(f"Failed to list instances: {e!s}")

                if args.purge:
                    print("\n--purge: also remove")
                    print("  - Entire /opt/logstash-agent (state, logs, cache, trees, downloads)")
                    print("  - CLI symlink /usr/local/bin/logstash-agent")
                    print("  - Legacy leftovers under /etc, /var/lib, /var/log, /var/cache if any")
                else:
                    print("\nPreserved under /opt/logstash-agent:")
                    print("  - state/  logs/  cache/")
                    print("  - managed-N / simulate-N trees (if any)")
                    print("  - CLI symlink /usr/local/bin/logstash-agent (until --purge)")
                    print("\nWipe everything:  sudo logstash-agent uninstall --purge")

            print()
            answer = input("Continue? [y/N]: ").strip().lower()
            if answer != 'y':
                print("Uninstallation cancelled.")
                sys.exit(0)

        try:
            installer.perform_uninstallation(
                purge=args.purge,
                instance=instance,
                keep_data=keep_data,
            )
            sys.exit(0)
        except installer.InstallError as e:
            logger.error(f"Uninstallation failed: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected uninstallation error: {e}", exc_info=True)
            sys.exit(1)

    # Check if we're in upgrade mode
    if args.command == 'upgrade':
        if not args.yes:
            print(f"\nThis will upgrade LogstashAgent to version {args.version}.")
            print("\nThe upgrade process will:")
            print(f"  1. Download version {args.version} from GitHub")
            print("  2. Stop the logstash-agent service")
            print("  3. Backup the current binary")
            print("  4. Replace the binary with the new version")
            print("  5. Restart the service")
            print("\nIf the new version fails to start, it will automatically rollback.")
            print("\nState and configuration will be preserved.")
            print()
            answer = input("Continue? [y/N]: ").strip().lower()
            if answer != 'y':
                print("Upgrade cancelled.")
                sys.exit(0)

        try:
            installer.perform_upgrade(version=args.version, auto=False)
            sys.exit(0)
        except installer.InstallError as e:
            logger.error(f"Upgrade failed: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected upgrade error: {e}", exc_info=True)
            sys.exit(1)

    # Check if we're in enrollment mode
    if args.enroll:
        logger.info("=" * 60)
        logger.info("LOGSTASH AGENT ENROLLMENT")
        logger.info("=" * 60)

        # Validate that logstash-ui-url is provided
        if not args.logstash_ui_url:
            logger.error("--logstash-ui-url is required when using --enroll")
            logger.error("Example: python main.py --enroll=TOKEN --logstash-ui-url=http://localhost:8080")
            sys.exit(1)

        if not args.yes:
            print("\nThis node will be enrolled into LogstashUI managed mode.")
            print("\nFuture policy applies may overwrite manual changes made directly on the host, including:")
            print("  - logstash.yml")
            print("  - jvm.options")
            print("  - log4j2.properties")
            print("  - pipelines")
            print("  - keystore contents")
            print()
            answer = input("Continue? [y/N]: ").strip().lower()
            if answer != 'y':
                print("Enrollment cancelled.")
                sys.exit(0)

        try:
            ensure_runtime_init(create_pipeline_dirs=False)
            enrollment.perform_enrollment(
                encoded_token=args.enroll,
                logstash_ui_url=args.logstash_ui_url,
                agent_id=AGENT_ID
            )
            sys.exit(0)
        except Exception as e:
            logger.error(f"Enrollment failed: {e}")
            sys.exit(1)

    # Setup file logging for normal operation (not install/uninstall/upgrade)
    # This creates the log file with the correct user permissions
    setup_file_logging()

    ensure_runtime_init(create_pipeline_dirs=True)

    # CLI overrides for mode / instance
    if getattr(args, 'mode', None):
        AGENT_CONFIG['mode'] = args.mode
        agent_state.update_state('mode', args.mode)
    if getattr(args, 'instance', None) is not None:
        AGENT_CONFIG['instance_id'] = args.instance
        agent_state.update_state('instance_id', args.instance)
        cli_mode = (getattr(args, 'mode', None) or agent_state.get_state().get('mode') or '').lower()
        if not agent_state.get_state().get('logstash_unit'):
            if cli_mode == 'managed':
                agent_state.update_state('logstash_unit', f'logstash-managed@{args.instance}')
                if not agent_state.get_state().get('agent_unit'):
                    agent_state.update_state('agent_unit', f'logstash-agent@{args.instance}')
            else:
                agent_state.update_state('logstash_unit', f'ls-simulate@{args.instance}')
                if not agent_state.get_state().get('agent_unit'):
                    agent_state.update_state('agent_unit', f'lsagent-simulate@{args.instance}')
        if not agent_state.get_state().get('agent_api_port'):
            base = 9600 if cli_mode == 'managed' else 9500
            agent_state.update_state('agent_api_port', base + int(args.instance))
        if not agent_state.get_state().get('logstash_api_port'):
            base = 9700 if cli_mode == 'managed' else 9560
            agent_state.update_state('logstash_api_port', base + int(args.instance))

    # Resolve effective mode: CLI > state > config (with legacy mapping)
    state_preview = agent_state.get_state()
    raw_mode = (
        getattr(args, 'mode', None)
        or state_preview.get('mode')
        or AGENT_CONFIG.get('mode')
        or 'embedded'
    )
    mode_probe = normalize_agent_mode({
        'mode': raw_mode,
        'simulation_mode': AGENT_CONFIG.get('simulation_mode'),
    })
    agent_mode = mode_probe.get('mode', 'embedded')
    mode_legacy = mode_probe.get('_mode_legacy') or AGENT_CONFIG.get('_mode_legacy')
    mode_source = (
        'cli' if getattr(args, 'mode', None)
        else ('state' if state_preview.get('mode') else 'config')
    )
    log_resolved_agent_mode(agent_mode, legacy=mode_legacy, source=mode_source)

    # Check if we're in run mode (controller for enrolled packaged/managed/simulate agents)
    if args.run:
        # Persist the Logstash API port from config/state so check_in uses the right port.
        # packaged: 9600; simulate: 9560+N; managed: 9700+N; embedded: 9560
        state = agent_state.get_state()
        if state.get('logstash_api_port'):
            logstash_api_port = state.get('logstash_api_port')
        elif agent_mode == 'simulate' and state.get('instance_id') is not None:
            logstash_api_port = 9560 + int(state['instance_id'])
        elif agent_mode == 'managed' and state.get('instance_id') is not None:
            logstash_api_port = 9700 + int(state['instance_id'])
        elif agent_mode == 'embedded':
            logstash_api_port = AGENT_CONFIG.get('logstash_api_port', 9560)
        else:
            logstash_api_port = AGENT_CONFIG.get('logstash_api_port', 9600)
        agent_state.update_state('api_port', logstash_api_port)
        # Persist normalized mode so later restarts and status_blob use the new vocabulary
        if not state.get('mode') or mode_legacy:
            agent_state.update_state('mode', agent_mode)
        logger.info(f"Logstash API port set to {logstash_api_port} (mode={agent_mode})")

        if agent_mode in ('simulate', 'managed'):
            # Multi-instance agents need controller reconciliation + FastAPI agent API.
            # Run controller in a background thread; uvicorn serves routes on agent port.
            import threading
            t = threading.Thread(
                target=controller.run_controller,
                name=f'{agent_mode}-controller',
                daemon=True,
            )
            t.start()
            default_base = 9600 if agent_mode == 'managed' else 9500
            agent_port = (
                state.get('agent_api_port')
                or AGENT_CONFIG.get('port')
                or (default_base + int(state['instance_id']) if state.get('instance_id') is not None else default_base)
            )
            logger.info(f"Starting {agent_mode} FastAPI on port {agent_port}")
            try:
                from logstashagent import tls_server

                tls_server.ensure_agent_server_tls(agent_config=AGENT_CONFIG)
                ssl_kw = tls_server.uvicorn_ssl_kwargs()
            except Exception as e:
                logger.warning("Agent server TLS setup failed: %s", e)
                ssl_kw = {}
            if ssl_kw:
                logger.info("%s FastAPI serving HTTPS (product-CA cert)", agent_mode.capitalize())
            else:
                logger.warning("%s FastAPI serving HTTP (no agent server cert yet)", agent_mode.capitalize())
            uvicorn.run(app, host="0.0.0.0", port=int(agent_port), **ssl_kw)
            sys.exit(0)

        controller.run_controller()
        sys.exit(0)

    # Non-run entry: FastAPI for embedded (and legacy simulation) only
    if agent_mode in ('default', 'packaged'):
        logger.info("mode=%s requires --run after enrollment (controller only)", agent_mode)
        sys.exit(1)
    if agent_mode not in ('embedded', 'simulate', 'managed', 'simulation'):
        logger.info(f"Unrecognized mode {agent_mode}; starting embedded-style FastAPI")
        # fall through to FastAPI

    # Start FastAPI server (simulation or host mode)


    # Get host and port from config or use defaults
    host = AGENT_CONFIG.get('host', '0.0.0.0')
    port = AGENT_CONFIG.get('port', 9500)
    env_port = (os.environ.get('LOGSTASH_AGENT_PORT') or '').strip()
    if env_port.isdigit():
        port = int(env_port)

    logger.info(f"Starting logstashagent in {agent_mode} mode on {host}:{port}")

    try:
        from logstashagent import tls_server

        # Embedded/compose: issue cert via LOGSTASHUI_AGENT_CSR_SECRET or prior enroll
        tls_server.ensure_agent_server_tls(agent_config=AGENT_CONFIG)
        ssl_kw = tls_server.uvicorn_ssl_kwargs()
    except Exception as e:
        logger.warning("Agent server TLS setup failed: %s", e)
        ssl_kw = {}
    if ssl_kw:
        logger.info("Agent FastAPI serving HTTPS on %s:%s (product-CA cert)", host, port)
    else:
        logger.warning(
            "Agent FastAPI serving HTTP on %s:%s — set LOGSTASH_UI_URL + "
            "LOGSTASHUI_AGENT_CSR_SECRET or enroll to obtain a server cert",
            host,
            port,
        )

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        **ssl_kw,
    )
