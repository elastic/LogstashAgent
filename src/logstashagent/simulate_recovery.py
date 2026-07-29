#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Bare recovery for simulation Logstash instances.

When Logstash crashes or becomes unresponsive under a bad slot pipeline,
we:
  1. Quarantine dynamic ``slot*-filter*.conf`` (and related yml entries)
  2. Re-seed static harness ``simulate-start`` / ``simulate-end``
  3. Write a bare ``pipelines.yml`` with only those two pipelines
  4. Clear in-memory slots
  5. Restart via systemd (``ls-simulate@N``) when requested

This is distinct from production check-in pipelines: sim uses the slot harness
only (see analysis of slot{N}-filter{i} naming).
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

STATIC_PIPELINE_IDS = ('simulate-start', 'simulate-end')
STATIC_CONF_NAMES = {
    'simulate-start': 'simulate_start.conf',
    'simulate-end': 'simulate_end.conf',
}

# Restart storm protection (module-level)
_recovery_times: list[float] = []
_MAX_RECOVERIES_PER_HOUR = 5
_MIN_SECONDS_BETWEEN_RECOVERIES = 45


def package_simulate_conf_dir() -> Path:
    """Directory of shipped simulate_start/end templates."""
    return Path(__file__).resolve().parent / 'config' / 'simulate'


def resolve_settings_path(
    settings_path: Optional[str] = None,
    agent_config: Optional[dict] = None,
) -> Path:
    """
    Resolve Logstash path.settings for this agent.

    Prefers explicit arg, then agent state / policy_config, then agent_config.
    """
    if settings_path:
        return Path(str(settings_path).rstrip('/\\'))

    try:
        from logstashagent import agent_state

        state = agent_state.get_state() or {}
    except Exception:
        state = {}

    path = (
        state.get('settings_path')
        or (state.get('policy_config') or {}).get('settings_path')
    )
    if not path and agent_config:
        path = agent_config.get('logstash_settings') or agent_config.get('settings_path')
    if not path:
        try:
            from logstashagent import main as _main

            path = (_main.AGENT_CONFIG or {}).get('logstash_settings')
        except Exception:
            path = None
    if not path:
        path = '/etc/logstash'
    return Path(str(path).rstrip('/\\'))


def _config_dir(settings_path: Path) -> Path:
    """Directory holding simulate_start.conf / simulate_end.conf (next to settings)."""
    # _save_pipelines_yml uses {settings}/config/simulate_*.conf
    return settings_path / 'config'


def _conf_d(settings_path: Path) -> Path:
    return settings_path / 'conf.d'


def _metadata_dir(settings_path: Path) -> Path:
    return settings_path / 'pipeline-metadata'


def _pipelines_yml(settings_path: Path) -> Path:
    return settings_path / 'pipelines.yml'


def seed_static_harness(settings_path: Path, force: bool = False) -> dict[str, Any]:
    """
    Ensure simulate_start.conf and simulate_end.conf exist under settings/config/.

    Copies from packaged templates when missing (or always when force=True).
    """
    settings_path = Path(settings_path)
    cfg = _config_dir(settings_path)
    cfg.mkdir(parents=True, exist_ok=True)
    src_dir = package_simulate_conf_dir()
    written = []
    missing_src = []

    for pipeline_id, conf_name in STATIC_CONF_NAMES.items():
        dest = cfg / conf_name
        src = src_dir / conf_name
        if not src.is_file():
            missing_src.append(str(src))
            logger.error("Packaged simulate conf missing: %s", src)
            continue
        if force or not dest.is_file():
            shutil.copy2(src, dest)
            written.append(str(dest))
            logger.info("Seeded static harness conf: %s", dest)

    return {
        'config_dir': str(cfg),
        'written': written,
        'missing_src': missing_src,
        'ok': not missing_src,
    }


def write_bare_pipelines_yml(settings_path: Path) -> Path:
    """
    Write pipelines.yml with only simulate-start and simulate-end.

    Paths match agent _save_pipelines_yml layout:
    ``{settings}/config/simulate_{start,end}.conf``.
    """
    settings_path = Path(settings_path)
    settings_path.mkdir(parents=True, exist_ok=True)
    yml_path = _pipelines_yml(settings_path)
    # Forward slashes in YAML (Logstash on Linux)
    base = str(settings_path).replace('\\', '/').rstrip('/') + '/'
    pipelines = [
        {
            'pipeline.id': 'simulate-start',
            'pipeline.workers': 1,
            'path.config': f'{base}config/simulate_start.conf',
        },
        {
            'pipeline.id': 'simulate-end',
            'pipeline.workers': 1,
            'path.config': f'{base}config/simulate_end.conf',
        },
    ]
    tmp = yml_path.with_suffix('.yml.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(
            "# Bare simulate recovery layout — static harness only.\n"
            "# Dynamic slot{N}-filter* pipelines are re-created by "
            "/_logstash/slots/allocate.\n"
        )
        yaml.dump(pipelines, f, default_flow_style=False, sort_keys=False)
    os.replace(tmp, yml_path)
    logger.info("Wrote bare simulate pipelines.yml at %s", yml_path)
    return yml_path


def write_health_null_fallback(settings_path: Path) -> Path:
    """Last-resort single empty pipeline if harness confs cannot be seeded."""
    settings_path = Path(settings_path)
    conf_d = _conf_d(settings_path)
    conf_d.mkdir(parents=True, exist_ok=True)
    conf_path = conf_d / 'health-null.conf'
    conf_path.write_text(
        "input { }\nfilter { }\noutput { }\n",
        encoding='utf-8',
    )
    yml_path = _pipelines_yml(settings_path)
    base = str(settings_path).replace('\\', '/').rstrip('/') + '/'
    pipelines = [
        {
            'pipeline.id': 'health-null',
            'pipeline.workers': 1,
            'path.config': f'{base}conf.d/health-null.conf',
        }
    ]
    tmp = yml_path.with_suffix('.yml.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        yaml.dump(pipelines, f, default_flow_style=False, sort_keys=False)
    os.replace(tmp, yml_path)
    logger.warning("Wrote health-null fallback pipelines.yml (harness unavailable)")
    return yml_path


def quarantine_dynamic_pipelines(settings_path: Path) -> dict[str, Any]:
    """
    Move slot* confs and non-static pipeline metadata into a quarantine dir.

    Does not delete so operators can inspect crash culprits.
    """
    settings_path = Path(settings_path)
    conf_d = _conf_d(settings_path)
    meta = _metadata_dir(settings_path)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    quarantine_root = settings_path / 'quarantine' / ts
    moved = []

    if conf_d.is_dir():
        q_conf = quarantine_root / 'conf.d'
        for name in list(os.listdir(conf_d)):
            # Dynamic sim slots and any stray health-null from prior recovery
            if not (
                (name.startswith('slot') and name.endswith('.conf'))
                or name == 'health-null.conf'
            ):
                continue
            q_conf.mkdir(parents=True, exist_ok=True)
            src = conf_d / name
            dest = q_conf / name
            try:
                shutil.move(str(src), str(dest))
                moved.append(str(dest))
            except OSError as e:
                logger.warning("Could not quarantine %s: %s", src, e)

    if meta.is_dir():
        q_meta = quarantine_root / 'pipeline-metadata'
        for name in list(os.listdir(meta)):
            # metadata files often named after pipeline id
            stem = name.split('.')[0]
            if stem.startswith('slot') or stem == 'health-null':
                q_meta.mkdir(parents=True, exist_ok=True)
                src = meta / name
                dest = q_meta / name
                try:
                    shutil.move(str(src), str(dest))
                    moved.append(str(dest))
                except OSError as e:
                    logger.warning("Could not quarantine metadata %s: %s", src, e)

    # Also quarantine prior pipelines.yml if present
    yml = _pipelines_yml(settings_path)
    if yml.is_file():
        quarantine_root.mkdir(parents=True, exist_ok=True)
        dest = quarantine_root / 'pipelines.yml'
        try:
            shutil.copy2(yml, dest)
            moved.append(str(dest))
        except OSError as e:
            logger.warning("Could not copy pipelines.yml to quarantine: %s", e)

    return {
        'quarantine_dir': str(quarantine_root) if moved else None,
        'moved': moved,
    }


def clear_slot_state() -> None:
    """Clear in-memory simulation slots so they do not reference deleted pipelines."""
    try:
        from logstashagent import slots

        slots.clear_all_slots()
        logger.info("Cleared in-memory simulation slots")
    except Exception as e:
        logger.warning("Could not clear slots state: %s", e)


def _recovery_allowed() -> tuple[bool, str]:
    """Rate-limit recoveries to avoid restart storms."""
    global _recovery_times
    now = time.time()
    _recovery_times = [t for t in _recovery_times if now - t < 3600]
    if _recovery_times and (now - _recovery_times[-1]) < _MIN_SECONDS_BETWEEN_RECOVERIES:
        return False, (
            f"recovery cooldown ({_MIN_SECONDS_BETWEEN_RECOVERIES}s since last)"
        )
    if len(_recovery_times) >= _MAX_RECOVERIES_PER_HOUR:
        return False, (
            f"max recoveries/hour reached ({_MAX_RECOVERIES_PER_HOUR})"
        )
    return True, ''


def sanitize_simulate_pipelines(
    settings_path: Optional[str] = None,
    *,
    agent_config: Optional[dict] = None,
) -> dict[str, Any]:
    """
    Quarantine dynamic slot pipelines and install bare static harness.

    Does not restart Logstash.
    """
    settings = resolve_settings_path(settings_path, agent_config=agent_config)
    logger.warning("Sanitizing simulate pipelines under %s", settings)

    _conf_d(settings).mkdir(parents=True, exist_ok=True)
    _config_dir(settings).mkdir(parents=True, exist_ok=True)

    quarantine = quarantine_dynamic_pipelines(settings)
    clear_slot_state()
    seed = seed_static_harness(settings, force=True)

    if seed.get('ok'):
        yml = write_bare_pipelines_yml(settings)
        layout = 'harness'
    else:
        yml = write_health_null_fallback(settings)
        layout = 'health-null'

    try:
        from logstashagent import agent_state

        agent_state.update_state(
            'simulate_last_recovery_at',
            datetime.now(timezone.utc).isoformat(),
        )
        agent_state.update_state('simulate_pipelines_quarantined', True)
    except Exception as e:
        logger.debug("Could not update recovery state flags: %s", e)

    return {
        'success': True,
        'settings_path': str(settings),
        'layout': layout,
        'pipelines_yml': str(yml),
        'quarantine': quarantine,
        'seed': seed,
    }


def recover_simulate_logstash(
    reason: str = 'unspecified',
    *,
    settings_path: Optional[str] = None,
    restart: bool = True,
    force: bool = False,
    agent_config: Optional[dict] = None,
) -> dict[str, Any]:
    """
    Full bare recovery: sanitize pipelines, then optionally systemctl-restart Logstash.

    Args:
        reason: Log-friendly cause (watchdog, sim failure, CLI, …).
        settings_path: Override path.settings.
        restart: Call controller.restart_logstash when True.
        force: Bypass rate limiting.
        agent_config: Optional config dict for path resolution.
    """
    global _recovery_times

    if not force:
        ok, msg = _recovery_allowed()
        if not ok:
            logger.error("Simulate recovery denied: %s (reason=%s)", msg, reason)
            return {'success': False, 'denied': True, 'error': msg, 'reason': reason}

    logger.warning("=== SIMULATE BARE RECOVERY start reason=%s ===", reason)
    try:
        result = sanitize_simulate_pipelines(
            settings_path, agent_config=agent_config
        )
    except Exception as e:
        logger.error("Sanitize failed: %s", e, exc_info=True)
        return {'success': False, 'error': str(e), 'reason': reason}

    result['reason'] = reason
    result['restarted'] = False

    if restart:
        try:
            from logstashagent import controller

            restarted = bool(controller.restart_logstash())
            result['restarted'] = restarted
            if not restarted:
                result['success'] = False
                result['error'] = 'sanitize ok but systemctl restart failed'
                logger.error(result['error'])
            else:
                _recovery_times.append(time.time())
                logger.warning(
                    "=== SIMULATE BARE RECOVERY complete (restarted via systemctl) ==="
                )
        except Exception as e:
            result['success'] = False
            result['error'] = f'restart error: {e}'
            logger.error(result['error'], exc_info=True)
    else:
        _recovery_times.append(time.time())
        logger.warning("=== SIMULATE BARE RECOVERY sanitize-only complete ===")

    return result
