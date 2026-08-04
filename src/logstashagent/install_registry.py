#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Host install registry — tracks package install + multi-instance deployments.

Stored at ``/opt/logstash-agent/state/install-registry.json`` so uninstall can
stop the right units and remove managed-/simulate- trees (per-instance or
``--purge`` for a full wipe).
"""

from __future__ import annotations

import json
import logging
import os
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

REGISTRY_VERSION = 1
REGISTRY_FILENAME = "install-registry.json"

# Match managed-N / simulate-N directory names under /opt/logstash-agent
_INSTANCE_DIR_RE = re.compile(r"^(managed|simulate)-([0-9]+)$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def registry_path(state_dir: Optional[str] = None) -> Path:
    """Path to install-registry.json (default production state_dir)."""
    if state_dir is None:
        try:
            from logstashagent.installer import INSTALL_PATHS

            state_dir = INSTALL_PATHS["state_dir"]
        except Exception:
            state_dir = "/opt/logstash-agent/state"
    return Path(state_dir) / REGISTRY_FILENAME


def empty_registry() -> dict[str, Any]:
    return {
        "version": REGISTRY_VERSION,
        "updated_at": _utc_now(),
        "package": None,
        "instances": {},
    }


def load_registry(state_dir: Optional[str] = None) -> dict[str, Any]:
    """Load registry from disk; return empty structure if missing/corrupt."""
    path = registry_path(state_dir)
    if not path.is_file():
        return empty_registry()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("Install registry is not an object; resetting")
            return empty_registry()
        data.setdefault("version", REGISTRY_VERSION)
        data.setdefault("instances", {})
        if not isinstance(data["instances"], dict):
            data["instances"] = {}
        data.setdefault("package", None)
        return data
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not read install registry %s: %s", path, e)
        return empty_registry()


def save_registry(reg: dict[str, Any], state_dir: Optional[str] = None) -> Path:
    """Atomic-ish write of registry JSON. Returns path written."""
    path = registry_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    reg = deepcopy(reg)
    reg["version"] = REGISTRY_VERSION
    reg["updated_at"] = _utc_now()
    tmp = path.with_suffix(".tmp")
    payload = json.dumps(reg, indent=2, sort_keys=True) + "\n"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(payload)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass
    # Best-effort ownership to logstash when available
    try:
        from logstashagent.installer import get_logstash_uid_gid

        uid, gid = get_logstash_uid_gid()
        os.chown(path, uid, gid)
    except Exception:
        pass
    logger.debug("Wrote install registry %s", path)
    return path


def instance_key(role: str, instance_id: Optional[int] = None) -> str:
    """
    Stable registry key for an instance.

    packaged/default → ``packaged``
    managed + N → ``managed-N``
    simulate + N → ``simulate-N``
    """
    r = (role or "").strip().lower()
    if r in ("packaged", "default", "package", ""):
        return "packaged"
    if r in ("managed", "simulate"):
        if instance_id is None:
            raise ValueError(f"instance_id required for role={r}")
        return f"{r}-{int(instance_id)}"
    # Allow passing full key already
    if _INSTANCE_DIR_RE.match(r) or r == "packaged":
        return r
    raise ValueError(f"Unknown role for registry key: {role!r}")


def register_package(
    *,
    agent_version: str = "",
    agent_id: Optional[str] = None,
    state_dir: Optional[str] = None,
    extra_paths: Optional[dict] = None,
) -> dict[str, Any]:
    """Record host package install (binary, shared unit templates, paths)."""
    from logstashagent.installer import INSTALL_PATHS

    reg = load_registry(state_dir)
    shared_units = [
        INSTALL_PATHS.get("systemd_service", "/etc/systemd/system/logstash-agent.service"),
        INSTALL_PATHS.get("lsagent_simulate_unit", ""),
        INSTALL_PATHS.get("ls_simulate_unit", ""),
        INSTALL_PATHS.get("logstash_agent_template_unit", ""),
        INSTALL_PATHS.get("logstash_managed_unit", ""),
    ]
    reg["package"] = {
        "installed_at": (reg.get("package") or {}).get("installed_at") or _utc_now(),
        "updated_at": _utc_now(),
        "agent_version": agent_version or "",
        "agent_id": agent_id,
        "paths": {
            "binary_dir": INSTALL_PATHS["binary_dir"],
            "binary": INSTALL_PATHS["binary"],
            "symlink": INSTALL_PATHS["symlink"],
            "systemctl_ctl": INSTALL_PATHS["systemctl_ctl"],
            "config_dir": INSTALL_PATHS["config_dir"],
            "state_dir": INSTALL_PATHS["state_dir"],
            "log_dir": INSTALL_PATHS["log_dir"],
            "cache_dir": INSTALL_PATHS["cache_dir"],
            "simulate_root": INSTALL_PATHS["simulate_root"],
            **(extra_paths or {}),
        },
        "shared_units": [u for u in shared_units if u],
        "sudoers": "/etc/sudoers.d/logstash-agent",
    }
    save_registry(reg, state_dir)
    logger.info("Registered package install in %s", registry_path(state_dir))
    return reg


def register_instance(
    *,
    role: str,
    instance_id: Optional[int] = None,
    agent_unit: str,
    logstash_unit: str,
    path_root: Optional[str] = None,
    agent_api_port: Optional[int] = None,
    logstash_api_port: Optional[int] = None,
    policy_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    connection_id: Optional[int] = None,
    policy_id: Optional[int] = None,
    deployment_id: Optional[str] = None,
    state_dir: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict[str, Any]:
    """Upsert an instance entry (packaged / managed-N / simulate-N)."""
    key = instance_key(role, instance_id)
    reg = load_registry(state_dir)
    existing = (reg.get("instances") or {}).get(key) or {}
    entry = {
        "id": key,
        "role": role.lower() if role else key.split("-")[0],
        "instance_id": int(instance_id) if instance_id is not None else existing.get("instance_id"),
        "agent_unit": agent_unit,
        "logstash_unit": logstash_unit,
        "path_root": path_root,
        "agent_api_port": agent_api_port,
        "logstash_api_port": logstash_api_port,
        "policy_type": (policy_type or existing.get("policy_type") or "").upper() or None,
        "agent_id": agent_id or existing.get("agent_id"),
        "connection_id": connection_id if connection_id is not None else existing.get("connection_id"),
        "policy_id": policy_id if policy_id is not None else existing.get("policy_id"),
        "deployment_id": deployment_id or existing.get("deployment_id") or key,
        "installed_at": existing.get("installed_at") or _utc_now(),
        "updated_at": _utc_now(),
    }
    if extra:
        entry.update(extra)
    reg.setdefault("instances", {})[key] = entry
    save_registry(reg, state_dir)
    logger.info("Registered instance %s (units %s / %s)", key, agent_unit, logstash_unit)
    return entry


def unregister_instance(key: str, state_dir: Optional[str] = None) -> bool:
    """Remove an instance entry. Returns True if it existed."""
    reg = load_registry(state_dir)
    instances = reg.get("instances") or {}
    if key not in instances:
        return False
    del instances[key]
    reg["instances"] = instances
    save_registry(reg, state_dir)
    logger.info("Unregistered instance %s", key)
    return True


def list_instances(
    state_dir: Optional[str] = None,
    *,
    include_discovered: bool = True,
) -> list[dict[str, Any]]:
    """
    Return instance entries, optionally merging filesystem discovery for
    managed-/simulate- trees not yet in the registry.
    """
    reg = load_registry(state_dir)
    instances = dict(reg.get("instances") or {})
    if include_discovered:
        for disc in discover_instances_from_disk():
            if disc["id"] not in instances:
                disc["discovered"] = True
                instances[disc["id"]] = disc
    # packaged entry from package only
    out = list(instances.values())
    out.sort(key=lambda e: (e.get("role") or "", e.get("instance_id") or 0, e.get("id") or ""))
    return out


def discover_instances_from_disk(
    opt_root: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Scan /opt/logstash-agent for managed-N / simulate-N directories."""
    if opt_root is None:
        try:
            from logstashagent.installer import INSTALL_PATHS

            opt_root = INSTALL_PATHS["simulate_root"]
        except Exception:
            opt_root = "/opt/logstash-agent"
    root = Path(opt_root)
    found: list[dict[str, Any]] = []
    if not root.is_dir():
        return found
    try:
        names = os.listdir(root)
    except OSError:
        return found
    for name in names:
        m = _INSTANCE_DIR_RE.match(name)
        if not m:
            continue
        role, n_s = m.group(1), m.group(2)
        n = int(n_s)
        path_root = str(root / name)
        if role == "managed":
            agent_unit = f"logstash-agent@{n}"
            logstash_unit = f"logstash-managed@{n}"
            agent_port = 9600 + n
            ls_port = 9700 + n
        else:
            agent_unit = f"lsagent-simulate@{n}"
            logstash_unit = f"ls-simulate@{n}"
            agent_port = 9500 + n
            ls_port = 9560 + n
        found.append(
            {
                "id": f"{role}-{n}",
                "role": role,
                "instance_id": n,
                "agent_unit": agent_unit,
                "logstash_unit": logstash_unit,
                "path_root": path_root,
                "agent_api_port": agent_port,
                "logstash_api_port": ls_port,
                "policy_type": role.upper(),
                "deployment_id": f"{role}-{n}",
                "discovered": True,
            }
        )
    return found


def format_instances_table(instances: list[dict[str, Any]]) -> str:
    """Human-readable listing for CLI."""
    if not instances:
        return "(no registered or discovered instances)"
    lines = [
        f"{'ID':<14} {'ROLE':<10} {'AGENT UNIT':<24} {'LOGSTASH UNIT':<22} {'PATH'}",
        "-" * 90,
    ]
    for e in instances:
        lines.append(
            f"{(e.get('id') or ''):<14} "
            f"{(e.get('role') or ''):<10} "
            f"{(e.get('agent_unit') or ''):<24} "
            f"{(e.get('logstash_unit') or ''):<22} "
            f"{e.get('path_root') or '-'}"
        )
    lines.append("")
    lines.append("Day-2: sudo systemctl status <AGENT UNIT>   # or logstash-agent-ctl status …")
    lines.append("Remove one role:  sudo logstash-agent uninstall --instance <ID>")
    lines.append("  e.g. sudo logstash-agent uninstall --instance simulate-1")
    lines.append("State: packaged → /opt/logstash-agent/state ; multi → {path}/state")
    lines.append("Config: packaged → /opt/logstash-agent/config/logstash-agent.yml ; multi → {path}/logstash-agent.yml")
    lines.append("Logs:   packaged → /opt/logstash-agent/logs")
    return "\n".join(lines)


def stop_disable_unit(unit: str) -> None:
    """Best-effort stop + disable a systemd unit."""
    if not unit:
        return
    import subprocess

    try:
        from logstashagent.installer import host_subprocess_env, _systemctl_bin

        env = host_subprocess_env()
        systemctl = _systemctl_bin()
    except Exception:
        env = None
        systemctl = "systemctl"

    for action in ("stop", "disable"):
        try:
            subprocess.run(
                [systemctl, action, unit],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )
        except Exception as e:
            logger.warning("systemctl %s %s failed: %s", action, unit, e)


def remove_path_tree(path: Optional[str]) -> bool:
    """Remove a path_root directory tree. Returns True if removed."""
    if not path:
        return False
    p = Path(path)
    # Safety: only under /opt/logstash-agent/(managed|simulate)-N
    try:
        resolved = p.resolve()
    except OSError:
        resolved = p
    parts = resolved.parts
    if len(parts) < 3:
        logger.warning("Refusing to remove suspicious path_root %s", path)
        return False
    # Expect .../logstash-agent/managed-N or simulate-N
    name = resolved.name
    if not _INSTANCE_DIR_RE.match(name):
        logger.warning("Refusing to remove non-instance path_root %s", path)
        return False
    if "logstash-agent" not in parts and "LogstashAgent" not in parts:
        logger.warning("Refusing to remove path outside logstash-agent tree: %s", path)
        return False
    if not resolved.exists():
        return False
    import shutil

    shutil.rmtree(resolved)
    logger.info("✓ Removed instance tree %s", resolved)
    return True


def teardown_instance(
    entry: dict[str, Any],
    *,
    purge_paths: bool = False,
    state_dir: Optional[str] = None,
    unregister: bool = True,
) -> None:
    """Stop units for one instance; optionally delete path_root and unregister."""
    agent_unit = entry.get("agent_unit") or ""
    logstash_unit = entry.get("logstash_unit") or ""
    # Never stop distro logstash on packaged teardown of multi-instance only
    if logstash_unit == "logstash" and entry.get("role") in ("managed", "simulate"):
        logstash_unit = ""
    logger.info(
        "Tearing down instance %s (agent=%s logstash=%s)",
        entry.get("id"),
        agent_unit,
        logstash_unit,
    )
    if agent_unit:
        stop_disable_unit(agent_unit)
    if logstash_unit and logstash_unit != "logstash":
        # For packaged role, leave distro logstash alone unless purge of whole host
        stop_disable_unit(logstash_unit)
    elif logstash_unit == "logstash" and entry.get("role") in ("packaged", "default"):
        # Do not stop live distro logstash on agent uninstall (live-safety)
        logger.info("Leaving distro logstash unit running (agent uninstall does not stop it)")
    if purge_paths:
        remove_path_tree(entry.get("path_root"))
    if unregister and entry.get("id"):
        unregister_instance(entry["id"], state_dir=state_dir)


def teardown_all_instances(
    *,
    purge_paths: bool = False,
    state_dir: Optional[str] = None,
    roles: Optional[set[str]] = None,
) -> list[str]:
    """
    Tear down all registered (+ discovered) instances.

    Returns list of instance ids handled.
    """
    handled: list[str] = []
    for entry in list_instances(state_dir, include_discovered=True):
        role = (entry.get("role") or "").lower()
        if roles is not None and role not in roles:
            continue
        teardown_instance(
            entry,
            purge_paths=purge_paths,
            state_dir=state_dir,
            unregister=True,
        )
        handled.append(entry.get("id") or "")
    return handled


def register_logstash_version(
    *,
    version: str,
    binary: str,
    download_dir: str,
    used_by: Optional[str] = None,
    state_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Record a downloaded Logstash VERSION tree in the install registry."""
    version = (version or "").strip()
    if not version:
        raise ValueError("version required")
    reg = load_registry(state_dir)
    versions = reg.setdefault("logstash_versions", {})
    if not isinstance(versions, dict):
        versions = {}
        reg["logstash_versions"] = versions
    prev = versions.get(version) or {}
    entry = {
        "version": version,
        "binary": binary,
        "download_dir": download_dir,
        "installed_at": prev.get("installed_at") or _utc_now(),
        "last_used_at": _utc_now(),
        "used_by": used_by or prev.get("used_by"),
    }
    versions[version] = entry
    save_registry(reg, state_dir)
    logger.info("Registered Logstash VERSION %s at %s", version, binary)
    return entry


def remove_shared_unit_files(reg: Optional[dict] = None) -> None:
    """Remove package-level systemd unit files recorded in the registry."""
    from logstashagent.installer import INSTALL_PATHS

    units = []
    if reg and reg.get("package") and reg["package"].get("shared_units"):
        units = list(reg["package"]["shared_units"])
    else:
        units = [
            INSTALL_PATHS.get("systemd_service"),
            INSTALL_PATHS.get("lsagent_simulate_unit"),
            INSTALL_PATHS.get("ls_simulate_unit"),
            INSTALL_PATHS.get("logstash_agent_template_unit"),
            INSTALL_PATHS.get("logstash_managed_unit"),
        ]
    for path in units:
        if not path:
            continue
        try:
            if os.path.isfile(path):
                os.remove(path)
                logger.info("✓ Removed unit file %s", path)
        except OSError as e:
            logger.warning("Could not remove %s: %s", path, e)
