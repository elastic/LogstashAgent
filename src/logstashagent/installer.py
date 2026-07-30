#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import os
import sys
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Optional

# Unix-only imports
try:
    import pwd
    import grp
except ImportError:
    # Not on Unix - installer won't work but module can still be imported
    pwd = None
    grp = None

logger = logging.getLogger(__name__)

INSTALL_PATHS = {
    'binary_dir': '/opt/logstash-agent/bin',
    'binary': '/opt/logstash-agent/bin/logstash-agent',
    'symlink': '/usr/local/bin/logstash-agent',
    # Validated systemctl wrapper (sudo-rs compatible — no wildcards in sudoers args)
    'systemctl_ctl': '/opt/logstash-agent/bin/logstash-agent-ctl',
    'config_dir': '/etc/logstash-agent',
    'state_dir': '/var/lib/logstash-agent',
    'log_dir': '/var/log/logstash-agent',
    'cache_dir': '/var/cache/logstash-agent',
    'systemd_service': '/etc/systemd/system/logstash-agent.service',
    'simulate_root': '/opt/logstash-agent',
    'lsagent_simulate_unit': '/etc/systemd/system/lsagent-simulate@.service',
    'ls_simulate_unit': '/etc/systemd/system/ls-simulate@.service',
}

# Shell helper invoked via sudo; validates unit names so sudoers need no arg wildcards
# (sudo-rs / Ubuntu 26+ rejects patterns like systemctl restart ls-simulate@*).
_SYSTEMCTL_CTL_SCRIPT = r'''#!/bin/sh
#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# Managed by logstash-agent install — do not edit by hand.
# Usage: logstash-agent-ctl <start|stop|restart|status|is-active|enable|disable> <unit>
set -eu
ACTION="${1:-}"
UNIT="${2:-}"
if [ -z "$ACTION" ] || [ -z "$UNIT" ]; then
  echo "usage: logstash-agent-ctl <action> <unit>" >&2
  exit 2
fi
case "$ACTION" in
  start|stop|restart|status|is-active|enable|disable) ;;
  *)
    echo "logstash-agent-ctl: disallowed action: $ACTION" >&2
    exit 2
    ;;
esac
# Allow fixed units and template instances with numeric instance ids only
if ! echo "$UNIT" | grep -Eq '^(logstash|logstash-agent|(ls-simulate|lsagent-simulate)@[0-9]+)$'; then
  echo "logstash-agent-ctl: disallowed unit: $UNIT" >&2
  exit 2
fi
SYSTEMCTL="$(command -v systemctl 2>/dev/null || true)"
if [ -z "$SYSTEMCTL" ]; then
  if [ -x /usr/bin/systemctl ]; then
    SYSTEMCTL=/usr/bin/systemctl
  else
    echo "logstash-agent-ctl: systemctl not found" >&2
    exit 127
  fi
fi
exec "$SYSTEMCTL" "$ACTION" "$UNIT"
'''


def install_systemctl_ctl() -> str:
    """
    Install the validated systemctl wrapper used by sudoers (path returned).
    Safe for both GNU sudo and sudo-rs (no wildcards in sudoers command args).
    """
    path = INSTALL_PATHS['systemctl_ctl']
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(_SYSTEMCTL_CTL_SCRIPT)
    os.chmod(path, 0o755)
    logger.info("✓ Installed systemctl helper: %s", path)
    return path

def _systemd_template_dir() -> Path:
    """
    Directory with lsagent-simulate@.service / ls-simulate@.service templates.

    Dev: package source tree. PyInstaller COLLECT: _internal/logstashagent/systemd/
    """
    beside = Path(__file__).resolve().parent / 'systemd'
    if beside.is_dir() and any(beside.glob('*.service')):
        return beside
    # Frozen / alternate layouts
    candidates = []
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidates.append(Path(meipass) / 'logstashagent' / 'systemd')
    exe = Path(sys.executable).resolve()
    candidates.extend([
        exe.parent / '_internal' / 'logstashagent' / 'systemd',
        exe.parent.parent / '_internal' / 'logstashagent' / 'systemd',
        exe.parent / 'logstashagent' / 'systemd',
    ])
    for c in candidates:
        if c.is_dir() and any(c.glob('*.service')):
            return c
    return beside


def _build_systemd_service() -> str:
    """
    Build the systemd service unit content.

    Runs as the logstash user/group when that account exists (i.e. Logstash is
    installed).  Falls back to root when Logstash is not yet present so the
    service can still be registered and start once Logstash is installed later.
    """
    try:
        pwd.getpwnam('logstash')
        grp.getgrnam('logstash')
        user_lines = "User=logstash\nGroup=logstash\n"
    except (KeyError, OSError):
        logger.warning("logstash user not found — service will run as root until Logstash is installed")
        user_lines = ""

    return f"""[Unit]
Description=LogstashAgent - Control plane agent for LogstashUI
After=network.target

[Service]
Type=simple
{user_lines}ExecStart=/opt/logstash-agent/bin/logstash-agent --run
Restart=always
RestartSec=10
WorkingDirectory=/var/lib/logstash-agent
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


class InstallError(Exception):
    """Installation error"""
    pass


def verify_root():
    """Verify running as root"""
    if os.geteuid() != 0:
        raise InstallError(
            "Installation requires root privileges.\n"
            "Run: sudo logstash-agent install --enroll=... --logstash-ui-url=..."
        )


def verify_platform():
    """Verify running on Linux"""
    if sys.platform != 'linux':
        raise InstallError(
            f"Install command only supported on Linux (detected: {sys.platform}).\n"
            "For other platforms, use manual installation."
        )


def verify_logstash_installed() -> bool:
    """
    Check whether Logstash appears to be installed on this host.

    Looks for the logstash system user, /etc/logstash, and /usr/share/logstash.
    Returns True if all checks pass, False if any are missing.  The caller decides
    whether to abort or continue with a warning.
    """
    logger.info("Checking Logstash installation...")

    missing = []

    try:
        pwd.getpwnam('logstash')
        logger.info("✓ User 'logstash' exists")
    except KeyError:
        missing.append("user: logstash")

    if not os.path.isdir('/etc/logstash'):
        missing.append("directory: /etc/logstash")
    else:
        logger.info("✓ Directory /etc/logstash exists")

    if not os.path.isdir('/usr/share/logstash'):
        missing.append("directory: /usr/share/logstash")
    else:
        logger.info("✓ Directory /usr/share/logstash exists")

    if os.path.isdir('/var/log/logstash'):
        logger.info("✓ Directory /var/log/logstash exists")

    if missing:
        logger.warning("⚠  Logstash does not appear to be installed on this host.")
        logger.warning("   Missing:")
        for item in missing:
            logger.warning(f"     - {item}")
        logger.warning("")
        logger.warning("   Installation will continue, but LogstashAgent will NOT be")
        logger.warning("   functional until Logstash is installed.")
        logger.warning("   After installing Logstash, update the paths in")
        logger.warning("   /etc/logstash-agent/logstash-agent.yml and restart the service.")
        return False

    logger.info("✓ Logstash installation verified")
    return True


def get_logstash_uid_gid():
    """
    Get the UID and GID for the logstash user.

    Returns (uid, gid) if the logstash user exists, or (0, 0) (root) with a
    warning if it does not.  Callers that perform chown operations will therefore
    fall back to root ownership when Logstash is not yet installed, which is safe
    and can be corrected later once Logstash is present.
    """
    try:
        pw = pwd.getpwnam('logstash')
        gr = grp.getgrnam('logstash')
        return pw.pw_uid, gr.gr_gid
    except (KeyError, OSError):
        logger.warning("logstash user/group not found — using root ownership as fallback")
        return 0, 0


def create_directories():
    """Create all required directories for LogstashAgent"""
    logger.info("Creating installation directories...")
    
    uid, gid = get_logstash_uid_gid()
    
    # Create binary directory (owned by root)
    os.makedirs(INSTALL_PATHS['binary_dir'], mode=0o755, exist_ok=True)
    logger.info(f"✓ Created {INSTALL_PATHS['binary_dir']}")
    
    # Create config directory (owned by logstash)
    os.makedirs(INSTALL_PATHS['config_dir'], mode=0o755, exist_ok=True)
    os.chown(INSTALL_PATHS['config_dir'], uid, gid)
    logger.info(f"✓ Created {INSTALL_PATHS['config_dir']} (owned by logstash)")
    
    # Create state directory (owned by logstash)
    os.makedirs(INSTALL_PATHS['state_dir'], mode=0o750, exist_ok=True)
    os.chown(INSTALL_PATHS['state_dir'], uid, gid)
    logger.info(f"✓ Created {INSTALL_PATHS['state_dir']} (owned by logstash)")
    
    # Create log directory (owned by logstash)
    os.makedirs(INSTALL_PATHS['log_dir'], mode=0o755, exist_ok=True)
    os.chown(INSTALL_PATHS['log_dir'], uid, gid)
    logger.info(f"✓ Created {INSTALL_PATHS['log_dir']} (owned by logstash)")
    
    # Create cache directory (owned by logstash)
    os.makedirs(INSTALL_PATHS['cache_dir'], mode=0o755, exist_ok=True)
    os.chown(INSTALL_PATHS['cache_dir'], uid, gid)
    logger.info(f"✓ Created {INSTALL_PATHS['cache_dir']} (owned by logstash)")


def install_binary():
    """
    Copy the current executable to /opt/logstash-agent/bin/logstash-agent
    For PyInstaller bundles, also copies the _internal directory with dependencies
    """
    logger.info("Installing binary...")
    
    # Check if we're running as a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller bundle
        source_binary = sys.executable
        source_dir = os.path.dirname(source_binary)
        
        # Copy the main executable
        shutil.copy2(source_binary, INSTALL_PATHS['binary'])
        os.chmod(INSTALL_PATHS['binary'], 0o755)
        logger.info(f"✓ Installed binary to {INSTALL_PATHS['binary']}")
        
        # Check for _internal directory (PyInstaller dependencies)
        internal_source = os.path.join(source_dir, '_internal')
        if os.path.exists(internal_source):
            internal_dest = os.path.join(INSTALL_PATHS['binary_dir'], '_internal')
            
            # Remove existing _internal if it exists
            if os.path.exists(internal_dest):
                shutil.rmtree(internal_dest)
            
            # Copy the entire _internal directory
            shutil.copytree(internal_source, internal_dest)
            logger.info(f"✓ Installed PyInstaller dependencies to {internal_dest}")
            
            # Set SELinux context for _internal directory on RHEL/CentOS
            try:
                result = subprocess.run(['which', 'restorecon'], capture_output=True)
                if result.returncode == 0:
                    subprocess.run(['restorecon', '-Rv', internal_dest], 
                                 check=False, capture_output=True)
                    logger.debug(f"Set SELinux context for {internal_dest}")
            except Exception:
                pass
        else:
            logger.warning("_internal directory not found - this may be a onefile build")
    else:
        # Running as Python script - this shouldn't happen in production
        # but we'll handle it for testing
        logger.warning("Running from Python script, not a compiled binary")
        logger.warning("In production, this should be a PyInstaller executable")
        source_binary = sys.executable
        
        # Copy the binary
        shutil.copy2(source_binary, INSTALL_PATHS['binary'])
        os.chmod(INSTALL_PATHS['binary'], 0o755)
        logger.info(f"✓ Installed binary to {INSTALL_PATHS['binary']}")
    
    # Set SELinux context for RHEL/CentOS systems
    try:
        result = subprocess.run(['which', 'restorecon'], capture_output=True)
        if result.returncode == 0:
            subprocess.run(['restorecon', '-v', INSTALL_PATHS['binary']], 
                         check=False, capture_output=True)
            logger.info(f"✓ Set SELinux context for {INSTALL_PATHS['binary']}")
    except Exception as e:
        logger.debug(f"SELinux context setting skipped: {e}")


def create_symlink():
    """Create symlink in /usr/local/bin or /usr/bin (RHEL)"""
    logger.info("Creating symlink...")
    
    # On RHEL, /usr/local/bin is not in default PATH, so use /usr/bin instead
    # Detect RHEL by checking for /etc/redhat-release
    symlink_path = INSTALL_PATHS['symlink']
    if os.path.exists('/etc/redhat-release'):
        symlink_path = '/usr/bin/logstash-agent'
        logger.info("RHEL detected, using /usr/bin for symlink")
    
    # Remove existing symlink if it exists
    if os.path.islink(symlink_path):
        os.unlink(symlink_path)
    elif os.path.exists(symlink_path):
        raise InstallError(
            f"{symlink_path} exists and is not a symlink. "
            "Please remove it manually."
        )
    
    # Create the symlink
    os.symlink(INSTALL_PATHS['binary'], symlink_path)
    logger.info(f"✓ Created symlink {symlink_path} -> {INSTALL_PATHS['binary']}")


def write_config_file(logstash_ui_url: str, policy_config: Optional[dict] = None):
    """Write the initial agent config file (default or simulate)."""
    logger.info("Writing configuration file...")
    policy_config = policy_config or {}
    policy_type = (policy_config.get('policy_type') or 'DEFAULT').upper()
    is_simulate = policy_type == 'SIMULATE'

    logstash_present = os.path.isdir('/usr/share/logstash') and os.path.isdir('/etc/logstash')

    if is_simulate:
        instance_id = policy_config.get('instance_id', 1)
        binary = policy_config.get('binary_path', '/usr/share/logstash/bin')
        if binary and not str(binary).endswith('logstash') and not str(binary).endswith('logstash.bat'):
            binary = str(Path(binary) / 'logstash')
        settings = policy_config.get(
            'settings_path', f"/opt/logstash-agent/simulate-{instance_id}/settings"
        )
        logs = policy_config.get(
            'logs_path', f"/opt/logstash-agent/simulate-{instance_id}/logs"
        )
        agent_port = policy_config.get('agent_api_port', 9500 + int(instance_id))
        ls_port = policy_config.get('logstash_api_port', 9560 + int(instance_id))
        config_content = f"""# LogstashAgent Configuration
# Generated during installation (SIMULATE instance)
mode: simulate
instance_id: {instance_id}

logstash_binary: {binary}
logstash_settings: {settings}
logstash_log_path: {logs}

logstash_api_port: {ls_port}
logstash_source: {policy_config.get('logstash_source') or 'SYSTEM'}
logstash_version: "{policy_config.get('logstash_version') or ''}"
logstash_download_dir: {policy_config.get('logstash_download_dir') or '/opt/logstash-agent/logstash-versions'}

# FastAPI sim API (simulate agents)
host: 0.0.0.0
port: {agent_port}

logstash_ui_url: {logstash_ui_url}
"""
    else:
        path_comment = ""
        if not logstash_present:
            path_comment = (
                "\n# ⚠  Logstash was NOT detected at install time.\n"
                "# Update the three paths below to match your Logstash installation\n"
                "# before starting the logstash-agent service.\n"
            )
        config_content = f"""# LogstashAgent Configuration
# Generated during installation
{path_comment}
mode: default

# Paths to this Logstash installation
logstash_binary: /usr/share/logstash/bin/logstash
logstash_settings: /etc/logstash
logstash_log_path: /var/log/logstash

# Port that Logstash's monitoring API listens on (default: 9600 for native installs)
# Embedded Docker uses 9560; simulate instances use 9560+N
logstash_api_port: 9600

# Agent API server (not used in default controller mode)
host: 127.0.0.1
port: 9600

# LogstashUI connection
logstash_ui_url: {logstash_ui_url}
"""

    config_path = os.path.join(INSTALL_PATHS['config_dir'], 'logstash-agent.yml')

    with open(config_path, 'w') as f:
        f.write(config_content)

    try:
        uid, gid = get_logstash_uid_gid()
        os.chown(config_path, uid, gid)
    except Exception:
        pass
    os.chmod(config_path, 0o640)

    logger.info(f"✓ Created configuration file {config_path}")


def _read_unit_template(name: str) -> str:
    path = _systemd_template_dir() / name
    if not path.is_file():
        raise InstallError(
            f"Missing systemd unit template: {path} "
            f"(searched under {_systemd_template_dir()})"
        )
    return path.read_text(encoding='utf-8')


def install_simulate_unit_templates() -> None:
    """Install lsagent-simulate@.service and ls-simulate@.service templates."""
    logger.info("Installing simulate systemd unit templates...")
    for template_name, dest_key in (
        ('lsagent-simulate@.service', 'lsagent_simulate_unit'),
        ('ls-simulate@.service', 'ls_simulate_unit'),
    ):
        content = _read_unit_template(template_name)
        # Inject User=logstash when available
        try:
            pwd.getpwnam('logstash')
            grp.getgrnam('logstash')
            if '# User=logstash' in content:
                content = content.replace('# User=logstash', 'User=logstash')
            if '# Group=logstash' in content:
                content = content.replace('# Group=logstash', 'Group=logstash')
        except (KeyError, OSError, TypeError):
            pass
        dest = INSTALL_PATHS[dest_key]
        with open(dest, 'w') as f:
            f.write(content)
        os.chmod(dest, 0o644)
        logger.info(f"✓ Installed {dest}")

    try:
        subprocess.run(
            ['systemctl', 'daemon-reload'],
            check=True, capture_output=True, text=True,
        )
        logger.info("✓ Reloaded systemd daemon")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning(f"daemon-reload failed (non-fatal): {e}")


def materialize_simulate_instance(policy_config: dict) -> dict:
    """
    Create /opt/logstash-agent/simulate-N tree, env files, seed configs.

    Returns dict with resolved binary path and paths used.
    """
    from logstashagent.logstash_download import resolve_binary_from_policy

    instance_id = policy_config.get('instance_id')
    if instance_id is None:
        raise InstallError("SIMULATE policy_config missing instance_id")

    instance_id = int(instance_id)
    root = Path(INSTALL_PATHS['simulate_root']) / f"simulate-{instance_id}"
    settings = Path(policy_config.get('settings_path') or root / 'settings')
    config_dir = Path(policy_config.get('config_path') or root / 'config')
    logs = Path(policy_config.get('logs_path') or root / 'logs')
    data = Path(policy_config.get('data_path') or root / 'data')
    env_file = Path(policy_config.get('keystore_env_file') or root / 'env')
    agent_env = root / 'agent.env'
    state_dir = root / 'state'

    for d in (settings, config_dir, logs, data, state_dir, settings / 'conf.d', settings / 'config'):
        d.mkdir(parents=True, exist_ok=True)
        logger.info(f"✓ Ensured directory {d}")

    # Seed config files from policy when provided
    for name, key in (
        ('logstash.yml', 'logstash_yml'),
        ('jvm.options', 'jvm_options'),
        ('log4j2.properties', 'log4j2_properties'),
    ):
        content = policy_config.get(key)
        if content:
            target = settings / name
            target.write_text(content if content.endswith('\n') else content + '\n', encoding='utf-8')
            logger.info(f"✓ Wrote {target}")

    # Seed simulation harness (simulate-start/end) + bare pipelines.yml
    try:
        from logstashagent import simulate_recovery

        seed = simulate_recovery.seed_static_harness(settings, force=False)
        if seed.get('ok'):
            if not (settings / 'pipelines.yml').is_file():
                simulate_recovery.write_bare_pipelines_yml(settings)
                logger.info("✓ Wrote bare simulate pipelines.yml (harness only)")
            else:
                logger.info("✓ Simulate harness confs ready (pipelines.yml already present)")
        else:
            logger.warning(
                "Could not seed full simulate harness: %s",
                seed.get('missing_src'),
            )
    except Exception as e:
        logger.warning("Simulate harness seed during materialize failed: %s", e)

    binary = resolve_binary_from_policy(
        logstash_source=policy_config.get('logstash_source') or 'SYSTEM',
        logstash_version=policy_config.get('logstash_version') or '',
        logstash_download_dir=policy_config.get('logstash_download_dir')
        or f"{INSTALL_PATHS['simulate_root']}/logstash-versions",
        binary_path=policy_config.get('binary_path') or '/usr/share/logstash/bin',
    )

    agent_port = policy_config.get('agent_api_port', 9500 + instance_id)
    ls_port = policy_config.get('logstash_api_port', 9560 + instance_id)

    # EnvironmentFile for ls-simulate@N
    env_lines = [
        f"LOGSTASH_BINARY={binary}",
        f"LOGSTASH_PATH_SETTINGS={settings}",
        f"LOGSTASH_PATH_CONFIG={config_dir}",
        f"LOGSTASH_PATH_LOGS={logs}",
        f"LOGSTASH_PATH_DATA={data}",
        # LOGSTASH_KEYSTORE_PASS added later when keystore password is set
    ]
    # Preserve existing keystore pass if re-materializing
    if env_file.exists():
        for line in env_file.read_text(encoding='utf-8').splitlines():
            if line.startswith('LOGSTASH_KEYSTORE_PASS='):
                env_lines.append(line)
    env_file.write_text('\n'.join(env_lines) + '\n', encoding='utf-8')
    os.chmod(env_file, 0o640)
    logger.info(f"✓ Wrote {env_file}")

    agent_env_lines = [
        f"INSTANCE_ID={instance_id}",
        f"AGENT_API_PORT={agent_port}",
        f"LOGSTASH_API_PORT={ls_port}",
        f"LOGSTASH_SETTINGS={settings}",
    ]
    agent_env.write_text('\n'.join(agent_env_lines) + '\n', encoding='utf-8')
    os.chmod(agent_env, 0o640)
    logger.info(f"✓ Wrote {agent_env}")

    # Ownership
    try:
        uid, gid = get_logstash_uid_gid()
        for path in (root, settings, config_dir, logs, data, state_dir, env_file, agent_env):
            if path.exists():
                if path.is_dir():
                    for walk_root, dirs, files in os.walk(path):
                        os.chown(walk_root, uid, gid)
                        for name in dirs + files:
                            try:
                                os.chown(os.path.join(walk_root, name), uid, gid)
                            except OSError:
                                pass
                else:
                    os.chown(path, uid, gid)
        logger.info(f"✓ Set ownership on {root}")
    except Exception as e:
        logger.warning(f"Could not set ownership on simulate tree: {e}")

    return {
        'root': str(root),
        'binary': binary,
        'settings_path': str(settings),
        'config_path': str(config_dir),
        'logs_path': str(logs),
        'data_path': str(data),
        'env_file': str(env_file),
        'agent_env': str(agent_env),
        'instance_id': instance_id,
        'agent_api_port': agent_port,
        'logstash_api_port': ls_port,
    }


def _systemctl_cmd(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['systemctl', *args],
        check=check,
        capture_output=True,
        text=True,
    )


def enable_package_logstash_only() -> None:
    """
    Enable distro ``logstash`` unit without starting/restarting it.

    Live hosts may already be serving traffic; the agent restarts Logstash
    later when policy apply requires it.
    """
    try:
        r = _systemctl_cmd('enable', 'logstash')
        if r.returncode == 0:
            logger.info(
                "✓ Enabled distro logstash unit (not started — agent will restart when needed)"
            )
        else:
            logger.warning(
                "Could not enable logstash unit (may be missing): %s",
                (r.stderr or r.stdout or "").strip(),
            )
    except FileNotFoundError:
        logger.warning("systemctl not available — skip enable of logstash")


def enable_and_start_default_agent() -> None:
    """Enable and start logstash-agent.service (Packaged/Default install)."""
    unit = 'logstash-agent'
    try:
        _systemctl_cmd('daemon-reload')
        r = _systemctl_cmd('enable', '--now', unit)
        if r.returncode == 0:
            logger.info("✓ Enabled and started %s", unit)
        else:
            # enable --now may fail on some systems if unit just written; try split
            _systemctl_cmd('enable', unit)
            r2 = _systemctl_cmd('start', unit)
            if r2.returncode == 0:
                logger.info("✓ Enabled and started %s", unit)
            else:
                logger.warning(
                    "Could not start %s: %s",
                    unit,
                    (r2.stderr or r.stderr or "").strip(),
                )
    except FileNotFoundError:
        logger.warning("systemctl not available — skip enable/start of %s", unit)


def enable_simulate_services(instance_id: int) -> None:
    """
    Enable simulate units and start the agent instance.

    Logstash unit is enabled only (not started) so the controller can apply
    config and restart via logstash-agent-ctl when ready — same live-safety
    idea as Packaged, even for new sim trees.
    """
    agent_unit = f"lsagent-simulate@{instance_id}"
    ls_unit = f"ls-simulate@{instance_id}"
    try:
        _systemctl_cmd('daemon-reload')
        _systemctl_cmd('enable', ls_unit)
        r = _systemctl_cmd('enable', '--now', agent_unit)
        if r.returncode != 0:
            _systemctl_cmd('enable', agent_unit)
            r2 = _systemctl_cmd('start', agent_unit)
            if r2.returncode != 0:
                logger.warning(
                    "Could not start %s: %s",
                    agent_unit,
                    (r2.stderr or r.stderr or "").strip(),
                )
            else:
                logger.info("✓ Enabled %s; enabled and started %s", ls_unit, agent_unit)
        else:
            logger.info("✓ Enabled %s; enabled and started %s", ls_unit, agent_unit)
    except FileNotFoundError:
        logger.warning("systemctl not available — skip enable of simulate units")


def setup_simulate_from_policy(policy_config: dict) -> dict:
    """Full simulate post-enroll setup: templates, tree, enable units."""
    install_simulate_unit_templates()
    result = materialize_simulate_instance(policy_config)
    enable_simulate_services(result['instance_id'])
    return result


def policy_config_from_state(state: Optional[dict] = None) -> dict:
    """
    Rebuild a policy_config dict from agent state (for deferred setup-simulate).
    Prefers the full ``policy_config`` blob saved at enroll.
    """
    from logstashagent import agent_state as _agent_state

    state = state if state is not None else _agent_state.get_state()
    if state.get('policy_config') and isinstance(state['policy_config'], dict):
        cfg = dict(state['policy_config'])
        # Ensure policy_type for SIMULATE setup detection
        if not cfg.get('policy_type') and state.get('mode') == 'simulate':
            cfg['policy_type'] = 'SIMULATE'
        return cfg

    instance_id = state.get('instance_id')
    cfg = {
        'policy_type': state.get('policy_type') or (
            'SIMULATE' if state.get('mode') == 'simulate' else 'DEFAULT'
        ),
        'instance_id': instance_id,
        'settings_path': state.get('settings_path'),
        'config_path': state.get('config_path'),
        'logs_path': state.get('logs_path'),
        'data_path': state.get('data_path'),
        'binary_path': state.get('binary_path'),
        'keystore_env_file': state.get('keystore_env_file'),
        'agent_api_port': state.get('agent_api_port'),
        'logstash_api_port': state.get('logstash_api_port'),
        'logstash_source': state.get('logstash_source') or 'SYSTEM',
        'logstash_version': state.get('logstash_version') or '',
        'logstash_download_dir': state.get('logstash_download_dir')
        or f"{INSTALL_PATHS['simulate_root']}/logstash-versions",
        'logstash_yml': '',
        'jvm_options': '',
        'log4j2_properties': '',
    }
    return cfg


def _can_write_simulate_tree(policy_config: dict) -> bool:
    """True if current user can create/write the simulate instance root."""
    instance_id = policy_config.get('instance_id')
    if instance_id is None:
        return False
    root = Path(INSTALL_PATHS['simulate_root']) / f"simulate-{instance_id}"
    parent = root.parent
    try:
        if root.exists():
            test = root / '.write_test'
            test.write_text('ok', encoding='utf-8')
            test.unlink(missing_ok=True)
            return True
        if parent.exists() and os.access(parent, os.W_OK):
            return True
        # Parent may not exist — check grandparent
        if parent.parent.exists() and os.access(parent.parent, os.W_OK):
            return True
    except OSError:
        return False
    return False


def _try_sudo_setup_simulate() -> Optional[dict]:
    """
    Attempt passwordless sudo to finish setup via setup-simulate subcommand.
    Returns result dict if sudo ran, None if sudo unavailable/denied.
    """
    binary_candidates = [
        INSTALL_PATHS.get('binary'),
        shutil.which('logstash-agent'),
        '/usr/local/bin/logstash-agent',
        '/opt/logstash-agent/bin/logstash-agent',
    ]
    agent_bin = next((b for b in binary_candidates if b and os.path.isfile(b)), None)
    if not agent_bin:
        # Fall back to current interpreter + module
        cmd = ['sudo', '-n', sys.executable, '-m', 'logstashagent.main', 'setup-simulate', '--yes']
    else:
        cmd = ['sudo', '-n', agent_bin, 'setup-simulate', '--yes']

    try:
        logger.info("Attempting passwordless sudo for simulate setup: %s", ' '.join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == 0:
            logger.info("✓ Simulate setup completed via passwordless sudo")
            if result.stdout:
                for line in result.stdout.strip().splitlines()[-20:]:
                    logger.info("  sudo: %s", line)
            return {
                'status': 'complete',
                'via': 'sudo',
                'messages': ['Simulate setup completed via passwordless sudo'],
            }
        logger.warning(
            "Passwordless sudo setup-simulate failed (rc=%s): %s",
            result.returncode,
            (result.stderr or result.stdout or '')[:500],
        )
        return None
    except FileNotFoundError:
        logger.debug("sudo not found")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("sudo setup-simulate timed out")
        return None
    except Exception as e:
        logger.warning("sudo setup-simulate error: %s", e)
        return None


def ensure_simulate_setup(policy_config: dict) -> dict:
    """
    Ensure simulate instance is fully set up after enrollment.

    Order:
      1. If root → full setup_simulate_from_policy
      2. Else try passwordless ``sudo -n … setup-simulate``
      3. Else if tree is writable → materialize only (no unit install); report partial
      4. Else pending with clear instructions

    Returns:
        dict with status: complete | partial | pending, messages: list[str]
    """
    policy_config = policy_config or {}
    if (policy_config.get('policy_type') or '').upper() != 'SIMULATE':
        return {'status': 'complete', 'messages': ['Not a SIMULATE policy'], 'via': 'n/a'}

    instance_id = policy_config.get('instance_id')
    messages = []

    # 1. Root
    try:
        if os.geteuid() == 0:
            logger.info("Running as root — full simulate setup")
            result = setup_simulate_from_policy(policy_config)
            return {
                'status': 'complete',
                'via': 'root',
                'messages': [f"Materialized simulate-{instance_id} and installed units"],
                'result': result,
            }
    except Exception as e:
        logger.error("Root simulate setup failed: %s", e, exc_info=True)
        return {
            'status': 'pending',
            'via': 'root_failed',
            'messages': [f"Root setup failed: {e}", "Retry: sudo logstash-agent setup-simulate"],
        }

    # 2. Passwordless sudo
    sudo_result = _try_sudo_setup_simulate()
    if sudo_result and sudo_result.get('status') == 'complete':
        return sudo_result

    # 3. Partial: writable tree only (no systemd unit install)
    if _can_write_simulate_tree(policy_config):
        try:
            logger.info(
                "Non-root but simulate tree is writable — materializing dirs/env "
                "(systemd units still need root)"
            )
            result = materialize_simulate_instance(policy_config)
            messages.append(
                f"Wrote simulate-{instance_id} directories and env files as non-root"
            )
            messages.append(
                "Still need root for systemd units: sudo logstash-agent setup-simulate"
            )
            return {
                'status': 'partial',
                'via': 'user_writable',
                'messages': messages,
                'result': result,
            }
        except Exception as e:
            logger.warning("Partial materialize failed: %s", e)
            messages.append(f"Partial materialize failed: {e}")

    # 4. Pending
    messages.extend([
        "Enrollment saved, but simulate host setup needs elevated privileges.",
        "Run as root (recommended):",
        "  sudo logstash-agent setup-simulate",
        "Or re-enroll with install:",
        "  sudo logstash-agent install --enroll <TOKEN> --logstash-ui-url <URL>",
    ])
    if sudo_result is None:
        messages.append(
            "(Passwordless sudo for setup-simulate was not available; "
            "configure NOPASSWD for setup-simulate if you want non-interactive finish.)"
        )
    return {
        'status': 'pending',
        'via': 'deferred',
        'messages': messages,
    }


def perform_setup_simulate(yes: bool = False) -> dict:
    """
    Entry point for ``logstash-agent setup-simulate``.

    Requires root. Reads enrollment state (policy_config) and runs full
    setup_simulate_from_policy. Idempotent.
    """
    from logstashagent import agent_state as _agent_state

    logger.info("=" * 60)
    logger.info("LOGSTASH AGENT - SETUP SIMULATE")
    logger.info("=" * 60)

    verify_root()
    verify_platform()

    state = _agent_state.get_state()
    if not state.get('enrolled'):
        raise InstallError(
            "Agent is not enrolled. Run enroll or install first, then setup-simulate."
        )

    policy_config = policy_config_from_state(state)
    if (policy_config.get('policy_type') or '').upper() != 'SIMULATE' and state.get('mode') != 'simulate':
        raise InstallError(
            "Agent is not a simulate enrollment (mode/policy_type is not SIMULATE). "
            f"mode={state.get('mode')} policy_type={policy_config.get('policy_type')}"
        )
    policy_config['policy_type'] = 'SIMULATE'
    if policy_config.get('instance_id') is None:
        raise InstallError(
            "Missing instance_id in agent state. Re-enroll with a Simulate policy token."
        )

    if not yes:
        print(f"\nThis will materialize /opt/logstash-agent/simulate-{policy_config['instance_id']}/")
        print("and install/enable lsagent-simulate@ and ls-simulate@ units.")
        answer = input("Continue? [y/N]: ").strip().lower()
        if answer != 'y':
            raise InstallError("setup-simulate cancelled")

    # Also write agent config if install path exists
    ui_url = state.get('logstash_ui_url') or ''
    if os.path.isdir(INSTALL_PATHS['config_dir']):
        try:
            write_config_file(ui_url, policy_config=policy_config)
        except Exception as e:
            logger.warning("Could not write agent config file: %s", e)

    result = setup_simulate_from_policy(policy_config)
    try:
        configure_logstash()
    except Exception as e:
        logger.warning("configure_logstash after setup-simulate: %s", e)

    _agent_state.update_state('simulate_setup_pending', False)

    logger.info("=" * 60)
    logger.info("SIMULATE SETUP COMPLETE")
    logger.info("=" * 60)
    logger.info(
        "Start: sudo systemctl start lsagent-simulate@%s",
        policy_config['instance_id'],
    )
    logger.info(
        "Status: sudo systemctl status lsagent-simulate@%s",
        policy_config['instance_id'],
    )
    return result


def configure_logstash() -> None:
    """
    Apply Logstash-specific setup required for agent management.

    Must run as root. Called automatically by perform_installation() when
    Logstash is already present, or manually via `logstash-agent configure`
    when Logstash was installed after the agent.

    Performs:
    - chown logstash:logstash on /etc/logstash, /var/log/logstash,
      and /usr/share/logstash/data
    - Write /etc/sudoers.d/logstash-agent (passwordless sudo grants)
    - Update systemd service unit to use User=logstash / Group=logstash
    - Reload systemd daemon
    """
    logger.info("Configuring Logstash for agent management...")
    uid, gid = get_logstash_uid_gid()

    # Fix ownership on the agent's own directories.  These may have been created
    # with root:root during installation if the logstash user didn't exist yet.
    for agent_dir in [
        INSTALL_PATHS['log_dir'],    # /var/log/logstash-agent
        INSTALL_PATHS['state_dir'],  # /var/lib/logstash-agent
        INSTALL_PATHS['config_dir'], # /etc/logstash-agent
        INSTALL_PATHS['cache_dir'],  # /var/cache/logstash-agent
    ]:
        if os.path.exists(agent_dir):
            try:
                for root, dirs, files in os.walk(agent_dir):
                    os.chown(root, uid, gid)
                    for d in dirs:
                        os.chown(os.path.join(root, d), uid, gid)
                    for f in files:
                        os.chown(os.path.join(root, f), uid, gid)
                logger.info(f"✓ Fixed ownership on {agent_dir} (logstash:logstash)")
            except Exception as e:
                logger.warning(f"Could not fix ownership on {agent_dir}: {e}")

    # chown /etc/logstash
    logstash_config_dir = '/etc/logstash'
    if os.path.exists(logstash_config_dir):
        try:
            for root, dirs, files in os.walk(logstash_config_dir):
                os.chown(root, uid, gid)
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)
            logger.info(f"✓ Set ownership on {logstash_config_dir} (logstash:logstash, recursive)")
        except Exception as e:
            logger.warning(f"Could not set ownership on {logstash_config_dir}: {e}")
            logger.warning("Agent may not be able to manage Logstash configuration")
    else:
        logger.warning(f"Logstash config directory not found at {logstash_config_dir}")

    # chown /var/log/logstash
    logstash_log_dir = '/var/log/logstash'
    if os.path.exists(logstash_log_dir):
        try:
            for root, dirs, files in os.walk(logstash_log_dir):
                os.chown(root, uid, gid)
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)
            logger.info(f"✓ Set ownership on {logstash_log_dir} (logstash:logstash, recursive)")
        except Exception as e:
            logger.warning(f"Could not set ownership on {logstash_log_dir}: {e}")
    else:
        logger.warning(f"Logstash log directory not found at {logstash_log_dir}")

    # chown /usr/share/logstash/data
    logstash_data_dir = '/usr/share/logstash/data'
    if os.path.exists(logstash_data_dir):
        try:
            for root, dirs, files in os.walk(logstash_data_dir):
                os.chown(root, uid, gid)
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)
            logger.info(f"✓ Set ownership on {logstash_data_dir} (logstash:logstash, recursive)")
        except Exception as e:
            logger.warning(f"Could not set ownership on {logstash_data_dir}: {e}")
    else:
        logger.warning(f"Logstash data directory not found at {logstash_data_dir}")

    # Validated systemctl helper + sudoers (sudo-rs forbids wildcards in args)
    try:
        install_systemctl_ctl()
    except Exception as e:
        logger.warning("Could not install systemctl helper: %s", e)

    # Write /etc/sudoers.d/logstash-agent
    sudoers_file = '/etc/sudoers.d/logstash-agent'
    using_sudo_rs = is_sudo_rs()
    if using_sudo_rs:
        logger.info(
            "sudo-rs detected — omitting 'Defaults:logstash !requiretty' and "
            "using logstash-agent-ctl (no command-argument wildcards)"
        )
        requiretty_line = ""
    else:
        requiretty_line = "Defaults:logstash !requiretty\n"

    ctl = INSTALL_PATHS['systemctl_ctl']
    agent_bin = INSTALL_PATHS['binary']
    # Note: no @* wildcards — sudo-rs (Ubuntu 26+) rejects them. Simulate units
    # go through logstash-agent-ctl which validates unit names itself.
    sudoers_content = f"""# LogstashAgent - Allow logstash user to manage Logstash service
# This file is managed by logstash-agent installation
# Compatible with GNU sudo and sudo-rs (no wildcards in command arguments)
{requiretty_line}
# Validated systemctl wrapper (logstash, logstash-agent, ls-simulate@N, lsagent-simulate@N)
logstash ALL=(ALL) NOPASSWD: {ctl}

# Allow LogstashAgent upgrade / privileged subcommands (fixed path; no arg wildcards)
logstash ALL=(ALL) NOPASSWD: {agent_bin}

# Allow modification of Logstash environment file (for keystore password)
logstash ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/default/logstash
logstash ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/default/logstash
logstash ALL=(ALL) NOPASSWD: /usr/bin/chmod 640 /etc/default/logstash
"""
    try:
        with open(sudoers_file, 'w') as f:
            f.write(sudoers_content)
        os.chmod(sudoers_file, 0o440)
        logger.info(f"✓ Created sudoers configuration: {sudoers_file}")

        result = subprocess.run(
            ['visudo', '-c', '-f', sudoers_file],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            logger.info("✓ Sudoers configuration validated successfully")
        else:
            err = (result.stderr or result.stdout or b"").decode(errors="replace")
            logger.warning(f"Sudoers validation warning: {err}")
    except Exception as e:
        logger.warning(f"Could not create sudoers configuration: {e}")
        logger.warning("Agent may not be able to restart Logstash service")
        logger.warning("Manual fix required:")
        logger.warning(f"  sudo tee {sudoers_file} << 'EOF'")
        logger.warning(sudoers_content)
        logger.warning("EOF")
        logger.warning(f"  sudo chmod 440 {sudoers_file}")

    # Update systemd service to use User=logstash / Group=logstash now that
    # the logstash user exists (it may have been written with root fallback)
    if os.path.exists(INSTALL_PATHS['systemd_service']):
        try:
            with open(INSTALL_PATHS['systemd_service'], 'w') as f:
                f.write(_build_systemd_service())
            os.chmod(INSTALL_PATHS['systemd_service'], 0o644)
            logger.info("✓ Updated systemd service unit (User=logstash)")

            subprocess.run(['systemctl', 'daemon-reload'],
                           check=True, capture_output=True, text=True)
            logger.info("✓ Reloaded systemd daemon")
        except Exception as e:
            logger.warning(f"Could not update systemd service: {e}")

    logger.info("✓ Logstash configuration complete")


def perform_configure() -> None:
    """
    Entry point for `logstash-agent configure`.

    Applies the Logstash-specific setup that requires Logstash to already be
    installed on the host.  Run this after installing Logstash when the agent
    was originally installed on a host without Logstash.
    """
    logger.info("="*60)
    logger.info("LOGSTASH AGENT - CONFIGURE")
    logger.info("="*60)

    try:
        verify_root()
        verify_platform()

        if not os.path.exists(INSTALL_PATHS['binary']):
            raise InstallError(
                "LogstashAgent is not installed. Run 'install' first.\n"
                "  sudo logstash-agent install --enroll <TOKEN> --logstash-ui-url <URL>"
            )

        logstash_present = verify_logstash_installed()
        if not logstash_present:
            raise InstallError(
                "Logstash must be installed before running configure.\n\n"
                "Install Logstash, then rerun:\n"
                "  sudo logstash-agent configure"
            )

        configure_logstash()
        # Enable distro logstash only — never start/restart on configure (live-system safe)
        enable_package_logstash_only()

        logger.info("\n" + "="*60)
        logger.info("CONFIGURE COMPLETED SUCCESSFULLY!")
        logger.info("="*60)
        logger.info("\nDistro logstash enabled only (not started).")
        logger.info("Restart the agent so it can manage Logstash when policy requires:")
        logger.info("    sudo systemctl restart logstash-agent")
        logger.info("="*60)

    except InstallError as e:
        logger.error(f"\nConfigure failed: {e}")
        raise
    except Exception as e:
        logger.error(f"\nUnexpected error during configure: {e}", exc_info=True)
        raise InstallError(f"Configure failed: {e}")


def install_systemd_service():
    """Install the systemd service unit"""
    logger.info("Installing systemd service...")

    # Write the service file
    with open(INSTALL_PATHS['systemd_service'], 'w') as f:
        f.write(_build_systemd_service())
    
    os.chmod(INSTALL_PATHS['systemd_service'], 0o644)
    logger.info(f"✓ Created systemd service {INSTALL_PATHS['systemd_service']}")
    
    # Reload systemd
    try:
        result = subprocess.run(['systemctl', 'daemon-reload'], 
                              check=True, capture_output=True, text=True)
        logger.info("✓ Reloaded systemd daemon")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to reload systemd: {e}")
        if e.stderr:
            logger.warning(f"stderr: {e.stderr}")
        if e.stdout:
            logger.warning(f"stdout: {e.stdout}")
        # Non-fatal - systemctl enable/start will trigger reload anyway
        logger.info("Continuing (daemon will reload on next systemctl command)")


def perform_installation(enroll_token: str, logstash_ui_url: str, agent_id: str, 
                        enrollment_func) -> None:
    """
    Perform the complete installation process.
    
    Args:
        enroll_token: Enrollment token for LogstashUI
        logstash_ui_url: URL of the LogstashUI instance
        agent_id: Agent ID for this installation
        enrollment_func: Function to call for enrollment (from enrollment module)
    """
    logger.info("="*60)
    logger.info("LOGSTASH AGENT INSTALLATION")
    logger.info("="*60)
    
    try:
        # Step 1: Verify prerequisites
        logger.info("\nStep 1: Verifying prerequisites...")
        verify_root()
        verify_platform()
        logstash_present = verify_logstash_installed()
        if not logstash_present:
            logger.warning(
                "\n⚠  Continuing installation without Logstash.\n"
                "   The agent will be enrolled and the service registered,\n"
                "   but pipeline management will not work until Logstash is\n"
                "   installed and /etc/logstash-agent/logstash-agent.yml is\n"
                "   updated with the correct binary and settings paths.\n"
            )
        
        # Step 2: Create directories
        logger.info("\nStep 2: Creating directories...")
        create_directories()
        
        # Step 3: Install binary
        logger.info("\nStep 3: Installing binary...")
        install_binary()
        
        # Step 4: Create symlink
        logger.info("\nStep 4: Creating symlink...")
        create_symlink()
        
        # Step 5: Enroll first so we know default vs simulate policy
        logger.info("\nStep 5: Enrolling with LogstashUI...")
        enroll_result = enrollment_func(
            encoded_token=enroll_token,
            logstash_ui_url=logstash_ui_url,
            agent_id=agent_id
        )
        logger.info("✓ Enrollment completed successfully")
        policy_config = {}
        if isinstance(enroll_result, dict):
            policy_config = enroll_result.get('policy_config') or {}
        policy_type = (policy_config.get('policy_type') or 'DEFAULT').upper()
        is_simulate = policy_type == 'SIMULATE'

        # Step 6: Write config file (mode-aware)
        logger.info("\nStep 6: Writing configuration...")
        write_config_file(logstash_ui_url, policy_config=policy_config)

        # Step 7: Install systemd units
        logger.info("\nStep 7: Installing systemd service(s)...")
        if is_simulate:
            setup_simulate_from_policy(policy_config)
            # Shared agent binary is still installed; default unit is optional
            # for coexistence with a production agent on the same host — do not
            # enable logstash-agent.service for pure simulate installs.
            logger.info("✓ Simulate units installed (lsagent-simulate@ / ls-simulate@)")
        else:
            install_systemd_service()

        # Step 8: Set ownership on state files and clean up log files
        logger.info("\nStep 8: Setting ownership on state files...")
        uid, gid = get_logstash_uid_gid()

        # Find and chown all files in state directory
        for root, dirs, files in os.walk(INSTALL_PATHS['state_dir']):
            for d in dirs:
                os.chown(os.path.join(root, d), uid, gid)
            for f in files:
                os.chown(os.path.join(root, f), uid, gid)

        logger.info(f"✓ Set ownership on {INSTALL_PATHS['state_dir']}")

        # Clean up any root-owned log files that may have been created during install
        log_file = os.path.join(INSTALL_PATHS['log_dir'], 'logstashagent.log')
        if os.path.exists(log_file):
            try:
                # Check if owned by root
                stat_info = os.stat(log_file)
                if stat_info.st_uid == 0:  # root
                    os.remove(log_file)
                    logger.info(f"✓ Removed root-owned log file (will be recreated by service)")
            except Exception as e:
                logger.warning(f"Could not clean up log file: {e}")

        # Step 9: Configure Logstash permissions for agent management
        if is_simulate:
            # Still write sudoers (simulate units + optional package logstash)
            logger.info("\nStep 9: Configuring permissions (simulate + sudoers)...")
            configure_logstash()
        elif logstash_present:
            logger.info("\nStep 9: Configuring Logstash permissions...")
            configure_logstash()
        else:
            logger.info("\nStep 9: Skipping Logstash configuration (Logstash not installed)")

        # Step 10: Final ownership fix for state files
        # This ensures state.json has correct ownership even if it was updated
        # during module initialization (agent_id, agent_version)
        logger.info("\nStep 10: Final ownership verification...")
        for root, dirs, files in os.walk(INSTALL_PATHS['state_dir']):
            for d in dirs:
                os.chown(os.path.join(root, d), uid, gid)
            for f in files:
                os.chown(os.path.join(root, f), uid, gid)
        logger.info(f"✓ Verified ownership on {INSTALL_PATHS['state_dir']}")

        # Step 11: Enable/start services (full deploy — no extra cut-paste for enable/start)
        logger.info("\nStep 11: Enabling and starting services...")
        if is_simulate:
            # enable_simulate_services already ran inside setup_simulate_from_policy
            pass
        else:
            enable_and_start_default_agent()
            if logstash_present:
                enable_package_logstash_only()

        # Installation complete
        logger.info("\n" + "="*60)
        logger.info("INSTALLATION COMPLETED SUCCESSFULLY!")
        logger.info("="*60)

        if is_simulate:
            instance_id = policy_config.get('instance_id')
            agent_unit = f"lsagent-simulate@{instance_id}"
            ls_unit = f"ls-simulate@{instance_id}"
            logger.info("\nSimulate agent installed and started.")
            logger.info(f"  Agent unit:    {agent_unit} (enabled + started)")
            logger.info(f"  Logstash unit: {ls_unit} (enabled; agent restarts when ready)")
            logger.info(f"  Paths under:   /opt/logstash-agent/simulate-{instance_id}/")
            logger.info("\nDay-2 operations:")
            logger.info(f"  sudo systemctl status {agent_unit}")
            logger.info(f"  sudo systemctl stop {agent_unit}")
            logger.info(f"  sudo systemctl start {agent_unit}")
            logger.info(f"  sudo journalctl -u {agent_unit} -f")
            logger.info("="*60)
        else:
            if not logstash_present:
                logger.warning("\n" + "!"*60)
                logger.warning("  ACTION REQUIRED: Logstash was NOT installed at install time.")
                logger.warning("")
                logger.warning("  You MUST run the following after you install Logstash to")
                logger.warning("  complete the setup, otherwise you may see issues:")
                logger.warning("")
                logger.warning("    sudo logstash-agent configure")
                logger.warning("")
                logger.warning("  This applies required permissions and service account")
                logger.warning("  configuration that could not be set up without Logstash.")
                logger.warning("!" * 60)

            logger.info("\nAgent service logstash-agent enabled and started.")
            if logstash_present:
                logger.info(
                    "Distro logstash unit enabled only (not started/restarted — "
                    "safe for live systems; agent will restart Logstash when policy requires)."
                )
            if not logstash_present:
                logger.info("\nAfter installing Logstash:")
                logger.info("  1. Update paths in /etc/logstash-agent/logstash-agent.yml if needed")
                logger.info("  2. sudo logstash-agent configure")
                logger.info("  3. sudo systemctl restart logstash-agent")
            logger.info("\nDay-2 operations:")
            logger.info("  sudo systemctl status logstash-agent")
            logger.info("  sudo systemctl stop logstash-agent")
            logger.info("  sudo systemctl start logstash-agent")
            logger.info("  sudo journalctl -u logstash-agent -f")
            logger.info("="*60)
        
    except InstallError as e:
        logger.error(f"\nInstallation failed: {e}")
        raise
    except Exception as e:
        logger.error(f"\nUnexpected error during installation: {e}", exc_info=True)
        raise InstallError(f"Installation failed: {e}")


def perform_uninstallation(purge: bool = False) -> None:
    """
    Perform the complete uninstallation process.
    
    Args:
        purge: If True, also remove state and log directories
    """
    logger.info("="*60)
    logger.info("LOGSTASH AGENT UNINSTALLATION")
    logger.info("="*60)
    
    try:
        # Step 1: Verify prerequisites
        logger.info("\nStep 1: Verifying prerequisites...")
        verify_root()
        verify_platform()
        
        # Step 2: Stop and disable service
        logger.info("\nStep 2: Stopping and disabling service...")
        if os.path.exists(INSTALL_PATHS['systemd_service']):
            try:
                # Stop the service
                subprocess.run(['systemctl', 'stop', 'logstash-agent'], 
                             check=False, capture_output=True)
                logger.info("✓ Stopped logstash-agent service")
                
                # Disable the service
                subprocess.run(['systemctl', 'disable', 'logstash-agent'], 
                             check=False, capture_output=True)
                logger.info("✓ Disabled logstash-agent service")
            except Exception as e:
                logger.warning(f"Failed to stop/disable service: {e}")
        else:
            logger.info("Service not found, skipping")
        
        # Step 3: Remove systemd service file
        logger.info("\nStep 3: Removing systemd service...")
        if os.path.exists(INSTALL_PATHS['systemd_service']):
            os.remove(INSTALL_PATHS['systemd_service'])
            logger.info(f"✓ Removed {INSTALL_PATHS['systemd_service']}")
            
            # Reload systemd
            try:
                result = subprocess.run(['systemctl', 'daemon-reload'], 
                                      check=True, capture_output=True, text=True)
                logger.info("✓ Reloaded systemd daemon")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to reload systemd: {e}")
                if e.stderr:
                    logger.warning(f"stderr: {e.stderr}")
                if e.stdout:
                    logger.warning(f"stdout: {e.stdout}")
                # Non-fatal - systemd will eventually pick up the change
                logger.info("Continuing (daemon will reload eventually)")
        else:
            logger.info("Service file not found, skipping")
        
        # Step 3b: Remove sudoers drop-in
        logger.info("\nRemoving sudoers configuration...")
        sudoers_file = '/etc/sudoers.d/logstash-agent'
        if os.path.exists(sudoers_file):
            try:
                os.remove(sudoers_file)
                logger.info(f"✓ Removed {sudoers_file}")
            except Exception as e:
                logger.warning(f"Could not remove sudoers file: {e}")
        else:
            logger.info("Sudoers file not found, skipping")
        
        # Step 4: Remove symlink (check both /usr/local/bin and /usr/bin for RHEL)
        logger.info("\nStep 4: Removing symlink...")
        symlink_removed = False
        
        # Check /usr/local/bin (default location)
        if os.path.islink(INSTALL_PATHS['symlink']):
            os.unlink(INSTALL_PATHS['symlink'])
            logger.info(f"✓ Removed {INSTALL_PATHS['symlink']}")
            symlink_removed = True
        elif os.path.exists(INSTALL_PATHS['symlink']):
            logger.warning(f"{INSTALL_PATHS['symlink']} exists but is not a symlink, skipping")
        
        # Check /usr/bin (RHEL location)
        rhel_symlink = '/usr/bin/logstash-agent'
        if os.path.islink(rhel_symlink):
            os.unlink(rhel_symlink)
            logger.info(f"✓ Removed {rhel_symlink}")
            symlink_removed = True
        elif os.path.exists(rhel_symlink):
            logger.warning(f"{rhel_symlink} exists but is not a symlink, skipping")
        
        if not symlink_removed:
            logger.info("Symlink not found, skipping")
        
        # Step 5: Remove binary directory
        logger.info("\nStep 5: Removing binary...")
        if os.path.exists(INSTALL_PATHS['binary_dir']):
            shutil.rmtree(INSTALL_PATHS['binary_dir'])
            logger.info(f"✓ Removed {INSTALL_PATHS['binary_dir']}")
            
            # Remove parent directory if empty
            parent_dir = os.path.dirname(INSTALL_PATHS['binary_dir'])
            if os.path.exists(parent_dir) and not os.listdir(parent_dir):
                os.rmdir(parent_dir)
                logger.info(f"✓ Removed {parent_dir}")
        else:
            logger.info("Binary directory not found, skipping")
        
        # Step 6: Remove config directory
        logger.info("\nStep 6: Removing configuration...")
        if os.path.exists(INSTALL_PATHS['config_dir']):
            shutil.rmtree(INSTALL_PATHS['config_dir'])
            logger.info(f"✓ Removed {INSTALL_PATHS['config_dir']}")
        else:
            logger.info("Config directory not found, skipping")
        
        # Step 7: Optionally remove state directory
        if purge:
            logger.info("\nStep 7: Removing state directory (--purge)...")
            if os.path.exists(INSTALL_PATHS['state_dir']):
                shutil.rmtree(INSTALL_PATHS['state_dir'])
                logger.info(f"✓ Removed {INSTALL_PATHS['state_dir']}")
            else:
                logger.info("State directory not found, skipping")
        else:
            logger.info("\nStep 7: Preserving state directory...")
            logger.info(f"State directory preserved: {INSTALL_PATHS['state_dir']}")
            logger.info("(Use --purge to remove state and secrets)")
        
        # Step 8: Optionally remove log directory
        if purge:
            logger.info("\nStep 8: Removing log directory (--purge)...")
            if os.path.exists(INSTALL_PATHS['log_dir']):
                shutil.rmtree(INSTALL_PATHS['log_dir'])
                logger.info(f"✓ Removed {INSTALL_PATHS['log_dir']}")
            else:
                logger.info("Log directory not found, skipping")
        else:
            logger.info("\nStep 8: Preserving log directory...")
            logger.info(f"Log directory preserved: {INSTALL_PATHS['log_dir']}")
            logger.info("(Use --purge to remove logs)")
        
        # Step 9: Optionally remove cache directory
        if purge:
            logger.info("\nStep 9: Removing cache directory (--purge)...")
            if os.path.exists(INSTALL_PATHS['cache_dir']):
                shutil.rmtree(INSTALL_PATHS['cache_dir'])
                logger.info(f"✓ Removed {INSTALL_PATHS['cache_dir']}")
            else:
                logger.info("Cache directory not found, skipping")
        else:
            logger.info("\nStep 9: Preserving cache directory...")
            logger.info(f"Cache directory preserved: {INSTALL_PATHS['cache_dir']}")
            logger.info("(Use --purge to remove cached downloads)")
        
        # Uninstallation complete
        logger.info("\n" + "="*60)
        logger.info("UNINSTALLATION COMPLETED SUCCESSFULLY!")
        logger.info("="*60)
        
        if not purge:
            logger.info("\nPreserved directories:")
            logger.info(f"  - {INSTALL_PATHS['state_dir']}")
            logger.info(f"  - {INSTALL_PATHS['log_dir']}")
            logger.info(f"  - {INSTALL_PATHS['cache_dir']}")
            logger.info("\nTo remove these, run:")
            logger.info("  sudo logstash-agent uninstall --purge")
        
        logger.info("="*60)
        
    except InstallError as e:
        logger.error(f"\nUninstallation failed: {e}")
        raise
    except Exception as e:
        logger.error(f"\nUnexpected error during uninstallation: {e}", exc_info=True)
        raise InstallError(f"Uninstallation failed: {e}")


def download_release(version: str, download_dir: str) -> str:
    """
    Download a specific release from GitHub.
    Uses a persistent cache directory to avoid re-downloading.
    
    Args:
        version: Version to download (e.g., "0.1.4")
        download_dir: Directory to download to (unused, kept for compatibility)
    
    Returns:
        Path to the downloaded tarball
    """
    import requests
    
    # Use persistent cache directory
    cache_dir = INSTALL_PATHS['cache_dir']
    
    # Create cache directory if it doesn't exist
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir, mode=0o755)
        logger.info(f"Created cache directory: {cache_dir}")
        
        # Set ownership to logstash:logstash
        try:
            logstash_uid = pwd.getpwnam('logstash').pw_uid
            logstash_gid = grp.getgrnam('logstash').gr_gid
            os.chown(cache_dir, logstash_uid, logstash_gid)
            logger.info(f"Set cache directory ownership to logstash:logstash")
        except (KeyError, OSError) as e:
            logger.warning(f"Could not set cache directory ownership: {e}")
    
    # Check if tarball already exists in cache
    cached_tarball = os.path.join(cache_dir, f"logstash-agent-{version}.tar.gz")
    
    if os.path.exists(cached_tarball):
        logger.info(f"✓ Found cached download: {cached_tarball}")
        logger.info("Skipping download (using cached version)")
        return cached_tarball
    
    # GitHub release URL
    url = f"https://github.com/elastic/LogstashAgent/releases/download/v{version}/logstash-agent-linux-amd64.tar.gz"
    
    logger.info(f"Downloading {url}...")
    logger.info(f"Cache location: {cached_tarball}")
    
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        
        # Download with progress
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        with open(cached_tarball, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        logger.debug(f"Downloaded {percent:.1f}%")
        
        # Set ownership to logstash:logstash so agent can read it
        try:
            logstash_uid = pwd.getpwnam('logstash').pw_uid
            logstash_gid = grp.getgrnam('logstash').gr_gid
            os.chown(cached_tarball, logstash_uid, logstash_gid)
            os.chmod(cached_tarball, 0o644)  # rw-r--r--
        except (KeyError, OSError) as e:
            logger.warning(f"Could not set tarball ownership: {e}")
        
        logger.info(f"✓ Downloaded to cache: {cached_tarball}")
        return cached_tarball
        
    except requests.exceptions.RequestException as e:
        raise InstallError(f"Failed to download release {version}: {e}")


def extract_binary(tarball_path: str, extract_dir: str) -> str:
    """
    Extract the binary from the tarball.
    
    Args:
        tarball_path: Path to the tarball
        extract_dir: Directory to extract to
    
    Returns:
        Path to the extracted binary
    """
    import tarfile
    
    logger.info(f"Extracting {tarball_path}...")
    
    try:
        with tarfile.open(tarball_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        
        # Find the binary
        binary_path = os.path.join(extract_dir, 'logstash-agent', 'logstash-agent')
        
        if not os.path.exists(binary_path):
            raise InstallError(f"Binary not found in tarball at expected location: {binary_path}")
        
        logger.info(f"✓ Extracted binary to {binary_path}")
        return binary_path
        
    except (tarfile.TarError, OSError) as e:
        raise InstallError(f"Failed to extract tarball: {e}")


def is_sudo_rs() -> bool:
    """
    Detect whether the system is using sudo-rs instead of GNU sudo.

    sudo-rs (Ubuntu 26+) does not support the 'Defaults:user !requiretty'
    directive — using it causes visudo validation to fail.  sudo-rs also does
    not require a TTY by default, so the directive is unnecessary there.

    sudo-rs also rejects wildcards in *command arguments* (e.g.
    ``systemctl restart ls-simulate@*``), which is why we use logstash-agent-ctl.
    """
    try:
        result = subprocess.run(
            ['sudo', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return 'sudo-rs' in result.stdout or 'sudo-rs' in result.stderr
    except Exception:
        return False


def systemctl_via_sudo(action: str, unit: str, *, timeout: int = 30) -> subprocess.CompletedProcess:
    """
    Run systemctl as root via the validated helper (preferred) or plain sudo.

    Prefer ``sudo logstash-agent-ctl <action> <unit>`` so sudoers never need
    wildcards (required for sudo-rs). Falls back to ``sudo systemctl`` for
    older installs that only have the legacy drop-in.
    """
    ctl = INSTALL_PATHS['systemctl_ctl']
    if os.path.isfile(ctl) and os.access(ctl, os.X_OK):
        return subprocess.run(
            ['sudo', ctl, action, unit],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    return subprocess.run(
        ['sudo', 'systemctl', action, unit],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def verify_service_running() -> bool:
    """
    Verify that the logstash-agent service is running.
    
    Returns:
        True if service is active, False otherwise
    """
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'logstash-agent'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False


def perform_upgrade(version: str, auto: bool = False) -> None:
    """
    Perform the upgrade process.
    
    Args:
        version: Version to upgrade to (e.g., "0.1.4")
        auto: If True, this is an automatic upgrade triggered by the controller
    """
    logger.info("="*60)
    logger.info(f"LOGSTASH AGENT UPGRADE TO VERSION {version}")
    logger.info("="*60)
    
    temp_dir = None
    backup_path = f"{INSTALL_PATHS['binary']}.backup"
    service_was_running = False
    
    try:
        # Step 1: Verify prerequisites
        logger.info("\nStep 1: Verifying prerequisites...")
        verify_root()
        verify_platform()
        
        # Verify agent is installed
        if not os.path.exists(INSTALL_PATHS['binary']):
            raise InstallError(
                f"LogstashAgent is not installed at {INSTALL_PATHS['binary']}. "
                "Run 'install' command first."
            )
        logger.info("✓ Agent installation verified")
        
        # Step 2: Create temporary directory
        logger.info("\nStep 2: Preparing download...")
        import tempfile
        temp_dir = tempfile.mkdtemp(prefix='logstash-agent-upgrade-')
        logger.info(f"✓ Created temporary directory: {temp_dir}")
        
        # Step 3: Download release
        logger.info(f"\nStep 3: Downloading version {version}...")
        tarball_path = download_release(version, temp_dir)
        
        # Step 4: Extract binary
        logger.info("\nStep 4: Extracting binary...")
        new_binary_path = extract_binary(tarball_path, temp_dir)
        
        # Make it executable
        os.chmod(new_binary_path, 0o755)
        logger.info("✓ Binary extracted and marked executable")
        
        # Step 5: Check if service is running
        logger.info("\nStep 5: Checking service status...")
        service_was_running = verify_service_running()
        if service_was_running:
            logger.info("Service is running, will be restarted")
        else:
            logger.info("Service is not running")
        
        # Step 6: Skip stopping service - just overwrite and restart
        # The atomic rename allows us to replace the binary while it's running
        # Then systemctl restart will cleanly stop old process and start new one
        logger.info("\nStep 6: Skipping service stop (will restart after binary replacement)...")
        logger.info("✓ Service will be restarted with new binary")
        
        # Step 7: Backup current binary and dependencies
        logger.info("\nStep 7: Backing up current binary...")
        if os.path.exists(backup_path):
            os.remove(backup_path)
        shutil.copy2(INSTALL_PATHS['binary'], backup_path)
        logger.info(f"✓ Backed up binary to {backup_path}")
        
        # Also backup _internal directory if it exists
        internal_backup_path = f"{INSTALL_PATHS['binary_dir']}/_internal.backup"
        internal_current = os.path.join(INSTALL_PATHS['binary_dir'], '_internal')
        if os.path.exists(internal_current):
            if os.path.exists(internal_backup_path):
                shutil.rmtree(internal_backup_path)
            shutil.copytree(internal_current, internal_backup_path)
            logger.info(f"✓ Backed up dependencies to {internal_backup_path}")
        
        # Step 8: Replace binary
        logger.info("\nStep 8: Installing new binary...")
        
        # Get source directory for PyInstaller bundle
        new_binary_dir = os.path.dirname(new_binary_path)
        
        # Check if binary is still in use before attempting copy
        try:
            # Try to check if any process is using the binary
            result = subprocess.run(['lsof', INSTALL_PATHS['binary']], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.warning(f"Binary is still in use by processes:")
                logger.warning(result.stdout.decode())
            else:
                logger.info("Binary is not in use by any processes")
        except Exception as e:
            logger.debug(f"Could not check if binary is in use: {e}")
        
        # Install the main binary using atomic rename
        # We can't use shutil.copy2() directly because the upgrade process itself
        # is running from this binary, causing "Text file busy" error
        logger.info(f"Installing new binary to {INSTALL_PATHS['binary']}")
        try:
            # First copy to a temporary location
            temp_binary = f"{INSTALL_PATHS['binary']}.new"
            shutil.copy2(new_binary_path, temp_binary)
            os.chmod(temp_binary, 0o755)
            logger.info(f"✓ Copied new binary to {temp_binary}")
            
            # Atomically rename over the old binary
            # This works even if the old binary is currently executing
            os.rename(temp_binary, INSTALL_PATHS['binary'])
            logger.info(f"✓ Installed new binary to {INSTALL_PATHS['binary']}")
        except OSError as e:
            logger.error(f"Failed to install binary: {e}")
            logger.error(f"Error code: {e.errno}")
            logger.error(f"Error message: {e.strerror}")
            # Check service status
            service_check = subprocess.run(['systemctl', 'is-active', 'logstash-agent'],
                                         capture_output=True)
            logger.error(f"Service status: {service_check.stdout.decode().strip()}")
            # Clean up temp file if it exists
            if os.path.exists(temp_binary):
                os.remove(temp_binary)
            raise
        
        # Check for _internal directory (PyInstaller dependencies)
        internal_source = os.path.join(new_binary_dir, '_internal')
        if os.path.exists(internal_source):
            internal_dest = os.path.join(INSTALL_PATHS['binary_dir'], '_internal')
            
            # Remove existing _internal if it exists
            if os.path.exists(internal_dest):
                shutil.rmtree(internal_dest)
            
            # Copy the entire _internal directory
            shutil.copytree(internal_source, internal_dest)
            logger.info(f"✓ Installed PyInstaller dependencies to {internal_dest}")
            
            # Set SELinux context for _internal directory on RHEL/CentOS
            try:
                result = subprocess.run(['which', 'restorecon'], capture_output=True)
                if result.returncode == 0:
                    subprocess.run(['restorecon', '-Rv', internal_dest], 
                                 check=False, capture_output=True)
                    logger.debug(f"Set SELinux context for {internal_dest}")
            except Exception:
                pass
        else:
            logger.warning("_internal directory not found in upgrade package")
        
        # Set SELinux context for upgraded binary on RHEL/CentOS
        try:
            result = subprocess.run(['which', 'restorecon'], capture_output=True)
            if result.returncode == 0:
                subprocess.run(['restorecon', '-v', INSTALL_PATHS['binary']], 
                             check=False, capture_output=True)
                logger.info(f"✓ Set SELinux context for upgraded binary")
        except Exception as e:
            logger.debug(f"SELinux context setting skipped: {e}")
        
        # Step 9: Restart service (always restart after upgrade)
        logger.info("\nStep 9: Restarting service with new binary...")
        try:
            subprocess.run(['systemctl', 'restart', 'logstash-agent'], 
                         check=True, capture_output=True, timeout=30)
            logger.info("✓ Service restarted")
            
            # Step 10: Verify service is running
            logger.info("\nStep 10: Verifying service health...")
            import time
            time.sleep(2)  # Give it a moment to start
            
            if verify_service_running():
                logger.info("✓ Service is running successfully")
            else:
                raise InstallError("Service failed to start with new binary")
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, InstallError) as e:
            # Rollback!
            logger.error(f"Service failed to start: {e}")
            logger.info("\nPerforming rollback...")
            
            rollback_success = True
            rollback_errors = []
            
            try:
                # Stop the failed service
                subprocess.run(['systemctl', 'stop', 'logstash-agent'], 
                             check=False, capture_output=True)
                logger.info("✓ Stopped failed service")
            except Exception as stop_error:
                logger.warning(f"Could not stop service: {stop_error}")
                rollback_errors.append(f"Failed to stop service: {stop_error}")
            
            try:
                # Restore backup binary
                if not os.path.exists(backup_path):
                    raise InstallError(f"Backup binary not found at {backup_path}")
                shutil.copy2(backup_path, INSTALL_PATHS['binary'])
                logger.info("✓ Restored previous binary")
            except Exception as restore_error:
                logger.error(f"Failed to restore binary: {restore_error}")
                rollback_errors.append(f"Failed to restore binary: {restore_error}")
                rollback_success = False
            
            try:
                # Restore backup _internal if it exists
                internal_backup_path = f"{INSTALL_PATHS['binary_dir']}/_internal.backup"
                if os.path.exists(internal_backup_path):
                    internal_dest = os.path.join(INSTALL_PATHS['binary_dir'], '_internal')
                    if os.path.exists(internal_dest):
                        shutil.rmtree(internal_dest)
                    shutil.copytree(internal_backup_path, internal_dest)
                    logger.info("✓ Restored previous dependencies")
            except Exception as deps_error:
                logger.warning(f"Failed to restore dependencies: {deps_error}")
                rollback_errors.append(f"Failed to restore dependencies: {deps_error}")
            
            if rollback_success:
                try:
                    # Start with old binary
                    subprocess.run(['systemctl', 'start', 'logstash-agent'], 
                                 check=True, capture_output=True, timeout=30)
                    logger.info("✓ Service restarted with previous version")
                    logger.info("\nRollback completed successfully")
                except Exception as start_error:
                    logger.error(f"Failed to start service after rollback: {start_error}")
                    rollback_errors.append(f"Failed to start service: {start_error}")
                    rollback_success = False
            
            if not rollback_success:
                logger.error("\n" + "="*60)
                logger.error("ROLLBACK FAILED - MANUAL INTERVENTION REQUIRED")
                logger.error("="*60)
                logger.error("\nRollback errors:")
                for error in rollback_errors:
                    logger.error(f"  - {error}")
                logger.error("\nManual recovery steps:")
                logger.error(f"  1. Check if backup exists: ls -la {backup_path}")
                logger.error(f"  2. Manually restore: sudo cp {backup_path} {INSTALL_PATHS['binary']}")
                logger.error(f"  3. Restore permissions: sudo chmod 755 {INSTALL_PATHS['binary']}")
                logger.error(f"  4. Start service: sudo systemctl start logstash-agent")
                logger.error(f"  5. Check status: sudo systemctl status logstash-agent")
                logger.error("="*60)
                raise InstallError(
                    f"Upgrade failed and rollback encountered errors. "
                    f"Manual recovery required. See log for details.")
            
            raise InstallError(f"Upgrade failed and was rolled back: {e}")
        
        # Step 11: Cleanup
        logger.info("\nStep 11: Cleaning up...")
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info("✓ Removed temporary files")
        
        # Remove backup files after successful upgrade
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
                logger.info(f"✓ Removed backup binary: {backup_path}")
            except OSError as e:
                logger.warning(f"Could not remove backup binary: {e}")
        
        internal_backup_path = f"{INSTALL_PATHS['binary_dir']}/_internal.backup"
        if os.path.exists(internal_backup_path):
            try:
                shutil.rmtree(internal_backup_path)
                logger.info(f"✓ Removed backup dependencies: {internal_backup_path}")
            except OSError as e:
                logger.warning(f"Could not remove backup dependencies: {e}")
        
        # Keep cached tarball for future upgrades (persistent cache)
        logger.debug(f"Cached tarball preserved at {INSTALL_PATHS['cache_dir']} for future use")
        
        # Upgrade complete
        logger.info("\n" + "="*60)
        logger.info(f"UPGRADE TO VERSION {version} COMPLETED SUCCESSFULLY!")
        logger.info("="*60)
        logger.info(f"\nBackup of previous version: {backup_path}")
        logger.info("(Backup will be overwritten on next upgrade)")
        
        if service_was_running:
            logger.info("\nService status:")
            logger.info("  sudo systemctl status logstash-agent")
        else:
            logger.info("\nTo start the service:")
            logger.info("  sudo systemctl start logstash-agent")
        
        logger.info("="*60)
        
    except InstallError as e:
        logger.error(f"\nUpgrade failed: {e}")
        # Cleanup temp directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise
    except Exception as e:
        logger.error(f"\nUnexpected error during upgrade: {e}", exc_info=True)
        # Cleanup temp directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise InstallError(f"Upgrade failed: {e}")
