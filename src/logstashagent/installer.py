#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Unix-only imports
try:
    import grp
    import pwd
except ImportError:
    # Not on Unix - installer won't work but module can still be imported
    pwd = None
    grp = None

logger = logging.getLogger(__name__)

# All agent-owned data lives under /opt/logstash-agent.
# The only intentional runtime path outside that tree is the CLI symlink
# (/usr/local/bin/logstash-agent). Systemd unit files and sudoers must remain
# under /etc (systemd/sudo requirements).
OPT_ROOT = '/opt/logstash-agent'

INSTALL_PATHS = {
    'opt_root': OPT_ROOT,
    'binary_dir': f'{OPT_ROOT}/bin',
    'binary': f'{OPT_ROOT}/bin/logstash-agent',
    'symlink': '/usr/local/bin/logstash-agent',
    # Validated systemctl wrapper (sudo-rs compatible — no wildcards in sudoers args)
    'systemctl_ctl': f'{OPT_ROOT}/bin/logstash-agent-ctl',
    'config_dir': f'{OPT_ROOT}/config',
    'state_dir': f'{OPT_ROOT}/state',
    'log_dir': f'{OPT_ROOT}/logs',
    'cache_dir': f'{OPT_ROOT}/cache',
    'simulate_root': OPT_ROOT,
    'systemd_service': '/etc/systemd/system/logstash-agent.service',
    'lsagent_simulate_unit': '/etc/systemd/system/lsagent-simulate@.service',
    'ls_simulate_unit': '/etc/systemd/system/ls-simulate@.service',
    # Managed multi-instance (agent-owned Logstash trees)
    'logstash_agent_template_unit': '/etc/systemd/system/logstash-agent@.service',
    'logstash_managed_unit': '/etc/systemd/system/logstash-managed@.service',
}

# Pre-consolidation FHS paths — read/migrate, never write for new installs
LEGACY_INSTALL_PATHS = {
    'config_dir': '/etc/logstash-agent',
    'state_dir': '/var/lib/logstash-agent',
    'log_dir': '/var/log/logstash-agent',
    'cache_dir': '/var/cache/logstash-agent',
}

# Legacy root from early simulate work — never recreate; rewrite inbound policy paths
_LEGACY_OPT_ROOT = '/opt/LogstashAgent'


def normalize_opt_path(path) -> str:
    """Rewrite /opt/LogstashAgent → /opt/logstash-agent on policy/enroll paths."""
    if path is None:
        return ''
    p = str(path)
    if not p:
        return ''
    if p.startswith(_LEGACY_OPT_ROOT):
        return INSTALL_PATHS['simulate_root'] + p[len(_LEGACY_OPT_ROOT):]
    return p.replace(_LEGACY_OPT_ROOT, INSTALL_PATHS['simulate_root'])

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
# Allow fixed units and template instances with numeric instance ids only.
# Packaged: logstash, logstash-agent
# Simulate: ls-simulate@N, lsagent-simulate@N
# Managed:  logstash-managed@N, logstash-agent@N
if ! echo "$UNIT" | grep -Eq '^(logstash|logstash-agent|((ls-simulate|lsagent-simulate|logstash-agent|logstash-managed)@[0-9]+))$'; then
  echo "logstash-agent-ctl: disallowed unit: $UNIT" >&2
  exit 2
fi
# Drop PyInstaller/frozen LD_LIBRARY_PATH so host systemctl uses distro OpenSSL
# (bundled libcrypto under _internal breaks systemd linked to OPENSSL_3.4+).
unset LD_LIBRARY_PATH
unset DYLD_LIBRARY_PATH
unset DYLD_FALLBACK_LIBRARY_PATH
if [ -n "${LD_LIBRARY_PATH_ORIG+x}" ]; then
  if [ -n "$LD_LIBRARY_PATH_ORIG" ]; then
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH_ORIG"
  fi
  unset LD_LIBRARY_PATH_ORIG
fi
SYSTEMCTL=""
if [ -x /usr/bin/systemctl ]; then
  SYSTEMCTL=/usr/bin/systemctl
elif [ -x /bin/systemctl ]; then
  SYSTEMCTL=/bin/systemctl
else
  SYSTEMCTL="$(command -v systemctl 2>/dev/null || true)"
fi
if [ -z "$SYSTEMCTL" ]; then
  echo "logstash-agent-ctl: systemctl not found" >&2
  exit 127
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
    Directory with multi-instance systemd unit templates
    (simulate + managed).

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
WorkingDirectory=/opt/logstash-agent/state
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


class InstallError(Exception):
    """Installation error"""


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
        logger.warning("   /opt/logstash-agent/config/logstash-agent.yml and restart the service.")
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


def migrate_legacy_fhs_paths() -> None:
    """
    One-time best-effort move of pre-consolidation dirs into /opt/logstash-agent.

    Old layout used /etc, /var/lib, /var/log, /var/cache. New installs never
    create those; upgrades copy content when the new location is empty.
    """
    for key, legacy in LEGACY_INSTALL_PATHS.items():
        new = INSTALL_PATHS[key]
        if not os.path.isdir(legacy):
            continue
        if os.path.isdir(new) and os.listdir(new):
            logger.info(
                "Legacy %s present but %s already populated — leaving legacy in place",
                legacy,
                new,
            )
            continue
        try:
            os.makedirs(os.path.dirname(new), mode=0o755, exist_ok=True)
            if os.path.isdir(new) and not os.listdir(new):
                os.rmdir(new)
            shutil.move(legacy, new)
            logger.info("✓ Migrated %s → %s", legacy, new)
        except OSError as e:
            try:
                if not os.path.isdir(new):
                    shutil.copytree(legacy, new, dirs_exist_ok=True)
                    logger.info("✓ Copied legacy %s → %s (%s)", legacy, new, e)
                else:
                    logger.warning("Could not migrate %s → %s: %s", legacy, new, e)
            except OSError as e2:
                logger.warning("Could not migrate %s → %s: %s", legacy, new, e2)


def create_directories():
    """Create all required directories for LogstashAgent under /opt/logstash-agent."""
    logger.info("Creating installation directories under %s ...", INSTALL_PATHS['opt_root'])

    uid, gid = get_logstash_uid_gid()

    migrate_legacy_fhs_paths()

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

    # VERSION download cache — owned by logstash so Logstash can read its tree
    versions_dir = os.path.join(INSTALL_PATHS['opt_root'], 'logstash-versions')
    os.makedirs(versions_dir, mode=0o755, exist_ok=True)
    try:
        from logstashagent.logstash_download import chown_tree_to_logstash

        chown_tree_to_logstash(versions_dir)
    except Exception:
        try:
            os.chown(versions_dir, uid, gid)
        except OSError:
            pass
    logger.info(f"✓ Ensured {versions_dir} (owned by logstash)")

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
                result = subprocess.run(
                    ['which', 'restorecon'],
                    capture_output=True,
                    check=False
                )
                if result.returncode == 0:
                    subprocess.run(
                        ['restorecon', '-Rv', internal_dest],
                        check=False,
                        capture_output=True
                    )
                    logger.debug(f"Set SELinux context for {internal_dest}")
            except Exception as e:
                logger.error(f"Failed to set SELinux context for {internal_dest}: {e}")
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
        result = subprocess.run(
            ['which', 'restorecon'],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            subprocess.run(
                ['restorecon', '-v', INSTALL_PATHS['binary']],
                check=False,
                capture_output=True,
            )
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


def write_config_file(
    logstash_ui_url: str,
    policy_config: dict | None = None,
    *,
    config_path: str | None = None,
) -> str:
    """
    Write the initial agent config file (packaged / managed / simulate).

    Packaged → ``/opt/logstash-agent/config/logstash-agent.yml`` (shared host default).
    Multi-instance → ``{path_root}/logstash-agent.yml`` so it does not clobber
    packaged config when roles coexist on one host.

    Returns the path written.
    """
    logger.info("Writing configuration file...")
    policy_config = policy_config or {}
    policy_type = (policy_config.get('policy_type') or 'PACKAGED').upper()
    if policy_type == 'DEFAULT':
        policy_type = 'PACKAGED'
    is_multi = policy_type in ('SIMULATE', 'MANAGED')

    logstash_present = os.path.isdir('/usr/share/logstash') and os.path.isdir('/etc/logstash')

    if is_multi:
        instance_id = policy_config.get('instance_id', 1)
        mode_name = 'managed' if policy_type == 'MANAGED' else 'simulate'
        default_prefix = (
            f"managed-{instance_id}" if policy_type == 'MANAGED' else f"simulate-{instance_id}"
        )
        path_root = normalize_opt_path(
            policy_config.get('path_root')
            or f"{INSTALL_PATHS['simulate_root']}/{default_prefix}"
        )
        binary = normalize_opt_path(
            policy_config.get('binary_path', '/usr/share/logstash/bin')
        ) or '/usr/share/logstash/bin'
        if binary and not str(binary).endswith('logstash') and not str(binary).endswith('logstash.bat'):
            binary = str(Path(binary) / 'logstash')
        settings = normalize_opt_path(
            policy_config.get(
                'settings_path', f"{path_root}/settings"
            )
        )
        logs = normalize_opt_path(
            policy_config.get(
                'logs_path', f"{path_root}/logs"
            )
        )
        if policy_type == 'MANAGED':
            agent_port = policy_config.get('agent_api_port', 9600 + int(instance_id))
            ls_port = policy_config.get('logstash_api_port', 9700 + int(instance_id))
        else:
            agent_port = policy_config.get('agent_api_port', 9500 + int(instance_id))
            ls_port = policy_config.get('logstash_api_port', 9560 + int(instance_id))
        download_dir = normalize_opt_path(
            policy_config.get('logstash_download_dir')
            or f"{INSTALL_PATHS['simulate_root']}/logstash-versions"
        )
        state_dir = f"{path_root}/state"
        config_content = f"""# LogstashAgent Configuration
# Generated during installation ({policy_type} instance — host-coexistence safe)
# Instance config lives under {path_root}/ so packaged /etc config is untouched.
mode: {mode_name}
instance_id: {instance_id}

logstash_binary: {binary}
logstash_settings: {settings}
logstash_log_path: {logs}

logstash_api_port: {ls_port}
logstash_source: {policy_config.get('logstash_source') or 'SYSTEM'}
logstash_version: "{policy_config.get('logstash_version') or ''}"
logstash_download_dir: {download_dir}

# FastAPI agent API (multi-instance roles)
host: 0.0.0.0
port: {agent_port}

logstash_ui_url: {logstash_ui_url}

# Per-instance state (also set via LOGSTASH_AGENT_STATE_DIR in agent.env)
# state_dir: {state_dir}
"""
        if not config_path:
            config_path = os.path.join(path_root, 'logstash-agent.yml')
    else:
        path_comment = ""
        if not logstash_present:
            path_comment = (
                "\n# ⚠  Logstash was NOT detected at install time.\n"
                "# Update the three paths below to match your Logstash installation\n"
                "# before starting the logstash-agent service.\n"
            )
        settings = normalize_opt_path(
            policy_config.get('settings_path') or '/etc/logstash'
        ) or '/etc/logstash'
        logs = normalize_opt_path(
            policy_config.get('logs_path') or '/var/log/logstash'
        ) or '/var/log/logstash'
        binary = normalize_opt_path(
            policy_config.get('binary_path') or '/usr/share/logstash/bin'
        ) or '/usr/share/logstash/bin'
        if binary and not str(binary).endswith('logstash') and not str(binary).endswith('logstash.bat'):
            binary = str(Path(binary) / 'logstash')
        ls_port = policy_config.get('logstash_api_port') or 9600
        config_content = f"""# LogstashAgent Configuration
# Generated during installation (PACKAGED / distro Logstash)
# Multi-instance roles use their own yml under /opt/logstash-agent/{{managed,simulate}}-N/
{path_comment}
mode: packaged

# Paths to this Logstash installation
logstash_binary: {binary}
logstash_settings: {settings}
logstash_log_path: {logs}

# Port that Logstash's monitoring API listens on (default: 9600 for package installs)
# Embedded Docker uses 9560; simulate instances use 9560+N; managed use 9700+N
logstash_api_port: {ls_port}

# Agent API server (not used in packaged controller mode)
host: 127.0.0.1
port: 9600

# LogstashUI connection
logstash_ui_url: {logstash_ui_url}
"""
        if not config_path:
            config_path = os.path.join(INSTALL_PATHS['config_dir'], 'logstash-agent.yml')

    os.makedirs(os.path.dirname(config_path), mode=0o755, exist_ok=True)
    with open(config_path, 'w') as f:
        f.write(config_content)

    try:
        uid, gid = get_logstash_uid_gid()
        os.chown(config_path, uid, gid)
    except Exception as e:
        logger.error(f"Failed to set ownership for {config_path}: {e}")
    os.chmod(config_path, 0o640)

    logger.info(f"✓ Created configuration file {config_path}")
    return config_path


def _read_unit_template(name: str) -> str:
    path = _systemd_template_dir() / name
    if not path.is_file():
        raise InstallError(
            f"Missing systemd unit template: {path} "
            f"(searched under {_systemd_template_dir()})"
        )
    return path.read_text(encoding='utf-8')


# (template filename, INSTALL_PATHS dest key)
_MULTI_INSTANCE_UNIT_TEMPLATES = (
    # Simulate
    ('lsagent-simulate@.service', 'lsagent_simulate_unit'),
    ('ls-simulate@.service', 'ls_simulate_unit'),
    # Managed
    ('logstash-agent@.service', 'logstash_agent_template_unit'),
    ('logstash-managed@.service', 'logstash_managed_unit'),
)


def install_multi_instance_unit_templates() -> None:
    """
    Install all multi-instance systemd unit templates (simulate + managed).

    Safe to call on every multi-instance install; overwrites templates in place
    and runs daemon-reload once.
    """
    logger.info("Installing multi-instance systemd unit templates...")
    for template_name, dest_key in _MULTI_INSTANCE_UNIT_TEMPLATES:
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
        _systemctl_cmd('daemon-reload', check=True)
        logger.info("✓ Reloaded systemd daemon")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning(f"daemon-reload failed (non-fatal): {e}")


def install_simulate_unit_templates() -> None:
    """Backward-compatible alias for install_multi_instance_unit_templates()."""
    install_multi_instance_unit_templates()


def _materialize_instance_logstash_yml(
    template: str,
    logstash_api_port: int,
    *,
    instance_id: int | None = None,
) -> str:
    """
    Rewrite Logstash yml so api.http.port matches *logstash_api_port*.

    Handles nested UI editor form (api.http.port) and flat api.http.port keys.
    Also expands ``{instance_id}`` path placeholders.
    """
    text = template or ""
    if instance_id is not None:
        text = text.replace("{instance_id}", str(instance_id))
    port = int(logstash_api_port)
    try:
        import yaml

        data = yaml.safe_load(text)
        if isinstance(data, dict):
            api = data.get("api")
            if not isinstance(api, dict):
                api = {}
                data["api"] = api
            http = api.get("http")
            if not isinstance(http, dict):
                http = {}
                api["http"] = http
            http["port"] = port
            if "host" not in http:
                http["host"] = "0.0.0.0"
            if "api.http.port" in data:
                data["api.http.port"] = port
            if "http.port" in data:
                data["http.port"] = port
            out = yaml.safe_dump(
                data,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
            return out if out.endswith("\n") else out + "\n"
    except Exception:
        pass
    lines: list[str] = []
    port_set = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("api.http.port:") or stripped.startswith("http.port:"):
            lines.append(f"api.http.port: {port}")
            port_set = True
        else:
            lines.append(line)
    if not port_set:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"api.http.port: {port}")
    return "\n".join(lines) + ("\n" if lines else "")


def materialize_simulate_instance(policy_config: dict) -> dict:
    """
    Create /opt/logstash-agent/simulate-N tree, env files, seed configs.

    Returns dict with resolved binary path and paths used.
    Always uses INSTALL_PATHS['simulate_root'] (/opt/logstash-agent); rewrites
    legacy /opt/LogstashAgent prefixes from older enroll payloads.
    """
    from logstashagent.logstash_download import resolve_binary_from_policy

    # Normalize inbound paths (stale UI DB / old enrollments)
    for key in (
        'settings_path', 'config_path', 'logs_path', 'data_path',
        'keystore_env_file', 'logstash_download_dir', 'binary_path',
    ):
        if policy_config.get(key):
            policy_config[key] = normalize_opt_path(policy_config[key])

    instance_id = policy_config.get('instance_id')
    if instance_id is None:
        raise InstallError("Multi-instance policy_config missing instance_id")

    instance_id = int(instance_id)
    pt = (policy_config.get('policy_type') or 'SIMULATE').upper()
    if pt == 'DEFAULT':
        pt = 'PACKAGED'
    # Prefer explicit path_root / deployment_id (managed-N or simulate-N)
    if policy_config.get('path_root'):
        root = Path(normalize_opt_path(policy_config['path_root']))
    elif policy_config.get('deployment_id'):
        root = Path(INSTALL_PATHS['simulate_root']) / str(policy_config['deployment_id'])
    elif pt == 'MANAGED':
        root = Path(INSTALL_PATHS['simulate_root']) / f"managed-{instance_id}"
    else:
        root = Path(INSTALL_PATHS['simulate_root']) / f"simulate-{instance_id}"
    # Prefer code-derived root so a bad settings_path under /opt/LogstashAgent cannot win
    settings = root / 'settings'
    if policy_config.get('settings_path'):
        sp = Path(normalize_opt_path(policy_config['settings_path']))
        if str(sp).startswith(str(root)):
            settings = sp
    config_dir = root / 'config'
    if policy_config.get('config_path'):
        cp = Path(normalize_opt_path(policy_config['config_path']))
        if str(cp).startswith(str(root)):
            config_dir = cp
    logs = root / 'logs'
    if policy_config.get('logs_path'):
        lp = Path(normalize_opt_path(policy_config['logs_path']))
        if str(lp).startswith(str(root)):
            logs = lp
    data = root / 'data'
    if policy_config.get('data_path'):
        dp = Path(normalize_opt_path(policy_config['data_path']))
        if str(dp).startswith(str(root)):
            data = dp
    env_file = root / 'env'
    if policy_config.get('keystore_env_file'):
        ep = Path(normalize_opt_path(policy_config['keystore_env_file']))
        if str(ep).startswith(str(root)):
            env_file = ep
    agent_env = root / 'agent.env'
    state_dir = root / 'state'

    # Pipeline .conf files live under settings/config/ (and settings/conf.d/ for
    # dynamic slots). Logstash is started with --path.settings only; each pipeline
    # path is listed in settings/pipelines.yml (no CLI --path.config).
    pipeline_config_dir = settings / 'config'
    for d in (settings, config_dir, logs, data, state_dir, settings / 'conf.d', pipeline_config_dir):
        d.mkdir(parents=True, exist_ok=True)
        logger.info(f"✓ Ensured directory {d}")

    # Seed config files from policy when provided.
    # Re-materialize logstash.yml so nested api.http.port matches instance port
    # even if the UI sent a template with port 9560 / {instance_id} paths.
    ls_port_for_yml = policy_config.get('logstash_api_port')
    if ls_port_for_yml is None:
        ls_port_for_yml = (9700 if pt == 'MANAGED' else 9560) + instance_id
    for name, key in (
        ('logstash.yml', 'logstash_yml'),
        ('jvm.options', 'jvm_options'),
        ('log4j2.properties', 'log4j2_properties'),
    ):
        content = policy_config.get(key)
        if content:
            if key == 'logstash_yml':
                content = _materialize_instance_logstash_yml(
                    content, int(ls_port_for_yml), instance_id=instance_id
                )
            target = settings / name
            target.write_text(content if content.endswith('\n') else content + '\n', encoding='utf-8')
            logger.info(f"✓ Wrote {target}")

    # Simulate-only: seed simulation harness (simulate-start/end) + bare pipelines.yml
    # Managed trees get a minimal placeholder pipelines.yml until the agent deploys policy.
    if pt == 'SIMULATE':
        try:
            from logstashagent import simulate_recovery

            seed = simulate_recovery.seed_static_harness(settings, force=False)
            if seed.get('ok'):
                # Always (re)write bare pipelines.yml so path.config entries match seed location
                simulate_recovery.write_bare_pipelines_yml(settings)
                logger.info(
                    "✓ Wrote bare simulate pipelines.yml (harness confs under %s)",
                    pipeline_config_dir,
                )
            else:
                logger.warning(
                    "Could not seed full simulate harness: %s",
                    seed.get('missing_src'),
                )
        except Exception as e:
            logger.warning("Simulate harness seed during materialize failed: %s", e)
    else:
        pipelines_yml = settings / 'pipelines.yml'
        if not pipelines_yml.is_file():
            pipelines_yml.write_text(
                "# Managed by LogstashAgent — pipelines deployed on check-in\n"
                "- pipeline.id: .agent-placeholder\n"
                "  path.config: \"/dev/null\"\n",
                encoding='utf-8',
            )
            logger.info("✓ Wrote placeholder pipelines.yml for managed instance")

    binary = resolve_binary_from_policy(
        logstash_source=policy_config.get('logstash_source') or 'SYSTEM',
        logstash_version=policy_config.get('logstash_version') or '',
        logstash_download_dir=policy_config.get('logstash_download_dir')
        or f"{INSTALL_PATHS['simulate_root']}/logstash-versions",
        binary_path=policy_config.get('binary_path') or '/usr/share/logstash/bin',
    )

    if pt == 'MANAGED':
        agent_port = policy_config.get('agent_api_port', 9600 + instance_id)
        ls_port = policy_config.get('logstash_api_port', 9700 + instance_id)
        agent_mode = 'managed'
        agent_unit = policy_config.get('agent_unit') or f'logstash-agent@{instance_id}'
        logstash_unit = policy_config.get('logstash_unit') or f'logstash-managed@{instance_id}'
    else:
        agent_port = policy_config.get('agent_api_port', 9500 + instance_id)
        ls_port = policy_config.get('logstash_api_port', 9560 + instance_id)
        agent_mode = 'simulate'
        agent_unit = policy_config.get('agent_unit') or f'lsagent-simulate@{instance_id}'
        logstash_unit = policy_config.get('logstash_unit') or f'ls-simulate@{instance_id}'

    # EnvironmentFile for logstash-managed@N / ls-simulate@N
    # Only path.settings (+ logs/data) are passed to Logstash. Pipeline conf
    # locations are exclusively in settings/pipelines.yml.
    # LOGSTASH_URL: base for simulate_start/end StreamSimulate HTTP outputs
    # (must be real UI URL on host simulate — not host.docker.internal:8080).
    stream_base = (
        (policy_config.get('logstash_ui_url') or '').strip()
        or (os.environ.get('LOGSTASH_URL') or '').strip()
        or (os.environ.get('LOGSTASH_UI_URL') or '').strip()
    )
    if not stream_base:
        try:
            from logstashagent import agent_state as _as_env

            stream_base = (_as_env.get_state() or {}).get('logstash_ui_url') or ''
        except Exception:
            stream_base = ''
    stream_base = str(stream_base).rstrip('/')

    env_lines = [
        f"LOGSTASH_BINARY={binary}",
        f"LOGSTASH_PATH_SETTINGS={settings}",
        f"LOGSTASH_PATH_LOGS={logs}",
        f"LOGSTASH_PATH_DATA={data}",
        # LOGSTASH_KEYSTORE_PASS added later when keystore password is set
    ]
    if stream_base:
        env_lines.append(f"LOGSTASH_URL={stream_base}")
        env_lines.append(f"LOGSTASH_UI_URL={stream_base}")
    # Preserve existing keystore pass / URL if re-materializing
    if env_file.exists():
        for line in env_file.read_text(encoding='utf-8').splitlines():
            if line.startswith('LOGSTASH_KEYSTORE_PASS='):
                env_lines.append(line)
            elif line.startswith('LOGSTASH_URL=') and not stream_base:
                env_lines.append(line)
            elif line.startswith('LOGSTASH_UI_URL=') and not stream_base:
                env_lines.append(line)
    env_file.write_text('\n'.join(env_lines) + '\n', encoding='utf-8')
    os.chmod(env_file, 0o640)
    logger.info(f"✓ Wrote {env_file}")
    if stream_base:
        logger.info(f"✓ StreamSimulate base LOGSTASH_URL={stream_base}")
    elif pt == 'SIMULATE':
        logger.warning(
            "LOGSTASH_URL not set in %s — simulate harness will fall back to "
            "host.docker.internal:8080 (broken on bare metal). Set after enroll "
            "from logstash_ui_url.",
            env_file,
        )

    # Per-instance state + config so packaged /var/lib and /etc are not shared
    state_dir_path = str(state_dir)
    agent_config_path = str(root / 'logstash-agent.yml')
    agent_env_lines = [
        f"INSTANCE_ID={instance_id}",
        f"AGENT_MODE={agent_mode}",
        f"AGENT_API_PORT={agent_port}",
        f"LOGSTASH_API_PORT={ls_port}",
        f"LOGSTASH_SETTINGS={settings}",
        f"AGENT_UNIT={agent_unit}",
        f"LOGSTASH_UNIT={logstash_unit}",
        # Host coexistence: isolate state/config from packaged agent
        f"LOGSTASH_AGENT_STATE_DIR={state_dir_path}",
        f"LOGSTASH_AGENT_CONFIG={agent_config_path}",
    ]
    agent_env.write_text('\n'.join(agent_env_lines) + '\n', encoding='utf-8')
    os.chmod(agent_env, 0o640)
    logger.info(f"✓ Wrote {agent_env} (isolated state/config for coexistence)")

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
        logger.warning(f"Could not set ownership on instance tree: {e}")

    return {
        'root': str(root),
        'binary': binary,
        'settings_path': str(settings),
        'config_path': str(pipeline_config_dir),
        'logs_path': str(logs),
        'data_path': str(data),
        'env_file': str(env_file),
        'agent_env': str(agent_env),
        'agent_config_path': agent_config_path,
        'state_dir': state_dir_path,
        'instance_id': instance_id,
        'agent_api_port': agent_port,
        'logstash_api_port': ls_port,
        'agent_unit': agent_unit,
        'logstash_unit': logstash_unit,
        'policy_type': pt,
        'mode': agent_mode,
    }


def host_subprocess_env(base: dict | None = None) -> dict:
    """
    Environment for host OS tools (systemctl, restorecon, sudo, …).

    PyInstaller freezes the agent with its own OpenSSL under ``_internal/`` and
    sets ``LD_LIBRARY_PATH`` so the agent finds those libs. Child processes
    inherit that path and break distro tools linked against a newer system
    libcrypto (e.g. systemd requiring OPENSSL_3.4.0)::

        systemctl: …/_internal/libcrypto.so.3: version `OPENSSL_3.4.0' not found

    Strip frozen library paths so host binaries use system libraries.
    """
    env = dict(os.environ if base is None else base)

    # Bootloader sometimes preserves the pre-launch path here
    orig = env.pop('LD_LIBRARY_PATH_ORIG', None)
    if orig is not None:
        if orig:
            env['LD_LIBRARY_PATH'] = orig
        else:
            env.pop('LD_LIBRARY_PATH', None)
    else:
        env.pop('LD_LIBRARY_PATH', None)

    for key in (
        'DYLD_LIBRARY_PATH',
        'DYLD_FALLBACK_LIBRARY_PATH',
        'DYLD_LIBRARY_PATH_ORIG',
    ):
        env.pop(key, None)

    # Drop SSL cert overrides that point into the frozen tree (if any)
    meipass = getattr(sys, '_MEIPASS', None) or ''
    frozen_roots: list[str] = []
    if meipass:
        frozen_roots.append(str(Path(meipass).resolve()))
    try:
        exe_parent = str(Path(sys.executable).resolve().parent)
        frozen_roots.append(exe_parent)
        frozen_roots.append(str(Path(exe_parent) / '_internal'))
    except Exception:
        pass
    for key in ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        val = env.get(key) or ''
        if not val or not frozen_roots:
            continue
        if any(val.startswith(root) for root in frozen_roots if root):
            env.pop(key, None)

    return env


def _systemctl_bin() -> str:
    """Absolute path to host systemctl (avoid PATH/library pollution)."""
    for candidate in ('/usr/bin/systemctl', '/bin/systemctl'):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return 'systemctl'


def _systemctl_cmd(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_systemctl_bin(), *args],
        check=check,
        capture_output=True,
        text=True,
        env=host_subprocess_env(),
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


def resolve_multi_instance_units(
    instance_id: int,
    policy_type: str | None = None,
    *,
    agent_unit: str | None = None,
    logstash_unit: str | None = None,
) -> tuple[str, str]:
    """
    Resolve agent + Logstash systemd unit names for a multi-instance role.

    Managed:  logstash-agent@N + logstash-managed@N
    Simulate: lsagent-simulate@N + ls-simulate@N
    """
    pt = (policy_type or 'SIMULATE').upper()
    if pt == 'DEFAULT':
        pt = 'PACKAGED'
    if agent_unit and logstash_unit:
        return agent_unit, logstash_unit
    if pt == 'MANAGED':
        return (
            agent_unit or f'logstash-agent@{instance_id}',
            logstash_unit or f'logstash-managed@{instance_id}',
        )
    return (
        agent_unit or f'lsagent-simulate@{instance_id}',
        logstash_unit or f'ls-simulate@{instance_id}',
    )


def _systemctl_ok(*args: str) -> tuple[bool, str]:
    """Run systemctl; return (ok, stderr_or_stdout)."""
    try:
        r = _systemctl_cmd(*args)
    except FileNotFoundError:
        return False, "systemctl not found"
    detail = (r.stderr or r.stdout or "").strip()
    return r.returncode == 0, detail


def _systemctl_is_enabled(unit: str) -> bool:
    ok, _ = _systemctl_ok('is-enabled', unit)
    return ok


def _systemctl_is_active(unit: str) -> bool:
    ok, _ = _systemctl_ok('is-active', unit)
    return ok


def enable_multi_instance_services(
    instance_id: int,
    *,
    agent_unit: str | None = None,
    logstash_unit: str | None = None,
    policy_type: str | None = None,
) -> dict:
    """
    Enable multi-instance units and start the agent instance.

    Logstash unit is enabled only (not started) so the controller can apply
    config and restart via logstash-agent-ctl when ready.

    Returns a status dict. Raises InstallError if enable/start fails.
    """
    agent_unit, ls_unit = resolve_multi_instance_units(
        instance_id,
        policy_type,
        agent_unit=agent_unit,
        logstash_unit=logstash_unit,
    )
    status = {
        'agent_unit': agent_unit,
        'logstash_unit': ls_unit,
        'ls_enabled': False,
        'agent_enabled': False,
        'agent_active': False,
        'errors': [],
    }
    try:
        ok, detail = _systemctl_ok('daemon-reload')
        if not ok:
            logger.warning("daemon-reload failed (continuing): %s", detail)

        ok, detail = _systemctl_ok('enable', ls_unit)
        if not ok:
            ok, detail = _systemctl_ok('enable', f'{ls_unit}.service')
        if not ok:
            msg = f"systemctl enable {ls_unit} failed: {detail or 'unknown error'}"
            status['errors'].append(msg)
            logger.error(msg)
        else:
            status['ls_enabled'] = _systemctl_is_enabled(ls_unit) or _systemctl_is_enabled(
                f'{ls_unit}.service'
            )
            if status['ls_enabled']:
                logger.info("✓ Enabled %s (not started)", ls_unit)
            else:
                msg = f"systemctl enable {ls_unit} reported success but is-enabled is false"
                status['errors'].append(msg)
                logger.error(msg)

        ok, detail = _systemctl_ok('enable', '--now', agent_unit)
        if not ok:
            ok_en, detail_en = _systemctl_ok('enable', agent_unit)
            if not ok_en:
                ok_en, detail_en = _systemctl_ok('enable', f'{agent_unit}.service')
            ok_st, detail_st = _systemctl_ok('start', agent_unit)
            if not ok_st:
                ok_st, detail_st = _systemctl_ok('start', f'{agent_unit}.service')
            if not ok_en:
                msg = f"systemctl enable {agent_unit} failed: {detail_en or detail or 'unknown error'}"
                status['errors'].append(msg)
                logger.error(msg)
            if not ok_st:
                msg = f"systemctl start {agent_unit} failed: {detail_st or detail or 'unknown error'}"
                status['errors'].append(msg)
                logger.error(msg)

        status['agent_enabled'] = _systemctl_is_enabled(agent_unit) or _systemctl_is_enabled(
            f'{agent_unit}.service'
        )
        status['agent_active'] = _systemctl_is_active(agent_unit) or _systemctl_is_active(
            f'{agent_unit}.service'
        )

        if status['agent_enabled'] and status['agent_active']:
            logger.info("✓ Enabled and started %s", agent_unit)
        elif status['agent_enabled'] and not status['agent_active']:
            msg = (
                f"{agent_unit} is enabled but not active "
                f"(check: journalctl -u {agent_unit} -e)"
            )
            status['errors'].append(msg)
            logger.error(msg)
        elif not status['agent_enabled']:
            if not any('enable' in e and agent_unit in e for e in status['errors']):
                status['errors'].append(f"{agent_unit} is not enabled after systemctl enable")
            logger.error("%s is not enabled", agent_unit)

        if status['errors']:
            raise InstallError(
                "Failed to enable/start multi-instance units:\n  - "
                + "\n  - ".join(status['errors'])
                + f"\n\nTemplates may still be installed under /etc/systemd/system/.\n"
                f"Retry manually:\n"
                f"  sudo systemctl daemon-reload\n"
                f"  sudo systemctl enable {ls_unit}\n"
                f"  sudo systemctl enable --now {agent_unit}\n"
                f"  sudo systemctl status {agent_unit}"
            )
        return status
    except InstallError:
        raise
    except FileNotFoundError:
        msg = "systemctl not available — cannot enable multi-instance units"
        logger.error(msg)
        raise InstallError(msg) from None


def enable_simulate_services(instance_id: int) -> dict:
    """Backward-compatible simulate-only enable (numeric N)."""
    return enable_multi_instance_services(instance_id, policy_type='SIMULATE')


def setup_simulate_from_policy(
    policy_config: dict,
    *,
    start_services: bool = True,
) -> dict:
    """
    Full multi-instance post-enroll setup: templates, tree, optionally enable units.

    ``start_services=False`` is used by ``perform_installation`` so enrollment
    state can be relocated and ``.secret_key`` ownership fixed *before* the
    agent unit is started as the logstash user.
    """
    install_multi_instance_unit_templates()
    result = materialize_simulate_instance(policy_config)
    pt = (policy_config.get('policy_type') or result.get('policy_type') or 'SIMULATE').upper()
    if pt == 'DEFAULT':
        pt = 'PACKAGED'
    agent_unit = policy_config.get('agent_unit') or result.get('agent_unit')
    logstash_unit = policy_config.get('logstash_unit') or result.get('logstash_unit')
    if start_services:
        svc = enable_multi_instance_services(
            result['instance_id'],
            agent_unit=agent_unit,
            logstash_unit=logstash_unit,
            policy_type=pt,
        )
        result['service_status'] = svc
        try:
            from logstashagent.encryption import ensure_secret_key_ownership

            ensure_secret_key_ownership(result.get('state_dir'))
            ensure_secret_key_ownership(None)
        except Exception as e:
            logger.warning("ensure_secret_key_ownership after start: %s", e)
    else:
        result['service_status'] = {'deferred': True}
    # Track in host install registry
    try:
        from logstashagent import agent_state as _as
        from logstashagent import install_registry as _reg

        role = 'managed' if pt == 'MANAGED' else 'simulate'
        state = _as.get_state() or {}
        _reg.register_package(
            agent_version=str(state.get('agent_version') or ''),
            agent_id=state.get('agent_id'),
        )
        _reg.register_instance(
            role=role,
            instance_id=result['instance_id'],
            agent_unit=agent_unit or '',
            logstash_unit=logstash_unit or '',
            path_root=result.get('root') or policy_config.get('path_root'),
            agent_api_port=result.get('agent_api_port'),
            logstash_api_port=result.get('logstash_api_port'),
            policy_type=pt,
            agent_id=state.get('agent_id'),
            connection_id=state.get('connection_id'),
            policy_id=state.get('policy_id'),
            deployment_id=policy_config.get('deployment_id') or result.get('root'),
        )
    except Exception as e:
        logger.warning("Could not update install registry: %s", e)
    return result


def policy_config_from_state(state: dict | None = None) -> dict:
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


def _try_sudo_setup_simulate() -> dict | None:
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
    pt = (policy_config.get('policy_type') or '').upper()
    if pt == 'DEFAULT':
        pt = 'PACKAGED'
    if pt not in ('SIMULATE', 'MANAGED'):
        return {'status': 'complete', 'messages': [f'Not a multi-instance policy ({pt or "none"})'], 'via': 'n/a'}

    instance_id = policy_config.get('instance_id')
    messages = []
    prefix = (
        policy_config.get('deployment_id')
        or (f'managed-{instance_id}' if pt == 'MANAGED' else f'simulate-{instance_id}')
    )

    # 1. Root
    try:
        if os.geteuid() == 0:
            logger.info("Running as root — full multi-instance setup (%s)", pt)
            result = setup_simulate_from_policy(policy_config)
            return {
                'status': 'complete',
                'via': 'root',
                'messages': [f"Materialized {prefix} and installed units"],
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
    pt = (policy_config.get('policy_type') or '').upper()
    if pt == 'DEFAULT':
        pt = 'PACKAGED'
    mode = (state.get('mode') or '').lower()
    if pt not in ('SIMULATE', 'MANAGED') and mode not in ('simulate', 'managed'):
        raise InstallError(
            "Agent is not a multi-instance enrollment (SIMULATE/MANAGED). "
            f"mode={state.get('mode')} policy_type={policy_config.get('policy_type')}"
        )
    if pt not in ('SIMULATE', 'MANAGED'):
        pt = 'MANAGED' if mode == 'managed' else 'SIMULATE'
    policy_config['policy_type'] = pt
    if policy_config.get('instance_id') is None:
        raise InstallError(
            "Missing instance_id in agent state. Re-enroll with a Simulate or Managed policy token."
        )

    prefix = (
        policy_config.get('deployment_id')
        or policy_config.get('path_root')
        or (
            f"managed-{policy_config['instance_id']}"
            if pt == 'MANAGED'
            else f"simulate-{policy_config['instance_id']}"
        )
    )
    agent_unit, ls_unit = resolve_multi_instance_units(
        int(policy_config['instance_id']),
        pt,
        agent_unit=policy_config.get('agent_unit'),
        logstash_unit=policy_config.get('logstash_unit'),
    )
    if not yes:
        print(f"\nThis will materialize /opt/logstash-agent/{Path(str(prefix)).name}/")
        print(f"and install/enable {agent_unit} and {ls_unit}.")
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
    # Persist resolved unit names for controller restarts
    _agent_state.update_state('agent_unit', agent_unit)
    _agent_state.update_state('logstash_unit', ls_unit)

    logger.info("=" * 60)
    logger.info("%s SETUP COMPLETE", pt)
    logger.info("=" * 60)
    logger.info("Start:  sudo systemctl start %s", agent_unit)
    logger.info("Status: sudo systemctl status %s", agent_unit)
    logger.info("Logstash unit (enable-only at setup): %s", ls_unit)
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
        INSTALL_PATHS['log_dir'],    # /opt/logstash-agent/logs
        INSTALL_PATHS['state_dir'],  # /opt/logstash-agent/state
        INSTALL_PATHS['config_dir'], # /opt/logstash-agent/config
        INSTALL_PATHS['cache_dir'],  # /opt/logstash-agent/cache
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
# Validated systemctl wrapper (logstash, logstash-agent, logstash-agent@N,
# logstash-managed@N, ls-simulate@N, lsagent-simulate@N)
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
            timeout=5,
            check=False,
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

            _systemctl_cmd('daemon-reload', check=True)
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
        _ = _systemctl_cmd('daemon-reload', check=True)
        logger.info("✓ Reloaded systemd daemon")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to reload systemd: {e}")
        if e.stderr:
            logger.warning(f"stderr: {e.stderr}")
        if e.stdout:
            logger.warning(f"stdout: {e.stdout}")
        # Non-fatal - systemctl enable/start will trigger reload anyway
        logger.info("Continuing (daemon will reload on next systemctl command)")


def perform_installation(
    enroll_token: str,
    logstash_ui_url: str,
    agent_id: str,
    enrollment_func,
) -> None:
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
                "   installed and /opt/logstash-agent/config/logstash-agent.yml is\n"
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

        # Host coexistence: if a packaged agent is already registered, protect its
        # state.json before multi-instance enroll writes temporary enrollment state
        # into /opt/logstash-agent/state.
        from logstashagent import agent_state as _as
        from logstashagent import install_registry as _reg

        packaged_state_path = Path(INSTALL_PATHS['state_dir']) / 'state.json'
        packaged_state_backup: bytes | None = None
        try:
            existing_reg = _reg.load_registry()
            has_packaged = 'packaged' in (existing_reg.get('instances') or {})
            if has_packaged and packaged_state_path.is_file():
                packaged_state_backup = packaged_state_path.read_bytes()
                logger.info(
                    "Protected existing packaged agent state (host coexistence)"
                )
        except Exception as e:
            logger.debug("Could not snapshot packaged state: %s", e)
            has_packaged = False

        # Step 5: Enroll first so we know packaged vs multi-instance policy
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
        policy_type = (policy_config.get('policy_type') or 'PACKAGED').upper()
        if policy_type == 'DEFAULT':
            policy_type = 'PACKAGED'
        is_multi = policy_type in ('SIMULATE', 'MANAGED')

        # Step 6: Write config file (mode-aware; multi → instance tree, not /etc)
        logger.info("\nStep 6: Writing configuration...")
        _ = write_config_file(logstash_ui_url, policy_config=policy_config)

        # Step 7: Install systemd units
        # Always install multi-instance templates so a later managed/simulate
        # enroll can coexist with an existing packaged agent without re-install.
        logger.info("\nStep 7: Installing systemd service(s)...")
        try:
            install_multi_instance_unit_templates()
        except Exception as e:
            logger.warning("Multi-instance unit templates install: %s", e)

        if is_multi:
            # Materialize tree only — do NOT start units until state is relocated
            # and .secret_key is owned by logstash (service runs as logstash).
            setup_simulate_from_policy(policy_config, start_services=False)
            # Relocate enrollment state into instance tree; restore packaged state
            path_root = (
                policy_config.get('path_root')
                or (
                    f"{INSTALL_PATHS['simulate_root']}/managed-{policy_config.get('instance_id')}"
                    if policy_type == 'MANAGED'
                    else f"{INSTALL_PATHS['simulate_root']}/simulate-{policy_config.get('instance_id')}"
                )
            )
            path_root = normalize_opt_path(path_root)
            inst_state = Path(path_root) / 'state'
            try:
                # Enrollment wrote into packaged STATE_DIR; move secrets to instance
                _as.configure_state_dir(INSTALL_PATHS['state_dir'])
                _as.relocate_state_to(inst_state, leave_source=True)
                if packaged_state_backup is not None:
                    packaged_state_path.write_bytes(packaged_state_backup)
                    logger.info(
                        "Restored packaged agent state after multi-instance enroll"
                    )
                elif packaged_state_path.is_file() and not has_packaged:
                    # No prior packaged role — remove transient enroll copy so
                    # only the instance tree holds enrollment secrets
                    try:
                        packaged_state_path.unlink()
                    except OSError:
                        pass
                _as.configure_state_dir(inst_state)
                # Re-write config under instance root with final paths
                write_config_file(
                    logstash_ui_url,
                    policy_config={
                        **policy_config,
                        'path_root': path_root,
                    },
                    config_path=str(Path(path_root) / 'logstash-agent.yml'),
                )
            except Exception as e:
                logger.warning("State relocate for multi-instance: %s", e)

            # Fix secret key ownership before the agent unit starts
            try:
                from logstashagent.encryption import ensure_secret_key_ownership

                ensure_secret_key_ownership(inst_state)
                ensure_secret_key_ownership(INSTALL_PATHS['state_dir'])
            except Exception as e:
                logger.warning("Pre-start ensure_secret_key_ownership: %s", e)

            # Refuse to start until instance state has enrollment (avoids Offline forever)
            inst_state_file = Path(inst_state) / 'state.json'
            try:
                if not inst_state_file.is_file():
                    raise InstallError(
                        f"Instance state missing after enroll relocate: {inst_state_file}"
                    )
                with open(inst_state_file, 'r', encoding='utf-8') as fh:
                    inst_blob = json.load(fh)
                if not inst_blob.get('enrolled') or not inst_blob.get('api_key'):
                    raise InstallError(
                        f"Instance state at {inst_state_file} is not enrolled "
                        f"(enrolled={inst_blob.get('enrolled')!r}). "
                        "Enrollment secrets were not relocated; not starting units."
                    )
                logger.info(
                    "✓ Instance enrollment present (connection_id=%s) before unit start",
                    inst_blob.get('connection_id'),
                )
            except InstallError:
                raise
            except Exception as e:
                raise InstallError(
                    f"Failed to verify enrolled instance state at {inst_state_file}: {e}"
                ) from e

            # Now enable + start agent (logstash user must be able to read .secret_key)
            try:
                enable_multi_instance_services(
                    int(policy_config.get('instance_id') or 0),
                    agent_unit=policy_config.get('agent_unit'),
                    logstash_unit=policy_config.get('logstash_unit'),
                    policy_type=policy_type,
                )
            except InstallError:
                raise
            except Exception as e:
                raise InstallError(f"Failed to enable multi-instance services: {e}") from e

            # Do not enable packaged logstash-agent.service for pure multi-instance
            if policy_type == 'MANAGED':
                logger.info(
                    "✓ Managed units installed (logstash-agent@N / logstash-managed@N); "
                    "packaged logstash-agent.service left unchanged for coexistence"
                )
            else:
                logger.info(
                    "✓ Simulate units installed (lsagent-simulate@N / ls-simulate@N); "
                    "packaged logstash-agent.service left unchanged for coexistence"
                )
        else:
            install_systemd_service()
            # If we somehow backed up packaged state and then re-enrolled packaged,
            # the new state is correct at packaged path (no restore).

        # Step 8: Set ownership on state files and clean up log files
        logger.info("\nStep 8: Setting ownership on state files...")
        uid, gid = get_logstash_uid_gid()

        def _chown_tree(path: str | Path) -> None:
            path = Path(path)
            if not path.exists():
                return
            for walk_root, dirs, files in os.walk(path):
                try:
                    os.chown(walk_root, uid, gid)
                except OSError:
                    pass
                for name in dirs + files:
                    try:
                        os.chown(os.path.join(walk_root, name), uid, gid)
                    except OSError:
                        pass
            # Explicitly fix .secret_key under this path and path/state/
            candidates = []
            if path.is_dir():
                candidates.append(path / '.secret_key')
                candidates.append(path / 'state' / '.secret_key')
            else:
                candidates.append(path.parent / '.secret_key')
            for secret in candidates:
                if secret.is_file():
                    try:
                        os.chown(secret, uid, gid)
                        os.chmod(secret, 0o600)
                    except OSError:
                        pass

        # Packaged state dir
        _chown_tree(INSTALL_PATHS['state_dir'])
        logger.info(f"✓ Set ownership on {INSTALL_PATHS['state_dir']}")

        # Multi-instance trees (state/.secret_key created after materialize chown)
        if is_multi:
            path_root = normalize_opt_path(
                policy_config.get('path_root')
                or (
                    f"{INSTALL_PATHS['simulate_root']}/managed-{policy_config.get('instance_id')}"
                    if policy_type == 'MANAGED'
                    else f"{INSTALL_PATHS['simulate_root']}/simulate-{policy_config.get('instance_id')}"
                )
            )
            _chown_tree(path_root)
            logger.info(f"✓ Set ownership on {path_root} (incl. state/.secret_key)")
            try:
                from logstashagent.encryption import ensure_secret_key_ownership

                ensure_secret_key_ownership(Path(path_root) / 'state')
                ensure_secret_key_ownership(INSTALL_PATHS['state_dir'])
            except Exception as e:
                logger.warning("ensure_secret_key_ownership: %s", e)

        # Clean up any root-owned log files that may have been created during install
        log_file = os.path.join(INSTALL_PATHS['log_dir'], 'logstashagent.log')
        if os.path.exists(log_file):
            try:
                # Check if owned by root
                stat_info = os.stat(log_file)
                if stat_info.st_uid == 0:  # root
                    os.remove(log_file)
                    logger.info("✓ Removed root-owned log file (will be recreated by service)")
            except Exception as e:
                logger.warning(f"Could not clean up log file: {e}")

        # Step 9: Configure Logstash permissions for agent management
        if is_multi:
            # Still write sudoers (multi-instance units + optional package logstash)
            logger.info("\nStep 9: Configuring permissions (multi-instance + sudoers)...")
            configure_logstash()
        elif logstash_present:
            logger.info("\nStep 9: Configuring Logstash permissions...")
            configure_logstash()
        else:
            logger.info("\nStep 9: Skipping Logstash configuration (Logstash not installed)")

        # Step 10: Final ownership fix for state files
        # This ensures state.json / .secret_key have correct ownership even if
        # updated during module init or multi-instance relocate after earlier chown.
        logger.info("\nStep 10: Final ownership verification...")
        _chown_tree(INSTALL_PATHS['state_dir'])
        logger.info(f"✓ Verified ownership on {INSTALL_PATHS['state_dir']}")
        if is_multi:
            path_root = normalize_opt_path(
                policy_config.get('path_root')
                or (
                    f"{INSTALL_PATHS['simulate_root']}/managed-{policy_config.get('instance_id')}"
                    if policy_type == 'MANAGED'
                    else f"{INSTALL_PATHS['simulate_root']}/simulate-{policy_config.get('instance_id')}"
                )
            )
            _chown_tree(path_root)
            logger.info(f"✓ Verified ownership on {path_root}")
            try:
                from logstashagent.encryption import ensure_secret_key_ownership

                # Catch keys created during relocate / late enroll writes as root
                ensure_secret_key_ownership(None)  # all instance trees under /opt
            except Exception as e:
                logger.warning("Final ensure_secret_key_ownership: %s", e)

        # VERSION trees must be readable by the logstash service user
        versions_dir = os.path.join(INSTALL_PATHS['opt_root'], 'logstash-versions')
        if os.path.isdir(versions_dir):
            try:
                from logstashagent.logstash_download import chown_tree_to_logstash

                chown_tree_to_logstash(versions_dir)
            except Exception as e:
                logger.warning("Could not chown logstash-versions: %s", e)

        # Step 11: Enable/start services (full deploy — no extra cut-paste for enable/start)
        logger.info("\nStep 11: Enabling and starting services...")
        if is_multi:
            # Multi-instance units were enabled after state relocate (see Step 7)
            pass
        else:
            enable_and_start_default_agent()
            if logstash_present:
                enable_package_logstash_only()

        # Record package + instance in install registry
        try:
            from logstashagent import agent_state as _as
            from logstashagent import install_registry as _reg

            state = _as.get_state() or {}
            ver = str(state.get('agent_version') or '')
            _reg.register_package(agent_version=ver, agent_id=agent_id or state.get('agent_id'))
            if is_multi:
                instance_id = policy_config.get('instance_id')
                agent_unit, ls_unit = resolve_multi_instance_units(
                    int(instance_id) if instance_id is not None else 0,
                    policy_type,
                    agent_unit=policy_config.get('agent_unit'),
                    logstash_unit=policy_config.get('logstash_unit'),
                )
                path_root = (
                    policy_config.get('path_root')
                    or (
                        f"/opt/logstash-agent/managed-{instance_id}"
                        if policy_type == 'MANAGED'
                        else f"/opt/logstash-agent/simulate-{instance_id}"
                    )
                )
                _reg.register_instance(
                    role='managed' if policy_type == 'MANAGED' else 'simulate',
                    instance_id=int(instance_id) if instance_id is not None else None,
                    agent_unit=agent_unit,
                    logstash_unit=ls_unit,
                    path_root=path_root,
                    agent_api_port=policy_config.get('agent_api_port'),
                    logstash_api_port=policy_config.get('logstash_api_port'),
                    policy_type=policy_type,
                    agent_id=agent_id or state.get('agent_id'),
                    connection_id=state.get('connection_id'),
                    policy_id=state.get('policy_id'),
                    deployment_id=policy_config.get('deployment_id'),
                )
            else:
                _reg.register_instance(
                    role='packaged',
                    agent_unit='logstash-agent',
                    logstash_unit='logstash',
                    path_root=None,
                    agent_api_port=None,
                    logstash_api_port=policy_config.get('logstash_api_port') or 9600,
                    policy_type='PACKAGED',
                    agent_id=agent_id or state.get('agent_id'),
                    connection_id=state.get('connection_id'),
                    policy_id=state.get('policy_id'),
                    deployment_id='package',
                )
        except Exception as e:
            logger.warning("Could not write install registry: %s", e)

        # Installation complete
        logger.info("\n" + "="*60)
        logger.info("INSTALLATION COMPLETED SUCCESSFULLY!")
        logger.info("="*60)

        if is_multi:
            instance_id = policy_config.get('instance_id')
            agent_unit, ls_unit = resolve_multi_instance_units(
                int(instance_id) if instance_id is not None else 0,
                policy_type,
                agent_unit=policy_config.get('agent_unit'),
                logstash_unit=policy_config.get('logstash_unit'),
            )
            path_root = (
                policy_config.get('path_root')
                or (
                    f"/opt/logstash-agent/managed-{instance_id}"
                    if policy_type == 'MANAGED'
                    else f"/opt/logstash-agent/simulate-{instance_id}"
                )
            )
            role = 'Managed' if policy_type == 'MANAGED' else 'Simulate'
            logger.info(f"\n{role} agent installed and started.")
            logger.info(f"  Agent unit:    {agent_unit} (enabled + started)")
            logger.info(f"  Logstash unit: {ls_unit} (enabled; agent restarts when ready)")
            logger.info(f"  Paths under:   {path_root}/")
            logger.info(f"  State:         {path_root}/state/  (isolated from packaged)")
            logger.info(f"  Config:        {path_root}/logstash-agent.yml")
            logger.info("\nDay-2 operations (this instance only):")
            logger.info(f"  sudo systemctl status {agent_unit}")
            logger.info(f"  sudo systemctl stop {agent_unit}")
            logger.info(f"  sudo systemctl start {agent_unit}")
            logger.info(f"  sudo journalctl -u {agent_unit} -f")
            logger.info(f"  # or via ctl: sudo logstash-agent-ctl status {agent_unit}")
            logger.info("  # host map:    logstash-agent list-instances")
            logger.info("  # drop only:   sudo logstash-agent uninstall --instance %s",
                        f"{'managed' if policy_type == 'MANAGED' else 'simulate'}-{instance_id}")
            try:
                others = [
                    e for e in _reg.list_instances(include_discovered=True)
                    if e.get('id') != f"{'managed' if policy_type == 'MANAGED' else 'simulate'}-{instance_id}"
                ]
                if others:
                    logger.info("\nOther roles on this host (untouched):")
                    for e in others:
                        logger.info(
                            "  - %s  unit=%s  path=%s",
                            e.get('id'),
                            e.get('agent_unit'),
                            e.get('path_root') or '(packaged)',
                        )
            except Exception as e:
                logger.warning(f"Failed to list other roles: {e}")
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
            logger.info("  State:  /opt/logstash-agent/state/")
            logger.info("  Config: /opt/logstash-agent/config/logstash-agent.yml")
            logger.info("  Logs:   /opt/logstash-agent/logs/")
            if logstash_present:
                logger.info(
                    "Distro logstash unit enabled only (not started/restarted — "
                    "safe for live systems; agent will restart Logstash when policy requires)."
                )
            if not logstash_present:
                logger.info("\nAfter installing Logstash:")
                logger.info("  1. Update paths in /opt/logstash-agent/config/logstash-agent.yml if needed")
                logger.info("  2. sudo logstash-agent configure")
                logger.info("  3. sudo systemctl restart logstash-agent")
            logger.info("\nDay-2 operations (packaged agent only):")
            logger.info("  sudo systemctl status logstash-agent")
            logger.info("  sudo systemctl stop logstash-agent")
            logger.info("  sudo systemctl start logstash-agent")
            logger.info("  sudo journalctl -u logstash-agent -f")
            logger.info("  # host map: logstash-agent list-instances")
            logger.info(
                "  # Multi-instance templates are also installed; enroll a Managed "
                "or Simulate policy later without re-installing the binary."
            )
            try:
                multi = [
                    e for e in _reg.list_instances(include_discovered=True)
                    if (e.get('role') or '') in ('managed', 'simulate')
                ]
                if multi:
                    logger.info("\nMulti-instance roles already on this host:")
                    for e in multi:
                        logger.info(
                            "  - %s  unit=%s  path=%s",
                            e.get('id'),
                            e.get('agent_unit'),
                            e.get('path_root'),
                        )
            except Exception as e:
                logger.warning(f"Failed to list other roles: {e}")
            logger.info("="*60)

    except InstallError as e:
        logger.error(f"\nInstallation failed: {e}")
        raise
    except Exception as e:
        logger.exception("\nUnexpected error during installation")
        raise InstallError(f"Installation failed: {e}")


def _remove_cli_symlinks() -> None:
    """Remove /usr/local/bin and /usr/bin logstash-agent symlinks if present."""
    for link in (INSTALL_PATHS['symlink'], '/usr/bin/logstash-agent'):
        try:
            if os.path.islink(link):
                os.unlink(link)
                logger.info("✓ Removed %s", link)
            elif os.path.exists(link):
                logger.warning("%s exists but is not a symlink, skipping", link)
        except OSError as e:
            logger.warning("Could not remove %s: %s", link, e)


def _opt_root_remaining() -> list[str]:
    root = INSTALL_PATHS['opt_root']
    if not os.path.isdir(root):
        return []
    try:
        return sorted(os.listdir(root))
    except OSError:
        return ['?']


def perform_uninstallation(
    purge: bool = False,
    *,
    instance: str | None = None,
    keep_data: bool = False,
) -> None:
    """
    Perform uninstallation using the host install registry.

    Args:
        purge: Full uninstall only — wipe all of ``/opt/logstash-agent`` and the CLI
            symlink (and legacy FHS leftovers).
        instance: If set (e.g. ``managed-1``, ``simulate-2``), tear down only that
            multi-instance role and leave the package installed. Path tree is
            removed unless ``keep_data`` is True.
        keep_data: With ``--instance``, stop/disable units but keep the instance
            path tree. Default for ``--instance`` is to delete the tree.
    """
    from logstashagent import install_registry as _reg

    logger.info("=" * 60)
    logger.info("LOGSTASH AGENT UNINSTALLATION")
    logger.info("=" * 60)

    try:
        logger.info("\nStep 1: Verifying prerequisites...")
        verify_root()
        verify_platform()

        reg = _reg.load_registry()
        all_instances = _reg.list_instances(include_discovered=True)

        # ---- Single-instance teardown (package remains) ----
        if instance:
            key = instance.strip().lower()
            entry = next((e for e in all_instances if (e.get('id') or '').lower() == key), None)
            if not entry and key.isdigit():
                matches = [
                    e for e in all_instances
                    if (e.get('id') or '') in (f'simulate-{key}', f'managed-{key}')
                ]
                if len(matches) == 1:
                    entry = matches[0]
                elif len(matches) > 1:
                    raise InstallError(
                        f"Ambiguous instance id '{instance}' matches both managed and "
                        f"simulate. Use --instance managed-{key} or simulate-{key}."
                    )
            if not entry and key in ('default', 'package', 'packaged'):
                raise InstallError(
                    "Packaged role cannot be removed with --instance "
                    "(that is the shared host agent). Use full "
                    "`sudo logstash-agent uninstall` instead, or "
                    "`uninstall --instance simulate-N` / `managed-N` for multi-instance roles."
                )
            if not entry:
                known = ", ".join(
                    sorted(
                        e.get('id') or '?'
                        for e in all_instances
                        if (e.get('role') or '') in ('managed', 'simulate')
                    )
                ) or "(none)"
                raise InstallError(
                    f"Instance '{instance}' not found.\n"
                    f"Known multi-instance ids: {known}\n"
                    f"Run: logstash-agent list-instances"
                )
            role = (entry.get('role') or '').lower()
            if role not in ('managed', 'simulate'):
                raise InstallError(
                    f"Instance '{entry.get('id')}' is role={role!r}; "
                    f"--instance only removes managed-N or simulate-N."
                )

            purge_paths = not keep_data
            logger.info(
                "\nStep 2: Removing instance %s only (path tree %s)...",
                entry.get('id'),
                "deleted" if purge_paths else "preserved (--keep-data)",
            )
            _reg.teardown_instance(entry, purge_paths=purge_paths, unregister=True)
            try:
                _systemctl_cmd('daemon-reload')
            except Exception as e:
                logger.warning("Failed to reload systemd: %s", e)
            logger.info("\n" + "=" * 60)
            logger.info("INSTANCE UNINSTALL COMPLETE: %s", entry.get('id'))
            if purge_paths:
                logger.info("Units stopped/disabled and path tree removed.")
            else:
                logger.info(
                    "Units stopped/disabled; path tree kept "
                    "(%s). Re-run without --keep-data to delete it.",
                    entry.get('path_root') or '(unknown)',
                )
            logger.info("Package install and other instances left in place.")
            logger.info("  Remaining: logstash-agent list-instances")
            logger.info("=" * 60)
            return

        # ---- Full package uninstall ----
        logger.info("\nStep 2: Stopping multi-instance agents...")
        multi = [
            e for e in all_instances
            if (e.get('role') or '').lower() in ('managed', 'simulate')
        ]
        packaged = [
            e for e in all_instances
            if (e.get('role') or '').lower() in ('packaged', 'default', '')
            or e.get('id') == 'packaged'
        ]
        if multi:
            for entry in multi:
                logger.info("  - %s (%s)", entry.get('id'), entry.get('agent_unit'))
                _reg.teardown_instance(
                    entry,
                    purge_paths=purge,
                    unregister=True,
                )
        else:
            logger.info("  (no managed/simulate instances registered or discovered)")

        logger.info("\nStep 3: Stopping packaged agent unit...")
        if packaged:
            for entry in packaged:
                _reg.teardown_instance(entry, purge_paths=False, unregister=True)
        else:
            if os.path.exists(INSTALL_PATHS['systemd_service']):
                try:
                    _systemctl_cmd('stop', 'logstash-agent')
                    _systemctl_cmd('disable', 'logstash-agent')
                    logger.info("✓ Stopped/disabled logstash-agent service")
                except Exception as e:
                    logger.warning("Failed to stop/disable service: %s", e)
            else:
                logger.info("Packaged service unit not found, skipping")

        logger.info("\nStep 4: Removing systemd unit files...")
        _reg.remove_shared_unit_files(reg)
        if os.path.exists(INSTALL_PATHS['systemd_service']):
            try:
                os.remove(INSTALL_PATHS['systemd_service'])
                logger.info("✓ Removed %s", INSTALL_PATHS['systemd_service'])
            except OSError as e:
                logger.warning("Could not remove packaged unit: %s", e)
        try:
            _systemctl_cmd('daemon-reload', check=True)
            logger.info("✓ Reloaded systemd daemon")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning("Failed to reload systemd: %s", e)

        logger.info("\nStep 5: Removing sudoers configuration...")
        sudoers_file = '/etc/sudoers.d/logstash-agent'
        if os.path.exists(sudoers_file):
            try:
                os.remove(sudoers_file)
                logger.info("✓ Removed %s", sudoers_file)
            except Exception as e:
                logger.warning("Could not remove sudoers file: %s", e)
        else:
            logger.info("Sudoers file not found, skipping")

        if purge:
            logger.info("\nStep 6: Purging /opt/logstash-agent and CLI symlink...")
            opt = INSTALL_PATHS['opt_root']
            if os.path.isdir(opt):
                shutil.rmtree(opt)
                logger.info("✓ Removed %s", opt)
            else:
                logger.info("%s not found, skipping", opt)
            _remove_cli_symlinks()
            for legacy in LEGACY_INSTALL_PATHS.values():
                if os.path.isdir(legacy):
                    try:
                        shutil.rmtree(legacy)
                        logger.info("✓ Removed legacy %s", legacy)
                    except OSError as e:
                        logger.warning("Could not remove legacy %s: %s", legacy, e)
        else:
            logger.info(
                "\nStep 6: Removing binary (preserving data under %s)...",
                INSTALL_PATHS['opt_root'],
            )
            if os.path.isdir(INSTALL_PATHS['binary_dir']):
                shutil.rmtree(INSTALL_PATHS['binary_dir'])
                logger.info("✓ Removed %s", INSTALL_PATHS['binary_dir'])
            else:
                logger.info("Binary directory not found, skipping")

            logger.info("\nStep 7: Removing packaged configuration...")
            if os.path.isdir(INSTALL_PATHS['config_dir']):
                shutil.rmtree(INSTALL_PATHS['config_dir'])
                logger.info("✓ Removed %s", INSTALL_PATHS['config_dir'])
            else:
                legacy_cfg = LEGACY_INSTALL_PATHS['config_dir']
                if os.path.isdir(legacy_cfg):
                    try:
                        shutil.rmtree(legacy_cfg)
                        logger.info("✓ Removed legacy %s", legacy_cfg)
                    except OSError as e:
                        logger.warning("Could not remove %s: %s", legacy_cfg, e)
                else:
                    logger.info("Config directory not found, skipping")

            logger.info(
                "\nStep 8: Preserving data directories under %s ...",
                INSTALL_PATHS['opt_root'],
            )
            for key in ('state_dir', 'log_dir', 'cache_dir'):
                path = INSTALL_PATHS[key]
                if os.path.isdir(path):
                    logger.info("  kept %s", path)
            remaining = _opt_root_remaining()
            if remaining:
                logger.info(
                    "  also under %s: %s",
                    INSTALL_PATHS['opt_root'],
                    ", ".join(remaining),
                )
            logger.info(
                "  CLI symlink %s kept while agent data remains "
                "(remove with: sudo logstash-agent uninstall --purge)",
                INSTALL_PATHS['symlink'],
            )
            try:
                reg2 = _reg.load_registry()
                reg2['package'] = None
                inst = reg2.get('instances') or {}
                inst.pop('packaged', None)
                reg2['instances'] = inst
                _reg.save_registry(reg2)
            except Exception as e:
                logger.warning("Could not update registry after uninstall: %s", e)

        logger.info("\n" + "=" * 60)
        logger.info("UNINSTALLATION COMPLETED SUCCESSFULLY!")
        logger.info("=" * 60)

        if not purge:
            logger.info("\nPreserved under %s:", INSTALL_PATHS['opt_root'])
            logger.info("  - state/  logs/  cache/  (and managed-N / simulate-N trees if any)")
            logger.info("  - %s (CLI symlink)", INSTALL_PATHS['symlink'])
            logger.info("\nRemove one multi-instance role:")
            logger.info("  sudo logstash-agent uninstall --instance simulate-1")
            logger.info("  sudo logstash-agent uninstall --instance managed-2")
            logger.info("\nWipe everything (including symlink and /opt/logstash-agent):")
            logger.info("  sudo logstash-agent uninstall --purge")
        else:
            logger.info("Removed /opt/logstash-agent and CLI symlink.")

        logger.info("=" * 60)

    except InstallError as e:
        logger.error("\nUninstallation failed: %s", e)
        raise
    except Exception as e:
        logger.exception("\nUnexpected error during uninstallation")
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
            logger.info("Set cache directory ownership to logstash:logstash")
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
            timeout=5,
            check=False,
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

    Uses :func:`host_subprocess_env` so PyInstaller LD_LIBRARY_PATH does not
    break host systemctl OpenSSL.
    """
    env = host_subprocess_env()
    ctl = INSTALL_PATHS['systemctl_ctl']
    if os.path.isfile(ctl) and os.access(ctl, os.X_OK):
        return subprocess.run(
            ['sudo', ctl, action, unit],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    return subprocess.run(
        ['sudo', _systemctl_bin(), action, unit],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def verify_service_running() -> bool:
    """
    Verify that the logstash-agent service is running.

    Returns:
        True if service is active, False otherwise
    """
    try:
        result = _systemctl_cmd('is-active', 'logstash-agent')
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
            result = subprocess.run(
                ['lsof', INSTALL_PATHS['binary']],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                logger.warning("Binary is still in use by processes:")
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
            service_check = _systemctl_cmd('is-active', 'logstash-agent')
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
                result = subprocess.run(
                    ['which', 'restorecon'],
                    capture_output=True,
                    check=False,
                )
                if result.returncode == 0:
                    subprocess.run(['restorecon', '-Rv', internal_dest],
                                 check=False, capture_output=True)
                    logger.debug(f"Set SELinux context for {internal_dest}")
            except Exception as e:
                logger.warning(f"Failed to set SELinux context for {internal_dest}: {e}")
        else:
            logger.warning("_internal directory not found in upgrade package")

        # Set SELinux context for upgraded binary on RHEL/CentOS
        try:
            result = subprocess.run(
                ['which', 'restorecon'],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                subprocess.run(['restorecon', '-v', INSTALL_PATHS['binary']],
                             check=False, capture_output=True)
                logger.info("✓ Set SELinux context for upgraded binary")
        except Exception as e:
            logger.debug(f"SELinux context setting skipped: {e}")

        # Step 9: Restart service (always restart after upgrade)
        logger.info("\nStep 9: Restarting service with new binary...")
        try:
            _systemctl_cmd('restart', 'logstash-agent', check=True)
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
                _systemctl_cmd('stop', 'logstash-agent')
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
                    _systemctl_cmd('start', 'logstash-agent', check=True)
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
                logger.error("  4. Start service: sudo systemctl start logstash-agent")
                logger.error("  5. Check status: sudo systemctl status logstash-agent")
                logger.error("="*60)
                raise InstallError(
                    "Upgrade failed and rollback encountered errors. "
                    "Manual recovery required. See log for details.")

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
        logger.exception("\nUnexpected error during upgrade")
        # Cleanup temp directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise InstallError(f"Upgrade failed: {e}")
