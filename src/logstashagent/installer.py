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
    'config_dir': '/etc/logstash-agent',
    'state_dir': '/var/lib/logstash-agent',
    'log_dir': '/var/log/logstash-agent',
    'systemd_service': '/etc/systemd/system/logstash-agent.service',
}

SYSTEMD_SERVICE_TEMPLATE = """[Unit]
Description=LogstashAgent - Control plane agent for LogstashUI
After=network.target

[Service]
Type=simple
User=logstash
Group=logstash
ExecStart=/opt/logstash-agent/bin/logstash-agent --run
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


def verify_logstash_installed():
    """
    Verify Logstash is installed by checking for:
    - user: logstash
    - directory: /etc/logstash
    - directory: /usr/share/logstash
    """
    logger.info("Verifying Logstash installation...")
    
    errors = []
    
    # Check for logstash user
    try:
        pwd.getpwnam('logstash')
        logger.info("✓ User 'logstash' exists")
    except KeyError:
        errors.append("- user: logstash")
    
    # Check for /etc/logstash
    if not os.path.isdir('/etc/logstash'):
        errors.append("- directory: /etc/logstash")
    else:
        logger.info("✓ Directory /etc/logstash exists")
    
    # Check for /usr/share/logstash
    if not os.path.isdir('/usr/share/logstash'):
        errors.append("- directory: /usr/share/logstash")
    else:
        logger.info("✓ Directory /usr/share/logstash exists")
    
    # Optional: check for /var/log/logstash
    if os.path.isdir('/var/log/logstash'):
        logger.info("✓ Directory /var/log/logstash exists")
    
    if errors:
        raise InstallError(
            "Logstash does not appear to be installed on this host.\n\n"
            "Expected:\n" + "\n".join(errors) + "\n\n"
            "Install Logstash first, then rerun:\n"
            "  sudo logstash-agent install --enroll=... --logstash-ui-url=..."
        )
    
    logger.info("✓ Logstash installation verified")


def get_logstash_uid_gid():
    """Get the UID and GID for the logstash user"""
    try:
        pw = pwd.getpwnam('logstash')
        gr = grp.getgrnam('logstash')
        return pw.pw_uid, gr.gr_gid
    except (KeyError, OSError) as e:
        raise InstallError(f"Failed to get logstash user/group info: {e}")


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


def create_symlink():
    """Create symlink in /usr/local/bin"""
    logger.info("Creating symlink...")
    
    # Remove existing symlink if it exists
    if os.path.islink(INSTALL_PATHS['symlink']):
        os.unlink(INSTALL_PATHS['symlink'])
    elif os.path.exists(INSTALL_PATHS['symlink']):
        raise InstallError(
            f"{INSTALL_PATHS['symlink']} exists and is not a symlink. "
            "Please remove it manually."
        )
    
    # Create the symlink
    os.symlink(INSTALL_PATHS['binary'], INSTALL_PATHS['symlink'])
    logger.info(f"✓ Created symlink {INSTALL_PATHS['symlink']} -> {INSTALL_PATHS['binary']}")


def write_config_file(logstash_ui_url: str):
    """Write the initial agent config file"""
    logger.info("Writing configuration file...")
    
    config_content = f"""# LogstashAgent Configuration
# Generated during installation

mode: agent
logstash_binary: /usr/share/logstash/bin/logstash
logstash_settings: /etc/logstash
logstash_log_path: /var/log/logstash
host: 127.0.0.1
port: 9600

# LogstashUI connection
logstash_ui_url: {logstash_ui_url}
"""
    
    config_path = os.path.join(INSTALL_PATHS['config_dir'], 'logstash-agent.yml')
    
    with open(config_path, 'w') as f:
        f.write(config_content)
    
    # Set ownership to logstash
    uid, gid = get_logstash_uid_gid()
    os.chown(config_path, uid, gid)
    os.chmod(config_path, 0o640)
    
    logger.info(f"✓ Created configuration file {config_path}")


def install_systemd_service():
    """Install the systemd service unit"""
    logger.info("Installing systemd service...")
    
    # Write the service file
    with open(INSTALL_PATHS['systemd_service'], 'w') as f:
        f.write(SYSTEMD_SERVICE_TEMPLATE)
    
    os.chmod(INSTALL_PATHS['systemd_service'], 0o644)
    logger.info(f"✓ Created systemd service {INSTALL_PATHS['systemd_service']}")
    
    # Reload systemd
    try:
        subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
        logger.info("✓ Reloaded systemd daemon")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to reload systemd: {e}")


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
        verify_logstash_installed()
        
        # Step 2: Create directories
        logger.info("\nStep 2: Creating directories...")
        create_directories()
        
        # Step 3: Install binary
        logger.info("\nStep 3: Installing binary...")
        install_binary()
        
        # Step 4: Create symlink
        logger.info("\nStep 4: Creating symlink...")
        create_symlink()
        
        # Step 5: Write config file
        logger.info("\nStep 5: Writing configuration...")
        write_config_file(logstash_ui_url)
        
        # Step 6: Install systemd service
        logger.info("\nStep 6: Installing systemd service...")
        install_systemd_service()
        
        # Step 7: Perform enrollment
        logger.info("\nStep 7: Enrolling with LogstashUI...")
        enrollment_func(
            encoded_token=enroll_token,
            logstash_ui_url=logstash_ui_url,
            agent_id=agent_id
        )
        logger.info("✓ Enrollment completed successfully")
        
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
        
        # Step 9: Fix /etc/logstash directory permissions
        logger.info("\nStep 9: Fixing Logstash directory permissions...")
        logstash_config_dir = '/etc/logstash'
        if os.path.exists(logstash_config_dir):
            try:
                # Change group to logstash and add group write permission
                # This allows the logstash user to manage keystore files
                os.chown(logstash_config_dir, 0, gid)  # root:logstash
                os.chmod(logstash_config_dir, 0o775)   # rwxrwxr-x
                logger.info(f"✓ Set permissions on {logstash_config_dir} (root:logstash, 775)")
                
                # Also fix keystore file ownership if it exists
                keystore_file = os.path.join(logstash_config_dir, 'logstash.keystore')
                if os.path.exists(keystore_file):
                    os.chown(keystore_file, uid, gid)  # logstash:logstash
                    logger.info(f"✓ Set ownership on {keystore_file} (logstash:logstash)")
            except Exception as e:
                logger.warning(f"Could not fix Logstash directory permissions: {e}")
                logger.warning("Agent may not be able to recreate keystore - manual fix required:")
                logger.warning(f"  sudo chown root:logstash {logstash_config_dir}")
                logger.warning(f"  sudo chmod 775 {logstash_config_dir}")
        else:
            logger.warning(f"Logstash config directory not found at {logstash_config_dir}")
            logger.warning("Agent may not be able to manage keystore")
        
        # Installation complete
        logger.info("\n" + "="*60)
        logger.info("INSTALLATION COMPLETED SUCCESSFULLY!")
        logger.info("="*60)
        logger.info("\nNext steps:")
        logger.info("  1. Enable the service:")
        logger.info("     sudo systemctl enable logstash-agent")
        logger.info("\n  2. Start the service:")
        logger.info("     sudo systemctl start logstash-agent")
        logger.info("\n  3. Check status:")
        logger.info("     sudo systemctl status logstash-agent")
        logger.info("\n  4. View logs:")
        logger.info("     sudo journalctl -u logstash-agent -f")
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
                subprocess.run(['systemctl', 'daemon-reload'], 
                             check=True, capture_output=True)
                logger.info("✓ Reloaded systemd daemon")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to reload systemd: {e}")
        else:
            logger.info("Service file not found, skipping")
        
        # Step 4: Remove symlink
        logger.info("\nStep 4: Removing symlink...")
        if os.path.islink(INSTALL_PATHS['symlink']):
            os.unlink(INSTALL_PATHS['symlink'])
            logger.info(f"✓ Removed {INSTALL_PATHS['symlink']}")
        elif os.path.exists(INSTALL_PATHS['symlink']):
            logger.warning(f"{INSTALL_PATHS['symlink']} exists but is not a symlink, skipping")
        else:
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
        
        # Uninstallation complete
        logger.info("\n" + "="*60)
        logger.info("UNINSTALLATION COMPLETED SUCCESSFULLY!")
        logger.info("="*60)
        
        if not purge:
            logger.info("\nPreserved directories:")
            logger.info(f"  - {INSTALL_PATHS['state_dir']}")
            logger.info(f"  - {INSTALL_PATHS['log_dir']}")
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
    
    Args:
        version: Version to download (e.g., "0.1.4")
        download_dir: Directory to download to
    
    Returns:
        Path to the downloaded tarball
    """
    import requests
    
    # GitHub release URL
    url = f"https://github.com/elastic/LogstashAgent/releases/download/{version}/logstash-agent-linux-amd64.tar.gz"
    tarball_path = os.path.join(download_dir, f"logstash-agent-{version}.tar.gz")
    
    logger.info(f"Downloading {url}...")
    
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        
        # Download with progress
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        with open(tarball_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        logger.debug(f"Downloaded {percent:.1f}%")
        
        logger.info(f"✓ Downloaded {tarball_path}")
        return tarball_path
        
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
        
        # Step 6: Stop service if running
        if service_was_running:
            logger.info("\nStep 6: Stopping service...")
            try:
                subprocess.run(['systemctl', 'stop', 'logstash-agent'], 
                             check=True, capture_output=True, timeout=30)
                logger.info("✓ Service stopped")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                raise InstallError(f"Failed to stop service: {e}")
        else:
            logger.info("\nStep 6: Service not running, skipping stop")
        
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
        
        # Copy the main binary
        shutil.copy2(new_binary_path, INSTALL_PATHS['binary'])
        os.chmod(INSTALL_PATHS['binary'], 0o755)
        logger.info(f"✓ Installed new binary to {INSTALL_PATHS['binary']}")
        
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
        else:
            logger.warning("_internal directory not found in upgrade package")
        
        # Step 9: Start service if it was running
        if service_was_running:
            logger.info("\nStep 9: Starting service with new binary...")
            try:
                subprocess.run(['systemctl', 'start', 'logstash-agent'], 
                             check=True, capture_output=True, timeout=30)
                logger.info("✓ Service started")
                
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
                
                # Stop the failed service
                subprocess.run(['systemctl', 'stop', 'logstash-agent'], 
                             check=False, capture_output=True)
                
                # Restore backup binary
                shutil.copy2(backup_path, INSTALL_PATHS['binary'])
                logger.info("✓ Restored previous binary")
                
                # Restore backup _internal if it exists
                internal_backup_path = f"{INSTALL_PATHS['binary_dir']}/_internal.backup"
                if os.path.exists(internal_backup_path):
                    internal_dest = os.path.join(INSTALL_PATHS['binary_dir'], '_internal')
                    if os.path.exists(internal_dest):
                        shutil.rmtree(internal_dest)
                    shutil.copytree(internal_backup_path, internal_dest)
                    logger.info("✓ Restored previous dependencies")
                
                # Start with old binary
                subprocess.run(['systemctl', 'start', 'logstash-agent'], 
                             check=True, capture_output=True, timeout=30)
                logger.info("✓ Service restarted with previous version")
                
                raise InstallError(f"Upgrade failed and was rolled back: {e}")
        else:
            logger.info("\nStep 9: Service was not running, skipping start")
            logger.info("Step 10: Verification skipped (service not running)")
        
        # Step 11: Cleanup
        logger.info("\nStep 11: Cleaning up...")
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info("✓ Removed temporary files")
        
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
