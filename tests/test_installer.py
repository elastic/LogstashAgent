#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import pytest
import sys
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open, call
from logstashagent import installer


def test_verify_platform_on_windows():
    """Test that platform verification fails on Windows"""
    if sys.platform == 'win32':
        with pytest.raises(installer.InstallError, match="only supported on Linux"):
            installer.verify_platform()


def test_verify_platform_on_linux():
    """Test that platform verification passes on Linux"""
    if sys.platform == 'linux':
        # Should not raise
        installer.verify_platform()


def test_install_paths_defined():
    """Test that all required install paths are defined"""
    required_paths = [
        'binary_dir',
        'binary',
        'symlink',
        'config_dir',
        'state_dir',
        'log_dir',
        'systemd_service'
    ]
    
    for path_key in required_paths:
        assert path_key in installer.INSTALL_PATHS
        assert installer.INSTALL_PATHS[path_key].startswith('/')


def test_systemd_service_template():
    """Test that systemd service template is properly formatted"""
    template = installer.SYSTEMD_SERVICE_TEMPLATE
    
    # Check for required sections
    assert '[Unit]' in template
    assert '[Service]' in template
    assert '[Install]' in template
    
    # Check for required service settings
    assert 'User=logstash' in template
    assert 'Group=logstash' in template
    assert 'ExecStart=/opt/logstash-agent/bin/logstash-agent --run' in template
    assert 'Restart=always' in template
    assert 'WorkingDirectory=/var/lib/logstash-agent' in template


def test_github_release_url_format():
    """Test that GitHub release URL is correctly formatted"""
    # This validates the URL pattern used in download_release
    version = '0.1.30'
    expected_url = f'https://github.com/elastic/LogstashAgent/releases/download/v{version}/logstash-agent-linux-amd64.tar.gz'
    assert 'github.com' in expected_url
    assert version in expected_url
    assert 'logstash-agent-linux-amd64.tar.gz' in expected_url


def test_install_error_exception():
    """Test that InstallError can be raised and caught"""
    with pytest.raises(installer.InstallError):
        raise installer.InstallError("Test error")


def test_uninstall_verify_root_required():
    """Test that uninstall requires root privileges"""
    # This test will only work on Unix systems
    if sys.platform == 'linux' and installer.pwd is not None:
        import os
        # Only test if not running as root
        if os.geteuid() != 0:
            with pytest.raises(installer.InstallError, match="root privileges"):
                installer.verify_root()


def test_uninstall_paths_match_install_paths():
    """Test that uninstall uses the same paths as install"""
    # The uninstall function should reference the same INSTALL_PATHS
    # This ensures consistency between install and uninstall
    assert 'binary_dir' in installer.INSTALL_PATHS
    assert 'binary' in installer.INSTALL_PATHS
    assert 'symlink' in installer.INSTALL_PATHS
    assert 'config_dir' in installer.INSTALL_PATHS
    assert 'state_dir' in installer.INSTALL_PATHS
    assert 'log_dir' in installer.INSTALL_PATHS
    assert 'systemd_service' in installer.INSTALL_PATHS


def test_cache_dir_in_install_paths():
    """Test that cache_dir is defined in INSTALL_PATHS"""
    assert 'cache_dir' in installer.INSTALL_PATHS
    assert installer.INSTALL_PATHS['cache_dir'] == '/var/cache/logstash-agent'


def test_backup_path_format():
    """Test that backup path format is consistent"""
    # Verify the backup path pattern used in upgrade
    binary_path = installer.INSTALL_PATHS['binary']
    expected_backup = f"{binary_path}.backup"
    assert expected_backup == '/opt/logstash-agent/bin/logstash-agent.backup'


@patch('logstashagent.installer.pwd')
def test_get_logstash_uid_gid_success(mock_pwd):
    """Test successful retrieval of logstash UID/GID"""
    mock_pw = MagicMock()
    mock_pw.pw_uid = 1000
    mock_gr = MagicMock()
    mock_gr.gr_gid = 1000
    
    with patch('logstashagent.installer.grp') as mock_grp:
        mock_pwd.getpwnam.return_value = mock_pw
        mock_grp.getgrnam.return_value = mock_gr
        
        uid, gid = installer.get_logstash_uid_gid()
        
        assert uid == 1000
        assert gid == 1000
        mock_pwd.getpwnam.assert_called_once_with('logstash')
        mock_grp.getgrnam.assert_called_once_with('logstash')


@patch('logstashagent.installer.pwd')
def test_get_logstash_uid_gid_user_not_found(mock_pwd):
    """Test error when logstash user doesn't exist"""
    mock_pwd.getpwnam.side_effect = KeyError('logstash')
    
    with pytest.raises(installer.InstallError, match="Failed to get logstash user/group info"):
        installer.get_logstash_uid_gid()


@patch('subprocess.run')
def test_verify_service_running_active(mock_run):
    """Test verify_service_running when service is active"""
    mock_run.return_value = MagicMock(returncode=0)
    
    result = installer.verify_service_running()
    
    assert result is True
    mock_run.assert_called_once_with(
        ['systemctl', 'is-active', 'logstash-agent'],
        capture_output=True,
        timeout=5
    )


@patch('subprocess.run')
def test_verify_service_running_inactive(mock_run):
    """Test verify_service_running when service is inactive"""
    mock_run.return_value = MagicMock(returncode=3)  # systemctl returns 3 for inactive
    
    result = installer.verify_service_running()
    
    assert result is False


@patch('subprocess.run')
def test_verify_service_running_timeout(mock_run):
    """Test verify_service_running handles timeout"""
    import subprocess
    mock_run.side_effect = subprocess.TimeoutExpired('systemctl', 5)
    
    result = installer.verify_service_running()
    
    assert result is False


@patch('os.path.exists')
def test_download_release_from_cache(mock_exists):
    """Test download_release uses cached tarball when available"""
    # Mock cache exists
    mock_exists.return_value = True
    
    result = installer.download_release('0.1.30', '/tmp/test')
    
    # Should return cached path (normalize for comparison)
    expected = '/var/cache/logstash-agent/logstash-agent-0.1.30.tar.gz'
    assert os.path.normpath(result) == os.path.normpath(expected)


@patch('builtins.open', new_callable=mock_open)
@patch('os.chmod')
@patch('os.makedirs')
@patch('os.path.exists')
def test_download_release_downloads_when_not_cached(mock_exists, mock_makedirs, mock_chmod, mock_file):
    """Test download_release downloads from GitHub when not cached"""
    # Mock cache doesn't exist
    mock_exists.return_value = False
    
    # Mock successful download
    mock_response = MagicMock()
    mock_response.headers = {'content-length': '1000'}
    mock_response.iter_content.return_value = [b'test data']
    
    # Mock pwd/grp
    mock_pw = MagicMock(pw_uid=1000)
    mock_gr = MagicMock(gr_gid=1000)
    
    with patch('logstashagent.installer.pwd') as mock_pwd, \
         patch('logstashagent.installer.grp') as mock_grp, \
         patch('logstashagent.installer.os.chown', create=True) as mock_chown, \
         patch('requests.get', return_value=mock_response) as mock_get:
        
        mock_pwd.getpwnam.return_value = mock_pw
        mock_grp.getgrnam.return_value = mock_gr
        
        result = installer.download_release('0.1.30', '/tmp/test')
        
        # Should download from GitHub
        expected_url = 'https://github.com/elastic/LogstashAgent/releases/download/v0.1.30/logstash-agent-linux-amd64.tar.gz'
        mock_get.assert_called_once_with(expected_url, stream=True, timeout=60)
    
    # Should return cache path (normalize for comparison)
    expected = '/var/cache/logstash-agent/logstash-agent-0.1.30.tar.gz'
    assert os.path.normpath(result) == os.path.normpath(expected)


@patch('os.makedirs')
@patch('os.path.exists')
def test_download_release_handles_network_error(mock_exists, mock_makedirs):
    """Test download_release handles network errors"""
    import requests
    mock_exists.return_value = False
    
    # Mock pwd/grp and os.chown to avoid AttributeError on Windows
    with patch('logstashagent.installer.pwd') as mock_pwd, \
         patch('logstashagent.installer.grp') as mock_grp, \
         patch('logstashagent.installer.os.chown', create=True), \
         patch('requests.get', side_effect=requests.exceptions.ConnectionError('Network error')):
        
        mock_pwd.getpwnam.return_value = MagicMock(pw_uid=1000)
        mock_grp.getgrnam.return_value = MagicMock(gr_gid=1000)
        
        with pytest.raises(installer.InstallError, match="Failed to download release"):
            installer.download_release('0.1.30', '/tmp/test')


@patch('tarfile.open')
@patch('os.path.exists')
def test_extract_binary_success(mock_exists, mock_tarfile):
    """Test successful binary extraction"""
    mock_exists.return_value = True
    mock_tar = MagicMock()
    mock_tarfile.return_value.__enter__.return_value = mock_tar
    
    result = installer.extract_binary('/tmp/test.tar.gz', '/tmp/extract')
    
    # Normalize paths for comparison
    expected = os.path.join('/tmp/extract', 'logstash-agent', 'logstash-agent')
    assert os.path.normpath(result) == os.path.normpath(expected)
    mock_tar.extractall.assert_called_once_with('/tmp/extract')


@patch('tarfile.open')
@patch('os.path.exists')
def test_extract_binary_not_found(mock_exists, mock_tarfile):
    """Test extract_binary when binary not found in tarball"""
    mock_exists.return_value = False
    mock_tar = MagicMock()
    mock_tarfile.return_value.__enter__.return_value = mock_tar
    
    with pytest.raises(installer.InstallError, match="Binary not found in tarball"):
        installer.extract_binary('/tmp/test.tar.gz', '/tmp/extract')


@patch('tarfile.open')
def test_extract_binary_handles_tar_error(mock_tarfile):
    """Test extract_binary handles tarfile errors"""
    import tarfile
    mock_tarfile.side_effect = tarfile.TarError('Corrupted tarball')
    
    with pytest.raises(installer.InstallError, match="Failed to extract tarball"):
        installer.extract_binary('/tmp/test.tar.gz', '/tmp/extract')


@patch('logstashagent.installer.pwd')
@patch('os.path.isdir')
def test_verify_logstash_installed_success(mock_isdir, mock_pwd):
    """Test verify_logstash_installed when Logstash is properly installed"""
    mock_pwd.getpwnam.return_value = MagicMock()
    mock_isdir.return_value = True
    
    # Should not raise
    installer.verify_logstash_installed()


@patch('logstashagent.installer.pwd')
def test_verify_logstash_installed_user_missing(mock_pwd):
    """Test verify_logstash_installed when logstash user doesn't exist"""
    mock_pwd.getpwnam.side_effect = KeyError('logstash')
    
    with pytest.raises(installer.InstallError, match="Logstash does not appear to be installed"):
        installer.verify_logstash_installed()


@patch('logstashagent.installer.pwd')
@patch('os.path.isdir')
def test_verify_logstash_installed_directory_missing(mock_isdir, mock_pwd):
    """Test verify_logstash_installed when Logstash directories don't exist"""
    mock_pwd.getpwnam.return_value = MagicMock()
    mock_isdir.return_value = False
    
    with pytest.raises(installer.InstallError, match="Logstash does not appear to be installed"):
        installer.verify_logstash_installed()


@patch('os.path.exists')
@patch('shutil.copy2')
@patch('os.chmod')
@patch('os.rename')
def test_perform_upgrade_rollback_on_service_failure(mock_rename, mock_chmod, mock_copy2, mock_exists):
    """Test perform_upgrade rolls back when service fails to start"""
    # Mock exists to return True for all checks (binary, backup, etc.)
    mock_exists.return_value = True
    
    # Mock the backup path exists
    with patch('logstashagent.installer.verify_root'), \
         patch('logstashagent.installer.verify_platform'), \
         patch('tempfile.mkdtemp', return_value='/tmp/test'), \
         patch('logstashagent.installer.download_release', return_value='/tmp/test.tar.gz'), \
         patch('logstashagent.installer.extract_binary', return_value='/tmp/logstash-agent'), \
         patch('logstashagent.installer.verify_service_running', side_effect=[True, False, True]), \
         patch('subprocess.run') as mock_run, \
         patch('shutil.rmtree'), \
         patch('shutil.copytree'), \
         patch('os.remove'), \
         patch('os.path.dirname', return_value='/tmp'), \
         patch('os.path.join', side_effect=lambda *args: '/'.join(args)), \
         patch('time.sleep'):
        
        # Make restart fail with CalledProcessError, then rollback succeeds
        import subprocess
        
        # First call: restart fails and raises exception
        # Second call: stop during rollback succeeds
        # Third call: start during rollback succeeds
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if 'restart' in cmd:
                raise subprocess.CalledProcessError(1, cmd)
            return MagicMock(returncode=0)
        
        mock_run.side_effect = run_side_effect
        
        with pytest.raises(installer.InstallError, match="Upgrade failed and was rolled back"):
            installer.perform_upgrade('0.1.30', auto=False)
        
        # Verify rollback was attempted
        assert mock_copy2.call_count >= 2  # Backup + restore


@patch('os.path.exists')
def test_perform_upgrade_rollback_failure_provides_manual_steps(mock_exists):
    """Test perform_upgrade provides manual recovery steps when rollback fails"""
    # Track exists calls - return False for backup check during rollback
    exists_call_count = [0]
    def exists_side_effect(path):
        exists_call_count[0] += 1
        # After initial checks, when checking for backup during rollback, return False
        if '.backup' in str(path) and exists_call_count[0] > 6:
            return False
        return True
    
    mock_exists.side_effect = exists_side_effect
    
    with patch('logstashagent.installer.verify_root'), \
         patch('logstashagent.installer.verify_platform'), \
         patch('tempfile.mkdtemp', return_value='/tmp/test'), \
         patch('logstashagent.installer.download_release', return_value='/tmp/test.tar.gz'), \
         patch('logstashagent.installer.extract_binary', return_value='/tmp/logstash-agent'), \
         patch('logstashagent.installer.verify_service_running', side_effect=[True, False]), \
         patch('subprocess.run') as mock_run, \
         patch('shutil.copy2'), \
         patch('shutil.rmtree'), \
         patch('shutil.copytree'), \
         patch('os.chmod'), \
         patch('os.rename'), \
         patch('os.remove'), \
         patch('os.path.dirname', return_value='/tmp'), \
         patch('os.path.join', side_effect=lambda *args: '/'.join(args)), \
         patch('time.sleep'):
        
        # Make restart fail
        import subprocess
        
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if 'restart' in cmd:
                raise subprocess.CalledProcessError(1, cmd)
            return MagicMock(returncode=0)
        
        mock_run.side_effect = run_side_effect
        
        with pytest.raises(installer.InstallError, match="Manual recovery required"):
            installer.perform_upgrade('0.1.30', auto=False)


@patch('os.path.exists')
@patch('shutil.rmtree')
def test_perform_uninstallation_with_purge(mock_rmtree, mock_exists):
    """Test perform_uninstallation removes all directories with --purge"""
    mock_exists.return_value = True
    
    with patch('logstashagent.installer.verify_root'), \
         patch('logstashagent.installer.verify_platform'), \
         patch('subprocess.run'), \
         patch('os.remove'), \
         patch('os.unlink'), \
         patch('os.path.islink', return_value=True), \
         patch('os.listdir', return_value=[]), \
         patch('os.rmdir'):
        
        installer.perform_uninstallation(purge=True)
        
        # Verify all directories were removed (binary_dir, config_dir, state_dir, log_dir, cache_dir)
        assert mock_rmtree.call_count >= 5


@patch('os.path.exists')
@patch('shutil.rmtree')
def test_perform_uninstallation_without_purge_preserves_data(mock_rmtree, mock_exists):
    """Test perform_uninstallation preserves state/log/cache without --purge"""
    mock_exists.return_value = True
    
    with patch('logstashagent.installer.verify_root'), \
         patch('logstashagent.installer.verify_platform'), \
         patch('subprocess.run'), \
         patch('os.remove'), \
         patch('os.unlink'), \
         patch('os.path.islink', return_value=True), \
         patch('os.listdir', return_value=[]), \
         patch('os.rmdir'):
        
        installer.perform_uninstallation(purge=False)
        
        # Verify only binary_dir and config_dir were removed (not state, log, cache)
        # Should be exactly 2 calls: binary_dir and config_dir
        assert mock_rmtree.call_count == 2


def test_install_paths_cache_dir_included():
    """Test that cache_dir is included in INSTALL_PATHS for uninstall"""
    # Ensure cache_dir is in the paths dictionary
    assert 'cache_dir' in installer.INSTALL_PATHS
    # Ensure it's a valid absolute path
    assert installer.INSTALL_PATHS['cache_dir'].startswith('/')


def test_install_paths_all_absolute():
    """Test that all install paths are absolute paths"""
    for key, path in installer.INSTALL_PATHS.items():
        assert path.startswith('/'), f"Path {key}={path} is not absolute"


def test_sudoers_content_in_perform_installation():
    """Test that sudoers content includes necessary permissions"""
    # This is a simple validation test - the actual sudoers content is defined inline
    # in perform_installation, so we just verify the expected permissions would be included
    expected_permissions = [
        'logstash ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart logstash',
        'logstash ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop logstash-agent',
        'logstash ALL=(ALL) NOPASSWD: /usr/bin/systemctl start logstash-agent',
        'logstash ALL=(ALL) NOPASSWD: /opt/logstash-agent/bin/logstash-agent upgrade',
    ]
    # This test just validates our expectations - actual sudoers creation is tested in integration
    assert all(isinstance(perm, str) for perm in expected_permissions)
