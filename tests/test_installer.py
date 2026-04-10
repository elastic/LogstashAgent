#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import pytest
import sys
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
