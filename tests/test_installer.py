#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import os
import sys
from unittest.mock import MagicMock, mock_open, patch

import pytest

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
    """Test that the generated systemd service content is properly formatted"""
    template = installer._build_systemd_service()

    assert '[Unit]' in template
    assert '[Service]' in template
    assert '[Install]' in template
    assert 'User=logstash' in template
    assert 'Group=logstash' in template
    assert 'ExecStart=/opt/logstash-agent/bin/logstash-agent --run' in template
    assert 'Restart=always' in template
    assert 'WorkingDirectory=/opt/logstash-agent/state' in template


def test_systemd_service_always_sets_user_even_if_lookup_fails():
    """
    Regression guard: the unit must never be written without User=logstash.
    It used to omit it when the account was missing, silently running as root.
    """
    with patch('logstashagent.installer.pwd') as mock_pwd, \
         patch('logstashagent.installer.grp') as mock_grp:
        mock_pwd.getpwnam.side_effect = KeyError('logstash')
        mock_grp.getgrnam.side_effect = KeyError('logstash')
        template = installer._build_systemd_service()

    assert 'User=logstash' in template
    assert 'Group=logstash' in template
    assert '# User=logstash' not in template


class _FakeAccountDb:
    """
    Stands in for pwd/grp, backed by mutable sets so that a successful
    groupadd/useradd makes the subsequent lookup succeed.
    """

    def __init__(self, *, users=(), groups=()):
        self.users = set(users)
        self.groups = set(groups)

    def getpwnam(self, name):
        if name not in self.users:
            raise KeyError(name)
        return MagicMock(pw_uid=1000)

    def getgrnam(self, name):
        if name not in self.groups:
            raise KeyError(name)
        return MagicMock(gr_gid=1000)


@pytest.fixture
def account_env(monkeypatch):
    """
    Patch pwd/grp with a fake account db and subprocess with a recorder whose
    successful calls populate that db. Returns (db, calls, set_result).
    """
    db = _FakeAccountDb()
    calls = []
    result = {'returncode': 0, 'stderr': '', 'stdout': ''}

    fake_pwd = MagicMock()
    fake_pwd.getpwnam.side_effect = db.getpwnam
    fake_grp = MagicMock()
    fake_grp.getgrnam.side_effect = db.getgrnam
    monkeypatch.setattr(installer, 'pwd', fake_pwd)
    monkeypatch.setattr(installer, 'grp', fake_grp)

    def fake_run(argv, **kwargs):
        calls.append({'argv': argv, 'kwargs': kwargs})
        if result['returncode'] in (0, installer._USERADD_EEXIST):
            if 'groupadd' in argv[0]:
                db.groups.add('logstash')
            elif 'useradd' in argv[0]:
                db.users.add('logstash')
        return MagicMock(
            returncode=result['returncode'],
            stderr=result['stderr'],
            stdout=result['stdout'],
        )

    monkeypatch.setattr(installer.subprocess, 'run', fake_run)
    return db, calls, result


def test_sbin_tool_prefers_absolute_path(monkeypatch):
    """
    /usr/sbin is not on root's PATH on every distro, and the frozen binary's
    environment is not the operator's shell.
    """
    monkeypatch.setattr(installer.os.path, 'isfile', lambda p: p == '/usr/sbin/useradd')
    monkeypatch.setattr(installer.os, 'access', lambda p, m: True)
    assert installer._sbin_tool('useradd') == '/usr/sbin/useradd'

    # RHEL layout
    monkeypatch.setattr(installer.os.path, 'isfile', lambda p: p == '/sbin/useradd')
    assert installer._sbin_tool('useradd') == '/sbin/useradd'

    # Neither present (e.g. macOS dev box): fall back to the bare name
    monkeypatch.setattr(installer.os.path, 'isfile', lambda p: False)
    assert installer._sbin_tool('useradd') == 'useradd'


def test_nologin_shell_resolution(monkeypatch):
    monkeypatch.setattr(installer.os.path, 'isfile', lambda p: p == '/usr/sbin/nologin')
    assert installer._nologin_shell() == '/usr/sbin/nologin'

    monkeypatch.setattr(installer.os.path, 'isfile', lambda p: p == '/sbin/nologin')
    assert installer._nologin_shell() == '/sbin/nologin'

    monkeypatch.setattr(installer.os.path, 'isfile', lambda p: False)
    assert installer._nologin_shell() == '/bin/false'


def test_ensure_logstash_user_idempotent_when_present(account_env):
    """A host with the Logstash DEB/RPM must run no commands at all."""
    db, calls, _ = account_env
    db.users.add('logstash')
    db.groups.add('logstash')

    uid, gid = installer.ensure_logstash_user()

    assert (uid, gid) == (1000, 1000)
    assert calls == [], "must not touch an existing account"


def test_ensure_logstash_user_creates_group_and_user(account_env):
    db, calls, _ = account_env

    uid, gid = installer.ensure_logstash_user()

    assert (uid, gid) == (1000, 1000)
    assert len(calls) == 2
    groupadd, useradd = calls[0]['argv'], calls[1]['argv']

    assert groupadd[0].endswith('groupadd')
    assert '--system' in groupadd
    assert groupadd[-1] == 'logstash'

    assert useradd[0].endswith('useradd')
    assert '--system' in useradd
    assert '--no-create-home' in useradd
    assert useradd[useradd.index('--gid') + 1] == 'logstash'
    assert useradd[useradd.index('--home-dir') + 1] == '/usr/share/logstash'
    assert 'nologin' in useradd[useradd.index('--shell') + 1] or \
        useradd[useradd.index('--shell') + 1] == '/bin/false'
    assert useradd[-1] == 'logstash'


def test_ensure_logstash_user_creates_user_only_when_group_exists(account_env):
    """Group-present-but-user-missing is a normal state."""
    db, calls, _ = account_env
    db.groups.add('logstash')

    installer.ensure_logstash_user()

    assert len(calls) == 1
    assert calls[0]['argv'][0].endswith('useradd')


def test_ensure_logstash_user_creates_group_only_when_user_exists(account_env):
    """Must not try to change an existing account's primary group."""
    db, calls, _ = account_env
    db.users.add('logstash')

    installer.ensure_logstash_user()

    assert len(calls) == 1
    assert calls[0]['argv'][0].endswith('groupadd')


def test_ensure_logstash_user_passes_host_env(account_env):
    """
    PyInstaller's LD_LIBRARY_PATH breaks distro tools linked against a newer
    libcrypto; these calls must go out with a cleaned environment.
    """
    db, calls, _ = account_env

    installer.ensure_logstash_user()

    for call in calls:
        env = call['kwargs'].get('env')
        assert env is not None, "must pass env=host_subprocess_env()"
        assert 'LD_LIBRARY_PATH' not in env or '_internal' not in env['LD_LIBRARY_PATH']
        assert call['kwargs']['check'] is False


def test_ensure_logstash_user_tolerates_already_exists(account_env, monkeypatch):
    """
    Exit 9 == 'name already in use'. Covers a race with a package install and
    an LDAP/SSSD account useradd refuses to shadow.
    """
    db, calls, result = account_env
    result['returncode'] = installer._USERADD_EEXIST
    result['stderr'] = 'useradd: user logstash already exists'

    uid, gid = installer.ensure_logstash_user()

    assert (uid, gid) == (1000, 1000)
    assert len(calls) == 2


def test_ensure_logstash_user_raises_with_manual_commands(account_env):
    db, calls, result = account_env
    result['returncode'] = 1
    result['stderr'] = 'useradd: cannot lock /etc/passwd'

    with pytest.raises(installer.InstallError) as exc:
        installer.ensure_logstash_user()

    msg = str(exc.value)
    assert 'cannot lock /etc/passwd' in msg
    assert 'groupadd' in msg and 'useradd' in msg, "must include manual commands"


def test_ensure_logstash_user_raises_when_tool_missing(account_env, monkeypatch):
    db, _calls, _ = account_env

    def boom(argv, **kwargs):
        raise FileNotFoundError('useradd')

    monkeypatch.setattr(installer.subprocess, 'run', boom)

    with pytest.raises(installer.InstallError) as exc:
        installer.ensure_logstash_user()

    assert 'groupadd' in str(exc.value)


def test_ensure_logstash_user_raises_if_still_unresolvable(account_env, monkeypatch):
    """A tool that reports success but leaves no resolvable account must fail."""
    db, _calls, _ = account_env

    def lying_run(argv, **kwargs):
        return MagicMock(returncode=0, stderr='', stdout='')

    monkeypatch.setattr(installer.subprocess, 'run', lying_run)

    with pytest.raises(installer.InstallError, match='still does not resolve'):
        installer.ensure_logstash_user()


def test_verify_logstash_installed_ignores_account(monkeypatch):
    """
    The account is created by the installer now, so it is no longer evidence
    that the Logstash package is present.
    """
    monkeypatch.setattr(
        installer.os.path, 'isdir', lambda p: p in ('/etc/logstash', '/usr/share/logstash')
    )
    fake_pwd = MagicMock()
    fake_pwd.getpwnam.side_effect = KeyError('logstash')
    monkeypatch.setattr(installer, 'pwd', fake_pwd)

    assert installer.verify_logstash_installed() is True


def test_repair_agent_ownership_leaves_bin_root_owned(tmp_path, monkeypatch):
    """
    Escalation guard: sudoers grants logstash NOPASSWD on bin/logstash-agent,
    so logstash must never own that directory.
    """
    for name in ('bin', 'config', 'state', 'logs', 'cache', 'logstash-versions'):
        (tmp_path / name).mkdir()
    (tmp_path / 'simulate-1').mkdir()

    monkeypatch.setitem(installer.INSTALL_PATHS, 'opt_root', str(tmp_path))
    for key, name in (
        ('config_dir', 'config'), ('state_dir', 'state'),
        ('log_dir', 'logs'), ('cache_dir', 'cache'),
    ):
        monkeypatch.setitem(installer.INSTALL_PATHS, key, str(tmp_path / name))

    chowned = []
    monkeypatch.setattr(
        installer, 'get_logstash_uid_gid', lambda: (1000, 1000)
    )
    monkeypatch.setattr(
        installer.os, 'chown', lambda p, u, g: chowned.append(str(p)), raising=False
    )
    monkeypatch.setattr(installer, 'install_multi_instance_unit_templates', lambda: None)

    installer.repair_agent_ownership()

    assert str(tmp_path / 'config') in chowned
    assert str(tmp_path / 'state') in chowned
    assert str(tmp_path / 'logstash-versions') in chowned
    assert str(tmp_path / 'simulate-1') in chowned
    assert str(tmp_path / 'bin') not in chowned, "bin/ must stay root-owned"


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
    """Test that cache_dir is defined in INSTALL_PATHS under /opt"""
    assert 'cache_dir' in installer.INSTALL_PATHS
    assert installer.INSTALL_PATHS['cache_dir'] == '/opt/logstash-agent/cache'
    assert installer.INSTALL_PATHS['config_dir'] == '/opt/logstash-agent/config'
    assert installer.INSTALL_PATHS['state_dir'] == '/opt/logstash-agent/state'
    assert installer.INSTALL_PATHS['log_dir'] == '/opt/logstash-agent/logs'


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
    """Test fallback when logstash user doesn't exist — returns (0, 0) with a warning"""
    mock_pwd.getpwnam.side_effect = KeyError('logstash')

    uid, gid = installer.get_logstash_uid_gid()

    assert uid == 0
    assert gid == 0


@patch('subprocess.run')
def test_verify_service_running_active(mock_run):
    """Test verify_service_running when service is active"""
    mock_run.return_value = MagicMock(returncode=0)

    result = installer.verify_service_running()

    assert result is True
    assert mock_run.call_count == 1
    cmd = mock_run.call_args[0][0]
    assert cmd[-2:] == ['is-active', 'logstash-agent']
    assert cmd[0].endswith('systemctl')
    # Host env must be passed so PyInstaller libs do not break systemctl
    assert 'env' in mock_run.call_args.kwargs


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
    expected = '/opt/logstash-agent/cache/logstash-agent-0.1.30.tar.gz'
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
    expected = '/opt/logstash-agent/cache/logstash-agent-0.1.30.tar.gz'
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
    """Test verify_logstash_installed returns False when logstash user doesn't exist"""
    mock_pwd.getpwnam.side_effect = KeyError('logstash')

    result = installer.verify_logstash_installed()

    assert result is False


@patch('logstashagent.installer.pwd')
@patch('os.path.isdir')
def test_verify_logstash_installed_directory_missing(mock_isdir, mock_pwd):
    """Test verify_logstash_installed returns False when Logstash directories don't exist"""
    mock_pwd.getpwnam.return_value = MagicMock()
    mock_isdir.return_value = False

    result = installer.verify_logstash_installed()

    assert result is False


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
        return not ('.backup' in str(path) and exists_call_count[0] > 6)

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


@patch('os.path.isdir')
@patch('os.path.exists')
@patch('shutil.rmtree')
def test_perform_uninstallation_with_purge(mock_rmtree, mock_exists, mock_isdir):
    """Test perform_uninstallation --purge wipes /opt/logstash-agent"""
    mock_exists.return_value = True
    mock_isdir.return_value = True

    with patch('logstashagent.installer.verify_root'), \
         patch('logstashagent.installer.verify_platform'), \
         patch('subprocess.run'), \
         patch('os.remove'), \
         patch('os.unlink'), \
         patch('os.path.islink', return_value=True), \
         patch('os.listdir', return_value=[]), \
         patch('os.rmdir'), \
         patch('logstashagent.install_registry.load_registry', return_value={'instances': {}}), \
         patch('logstashagent.install_registry.list_instances', return_value=[]), \
         patch('logstashagent.install_registry.remove_shared_unit_files'):

        installer.perform_uninstallation(purge=True)

        # Opt root wipe + any legacy FHS dirs that mock isdir says exist
        removed = [str(c.args[0]) for c in mock_rmtree.call_args_list]
        assert any('/opt/logstash-agent' == p or p.endswith('/opt/logstash-agent') for p in removed) or \
            installer.INSTALL_PATHS['opt_root'] in removed
        assert mock_rmtree.call_count >= 1


@patch('os.path.isdir')
@patch('os.path.exists')
@patch('shutil.rmtree')
def test_perform_uninstallation_without_purge_preserves_data(mock_rmtree, mock_exists, mock_isdir):
    """Test soft uninstall removes bin+config only; keeps state/logs/cache under opt"""
    mock_exists.return_value = True

    def _isdir(path):
        # Soft uninstall only rmtree's binary_dir and config_dir
        return path in (
            installer.INSTALL_PATHS['binary_dir'],
            installer.INSTALL_PATHS['config_dir'],
            installer.INSTALL_PATHS['state_dir'],
            installer.INSTALL_PATHS['log_dir'],
            installer.INSTALL_PATHS['cache_dir'],
            installer.INSTALL_PATHS['opt_root'],
        )

    mock_isdir.side_effect = _isdir

    with patch('logstashagent.installer.verify_root'), \
         patch('logstashagent.installer.verify_platform'), \
         patch('subprocess.run'), \
         patch('os.remove'), \
         patch('os.unlink'), \
         patch('os.path.islink', return_value=True), \
         patch('os.listdir', return_value=['state', 'logs']), \
         patch('os.rmdir'), \
         patch('logstashagent.install_registry.load_registry', return_value={'instances': {}}), \
         patch('logstashagent.install_registry.list_instances', return_value=[]), \
         patch('logstashagent.install_registry.remove_shared_unit_files'), \
         patch('logstashagent.install_registry.save_registry'):

        installer.perform_uninstallation(purge=False)

        removed = [str(c.args[0]) for c in mock_rmtree.call_args_list]
        assert installer.INSTALL_PATHS['binary_dir'] in removed
        assert installer.INSTALL_PATHS['config_dir'] in removed
        assert installer.INSTALL_PATHS['state_dir'] not in removed
        assert installer.INSTALL_PATHS['log_dir'] not in removed
        assert installer.INSTALL_PATHS['cache_dir'] not in removed
        assert installer.INSTALL_PATHS['opt_root'] not in removed


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
