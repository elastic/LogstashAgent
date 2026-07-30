#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

from pathlib import Path
from unittest.mock import patch

import pytest

from logstashagent import installer


SIM_CFG = {
    'policy_type': 'SIMULATE',
    'instance_id': 3,
    'settings_path': None,
    'config_path': None,
    'logs_path': None,
    'data_path': None,
    'keystore_env_file': None,
    'binary_path': '/usr/share/logstash/bin',
    'logstash_source': 'SYSTEM',
    'logstash_version': '',
    'logstash_download_dir': '',
    'agent_api_port': 9503,
    'logstash_api_port': 9563,
    'logstash_yml': 'api.http.port: 9563\n',
    'jvm_options': '-Xms1g\n',
    'log4j2_properties': 'x=1\n',
}


def test_ensure_simulate_setup_as_root():
    with patch.object(installer.os, 'geteuid', return_value=0), patch.object(
        installer, 'setup_simulate_from_policy', return_value={'instance_id': 3}
    ) as setup:
        out = installer.ensure_simulate_setup(dict(SIM_CFG))
    assert out['status'] == 'complete'
    assert out['via'] == 'root'
    setup.assert_called_once()


def test_ensure_simulate_setup_sudo_success():
    with patch.object(installer.os, 'geteuid', return_value=1000), patch.object(
        installer, '_try_sudo_setup_simulate',
        return_value={'status': 'complete', 'via': 'sudo', 'messages': ['ok']},
    ) as sudo, patch.object(installer, 'setup_simulate_from_policy') as setup:
        out = installer.ensure_simulate_setup(dict(SIM_CFG))
    assert out['status'] == 'complete'
    assert out['via'] == 'sudo'
    setup.assert_not_called()
    sudo.assert_called_once()


def test_ensure_simulate_setup_partial_writable(tmp_path):
    cfg = dict(SIM_CFG)
    cfg['settings_path'] = str(tmp_path / 'simulate-3' / 'settings')
    cfg['config_path'] = str(tmp_path / 'simulate-3' / 'config')
    cfg['logs_path'] = str(tmp_path / 'simulate-3' / 'logs')
    cfg['data_path'] = str(tmp_path / 'simulate-3' / 'data')
    cfg['keystore_env_file'] = str(tmp_path / 'simulate-3' / 'env')

    with patch.object(installer.os, 'geteuid', return_value=1000), patch.object(
        installer, '_try_sudo_setup_simulate', return_value=None
    ), patch.object(
        installer, '_can_write_simulate_tree', return_value=True
    ), patch.dict(
        installer.INSTALL_PATHS, {'simulate_root': str(tmp_path)}
    ), patch(
        'logstashagent.logstash_download.resolve_binary_from_policy',
        return_value='/usr/share/logstash/bin/logstash',
    ), patch.object(
        installer, 'get_logstash_uid_gid', return_value=(1000, 1000)
    ), patch.object(installer.os, 'chown'):
        out = installer.ensure_simulate_setup(cfg)

    assert out['status'] == 'partial'
    assert out['via'] == 'user_writable'
    assert any('setup-simulate' in m for m in out['messages'])
    assert Path(cfg['settings_path']).is_dir()


def test_ensure_simulate_setup_pending_when_no_privs():
    with patch.object(installer.os, 'geteuid', return_value=1000), patch.object(
        installer, '_try_sudo_setup_simulate', return_value=None
    ), patch.object(installer, '_can_write_simulate_tree', return_value=False):
        out = installer.ensure_simulate_setup(dict(SIM_CFG))
    assert out['status'] == 'pending'
    assert out['via'] == 'deferred'
    assert any('setup-simulate' in m for m in out['messages'])


def test_ensure_simulate_setup_skips_non_simulate():
    out = installer.ensure_simulate_setup({'policy_type': 'DEFAULT'})
    assert out['status'] == 'complete'
    assert out['via'] == 'n/a'


def test_policy_config_from_state_prefers_blob():
    blob = {'policy_type': 'SIMULATE', 'instance_id': 9, 'settings_path': '/x'}
    with patch('logstashagent.agent_state.get_state', return_value={
        'policy_config': blob,
        'instance_id': 1,
    }):
        cfg = installer.policy_config_from_state()
    assert cfg['instance_id'] == 9
    assert cfg['settings_path'] == '/x'


def test_policy_config_from_state_rebuilds_from_fields():
    with patch('logstashagent.agent_state.get_state', return_value={
        'mode': 'simulate',
        'instance_id': 4,
        'settings_path': '/opt/logstash-agent/simulate-4/settings',
        'config_path': '/opt/logstash-agent/simulate-4/config',
        'logs_path': '/opt/logstash-agent/simulate-4/logs',
        'data_path': '/opt/logstash-agent/simulate-4/data',
        'binary_path': '/usr/share/logstash/bin',
        'keystore_env_file': '/opt/logstash-agent/simulate-4/env',
        'agent_api_port': 9504,
        'logstash_api_port': 9564,
        'logstash_source': 'SYSTEM',
    }):
        cfg = installer.policy_config_from_state()
    assert cfg['policy_type'] == 'SIMULATE'
    assert cfg['instance_id'] == 4
    assert cfg['settings_path'].endswith('simulate-4/settings')
    assert cfg['agent_api_port'] == 9504


def test_perform_setup_simulate_requires_enrolled():
    with patch.object(installer, 'verify_root'), patch.object(
        installer, 'verify_platform'
    ), patch('logstashagent.agent_state.get_state', return_value={'enrolled': False}):
        with pytest.raises(installer.InstallError, match='not enrolled'):
            installer.perform_setup_simulate(yes=True)


def test_perform_setup_simulate_success():
    state = {
        'enrolled': True,
        'mode': 'simulate',
        'logstash_ui_url': 'http://ui',
        'policy_config': dict(SIM_CFG),
    }
    with patch.object(installer, 'verify_root'), patch.object(
        installer, 'verify_platform'
    ), patch('logstashagent.agent_state.get_state', return_value=state), patch.object(
        installer, 'setup_simulate_from_policy', return_value={'instance_id': 3}
    ) as setup, patch.object(
        installer, 'configure_logstash'
    ), patch.object(
        installer.os.path, 'isdir', return_value=False
    ), patch(
        'logstashagent.agent_state.update_state'
    ) as upd:
        out = installer.perform_setup_simulate(yes=True)

    assert out['instance_id'] == 3
    setup.assert_called_once()
    upd.assert_any_call('simulate_setup_pending', False)


def test_perform_setup_simulate_rejects_packaged_mode():
    with patch.object(installer, 'verify_root'), patch.object(
        installer, 'verify_platform'
    ), patch(
        'logstashagent.agent_state.get_state',
        return_value={
            'enrolled': True,
            'mode': 'packaged',
            'policy_config': {'policy_type': 'PACKAGED'},
        },
    ):
        with pytest.raises(installer.InstallError, match='not a multi-instance'):
            installer.perform_setup_simulate(yes=True)
