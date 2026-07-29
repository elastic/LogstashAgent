#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for bare simulate recovery (quarantine + harness pipelines.yml)."""

from pathlib import Path
from unittest.mock import patch

import yaml

from logstashagent import simulate_recovery


def test_package_confs_exist():
    d = simulate_recovery.package_simulate_conf_dir()
    assert (d / 'simulate_start.conf').is_file()
    assert (d / 'simulate_end.conf').is_file()


def test_seed_and_bare_pipelines_yml(tmp_path):
    settings = tmp_path / 'settings'
    seed = simulate_recovery.seed_static_harness(settings, force=True)
    assert seed['ok'] is True
    assert (settings / 'config' / 'simulate_start.conf').is_file()
    assert (settings / 'config' / 'simulate_end.conf').is_file()

    yml = simulate_recovery.write_bare_pipelines_yml(settings)
    assert yml.is_file()
    data = yaml.safe_load(yml.read_text(encoding='utf-8'))
    ids = [p['pipeline.id'] for p in data]
    assert ids == ['simulate-start', 'simulate-end']
    assert 'simulate_start.conf' in data[0]['path.config']
    assert 'slot' not in str(data)


def test_quarantine_moves_slot_confs(tmp_path):
    settings = tmp_path / 'settings'
    conf_d = settings / 'conf.d'
    conf_d.mkdir(parents=True)
    (conf_d / 'slot3-filter1.conf').write_text('filter { }\n', encoding='utf-8')
    (conf_d / 'keep-me.conf').write_text('x\n', encoding='utf-8')
    (settings / 'pipelines.yml').write_text('[]\n', encoding='utf-8')

    out = simulate_recovery.quarantine_dynamic_pipelines(settings)
    assert out['moved']
    assert not (conf_d / 'slot3-filter1.conf').exists()
    assert (conf_d / 'keep-me.conf').exists()  # not a slot* file
    assert any('slot3-filter1.conf' in m for m in out['moved'])


def test_sanitize_clears_slots_and_writes_harness(tmp_path):
    settings = tmp_path / 'settings'
    conf_d = settings / 'conf.d'
    conf_d.mkdir(parents=True)
    (conf_d / 'slot1-filter1.conf').write_text('bad\n', encoding='utf-8')

    with patch.object(simulate_recovery, 'clear_slot_state') as clear:
        result = simulate_recovery.sanitize_simulate_pipelines(str(settings))

    assert result['success'] is True
    assert result['layout'] == 'harness'
    clear.assert_called_once()
    assert not (conf_d / 'slot1-filter1.conf').exists()
    data = yaml.safe_load(Path(result['pipelines_yml']).read_text(encoding='utf-8'))
    assert [p['pipeline.id'] for p in data] == ['simulate-start', 'simulate-end']


def test_recover_calls_restart(tmp_path):
    settings = tmp_path / 'settings'
    with patch.object(
        simulate_recovery, 'sanitize_simulate_pipelines',
        return_value={'success': True, 'layout': 'harness'},
    ), patch(
        'logstashagent.controller.restart_logstash', return_value=True
    ) as restart:
        # force bypasses rate limit
        out = simulate_recovery.recover_simulate_logstash(
            reason='test',
            settings_path=str(settings),
            restart=True,
            force=True,
        )
    assert out['success'] is True
    assert out['restarted'] is True
    restart.assert_called_once()


def test_recover_rate_limit(tmp_path):
    simulate_recovery._recovery_times.clear()
    settings = tmp_path / 'settings'
    with patch.object(
        simulate_recovery, 'sanitize_simulate_pipelines',
        return_value={'success': True},
    ), patch('logstashagent.controller.restart_logstash', return_value=True):
        first = simulate_recovery.recover_simulate_logstash(
            reason='a', settings_path=str(settings), force=False
        )
        second = simulate_recovery.recover_simulate_logstash(
            reason='b', settings_path=str(settings), force=False
        )
    assert first['success'] is True
    assert second.get('denied') is True


def test_trigger_sim_restart_uses_recovery(monkeypatch):
    from logstashagent import main

    monkeypatch.setattr(main, 'is_systemctl_managed_simulate', lambda: True)
    called = {}

    def fake_recover(**kwargs):
        called.update(kwargs)
        return {'success': True, 'restarted': True}

    with patch(
        'logstashagent.simulate_recovery.recover_simulate_logstash',
        side_effect=fake_recover,
    ):
        ok = main.trigger_sim_logstash_restart('sim failed')
    assert ok is True
    assert called.get('reason') == 'sim failed'
    assert called.get('restart') is True
