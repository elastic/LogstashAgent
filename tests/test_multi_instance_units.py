#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Managed multi-instance unit names, materialize, and template install."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from logstashagent import install_registry, installer


def test_canonical_managed_and_simulate():
    """acceptance A1: <nodetype>-<instance>@N for both multi-instance roles."""
    assert installer.resolve_multi_instance_units(2, 'MANAGED') == (
        'managed-agent@2',
        'managed-logstash@2',
    )
    assert installer.resolve_multi_instance_units(3, 'SIMULATE') == (
        'simulate-agent@3',
        'simulate-logstash@3',
    )


def test_packaged_not_templated():
    """acceptance A1: packaged units stay logstash-agent / logstash, never @-templated."""
    assert installer.INSTALL_PATHS['systemd_service'].endswith('/logstash-agent.service')
    assert '@' not in installer.INSTALL_PATHS['systemd_service']
    # Bare logstash-agent (no @) is never rewritten to managed-agent.
    agent, ls = installer.resolve_multi_instance_units(
        1, 'MANAGED', agent_unit='logstash-agent', logstash_unit='logstash'
    )
    assert (agent, ls) == ('logstash-agent', 'logstash')
    assert installer._is_logstash_unit('logstash')
    assert not installer._is_logstash_unit('logstash-agent')


def test_resolve_multi_instance_units_uses_new_names(tmp_path):
    """acceptance A2: resolver and registry discovery agree on canonical names."""
    for pt in ('MANAGED', 'SIMULATE'):
        agent, ls = installer.resolve_multi_instance_units(4, pt)
        for old in ('lsagent-simulate@', 'ls-simulate@', 'logstash-agent@', 'logstash-managed@'):
            assert not agent.startswith(old), agent
            assert not ls.startswith(old), ls
    (tmp_path / 'managed-1').mkdir()
    (tmp_path / 'simulate-2').mkdir()
    found = {d['id']: d for d in install_registry.discover_instances_from_disk(str(tmp_path))}
    assert (found['managed-1']['agent_unit'], found['managed-1']['logstash_unit']) == (
        'managed-agent@1',
        'managed-logstash@1',
    )
    assert (found['simulate-2']['agent_unit'], found['simulate-2']['logstash_unit']) == (
        'simulate-agent@2',
        'simulate-logstash@2',
    )
    assert found['managed-1']['agent_unit'] == installer.resolve_multi_instance_units(1, 'MANAGED')[0]
    assert found['simulate-2']['agent_unit'] == installer.resolve_multi_instance_units(2, 'SIMULATE')[0]


@pytest.mark.parametrize(
    'unit,expected',
    [
        ('logstash', True),
        ('logstash.service', True),
        ('simulate-logstash@3', True),
        ('managed-logstash@1', True),
        ('managed-logstash@1.service', True),
        ('ls-simulate@3', True),
        ('logstash-managed@1', True),
        ('logstash-agent', False),
        ('logstash-agent.service', False),
        ('simulate-agent@3', False),
        ('managed-agent@1', False),
        ('logstash-agent@1', False),
        ('lsagent-simulate@3', False),
        ('', False),
    ],
)
def test_is_logstash_unit_prefixes(unit, expected):
    """acceptance A8: Logstash units vs agent units, new and old names."""
    assert installer._is_logstash_unit(unit) is expected


def test_resolve_multi_instance_units_honors_explicit():
    # A1: explicit old @N names are rewritten to canonical.
    agent, ls = installer.resolve_multi_instance_units(
        1,
        'MANAGED',
        agent_unit='logstash-agent@9',
        logstash_unit='logstash-managed@9',
    )
    assert agent == 'managed-agent@9'
    assert ls == 'managed-logstash@9'


def test_resolve_rewrites_legacy_at_names_not_packaged():
    """acceptance A1: old @N names rewritten; bare logstash-agent passthrough."""
    # Managed old pair.
    agent, ls = installer.resolve_multi_instance_units(
        2, "MANAGED",
        agent_unit="logstash-agent@2", logstash_unit="logstash-managed@2"
    )
    assert agent == "managed-agent@2", agent
    assert ls == "managed-logstash@2", ls

    # Simulate old pair.
    agent, ls = installer.resolve_multi_instance_units(
        2, "SIMULATE",
        agent_unit="lsagent-simulate@2", logstash_unit="ls-simulate@2"
    )
    assert agent == "simulate-agent@2", agent
    assert ls == "simulate-logstash@2", ls

    # Bare packaged name (no @) must NOT be rewritten.
    agent, ls = installer.resolve_multi_instance_units(
        1, "MANAGED",
        agent_unit="logstash-agent", logstash_unit="logstash"
    )
    assert agent == "logstash-agent", f"bare packaged agent rewritten to {agent}"
    assert ls == "logstash", ls


def test_materialize_managed_tree(tmp_path, monkeypatch):
    root = tmp_path / "managed-1"
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))

    policy = {
        "policy_type": "MANAGED",
        "instance_id": 1,
        "path_root": str(root),
        "settings_path": str(root / "settings"),
        "config_path": str(root / "config"),
        "logs_path": str(root / "logs"),
        "data_path": str(root / "data"),
        "keystore_env_file": str(root / "env"),
        "binary_path": "/usr/share/logstash/bin",
        "logstash_source": "SYSTEM",
        "agent_api_port": 9601,
        "logstash_api_port": 9701,
        "logstash_yml": "api.http.port: 9701\n",
        "jvm_options": "-Xms1g\n",
        "log4j2_properties": "status=error\n",
        "agent_unit": "managed-agent@1",
        "logstash_unit": "managed-logstash@1",
    }

    with patch.object(installer, "get_logstash_uid_gid", return_value=(0, 0)), patch.object(
        installer.os, "chown", create=True
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ):
        result = installer.materialize_simulate_instance(policy)

    assert result["agent_unit"] == "managed-agent@1"
    assert result["logstash_unit"] == "managed-logstash@1"
    assert result["mode"] == "managed"
    assert (root / "settings" / "logstash.yml").is_file()
    assert (root / "env").is_file()
    agent_env = (root / "agent.env").read_text()
    assert "AGENT_MODE=managed" in agent_env
    assert "AGENT_UNIT=managed-agent@1" in agent_env
    # No simulate harness confs for managed
    assert not (root / "settings" / "conf.d" / "simulate-start.conf").exists()
    pipelines = (root / "settings" / "pipelines.yml").read_text()
    assert "agent-placeholder" in pipelines or "Managed by LogstashAgent" in pipelines


def _instance_policy(root: Path, policy_type: str, **extra) -> dict:
    policy = {
        "policy_type": policy_type,
        "instance_id": 1,
        "path_root": str(root),
        "settings_path": str(root / "settings"),
        "config_path": str(root / "config"),
        "logs_path": str(root / "logs"),
        "data_path": str(root / "data"),
        "keystore_env_file": str(root / "env"),
        "binary_path": "/usr/share/logstash/bin",
        "logstash_source": "SYSTEM",
        "agent_api_port": 9601,
        "logstash_api_port": 9701,
        "logstash_yml": "api.http.port: 9701\n",
        "log4j2_properties": "status=error\n",
    }
    policy.update(extra)
    return policy


def _materialize(policy: dict) -> dict:
    with patch.object(installer, "get_logstash_uid_gid", return_value=(0, 0)), patch.object(
        installer.os, "chown", create=True
    ), patch(
        "logstashagent.logstash_download.resolve_binary_from_policy",
        return_value="/usr/share/logstash/bin/logstash",
    ):
        return installer.materialize_simulate_instance(policy)


@pytest.mark.parametrize("policy_type", ["MANAGED", "SIMULATE"])
def test_env_file_exports_ls_jvm_opts(tmp_path, monkeypatch, policy_type):
    """The env file must name jvm.options outright, not rely on the argv scan."""
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    root = tmp_path / "inst"
    policy = _instance_policy(root, policy_type, jvm_options="-Xmx1234m\n")

    _materialize(policy)

    settings = root / "settings"
    assert f"LS_JVM_OPTS={settings}/jvm.options" in (root / "env").read_text()
    assert (settings / "jvm.options").read_text() == "-Xmx1234m\n"


def test_env_file_omits_ls_jvm_opts_when_no_jvm_options(tmp_path, monkeypatch):
    """
    LS_JVM_OPTS naming a missing file makes JvmOptionsParser fail and Logstash
    refuse to start, so a policy with no jvm_options must not get the line.
    """
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    root = tmp_path / "inst"

    _materialize(_instance_policy(root, "MANAGED"))

    assert not (root / "settings" / "jvm.options").exists()
    assert "LS_JVM_OPTS" not in (root / "env").read_text()


def test_materialize_makes_jvm_options_readable(tmp_path, monkeypatch):
    """
    logstash.lib.sh only honours jvm.options when `[ -r ... ]` passes for the
    logstash user; a restrictive umask would otherwise revert Logstash to stock
    JVM settings.
    """
    monkeypatch.setitem(installer.INSTALL_PATHS, "simulate_root", str(tmp_path))
    root = tmp_path / "inst"
    old_umask = os.umask(0o077)
    try:
        _materialize(_instance_policy(root, "MANAGED", jvm_options="-Xmx1234m\n"))
    finally:
        os.umask(old_umask)

    mode = (root / "settings" / "jvm.options").stat().st_mode & 0o777
    assert mode == 0o644, oct(mode)


def test_unit_templates_exist_on_disk():
    d = installer._systemd_template_dir()
    for name in (
        "simulate-agent@.service",
        "simulate-logstash@.service",
        "managed-agent@.service",
        "managed-logstash@.service",
    ):
        p = d / name
        assert p.is_file(), f"missing template {p}"
    managed_agent = (d / "managed-agent@.service").read_text()
    assert "--mode managed" in managed_agent
    assert "managed-%i" in managed_agent
    managed_ls = (d / "managed-logstash@.service").read_text()
    assert "managed-%i" in managed_ls


def test_new_templates_exist_and_alias_old_names():
    """acceptance A3: new templates exist with correct Alias= entries."""
    d = installer._systemd_template_dir()
    aliases = {
        "simulate-agent@.service": "lsagent-simulate@%i",
        "simulate-logstash@.service": "ls-simulate@%i",
        "managed-agent@.service": "logstash-agent@%i",
        "managed-logstash@.service": "logstash-managed@%i",
    }
    for name, expected_alias in aliases.items():
        p = d / name
        assert p.is_file(), f"missing new template {p}"
        text = p.read_text()
        assert "\nUser=logstash" in text, f"{name} missing User=logstash"
        assert "\nGroup=logstash" in text, f"{name} missing Group=logstash"
        assert f"Alias={expected_alias}.service" in text, (
            f"{name} missing Alias={expected_alias}.service"
        )


def test_old_template_filenames_removed():
    """acceptance A4: old template files must not exist (Alias= collision guard)."""
    d = installer._systemd_template_dir()
    for name in (
        "lsagent-simulate@.service",
        "ls-simulate@.service",
        "logstash-agent@.service",
        "logstash-managed@.service",
    ):
        assert not (d / name).exists(), f"old template still present: {name}"


def test_spec_bundles_new_units():
    """acceptance A3/A5: logstash-agent.spec bundles new names, not old."""
    spec_path = installer._systemd_template_dir().parents[2] / "logstash-agent.spec"
    if not spec_path.is_file():
        import pytest
        pytest.skip("spec file not available in test environment")
    text = spec_path.read_text()
    for new_name in ("simulate-agent@.service", "simulate-logstash@.service",
                     "managed-agent@.service", "managed-logstash@.service"):
        assert new_name in text, f"spec does not bundle {new_name}"
    for old_name in ("lsagent-simulate@.service", "ls-simulate@.service",
                     "logstash-agent@.service", "logstash-managed@.service"):
        assert old_name not in text, f"spec still bundles old name {old_name}"


def test_install_multi_instance_templates(tmp_path, monkeypatch):
    dests = {
        "lsagent_simulate_unit": str(tmp_path / "simulate-agent@.service"),
        "ls_simulate_unit": str(tmp_path / "simulate-logstash@.service"),
        "logstash_agent_template_unit": str(tmp_path / "managed-agent@.service"),
        "logstash_managed_unit": str(tmp_path / "managed-logstash@.service"),
    }
    for k, v in dests.items():
        monkeypatch.setitem(installer.INSTALL_PATHS, k, v)

    with patch.object(installer.subprocess, "run", return_value=type("R", (), {"returncode": 0})()):
        installer.install_multi_instance_unit_templates()

    for path in dests.values():
        assert Path(path).is_file()
    assert "--mode managed" in Path(dests["logstash_agent_template_unit"]).read_text()


def test_no_template_uses_equals_form_path_settings():
    """
    Regression guard for the whole class of bug.

    logstash.lib.sh discovers jvm.options by scanning "$@" for an argv entry
    *equal to* "--path.settings" and reading the next one. With
    `--path.settings=<dir>` it never matches, LS_JVM_OPTS is never exported, and
    Logstash silently uses the stock jvm.options from LOGSTASH_HOME — so
    policy-pushed heap settings never reach the JVM and nothing is logged.
    """
    d = installer._systemd_template_dir()
    for path in sorted(d.glob("*.service")):
        # Comments are inert; only directives matter.
        directives = [
            ln for ln in path.read_text().splitlines()
            if not ln.lstrip().startswith("#")
        ]
        assert "--path.settings=" not in "\n".join(directives), (
            f"{path.name} uses the equals form; jvm.options will be ignored"
        )


def test_logstash_templates_pass_path_settings_as_two_args():
    d = installer._systemd_template_dir()
    for name in ("simulate-logstash@.service", "managed-logstash@.service"):
        text = (d / name).read_text()
        assert '--path.settings "${LOGSTASH_PATH_SETTINGS}"' in text, name


def test_installed_templates_always_run_as_logstash(tmp_path, monkeypatch):
    """
    Every unit must declare User=logstash as shipped. These used to be written
    with `# User=logstash` commented out and uncommented only when the account
    happened to resolve, so a host without the Logstash DEB/RPM silently ran
    Logstash as root.
    """
    dests = {
        "lsagent_simulate_unit": str(tmp_path / "simulate-agent@.service"),
        "ls_simulate_unit": str(tmp_path / "simulate-logstash@.service"),
        "logstash_agent_template_unit": str(tmp_path / "managed-agent@.service"),
        "logstash_managed_unit": str(tmp_path / "managed-logstash@.service"),
    }
    for k, v in dests.items():
        monkeypatch.setitem(installer.INSTALL_PATHS, k, v)

    # No logstash account on this host — must make no difference.
    fake_pwd = MagicMock()
    fake_pwd.getpwnam.side_effect = KeyError("logstash")
    fake_grp = MagicMock()
    fake_grp.getgrnam.side_effect = KeyError("logstash")
    monkeypatch.setattr(installer, "pwd", fake_pwd)
    monkeypatch.setattr(installer, "grp", fake_grp)

    with patch.object(installer.subprocess, "run", return_value=type("R", (), {"returncode": 0})()):
        installer.install_multi_instance_unit_templates()

    for name, path in dests.items():
        text = Path(path).read_text()
        assert "\nUser=logstash" in text, f"{name} missing User=logstash"
        assert "\nGroup=logstash" in text, f"{name} missing Group=logstash"
        assert "# User=logstash" not in text, f"{name} still has User= commented out"


def test_resolve_multi_instance_units_packaged_passthrough():
    """acceptance S1 gap: bare packaged logstash-agent is NEVER rewritten to managed-agent."""
    # Explicit agent_unit passes through regardless of policy_type.
    agent, ls = installer.resolve_multi_instance_units(
        1, "MANAGED", agent_unit="logstash-agent", logstash_unit="logstash"
    )
    assert agent == "logstash-agent", f"expected logstash-agent, got {agent}"
    assert ls == "logstash"


def test_migrate_template_file_notice_mapping(tmp_path, monkeypatch, capsys):
    """acceptance A1: template-file path produces exact per-mapping notices."""
    sysdir = tmp_path / "systemd"
    sysdir.mkdir()

    # Plant exactly two old templates; no systemctl hits (stub returns nothing).
    (sysdir / "ls-simulate@.service").write_text("[Unit]\n")
    (sysdir / "logstash-agent@.service").write_text("[Unit]\n")

    def fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = ""  # no enabled instances
        return r

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    monkeypatch.setattr(installer, "_systemctl_bin", lambda: "/usr/bin/systemctl")

    installer.migrate_legacy_systemd_units(systemd_dir=str(sysdir))

    out = capsys.readouterr().out
    # Parse notices into {old_stem: canonical_stem} pairs from the template-file lines.
    # Expected format: "renamed: {stem} → {canonical_stem}  (old template found at {path})"
    mapping: dict[str, str] = {}
    for line in out.splitlines():
        if "old template found" in line and line.startswith("renamed:"):
            # "renamed: ls-simulate@ → simulate-logstash@  (old template found at ...)"
            parts = line.split("→")
            if len(parts) >= 2:
                old = parts[0].replace("renamed:", "").strip()
                new = parts[1].split("(")[0].strip()
                mapping[old] = new

    assert "ls-simulate@" in mapping, f"ls-simulate@ not in template-file notices: {out!r}"
    assert mapping["ls-simulate@"] == "simulate-logstash@", (
        f"ls-simulate@ mapped to {mapping.get('ls-simulate@')!r}, expected simulate-logstash@"
    )
    assert "logstash-agent@" in mapping, f"logstash-agent@ not in template-file notices: {out!r}"
    assert mapping["logstash-agent@"] == "managed-agent@", (
        f"logstash-agent@ mapped to {mapping.get('logstash-agent@')!r}, expected managed-agent@"
    )
    # Full line format check (not just substrings)
    assert any("renamed: ls-simulate@ →" in ln and "simulate-logstash@" in ln
               and "old template found" in ln for ln in out.splitlines())
    assert any("renamed: logstash-agent@ →" in ln and "managed-agent@" in ln
               and "old template found" in ln for ln in out.splitlines())


def test_migrate_enabled_instance_notice_mapping(tmp_path, monkeypatch, capsys):
    """acceptance A2: enabled-instance path produces exact per-mapping notices."""
    sysdir = tmp_path / "systemd"
    sysdir.mkdir()
    # No planted old template files — only systemctl hits.

    def fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        unit_filter = next((a for a in cmd if "@" in a), "")
        if "lsagent-simulate@" in unit_filter:
            r.stdout = "lsagent-simulate@3.service loaded active running ...\n"
        elif "logstash-managed@" in unit_filter:
            r.stdout = "logstash-managed@1.service loaded active running ...\n"
        else:
            r.stdout = ""
        return r

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    monkeypatch.setattr(installer, "_systemctl_bin", lambda: "/usr/bin/systemctl")

    installer.migrate_legacy_systemd_units(systemd_dir=str(sysdir))

    out = capsys.readouterr().out
    # Parse instance notices: "renamed: {unit} → {canonical}"
    mapping: dict[str, str] = {}
    for line in out.splitlines():
        if "old template found" in line:
            continue  # template-file path; not tested here
        if line.startswith("renamed:") and "→" in line:
            parts = line.split("→")
            if len(parts) >= 2:
                old = parts[0].replace("renamed:", "").strip()
                new = parts[1].strip()
                mapping[old] = new

    assert "lsagent-simulate@3" in mapping, (
        f"lsagent-simulate@3 not in instance notices: {out!r}"
    )
    assert mapping["lsagent-simulate@3"] == "simulate-agent@3", (
        f"lsagent-simulate@3 mapped to {mapping.get('lsagent-simulate@3')!r}"
    )
    assert "logstash-managed@1" in mapping, (
        f"logstash-managed@1 not in instance notices: {out!r}"
    )
    assert mapping["logstash-managed@1"] == "managed-logstash@1", (
        f"logstash-managed@1 mapped to {mapping.get('logstash-managed@1')!r}"
    )
    # Full line format check
    assert any(ln == "renamed: lsagent-simulate@3 → simulate-agent@3" for ln in out.splitlines())
    assert any(ln == "renamed: logstash-managed@1 → managed-logstash@1" for ln in out.splitlines())


def test_migrate_legacy_systemd_units_prints_rename(tmp_path, monkeypatch, capsys):
    """acceptance A7 parent contract: both detection paths covered together."""
    sysdir = tmp_path / "systemd"
    sysdir.mkdir()

    # Plant an old template file to simulate a not-yet-upgraded host.
    (sysdir / "ls-simulate@.service").write_text("[Unit]\n")
    (sysdir / "logstash-agent@.service").write_text("[Unit]\n")

    # Mock systemctl so list-units returns an enabled old instance.
    def fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        unit_filter = next((a for a in cmd if "@" in a), "")
        if "lsagent-simulate@" in unit_filter:
            r.stdout = "lsagent-simulate@3.service loaded active running ...\n"
        elif "logstash-managed@" in unit_filter:
            r.stdout = "logstash-managed@1.service loaded active running ...\n"
        else:
            r.stdout = ""
        return r

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    monkeypatch.setattr(installer, "_systemctl_bin", lambda: "/usr/bin/systemctl")

    installer.migrate_legacy_systemd_units(systemd_dir=str(sysdir))

    out = capsys.readouterr().out
    # Template-file path: full line with correct mapping
    assert any("renamed: ls-simulate@ →" in ln and "simulate-logstash@" in ln
               and "old template found" in ln for ln in out.splitlines())
    assert any("renamed: logstash-agent@ →" in ln and "managed-agent@" in ln
               and "old template found" in ln for ln in out.splitlines())
    # Enabled-instance path: full canonical line
    assert any(ln == "renamed: lsagent-simulate@3 → simulate-agent@3" for ln in out.splitlines())
    assert any(ln == "renamed: logstash-managed@1 → managed-logstash@1" for ln in out.splitlines())


def test_enable_multi_instance_services_enables_canonical_not_alias():
    """acceptance A2: enable_multi_instance_services uses canonical units, not Alias names."""
    from unittest.mock import MagicMock

    calls = []

    def fake_systemctl_cmd(*args, check=False):
        calls.append(list(args))
        r = MagicMock()
        r.returncode = 0
        r.stdout = "enabled\n"
        r.stderr = ""
        return r

    with patch.object(installer, "_systemctl_cmd", side_effect=fake_systemctl_cmd):
        installer.enable_multi_instance_services(
            2,
            agent_unit="logstash-agent@2",
            logstash_unit="logstash-managed@2",
            policy_type="MANAGED",
        )

    enabled = [args for args in calls if args and args[0] == "enable"]
    enabled_units = [args[-1] for args in enabled]

    # Canonical units must appear in enable calls.
    assert any(u == "managed-logstash@2" or u == "managed-logstash@2.service"
               for u in enabled_units), f"managed-logstash@2 not enabled; enable calls: {enabled}"
    assert any(u in ("managed-agent@2", "managed-agent@2.service")
               for u in enabled_units), f"managed-agent@2 not enabled; enable calls: {enabled}"

    # Old Alias names must NOT appear in enable calls.
    for old in ("logstash-agent@2", "logstash-agent@2.service",
                "logstash-managed@2", "logstash-managed@2.service"):
        assert old not in enabled_units, f"old alias {old!r} appeared in enable calls: {enabled}"


def test_controller_unenrolled_hint_canonical():
    """acceptance A3d: controller unenrolled restart hint uses canonical simulate unit."""
    src = open('/Users/buh/WORK/LogstashAgent/src/logstashagent/controller.py').read()
    # The canonical simulate unit string must appear in the source.
    assert 'simulate-agent@' in src, "simulate-agent@ not found in controller.py"
    # Old lsagent-simulate@ must NOT appear in the hint f-string.
    assert 'lsagent-simulate@' not in src, (
        "old lsagent-simulate@ still present in controller.py"
    )
    # Bare logstash-agent (no @) must still appear for packaged mode fallback.
    assert '"logstash-agent"' in src or "'logstash-agent'" in src, (
        "bare logstash-agent fallback not found in controller.py"
    )


# ---------------------------------------------------------------------------
# systemd-migrate-upgrade-p1s r11 — S2 host-side migrate mechanics
# ---------------------------------------------------------------------------

_OLD_TEMPLATES = (
    "lsagent-simulate@.service",
    "ls-simulate@.service",
    "logstash-agent@.service",
    "logstash-managed@.service",
)
_NEW_TEMPLATES = (
    "simulate-agent@.service",
    "simulate-logstash@.service",
    "managed-agent@.service",
    "managed-logstash@.service",
)


def _legacy_registry(state_dir, instance_id=2):
    """Write a registry whose stored managed-<N> names are still the old style."""
    import json

    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "install-registry.json").write_text(json.dumps({
        "package": {},
        "instances": {
            f"managed-{instance_id}": {
                "id": f"managed-{instance_id}",
                "role": "managed",
                "instance_id": instance_id,
                "agent_unit": f"logstash-agent@{instance_id}",
                "logstash_unit": f"logstash-managed@{instance_id}",
            },
        },
    }))


def _matrix_systemctl(monkeypatch, recorder, *, legacy_exist=True,
                      enabled=(), active=()):
    """Fake _systemctl_cmd driven by per-unit state sets.

    *enabled* / *active* hold the LEGACY unit names that report enabled/active.
    When *legacy_exist* is False, `systemctl cat` fails for every legacy name
    (simulating a host that never had those units).
    """
    def fake_systemctl_cmd(*args, check=False):
        recorder.append(list(args))
        r = MagicMock()
        r.returncode = 0
        r.stdout = ""
        r.stderr = ""
        action = args[0] if args else ""
        unit = args[1] if len(args) > 1 else ""
        if action == "cat":
            r.returncode = 0 if legacy_exist else 1
        elif action == "is-enabled":
            r.returncode = 0 if unit in enabled else 1
        elif action == "is-active":
            r.returncode = 0 if unit in active else 1
        return r

    monkeypatch.setattr(installer, "_systemctl_cmd", fake_systemctl_cmd)


def _run_migrate(tmp_path, monkeypatch, recorder, *, registry=True,
                 plant_old=True, legacy_exist=True, enabled=(), active=()):
    """Run migrate against a tmp systemd dir + tmp registry; return (sysdir, state_dir)."""
    sysdir = tmp_path / "systemd"
    sysdir.mkdir(exist_ok=True)
    if plant_old:
        for name in _OLD_TEMPLATES:
            (sysdir / name).write_text("[Unit]\n")
    state_dir = tmp_path / "state"
    if registry:
        _legacy_registry(state_dir)
    _matrix_systemctl(
        monkeypatch, recorder,
        legacy_exist=legacy_exist, enabled=enabled, active=active,
    )
    # list-units sweep (direct subprocess.run) returns nothing.
    monkeypatch.setattr(
        installer.subprocess, "run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": ""})(),
    )
    # ctl must never be used for legacy probes.
    monkeypatch.setattr(
        installer, "systemctl_via_sudo",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("ctl used for legacy probe")),
    )
    installer.migrate_legacy_systemd_units(
        systemd_dir=str(sysdir), state_dir=str(state_dir),
    )
    return sysdir, state_dir


def test_a1_migrate_removes_old_host_templates(tmp_path, monkeypatch):
    """acceptance A1: after migrate the four old host files are gone, not just printed."""
    recorder = []
    sysdir, _ = _run_migrate(tmp_path, monkeypatch, recorder)

    for name in _OLD_TEMPLATES:
        assert not (sysdir / name).exists(), f"old template survived migrate: {name}"
    # Canonical files are written, not deleted.
    for name in _NEW_TEMPLATES:
        p = sysdir / name
        assert p.is_file(), f"canonical template missing after migrate: {name}"
        assert p.read_text().strip(), f"canonical template empty: {name}"


def test_a1_retry_failed_migrate_retries_unlink(tmp_path, monkeypatch):
    """acceptance A1-retry: a later run still attempts the unlink while old files exist."""
    recorder = []
    sysdir = tmp_path / "systemd"
    sysdir.mkdir()
    for name in _OLD_TEMPLATES:
        (sysdir / name).write_text("[Unit]\n")
    state_dir = tmp_path / "state"
    _legacy_registry(state_dir)

    real_unlink = os.unlink
    calls = {"n": 0}

    def flaky_unlink(path):
        if str(path).endswith("logstash-agent@.service") and calls["n"] == 0:
            calls["n"] += 1
            raise PermissionError("simulated unlink failure")
        return real_unlink(path)

    monkeypatch.setattr(os, "unlink", flaky_unlink)
    _matrix_systemctl(monkeypatch, recorder, legacy_exist=False)
    monkeypatch.setattr(
        installer.subprocess, "run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": ""})(),
    )

    installer.migrate_legacy_systemd_units(systemd_dir=str(sysdir), state_dir=str(state_dir))
    assert (sysdir / "logstash-agent@.service").is_file(), "failed unlink did not leave the file for retry"

    # Second run: the retry must unlink it.
    installer.migrate_legacy_systemd_units(systemd_dir=str(sysdir), state_dir=str(state_dir))
    assert not (sysdir / "logstash-agent@.service").exists(), "retry did not unlink the old template"


def _probe_calls(recorder):
    return [c for c in recorder if c and c[0] in ("cat", "is-enabled", "is-active")]


def _apply_calls(recorder):
    return [c for c in recorder if c and c[0] in ("enable", "start")]


def test_a3a_legacy_enabled_active_copies_both(tmp_path, monkeypatch):
    """acceptance A3a: legacy enabled+active -> canonical enabled AND started."""
    recorder = []
    _run_migrate(
        tmp_path, monkeypatch, recorder,
        enabled=("logstash-agent@2", "logstash-managed@2"),
        active=("logstash-agent@2", "logstash-managed@2"),
    )
    applied = [tuple(c) for c in _apply_calls(recorder)]
    assert ("enable", "managed-agent@2") in applied, applied
    assert ("start", "managed-agent@2") in applied, applied
    assert ("enable", "managed-logstash@2") in applied, applied
    assert ("start", "managed-logstash@2") in applied, applied


def test_a3b_legacy_enabled_inactive_enables_without_starting(tmp_path, monkeypatch):
    """acceptance A3b: legacy enabled+inactive -> enabled, never started."""
    recorder = []
    _run_migrate(
        tmp_path, monkeypatch, recorder,
        enabled=("logstash-agent@2", "logstash-managed@2"),
        active=(),
    )
    applied = [tuple(c) for c in _apply_calls(recorder)]
    assert ("enable", "managed-agent@2") in applied, applied
    assert ("enable", "managed-logstash@2") in applied, applied
    starts = [c for c in applied if c[0] == "start"]
    assert not starts, f"an operator-stopped unit must not be started: {applied}"


def test_a3c_legacy_disabled_active_starts_without_enabling(tmp_path, monkeypatch):
    """acceptance A3c: legacy disabled+active -> started, never enabled."""
    recorder = []
    _run_migrate(
        tmp_path, monkeypatch, recorder,
        enabled=(),
        active=("logstash-agent@2", "logstash-managed@2"),
    )
    applied = [tuple(c) for c in _apply_calls(recorder)]
    assert ("start", "managed-agent@2") in applied, applied
    assert ("start", "managed-logstash@2") in applied, applied
    enables = [c for c in applied if c[0] == "enable"]
    assert not enables, f"an operator-disabled unit must not be enabled: {applied}"


def test_a3d_legacy_disabled_inactive_is_noop(tmp_path, monkeypatch):
    """acceptance A3d: legacy disabled+inactive -> neither enabled nor started."""
    recorder = []
    _run_migrate(
        tmp_path, monkeypatch, recorder,
        enabled=(), active=(),
    )
    applied = _apply_calls(recorder)
    assert not applied, f"disabled+inactive legacy unit must be left alone: {applied}"


def test_a3e_legacy_missing_is_noop(tmp_path, monkeypatch):
    """acceptance A3e: legacy unit missing on the host -> nothing enabled/started.

    The enabled/active readings are deliberately truthy here: a missing unit
    still reads as disabled+inactive through the returncode-only wrappers, which
    is exactly why existence needs its own probe. The existence gate must win —
    a missing legacy unit must never enable or start its canonical replacement,
    and with no old template files on disk the privileged work must not run.
    """
    recorder = []
    _run_migrate(
        tmp_path, monkeypatch, recorder,
        registry=True, plant_old=False,
        legacy_exist=False,
        enabled=("logstash-agent@2", "logstash-managed@2"),
        active=("logstash-agent@2", "logstash-managed@2"),
    )
    applied = _apply_calls(recorder)
    assert not applied, f"missing legacy unit produced enable/start calls: {applied}"
    reloads = [c for c in recorder if c and c[0] == "daemon-reload"]
    assert not reloads, (
        f"no legacy artifact exists, yet privileged work ran: {recorder}"
    )


def test_a3_probes_legacy_names_via_direct_systemctl(tmp_path, monkeypatch):
    """acceptance A3: the probe uses LEGACY names and direct systemctl, never ctl/registry."""
    recorder = []
    _run_migrate(
        tmp_path, monkeypatch, recorder,
        enabled=("logstash-agent@2",), active=(),
    )
    probes = _probe_calls(recorder)
    probe_units = {c[1] for c in probes if len(c) > 1}
    assert probe_units, f"no probe calls recorded: {recorder}"
    assert probe_units <= {"logstash-agent@2", "logstash-managed@2"}, (
        f"probe used non-legacy units: {probe_units}"
    )
    # Never --now: an unconditional enable --now is the defect this slice removes.
    for call in recorder:
        assert call[:2] != ["enable", "--now"], f"enable --now issued: {call}"


def test_a3_probe_runs_before_unlink_and_daemon_reload(tmp_path, monkeypatch):
    """acceptance A3/A7a: probe happens BEFORE the unlink and BEFORE the first reload."""
    import os as _os

    recorder = []
    sysdir = tmp_path / "systemd"
    sysdir.mkdir()
    for name in _OLD_TEMPLATES:
        (sysdir / name).write_text("[Unit]\n")
    old_path = sysdir / "logstash-agent@.service"
    state_dir = tmp_path / "state"
    _legacy_registry(state_dir)

    unlink_observed = []

    def fake_systemctl_cmd(*args, check=False):
        recorder.append(list(args))
        r = MagicMock()
        r.returncode = 0
        r.stdout = ""
        r.stderr = ""
        action = args[0] if args else ""
        if action in ("cat", "is-enabled", "is-active"):
            unlink_observed.append(_os.path.isfile(old_path))
        if action == "is-enabled":
            r.returncode = 0 if args[1] == "logstash-agent@2" else 1
        if action == "is-active":
            r.returncode = 1
        return r

    monkeypatch.setattr(installer, "_systemctl_cmd", fake_systemctl_cmd)
    monkeypatch.setattr(
        installer.subprocess, "run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": ""})(),
    )
    installer.migrate_legacy_systemd_units(systemd_dir=str(sysdir), state_dir=str(state_dir))

    assert unlink_observed, "no probe calls recorded"
    assert all(unlink_observed), "legacy probe ran AFTER the unlink"


def _reload_snapshots_for(tmp_path, monkeypatch):
    """Run migrate against a planted legacy host; return reload snapshots.

    Each snapshot is (old_present, new_present) captured at daemon-reload time.
    """
    sysdir = tmp_path / "systemd"
    sysdir.mkdir()
    for name in _OLD_TEMPLATES:
        (sysdir / name).write_text("[Unit]\n")
    state_dir = tmp_path / "state"
    _legacy_registry(state_dir)

    reload_snapshots = []

    def fake_systemctl_cmd(*args, check=False):
        r = MagicMock()
        r.returncode = 1
        r.stdout = ""
        r.stderr = ""
        if args and args[0] == "daemon-reload":
            assert len(args) == 1, f"daemon-reload must take no unit: {args}"
            reload_snapshots.append((
                any((sysdir / n).exists() for n in _OLD_TEMPLATES),
                any((sysdir / n).exists() for n in _NEW_TEMPLATES),
            ))
            r.returncode = 0
        return r

    monkeypatch.setattr(installer, "_systemctl_cmd", fake_systemctl_cmd)
    monkeypatch.setattr(
        installer.subprocess, "run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": ""})(),
    )
    installer.migrate_legacy_systemd_units(systemd_dir=str(sysdir), state_dir=str(state_dir))
    return reload_snapshots


def test_a7a_daemon_reload_after_unlink_before_install(tmp_path, monkeypatch):
    """acceptance A7a: reload happens after the unlink and before the new templates."""
    reload_snapshots = _reload_snapshots_for(tmp_path, monkeypatch)
    assert len(reload_snapshots) >= 2, f"expected A7a and A7b reloads: {reload_snapshots}"
    a7a_old_present, a7a_new_present = reload_snapshots[0]
    assert not a7a_old_present, "A7a reload ran before the old templates were unlinked"
    assert not a7a_new_present, "A7a reload ran after the new templates were installed"


def test_a7b_daemon_reload_after_template_install(tmp_path, monkeypatch):
    """acceptance A7b: after the new templates land, a second unit-less reload runs."""
    reload_snapshots = _reload_snapshots_for(tmp_path, monkeypatch)
    assert len(reload_snapshots) >= 2, f"expected A7a and A7b reloads: {reload_snapshots}"
    a7b_old_present, a7b_new_present = reload_snapshots[1]
    assert a7b_new_present, "A7b reload ran before the new templates were installed"
    assert not a7b_old_present, "old templates returned before A7b"


def test_recursion_edge1_migrate_list_instances_migrate(tmp_path, monkeypatch):
    """acceptance A4/recursion edge 1: migrate -> list_instances -> migrate cannot recurse."""
    recorder = []
    # The dirty-registry path makes list_instances call migrate from inside the
    # outer migrate's own list_instances call. Unguarded this is a RecursionError.
    _run_migrate(tmp_path, monkeypatch, recorder, enabled=("logstash-agent@2",))

    # Direct proof of the guard: a call while a migration is active is a no-op.
    installer._MIGRATE_REENTRY.active = True
    try:
        before = len(recorder)
        installer.migrate_legacy_systemd_units(
            systemd_dir=str(tmp_path / "systemd"), state_dir=str(tmp_path / "state"),
        )
        assert len(recorder) == before, "re-entrant migrate was not suppressed"
    finally:
        installer._MIGRATE_REENTRY.active = False
