# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

# PyInstaller defines SPECPATH as the directory containing this .spec
try:
    _root = Path(SPECPATH)
except NameError:
    _root = Path(".").resolve()

_systemd = _root / "src" / "logstashagent" / "systemd"
_unit_datas = []
for _name in (
    "lsagent-simulate@.service",
    "ls-simulate@.service",
    "logstash-agent@.service",
    "logstash-managed@.service",
):
    _p = _systemd / _name
    if _p.is_file():
        # Land next to installer.py: _internal/logstashagent/systemd/
        _unit_datas.append((str(_p), "logstashagent/systemd"))
if len(_unit_datas) < 4:
    raise SystemExit(
        f"logstash-agent.spec: expected 4 systemd unit templates under {_systemd}, "
        f"found {len(_unit_datas)}"
    )

# Simulate harness confs (seeded into each simulate-N settings tree)
_sim_conf = _root / "src" / "logstashagent" / "config" / "simulate"
_sim_datas = []
for _name in ("simulate_start.conf", "simulate_end.conf"):
    _p = _sim_conf / _name
    if _p.is_file():
        _sim_datas.append((str(_p), "logstashagent/config/simulate"))
if len(_sim_datas) < 2:
    raise SystemExit(
        f"logstash-agent.spec: expected simulate_start/end.conf under {_sim_conf}, "
        f"found {len(_sim_datas)}"
    )
_bundle_datas = _unit_datas + _sim_datas


a = Analysis(
    ['src/logstashagent/main.py'],
    pathex=[],
    binaries=[],
    datas=_bundle_datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='logstash-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='logstash-agent',
)
