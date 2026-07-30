# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

# PyInstaller defines SPECPATH as the directory containing this .spec
try:
    _root = Path(SPECPATH)
except NameError:
    _root = Path(".").resolve()

_systemd = _root / "src" / "logstashagent" / "systemd"
_unit_datas = []
for _name in ("lsagent-simulate@.service", "ls-simulate@.service"):
    _p = _systemd / _name
    if _p.is_file():
        # Land next to installer.py: _internal/logstashagent/systemd/
        _unit_datas.append((str(_p), "logstashagent/systemd"))
if not _unit_datas:
    raise SystemExit(
        f"logstash-agent.spec: missing systemd unit templates under {_systemd}"
    )


a = Analysis(
    ['src/logstashagent/main.py'],
    pathex=[],
    binaries=[],
    datas=_unit_datas,
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
