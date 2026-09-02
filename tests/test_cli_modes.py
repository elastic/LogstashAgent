#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""CLI --mode aliases, help text, and lightweight import path."""

import subprocess
import sys
from pathlib import Path

import pytest

from logstashagent import main


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestCliModeType:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("packaged", "packaged"),
            ("managed", "managed"),
            ("simulate", "simulate"),
            ("embedded", "embedded"),
            ("default", "packaged"),
            ("agent", "packaged"),
            ("host", "managed"),
            ("PACKAGED", "packaged"),
            ("Default", "packaged"),
        ],
    )
    def test_maps_aliases_and_canonical(self, raw, expected):
        assert main.cli_mode_type(raw) == expected

    def test_rejects_unknown(self):
        import argparse

        with pytest.raises(argparse.ArgumentTypeError):
            main.cli_mode_type("banana")


class TestParseModeArgument:
    def _parse(self, monkeypatch, *argv):
        monkeypatch.setattr(sys, "argv", ["logstash-agent", *argv])
        return main.parse_arguments()

    def test_accepts_managed(self, monkeypatch):
        args = self._parse(monkeypatch, "--run", "--mode", "managed", "--instance", "2")
        assert args.mode == "managed"
        assert args.instance == 2

    def test_accepts_packaged(self, monkeypatch):
        args = self._parse(monkeypatch, "--mode", "packaged")
        assert args.mode == "packaged"

    def test_default_alias_stored_as_packaged(self, monkeypatch):
        args = self._parse(monkeypatch, "--mode", "default")
        assert args.mode == "packaged"

    def test_host_alias_stored_as_managed(self, monkeypatch):
        args = self._parse(monkeypatch, "--mode", "host")
        assert args.mode == "managed"

    def test_rejects_unknown(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["logstash-agent", "--mode", "banana"])
        with pytest.raises(SystemExit):
            main.parse_arguments()


class TestLightweightCli:
    def test_help_flag(self):
        assert main._is_lightweight_cli(["--help"]) is True
        assert main._is_lightweight_cli(["-h"]) is True

    def test_admin_commands(self):
        assert main._is_lightweight_cli(["install", "--enroll", "x", "--logstash-ui-url", "http://x"]) is True
        assert main._is_lightweight_cli(["list-instances"]) is True
        assert main._is_lightweight_cli(["uninstall", "--purge"]) is True

    def test_run_is_not_lightweight(self):
        assert main._is_lightweight_cli(["--run", "--mode", "managed", "--instance", "1"]) is False

    def test_enroll_is_lightweight(self):
        assert main._is_lightweight_cli(["--enroll", "TOKEN", "--logstash-ui-url", "http://x"]) is True
        assert main._is_lightweight_cli(["--enroll=TOKEN"]) is True

    def test_bare_invocation_is_not_lightweight(self):
        # python -m logstashagent.main  (starts FastAPI) must still init
        assert main._is_lightweight_cli([]) is False


class TestRestartLogstashForSim:
    def test_canonical_modes_use_controller(self, monkeypatch):
        from logstashagent import controller

        calls = []
        monkeypatch.setattr(controller, "restart_logstash", lambda: calls.append("ctrl") or True)

        for mode in ("packaged", "managed", "simulate", "default", "host"):
            calls.clear()
            monkeypatch.setattr(main.agent_state, "get_state", lambda m=mode: {"mode": m})
            monkeypatch.setattr(main, "AGENT_CONFIG", {})
            assert main._restart_logstash_for_sim() is True
            assert calls == ["ctrl"], mode


class TestHelpSubprocess:
    def test_help_exits_zero_lists_first_class_modes(self):
        result = subprocess.run(
            [sys.executable, "-m", "logstashagent.main", "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        )
        assert result.returncode == 0, result.stderr
        out = result.stdout
        for token in ("packaged", "managed", "simulate", "embedded"):
            assert token in out
        assert "default|agent" in out or "aliases" in out.lower()

    def test_help_does_not_probe_config_or_etc_logstash(self):
        result = subprocess.run(
            [sys.executable, "-m", "logstashagent.main", "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        )
        combined = result.stdout + result.stderr
        assert "Config file" not in combined
        assert "/etc/logstash" not in combined
        assert "using embedded mode defaults" not in combined
