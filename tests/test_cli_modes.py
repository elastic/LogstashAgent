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
