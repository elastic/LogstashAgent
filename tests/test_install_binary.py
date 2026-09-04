#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

from logstashagent.main import parse_arguments, AGENT_VERSION, _is_lightweight_cli


def test_top_level_version_is_lightweight():
    assert _is_lightweight_cli(["--version"]) is True


def test_parse_arguments_version(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["logstash-agent", "--version"])
    try:
        parse_arguments()
    except SystemExit as e:
        assert e.code == 0
    else:
        raise AssertionError("expected SystemExit")
    assert AGENT_VERSION in capsys.readouterr().out


def test_upgrade_version_still_parses(monkeypatch):
    monkeypatch.setattr("sys.argv", ["logstash-agent", "upgrade", "--version", "0.1.4"])
    args = parse_arguments()
    assert args.command == "upgrade"
    assert args.version == "0.1.4"
