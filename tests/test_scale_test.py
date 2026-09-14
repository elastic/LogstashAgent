#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Error aggregation helpers used by scripts/scale_test.py."""

import sys
from pathlib import Path

import httpx

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import scale_test  # noqa: E402


def _response(status: int, text: str, *, json_body=None) -> httpx.Response:
    if json_body is not None:
        return httpx.Response(status, json=json_body)
    return httpx.Response(status, text=text)


def test_http_error_text_uses_json_error_field():
    response = _response(500, "", json_body={"success": False, "error": "token expired"})
    assert scale_test.http_error_text(response, response.json()) == "token expired"


def test_http_error_text_extracts_django_debug_page():
    html = """
    <html><head>
      <title>OperationalError
          at /ConnectionManager/Enroll/</title>
    </head><body>
      <tr><th>Exception Value:</th>
          <td><pre>database is locked</pre></td></tr>
    </body></html>
    """
    message = scale_test.http_error_text(_response(500, html))
    assert "OperationalError at /ConnectionManager/Enroll/" in message
    assert "database is locked" in message


def test_error_sample_keeps_traceback_tail():
    trace = ("frame\n" * 400) + "httpx.ConnectError: [Errno 111] Connection refused"
    sample = scale_test.error_sample(trace)
    assert sample.startswith("…")
    assert sample.endswith("httpx.ConnectError: [Errno 111] Connection refused")


def test_metric_bucket_aggregates_and_prints_error_messages(capsys):
    bucket = scale_test.MetricBucket("enrollment")
    now = 1.0
    for _ in range(3):
        bucket.record(
            scale_test.RequestResult(
                ok=False,
                latency=0.1,
                status_code=500,
                error="OperationalError at /ConnectionManager/Enroll/: database is locked",
                sent_bytes=0,
                received_bytes=0,
                completed_at=now,
            )
        )
    bucket.record(
        scale_test.RequestResult(
            ok=False,
            latency=0.2,
            status_code=None,
            error="ConnectError: [Errno 111] Connection refused\n  File \"scale_test.py\", line 1",
            sent_bytes=0,
            received_bytes=0,
            completed_at=now,
        )
    )
    summary = bucket.summary()
    assert summary["error_messages"] == {
        "OperationalError at /ConnectionManager/Enroll/: database is locked": 3,
        'ConnectError: [Errno 111] Connection refused\n  File "scale_test.py", line 1': 1,
    }
    scale_test.print_aggregated_errors(summary["error_messages"])
    out = capsys.readouterr().out
    assert "[3x] OperationalError at /ConnectionManager/Enroll/: database is locked" in out
    assert "[1x] ConnectError: [Errno 111] Connection refused" in out
    assert 'File "scale_test.py", line 1' in out
