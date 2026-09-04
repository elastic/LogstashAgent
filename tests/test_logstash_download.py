#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import io
import tarfile
import threading
import time
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from logstashagent import logstash_download as ld

_UI_BASE = "https://logstashui.example:8443"
_UI_KEY = "test-api-key-abc"
_UI_CID = 7


def _ui_state(**extra) -> dict:
    """State with everything the via-UI artifact path needs."""
    state = {
        "logstash_ui_url": _UI_BASE,
        "api_key": _UI_KEY,
        "connection_id": _UI_CID,
    }
    state.update(extra)
    return state


def _artifact_ui_url(version: str, arch: str = "linux-x86_64") -> str:
    name = ld.artifact_filename(version, arch)
    return f"{_UI_BASE}/ConnectionManager/LogstashArtifact/{_UI_CID}/{name}"


def _http_error(url: str, status: int, headers=None) -> urllib.error.HTTPError:
    """HTTPError with a readable body, as the real proxy sends."""
    body = io.BytesIO(b'{"status":"fetching","percent":41}')
    return urllib.error.HTTPError(url, status, "err", hdrs=headers, fp=body)


class _Resp:
    """Duck-typed urlopen result: context manager + .read(n) + .status."""

    def __init__(self, payload: bytes, status: int = 200):
        self._buf = io.BytesIO(payload)
        self.status = status

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _stream_resp(payload: bytes, status: int = 200) -> _Resp:
    return _Resp(payload, status)


def _sha_resp(tarball_bytes: bytes) -> _Resp:
    import hashlib

    digest = hashlib.sha512(tarball_bytes).hexdigest()
    return _Resp(f"{digest}  logstash.tar.gz".encode())


def _urlopen_url(req) -> str:
    return req.full_url if hasattr(req, "full_url") else str(req)


def _urlopen_headers(req) -> dict:
    if hasattr(req, "headers"):
        return {str(k).lower(): v for k, v in req.headers.items()}
    return {}


@pytest.fixture(autouse=True)
def _clear_via_ui_env(monkeypatch):
    monkeypatch.delenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", raising=False)
    monkeypatch.delenv("LOGSTASH_AGENT_ARTIFACT_DEADLINE_SEC", raising=False)


@pytest.fixture
def no_sleep(monkeypatch):
    """Make retry backoff instant; record what the code asked to wait."""
    slept: list[float] = []
    monkeypatch.setattr(ld.time, "sleep", lambda s: slept.append(s))
    return slept


def test_version_is_present(tmp_path):
    version = "9.4.3"
    assert ld.version_is_present("", str(tmp_path)) is False
    assert ld.version_is_present(version, str(tmp_path)) is False
    assert not (tmp_path / f"logstash-{version}").exists()

    binary = tmp_path / f"logstash-{version}" / "bin" / "logstash"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    assert ld.version_is_present(version, str(tmp_path)) is True


def test_artifact_filename_and_url():
    name = ld.artifact_filename("9.4.3", "linux-x86_64")
    assert name == "logstash-9.4.3-linux-x86_64.tar.gz"
    url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert url.endswith(name)
    assert "artifacts.elastic.co" in url


def test_artifact_url_via_ui_env(monkeypatch):
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    state = _ui_state(logstash_via_ui=False)
    with patch("logstashagent.agent_state.get_state", return_value=state):
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert url == _artifact_ui_url("9.4.3")
    assert "artifacts.elastic.co" not in url


def test_artifact_url_via_ui_includes_connection_id(monkeypatch):
    """The proxy needs connection_id in the path: a GET has no body to carry it."""
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    with patch("logstashagent.agent_state.get_state", return_value=_ui_state()):
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert url == (
        f"{_UI_BASE}/ConnectionManager/LogstashArtifact/7/"
        f"logstash-9.4.3-linux-x86_64.tar.gz"
    )
    # explicit argument beats state
    with patch("logstashagent.agent_state.get_state", return_value=_ui_state()):
        url = ld.artifact_url("9.4.3", "linux-x86_64", connection_id=42)
    assert "/LogstashArtifact/42/" in url


def test_artifact_url_via_ui_missing_connection_id_raises(monkeypatch):
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    state = {"logstash_ui_url": _UI_BASE, "api_key": _UI_KEY}
    with patch("logstashagent.agent_state.get_state", return_value=state):
        with pytest.raises(ld.LogstashDownloadError, match="connection_id"):
            ld.artifact_url("9.4.3", "linux-x86_64")


def test_via_ui_admin_token_prefix_rejected():
    """lsui_ values are admin tokens; the middleware 401s them before the view."""
    state = _ui_state(api_key="lsui_deadbeef")
    with pytest.raises(ld.LogstashDownloadError, match="lsui_"):
        ld._via_ui_auth_headers(state=state)
    assert ld._via_ui_auth_headers(state=_ui_state()) == {
        "Authorization": f"ApiKey {_UI_KEY}"
    }


def test_via_ui_env_wins_over_state(monkeypatch):
    state_on = _ui_state(logstash_via_ui=True)
    state_off = _ui_state(logstash_via_ui=False)
    name = ld.artifact_filename("9.4.3", "linux-x86_64")

    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "0")
    with patch("logstashagent.agent_state.get_state", return_value=state_on):
        assert ld.logstash_via_ui_enabled(state_on) is False
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert "artifacts.elastic.co" in url
    assert url.endswith(name)

    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "false")
    with patch("logstashagent.agent_state.get_state", return_value=state_on):
        assert ld.logstash_via_ui_enabled(state_on) is False
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert "artifacts.elastic.co" in url

    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    with patch("logstashagent.agent_state.get_state", return_value=state_off):
        assert ld.logstash_via_ui_enabled(state_off) is True
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert url == _artifact_ui_url("9.4.3")
    assert "artifacts.elastic.co" not in url


def test_via_ui_state_used_when_env_unset(monkeypatch):
    monkeypatch.delenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", raising=False)
    state = _ui_state(logstash_via_ui="yes")
    with patch("logstashagent.agent_state.get_state", return_value=state):
        assert ld.logstash_via_ui_enabled() is True
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert url == _artifact_ui_url("9.4.3")


def test_via_ui_missing_url_or_api_key_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    with patch("logstashagent.agent_state.get_state", return_value={}):
        with pytest.raises(ld.LogstashDownloadError):
            ld.artifact_url("9.4.3", "linux-x86_64")
        with pytest.raises(ld.LogstashDownloadError):
            ld.ensure_logstash_version(
                "9.4.3", str(tmp_path), platform_arch="linux-x86_64"
            )
    with patch(
        "logstashagent.agent_state.get_state",
        return_value={"logstash_ui_url": _UI_BASE},
    ):
        with pytest.raises(ld.LogstashDownloadError):
            ld.ensure_logstash_version(
                "9.4.3", str(tmp_path), platform_arch="linux-x86_64"
            )


def test_artifact_url_flag_off_is_elastic(monkeypatch):
    monkeypatch.delenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", raising=False)
    with patch(
        "logstashagent.agent_state.get_state",
        return_value={"logstash_via_ui": False, "logstash_ui_url": _UI_BASE},
    ):
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert "artifacts.elastic.co" in url
    assert "ConnectionManager/LogstashArtifact" not in url


def _fake_tarball_urlopen(tarball_bytes, seen, *, expect_ui=False):
    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        headers = _urlopen_headers(req)
        seen.append({"url": url, "headers": headers, "timeout": timeout, "req": req, "context": context})
        if expect_ui:
            assert "artifacts.elastic.co" not in url
            assert "/ConnectionManager/LogstashArtifact/" in url
            assert headers.get("authorization") == f"ApiKey {_UI_KEY}"
        else:
            assert "artifacts.elastic.co" in url
            assert "authorization" not in headers

        class Stream:
            def __enter__(self):
                return io.BytesIO(tarball_bytes)

            def __exit__(self, *a):
                return False

        class Resp:
            def read(self):
                import hashlib

                h = hashlib.sha512(tarball_bytes).hexdigest()
                return f"{h}  logstash.tar.gz".encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        if url.endswith(".sha512"):
            return Resp()
        return Stream()

    return fake_urlopen


def test_ensure_logstash_version_via_ui_sends_apikey(tmp_path, monkeypatch):
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    seen = []
    state = _ui_state(logstash_via_ui=False)
    with patch("logstashagent.agent_state.get_state", return_value=state), patch.object(
        ld.urllib.request, "urlopen", side_effect=_fake_tarball_urlopen(
            tarball_bytes, seen, expect_ui=True
        )
    ):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    tar_hits = [s for s in seen if not s["url"].endswith(".sha512")]
    sha_hits = [s for s in seen if s["url"].endswith(".sha512")]
    assert tar_hits and sha_hits
    assert tar_hits[0]["url"] == _artifact_ui_url(version)
    assert sha_hits[0]["url"] == tar_hits[0]["url"] + ".sha512"
    assert sha_hits[0]["url"].startswith(_UI_BASE)
    assert sha_hits[0]["timeout"] == 600
    assert tar_hits[0]["timeout"] == 600
    for hit in seen:
        assert hit["headers"].get("authorization") == f"ApiKey {_UI_KEY}"


def test_ensure_logstash_version_flag_off_no_apikey(tmp_path, monkeypatch):
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "false")
    seen = []
    with patch("logstashagent.agent_state.get_state", return_value={
        "logstash_via_ui": True,
        "logstash_ui_url": _UI_BASE,
        "api_key": _UI_KEY,
    }), patch.object(
        ld.urllib.request,
        "urlopen",
        side_effect=_fake_tarball_urlopen(tarball_bytes, seen, expect_ui=False),
    ):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    assert seen
    for hit in seen:
        assert "artifacts.elastic.co" in hit["url"]
        assert "authorization" not in hit["headers"]


@pytest.mark.parametrize("status", [401, 404, 405])
def test_via_ui_fatal_status_fails_immediately(tmp_path, monkeypatch, status, no_sleep):
    """401/404/405 are agent-side bugs or bad enrollment: fail, do not loop."""
    version = "9.4.3"
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    calls = []

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if "artifacts.elastic.co" in url:
            pytest.fail("must not fall back to artifacts.elastic.co")
        calls.append(url)
        raise _http_error(url, status)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        with pytest.raises(ld.LogstashDownloadError):
            ld.ensure_logstash_version(
                version, str(tmp_path), platform_arch="linux-x86_64"
            )
    assert len(calls) == 1, "fatal status must not be retried"
    assert no_sleep == []


@pytest.mark.parametrize("status", [503, 429, 502])
def test_via_ui_retryable_status_then_success(tmp_path, monkeypatch, status, no_sleep):
    """Cold cache / back-pressure / upstream failure retry until the file lands."""
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    attempts = {"tar": 0}

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if "artifacts.elastic.co" in url:
            pytest.fail("must not fall back to artifacts.elastic.co")
        if url.endswith(".sha512"):
            return _sha_resp(tarball_bytes)
        attempts["tar"] += 1
        if attempts["tar"] <= 3:
            raise _http_error(url, status, headers={"Retry-After": "30"})
        return _stream_resp(tarball_bytes)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    assert attempts["tar"] == 4
    # Retry-After honoured verbatim, not the agent's own 15s schedule
    assert no_sleep == [30.0, 30.0, 30.0]


def test_via_ui_retry_uses_own_backoff_without_header(tmp_path, monkeypatch, no_sleep):
    """No Retry-After → exponential from 15s, ceiling 300s."""
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    attempts = {"tar": 0}

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if url.endswith(".sha512"):
            return _sha_resp(tarball_bytes)
        attempts["tar"] += 1
        if attempts["tar"] <= 3:
            raise _http_error(url, 503)
        return _stream_resp(tarball_bytes)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert no_sleep == [15.0, 30.0, 60.0]
    assert ld._own_backoff(99) == 300.0


def test_via_ui_deadline_expiry_keeps_partial(tmp_path, monkeypatch, no_sleep):
    """
    A server stuck on 503 eventually gives up, but retains the .part so the
    next check-in resumes instead of re-pulling 450 MB.
    """
    version = "9.4.3"
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    monkeypatch.setenv("LOGSTASH_AGENT_ARTIFACT_DEADLINE_SEC", "0.0001")
    name = ld.artifact_filename(version, "linux-x86_64")
    part = tmp_path / ".partial" / f"{name}.part"
    part.parent.mkdir(parents=True)
    part.write_bytes(b"x" * 1024)

    calls = []

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        calls.append(url)
        raise _http_error(url, 503, headers={"Retry-After": "30"})

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        with pytest.raises(ld.LogstashDownloadError, match="deadline"):
            ld.ensure_logstash_version(
                version, str(tmp_path), platform_arch="linux-x86_64"
            )
    # At least one attempt is always made, then the deadline stops the loop.
    assert len(calls) >= 1
    assert all("artifacts.elastic.co" not in u for u in calls)
    assert part.exists(), "partial must survive for resume"
    assert part.stat().st_size == 1024


def test_via_ui_urlopen_uses_ssl_context(tmp_path, monkeypatch):
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    fake_ctx = object()
    seen = []

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        seen.append({"url": url, "context": context})
        class Stream:
            def __enter__(self):
                return io.BytesIO(tarball_bytes)

            def __exit__(self, *a):
                return False

        class Resp:
            def read(self):
                import hashlib

                h = hashlib.sha512(tarball_bytes).hexdigest()
                return f"{h}  logstash.tar.gz".encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        if url.endswith(".sha512"):
            return Resp()
        return Stream()

    with patch("logstashagent.tls_trust.build_ssl_context", return_value=fake_ctx), patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    assert seen
    for hit in seen:
        assert hit["context"] is fake_ctx


def test_via_ui_sha512_http_error_is_fatal(tmp_path, monkeypatch, no_sleep):
    """A 404 on the sidecar is fatal: the server always has one once READY."""
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if "artifacts.elastic.co" in url:
            pytest.fail("must not fall back to artifacts.elastic.co")
        if url.endswith(".sha512"):
            raise _http_error(url, 404)
        return _stream_resp(tarball_bytes)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        with pytest.raises(ld.LogstashDownloadError):
            ld.ensure_logstash_version(
                version, str(tmp_path), platform_arch="linux-x86_64"
            )
    assert not (tmp_path / f"logstash-{version}").exists()


def test_via_ui_sha512_cold_cache_retries(tmp_path, monkeypatch, no_sleep):
    """The sidecar can 503 on a cold cache too — retry rather than fail."""
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    attempts = {"sha": 0}

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if url.endswith(".sha512"):
            attempts["sha"] += 1
            if attempts["sha"] <= 2:
                raise _http_error(url, 503, headers={"Retry-After": "30"})
            return _sha_resp(tarball_bytes)
        return _stream_resp(tarball_bytes)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    assert attempts["sha"] == 3
    assert no_sleep == [30.0, 30.0]


def test_via_ui_resume_sends_range_and_appends(tmp_path, monkeypatch, no_sleep):
    """A pre-existing .part resumes with Range; the reassembled file verifies."""
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    split = len(tarball_bytes) // 2
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")

    name = ld.artifact_filename(version, "linux-x86_64")
    part = tmp_path / ".partial" / f"{name}.part"
    part.parent.mkdir(parents=True)
    part.write_bytes(tarball_bytes[:split])

    seen = []

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        headers = _urlopen_headers(req)
        seen.append({"url": url, "range": headers.get("range")})
        if url.endswith(".sha512"):
            return _sha_resp(tarball_bytes)
        assert headers.get("range") == f"bytes={split}-"
        return _stream_resp(tarball_bytes[split:], status=206)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )

    # Extraction succeeded, so the reassembled bytes hashed correctly.
    assert Path(binary).is_file()
    assert (tmp_path / f"logstash-{version}" / "bin" / "logstash").is_file()
    tar_hits = [s for s in seen if not s["url"].endswith(".sha512")]
    assert tar_hits[0]["range"] == f"bytes={split}-"
    assert not part.exists(), ".part must be cleaned up after success"


def test_via_ui_no_range_header_on_fresh_download(tmp_path, monkeypatch, no_sleep):
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    seen = []

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        seen.append(_urlopen_headers(req).get("range"))
        if url.endswith(".sha512"):
            return _sha_resp(tarball_bytes)
        return _stream_resp(tarball_bytes)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert all(r is None for r in seen)


def test_via_ui_416_discards_partial_and_restarts(tmp_path, monkeypatch, no_sleep):
    """Range past EOF means our partial is wrong: drop it, restart from zero."""
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")

    name = ld.artifact_filename(version, "linux-x86_64")
    part = tmp_path / ".partial" / f"{name}.part"
    part.parent.mkdir(parents=True)
    part.write_bytes(b"garbage" * 5000)  # bogus partial, longer than the real file

    ranges = []

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if url.endswith(".sha512"):
            return _sha_resp(tarball_bytes)
        rng = _urlopen_headers(req).get("range")
        ranges.append(rng)
        if rng is not None:
            raise _http_error(url, 416)
        return _stream_resp(tarball_bytes)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    # First attempt ranged and got 416; second started from zero.
    assert ranges[0] is not None and ranges[1] is None
    assert not part.exists()


def test_via_ui_interrupted_transfer_resumes(tmp_path, monkeypatch, no_sleep):
    """A reset mid-transfer keeps the bytes already written and resumes."""
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    split = len(tarball_bytes) // 2
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    attempts = {"tar": 0}
    ranges = []

    class _Truncated(_Resp):
        """Delivers the first half, then the connection dies."""

        def __init__(self, payload):
            super().__init__(payload)
            self._served = 0

        def read(self, n=-1):
            if self._served >= split:
                raise ConnectionResetError("peer went away")
            chunk = self._buf.read(min(n, split - self._served))
            self._served += len(chunk)
            return chunk

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if url.endswith(".sha512"):
            return _sha_resp(tarball_bytes)
        attempts["tar"] += 1
        rng = _urlopen_headers(req).get("range")
        ranges.append(rng)
        if attempts["tar"] == 1:
            return _Truncated(tarball_bytes)
        assert rng == f"bytes={split}-"
        return _stream_resp(tarball_bytes[split:], status=206)

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    assert attempts["tar"] == 2
    assert ranges == [None, f"bytes={split}-"]


def test_via_ui_programming_error_is_not_retried(tmp_path, monkeypatch, no_sleep):
    """Only transient network errors retry; a bug must fail immediately."""
    version = "9.4.3"
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    calls = []

    def fake_urlopen(req, timeout=60, context=None):
        calls.append(_urlopen_url(req))
        raise TypeError("bug in the agent")

    with patch(
        "logstashagent.agent_state.get_state", return_value=_ui_state()
    ), patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        with pytest.raises(ld.LogstashDownloadError):
            ld.ensure_logstash_version(
                version, str(tmp_path), platform_arch="linux-x86_64"
            )
    assert len(calls) == 1
    assert no_sleep == []


def test_sweep_stale_partials(tmp_path):
    pdir = tmp_path / ".partial"
    pdir.mkdir()
    fresh = pdir / "fresh.tar.gz.part"
    stale = pdir / "stale.tar.gz.part"
    other = pdir / "notapart.txt"
    for p in (fresh, stale, other):
        p.write_bytes(b"x")
    old = time.time() - (48 * 3600)
    import os as _os

    _os.utime(stale, (old, old))

    ld._sweep_stale_partials(str(tmp_path))

    assert fresh.exists()
    assert other.exists(), "non-.part files are left alone"
    assert not stale.exists()


def test_elastic_sha512_fetch_failure_skips_verify(tmp_path, monkeypatch):
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "false")

    def fake_urlopen(req, timeout=60, context=None):
        url = _urlopen_url(req)
        if url.endswith(".sha512"):
            raise urllib.error.HTTPError(url, 404, "err", hdrs=None, fp=None)

        class Stream:
            def __enter__(self):
                return io.BytesIO(tarball_bytes)

            def __exit__(self, *a):
                return False

        return Stream()

    with patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()


def test_detect_platform_arch_known():
    with patch.object(ld.platform, "system", return_value="Linux"), patch.object(
        ld.platform, "machine", return_value="x86_64"
    ):
        assert ld.detect_platform_arch() == "linux-x86_64"
    with patch.object(ld.platform, "system", return_value="Linux"), patch.object(
        ld.platform, "machine", return_value="aarch64"
    ):
        assert ld.detect_platform_arch() == "linux-aarch64"


def test_resolve_binary_system_dir(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "logstash"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    path = ld.resolve_binary_from_policy(
        logstash_source="SYSTEM",
        binary_path=str(bin_dir),
    )
    assert path == str(exe)


def test_ensure_logstash_version_idempotent_extract(tmp_path):
    version = "9.4.3"
    tarball_bytes = _minimal_logstash_tarball(version)

    def fake_urlopen(url, timeout=60, context=None):
        class Resp:
            def read(self):
                if url.endswith(".sha512"):
                    import hashlib

                    h = hashlib.sha512(tarball_bytes).hexdigest()
                    return f"{h}  logstash.tar.gz".encode()
                return tarball_bytes

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        if "artifacts.elastic.co" in url and not url.endswith(".sha512"):
            # stream body for download path uses copyfileobj
            class Stream:
                def read(self, n=-1):
                    return tarball_bytes if n < 0 else tarball_bytes[:n]

                def __enter__(self):
                    return io.BytesIO(tarball_bytes)

                def __exit__(self, *a):
                    return False

            return Stream()
        return Resp()

    with patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    assert Path(binary).is_file()
    # Second call skips download
    with patch.object(ld.urllib.request, "urlopen") as mock_open:
        binary2 = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
        mock_open.assert_not_called()
    assert binary2 == binary


def test_empty_version_raises():
    with pytest.raises(ld.LogstashDownloadError):
        ld.ensure_logstash_version("")


def test_list_installed_versions(tmp_path):
    v = "9.4.3"
    # Canonical flat layout: logstash-versions/logstash-9.4.3/bin/logstash
    binary = tmp_path / f"logstash-{v}" / "bin" / "logstash"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    found = ld.list_installed_versions(str(tmp_path))
    assert len(found) == 1
    assert found[0]["version"] == v
    assert found[0]["binary"] == str(binary)
    assert found[0]["install_dir"] == str(tmp_path / f"logstash-{v}")
    table = ld.format_versions_table(found)
    assert v in table


def test_list_installed_versions_legacy_nested(tmp_path):
    v = "9.4.3"
    binary = tmp_path / v / f"logstash-{v}" / "bin" / "logstash"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    found = ld.list_installed_versions(str(tmp_path))
    assert any(f["version"] == v for f in found)
    assert ld.resolve_logstash_binary(v, str(tmp_path)) == binary


def test_prune_versions_keeps_used(tmp_path, monkeypatch):
    for v in ("9.4.3", "8.19.0"):
        b = tmp_path / f"logstash-{v}" / "bin" / "logstash"
        b.parent.mkdir(parents=True)
        b.write_text("x", encoding="utf-8")

    monkeypatch.setattr(
        ld,
        "collect_in_use_versions",
        lambda *a, **k: {"9.4.3"},
    )
    result = ld.prune_versions(str(tmp_path), keep=set(), keep_used=True, dry_run=False)
    assert "8.19.0" in result["removed"]
    assert "9.4.3" in result["kept"]
    assert (tmp_path / "logstash-9.4.3").is_dir()
    assert not (tmp_path / "logstash-8.19.0").exists()


def test_ensure_extracts_flat_not_nested(tmp_path):
    version = "9.4.3"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        data = b"#!/bin/sh\necho logstash\n"
        info = tarfile.TarInfo(name=f"logstash-{version}/bin/logstash")
        info.size = len(data)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(data))
    raw.seek(0)
    tarball_bytes = raw.read()

    def fake_urlopen(url, timeout=60, context=None):
        class Stream:
            def __enter__(self):
                return io.BytesIO(tarball_bytes)

            def __exit__(self, *a):
                return False

        class Resp:
            def read(self):
                import hashlib

                h = hashlib.sha512(tarball_bytes).hexdigest()
                return f"{h}  logstash.tar.gz".encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        if url.endswith(".sha512"):
            return Resp()
        return Stream()

    with patch.object(ld.urllib.request, "urlopen", side_effect=fake_urlopen):
        binary = ld.ensure_logstash_version(
            version, str(tmp_path), platform_arch="linux-x86_64"
        )
    # Flat: <root>/logstash-9.4.3/bin/logstash — NOT <root>/9.4.3/logstash-9.4.3/...
    assert Path(binary) == tmp_path / f"logstash-{version}" / "bin" / "logstash"
    assert not (tmp_path / version).exists()


def test_ensure_logstash_version_flock_serializes_extract(tmp_path):
    """Two threads targeting the same missing version download once."""
    version = "9.5.0"
    tarball_bytes = _minimal_logstash_tarball(version)
    downloads = []
    started = threading.Event()
    proceed = threading.Event()

    def slow_download(url, dest, timeout=600, **_kwargs):
        downloads.append(url)
        started.set()
        assert proceed.wait(5), "first downloader stuck"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(tarball_bytes)

    results = []
    errors = []

    def worker():
        try:
            results.append(
                ld.ensure_logstash_version(
                    version, str(tmp_path), platform_arch="linux-x86_64"
                )
            )
        except Exception as e:
            errors.append(e)

    with patch.object(ld, "_download_file", side_effect=slow_download), patch.object(
        ld, "_verify_sha512", return_value=None
    ):
        t1 = threading.Thread(target=worker)
        t1.start()
        assert started.wait(5)
        t2 = threading.Thread(target=worker)
        t2.start()
        time.sleep(0.2)
        assert len(downloads) == 1
        proceed.set()
        t1.join(timeout=10)
        t2.join(timeout=10)

    assert errors == []
    assert len(downloads) == 1
    assert len(results) == 2
    assert results[0] == results[1]
    assert Path(results[0]).is_file()


def _minimal_logstash_tarball(version: str) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        data = b"#!/bin/sh\necho logstash\n"
        info = tarfile.TarInfo(name=f"logstash-{version}/bin/logstash")
        info.size = len(data)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(data))
    raw.seek(0)
    return raw.read()
