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


def _urlopen_url(req) -> str:
    return req.full_url if hasattr(req, "full_url") else str(req)


def _urlopen_headers(req) -> dict:
    if hasattr(req, "headers"):
        return {str(k).lower(): v for k, v in req.headers.items()}
    return {}


@pytest.fixture(autouse=True)
def _clear_via_ui_env(monkeypatch):
    monkeypatch.delenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", raising=False)


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
    state = {
        "logstash_ui_url": _UI_BASE,
        "api_key": _UI_KEY,
        "logstash_via_ui": False,
    }
    with patch("logstashagent.agent_state.get_state", return_value=state):
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    name = ld.artifact_filename("9.4.3", "linux-x86_64")
    assert url == f"{_UI_BASE}/ConnectionManager/LogstashArtifact/{name}"
    assert "artifacts.elastic.co" not in url


def test_via_ui_env_wins_over_state(monkeypatch):
    state_on = {
        "logstash_ui_url": _UI_BASE,
        "api_key": _UI_KEY,
        "logstash_via_ui": True,
    }
    state_off = {
        "logstash_ui_url": _UI_BASE,
        "api_key": _UI_KEY,
        "logstash_via_ui": False,
    }
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
    assert url == f"{_UI_BASE}/ConnectionManager/LogstashArtifact/{name}"
    assert "artifacts.elastic.co" not in url


def test_via_ui_state_used_when_env_unset(monkeypatch):
    monkeypatch.delenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", raising=False)
    state = {
        "logstash_ui_url": _UI_BASE,
        "api_key": _UI_KEY,
        "logstash_via_ui": "yes",
    }
    with patch("logstashagent.agent_state.get_state", return_value=state):
        assert ld.logstash_via_ui_enabled() is True
        url = ld.artifact_url("9.4.3", "linux-x86_64")
    name = ld.artifact_filename("9.4.3", "linux-x86_64")
    assert url == f"{_UI_BASE}/ConnectionManager/LogstashArtifact/{name}"


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
    def fake_urlopen(req, timeout=60):
        url = _urlopen_url(req)
        headers = _urlopen_headers(req)
        seen.append({"url": url, "headers": headers, "timeout": timeout, "req": req})
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
    state = {"logstash_ui_url": _UI_BASE, "api_key": _UI_KEY, "logstash_via_ui": False}
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
    name = ld.artifact_filename(version, "linux-x86_64")
    assert tar_hits[0]["url"] == (
        f"{_UI_BASE}/ConnectionManager/LogstashArtifact/{name}"
    )
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


@pytest.mark.parametrize("status", [404, 502])
def test_via_ui_http_error_no_elastic_fallback(tmp_path, monkeypatch, status):
    version = "9.4.3"
    monkeypatch.setenv("LOGSTASH_AGENT_LOGSTASH_VIA_UI", "true")
    elastic_hits = []

    def fake_urlopen(req, timeout=60):
        url = _urlopen_url(req)
        if "artifacts.elastic.co" in url:
            elastic_hits.append(url)
            pytest.fail("must not fall back to artifacts.elastic.co")
        raise urllib.error.HTTPError(url, status, "err", hdrs=None, fp=None)

    state = {"logstash_ui_url": _UI_BASE, "api_key": _UI_KEY}
    with patch("logstashagent.agent_state.get_state", return_value=state), patch.object(
        ld.urllib.request, "urlopen", side_effect=fake_urlopen
    ):
        with pytest.raises(ld.LogstashDownloadError):
            ld.ensure_logstash_version(
                version, str(tmp_path), platform_arch="linux-x86_64"
            )
    assert elastic_hits == []


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

    def fake_urlopen(url, timeout=60):
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

    def fake_urlopen(url, timeout=60):
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

    def slow_download(url, dest, timeout=600):
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
