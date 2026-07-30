#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from logstashagent import logstash_download as ld


def test_artifact_filename_and_url():
    name = ld.artifact_filename("9.4.3", "linux-x86_64")
    assert name == "logstash-9.4.3-linux-x86_64.tar.gz"
    url = ld.artifact_url("9.4.3", "linux-x86_64")
    assert url.endswith(name)
    assert "artifacts.elastic.co" in url


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
    # Build a fake tarball layout: logstash-9.4.3/bin/logstash
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
    binary = tmp_path / v / "bin" / "logstash"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    found = ld.list_installed_versions(str(tmp_path))
    assert len(found) == 1
    assert found[0]["version"] == v
    assert found[0]["binary"] == str(binary)
    table = ld.format_versions_table(found)
    assert v in table


def test_prune_versions_keeps_used(tmp_path, monkeypatch):
    for v in ("9.4.3", "8.19.0"):
        b = tmp_path / v / "bin" / "logstash"
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
    assert (tmp_path / "9.4.3").is_dir()
    assert not (tmp_path / "8.19.0").exists()
