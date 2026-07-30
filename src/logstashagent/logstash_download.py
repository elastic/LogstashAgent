#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Download and extract official Logstash distributions for simulate agents
when policy logstash_source=VERSION.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DOWNLOAD_ROOT = "/opt/logstash-agent/logstash-versions"
_LEGACY_DOWNLOAD_ROOT = "/opt/LogstashAgent/logstash-versions"
ARTIFACTS_BASE = "https://artifacts.elastic.co/downloads/logstash"


class LogstashDownloadError(Exception):
    """Failed to obtain a Logstash distribution."""


def detect_platform_arch() -> str:
    """
    Map host platform to Elastic artifact arch token.

    Returns e.g. 'linux-x86_64' or 'linux-aarch64'.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system != "linux":
        # Best-effort for non-Linux (download still uses linux artifacts in v1)
        logger.warning(
            "Logstash version download is primarily for Linux; detected system=%s",
            system,
        )

    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "aarch64"
    else:
        raise LogstashDownloadError(
            f"Unsupported CPU architecture for Logstash download: {machine}"
        )

    return f"linux-{arch}"


def artifact_filename(version: str, platform_arch: Optional[str] = None) -> str:
    platform_arch = platform_arch or detect_platform_arch()
    return f"logstash-{version}-{platform_arch}.tar.gz"


def artifact_url(version: str, platform_arch: Optional[str] = None) -> str:
    name = artifact_filename(version, platform_arch)
    return f"{ARTIFACTS_BASE}/{name}"


def version_install_dir(version: str, download_root: str = DEFAULT_DOWNLOAD_ROOT) -> Path:
    return Path(download_root) / version


def resolve_logstash_binary(
    version: str, download_root: str = DEFAULT_DOWNLOAD_ROOT
) -> Path:
    """
    Path to bin/logstash inside an extracted version tree.

    Elastic tarballs extract to logstash-<version>/ under the target dir.
    We also accept a flattened layout: <download_root>/<version>/bin/logstash
    """
    root = version_install_dir(version, download_root)
    candidates = [
        root / "bin" / "logstash",
        root / f"logstash-{version}" / "bin" / "logstash",
    ]
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    # Non-executable is still usable if present (perms fixed later)
    for path in candidates:
        if path.is_file():
            return path
    raise LogstashDownloadError(
        f"Logstash binary not found under {root} for version {version}"
    )


def _download_file(url: str, dest: Path, timeout: int = 600) -> None:
    logger.info("Downloading %s -> %s", url, dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp, open(dest, "wb") as out:
            shutil.copyfileobj(resp, out)
    except Exception as exc:
        raise LogstashDownloadError(f"Download failed for {url}: {exc}") from exc


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_sha512(tarball: Path, sha_url: str) -> None:
    """
    Verify tarball against Elastic .sha512 sidecar when available.
    Non-fatal if the sidecar cannot be fetched (log warning).
    """
    try:
        with urllib.request.urlopen(sha_url, timeout=60) as resp:
            text = resp.read().decode("utf-8", errors="replace").strip()
    except Exception as exc:
        logger.warning("Could not fetch checksum %s: %s (skipping verify)", sha_url, exc)
        return

    # Format is typically: "<hex>  filename" or just hex
    expected = text.split()[0].lower()
    actual = _sha512_file(tarball).lower()
    if expected != actual:
        raise LogstashDownloadError(
            f"SHA-512 mismatch for {tarball.name}: expected {expected[:16]}… got {actual[:16]}…"
        )
    logger.info("✓ Verified SHA-512 for %s", tarball.name)


def ensure_logstash_version(
    version: str,
    download_root: str = DEFAULT_DOWNLOAD_ROOT,
    *,
    platform_arch: Optional[str] = None,
    force: bool = False,
) -> Path:
    """
    Ensure Logstash ``version`` is present under download_root.

    Returns path to the logstash binary.
    Idempotent: skips download if binary already resolves.
    """
    version = (version or "").strip()
    if not version:
        raise LogstashDownloadError("logstash_version is empty")

    download_root = download_root or DEFAULT_DOWNLOAD_ROOT
    install_dir = version_install_dir(version, download_root)

    if not force:
        try:
            binary = resolve_logstash_binary(version, download_root)
            logger.info("Logstash %s already present at %s", version, binary)
            return binary
        except LogstashDownloadError:
            pass

    platform_arch = platform_arch or detect_platform_arch()
    url = artifact_url(version, platform_arch)
    sha_url = url + ".sha512"

    install_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ls-download-") as tmp:
        tmp_path = Path(tmp)
        tarball = tmp_path / artifact_filename(version, platform_arch)
        _download_file(url, tarball)
        _verify_sha512(tarball, sha_url)

        logger.info("Extracting %s into %s", tarball.name, install_dir)
        try:
            with tarfile.open(tarball, "r:gz") as tar:
                # Python 3.12+ filter= for safer extract; fall back if unavailable
                try:
                    tar.extractall(path=install_dir, filter="data")
                except TypeError:
                    tar.extractall(path=install_dir)
        except Exception as exc:
            raise LogstashDownloadError(f"Failed to extract {tarball}: {exc}") from exc

    binary = resolve_logstash_binary(version, download_root)
    try:
        os.chmod(binary, 0o755)
    except OSError:
        pass
    logger.info("✓ Logstash %s ready at %s", version, binary)
    return binary


def normalize_download_dir(path: str | None) -> str:
    """Force downloads under /opt/logstash-agent (rewrite legacy /opt/LogstashAgent)."""
    p = (path or DEFAULT_DOWNLOAD_ROOT).strip() or DEFAULT_DOWNLOAD_ROOT
    if p.startswith("/opt/LogstashAgent"):
        return "/opt/logstash-agent" + p[len("/opt/LogstashAgent") :]
    return p


def resolve_binary_from_policy(
    *,
    logstash_source: str = "SYSTEM",
    logstash_version: str = "",
    logstash_download_dir: str = DEFAULT_DOWNLOAD_ROOT,
    binary_path: str = "/usr/share/logstash/bin",
) -> str:
    """
    Return absolute path to the logstash executable for a policy.

    SYSTEM: binary_path may be a directory (…/bin) or full path to the binary.
    VERSION: ensure download and return extracted binary.
    """
    source = (logstash_source or "SYSTEM").upper()
    if source == "VERSION":
        binary = ensure_logstash_version(
            logstash_version,
            normalize_download_dir(logstash_download_dir),
        )
        return str(binary)

    # SYSTEM
    path = Path(binary_path or "/usr/share/logstash/bin")
    if path.is_dir():
        candidate = path / "logstash"
    else:
        candidate = path
    if not candidate.exists():
        # Still return intended path; runtime will fail clearly if missing
        logger.warning("System Logstash binary not found at %s", candidate)
    return str(candidate)


def list_installed_versions(
    download_root: str | None = None,
) -> list[dict]:
    """
    Scan download_root for extracted Logstash versions.

    Returns list of dicts: version, binary, install_dir, size_bytes (optional).
    """
    root = Path(normalize_download_dir(download_root or DEFAULT_DOWNLOAD_ROOT))
    if not root.is_dir():
        return []

    found: list[dict] = []
    try:
        names = sorted(os.listdir(root))
    except OSError as e:
        logger.warning("Cannot list %s: %s", root, e)
        return []

    for name in names:
        # Skip temp / non-version dirs
        if name.startswith(".") or name.startswith("ls-download-"):
            continue
        vdir = root / name
        if not vdir.is_dir():
            continue
        try:
            binary = resolve_logstash_binary(name, str(root))
        except LogstashDownloadError:
            # Nested layout may use directory name != version; try probe
            nested = list(vdir.glob("logstash-*/bin/logstash"))
            if nested and nested[0].is_file():
                binary = nested[0]
            else:
                continue
        size = None
        try:
            # Rough tree size (may be slow on huge trees; cap depth walk)
            total = 0
            for dirpath, _dirnames, filenames in os.walk(vdir):
                for fn in filenames:
                    try:
                        total += (Path(dirpath) / fn).stat().st_size
                    except OSError:
                        pass
            size = total
        except OSError:
            pass
        found.append(
            {
                "version": name,
                "binary": str(binary),
                "install_dir": str(vdir),
                "size_bytes": size,
            }
        )
    return found


def collect_in_use_versions(
    download_root: str | None = None,
    *,
    extra_versions: set[str] | None = None,
) -> set[str]:
    """
    Versions that should not be pruned: agent state, install registry, extras.
    """
    used: set[str] = set(extra_versions or ())
    try:
        from logstashagent import agent_state as _as

        st = _as.get_state() or {}
        if (st.get("logstash_source") or "").upper() == "VERSION":
            v = (st.get("logstash_version_resolved") or st.get("logstash_version") or "").strip()
            if v:
                used.add(v)
    except Exception:
        pass
    try:
        from logstashagent import install_registry as _reg

        reg = _reg.load_registry()
        for ver, meta in (reg.get("logstash_versions") or {}).items():
            if ver:
                used.add(str(ver))
        for inst in (reg.get("instances") or {}).values():
            if not isinstance(inst, dict):
                continue
            if (inst.get("logstash_source") or "").upper() == "VERSION":
                v = (inst.get("logstash_version") or "").strip()
                if v:
                    used.add(v)
    except Exception:
        pass
    # Also mark any version still referenced by env files under managed-/simulate-
    try:
        from logstashagent.installer import INSTALL_PATHS

        opt = Path(INSTALL_PATHS.get("simulate_root") or "/opt/logstash-agent")
        if opt.is_dir():
            for env_path in opt.glob("*/env"):
                try:
                    for line in env_path.read_text(encoding="utf-8").splitlines():
                        if line.startswith("LOGSTASH_BINARY="):
                            b = line.split("=", 1)[1].strip()
                            # .../logstash-versions/<ver>/...
                            parts = Path(b).parts
                            if "logstash-versions" in parts:
                                i = parts.index("logstash-versions")
                                if i + 1 < len(parts):
                                    used.add(parts[i + 1])
                except OSError:
                    pass
    except Exception:
        pass
    return used


def prune_versions(
    download_root: str | None = None,
    *,
    keep: set[str] | None = None,
    keep_used: bool = True,
    dry_run: bool = False,
) -> dict:
    """
    Remove extracted version trees not in ``keep`` (and not in-use if keep_used).

    Returns dict: removed (list), kept (list), errors (list).
    """
    root = Path(normalize_download_dir(download_root or DEFAULT_DOWNLOAD_ROOT))
    keep_set = set(keep or ())
    if keep_used:
        keep_set |= collect_in_use_versions(str(root))

    installed = list_installed_versions(str(root))
    removed: list[str] = []
    kept: list[str] = []
    errors: list[str] = []

    for entry in installed:
        ver = entry["version"]
        if ver in keep_set:
            kept.append(ver)
            continue
        path = Path(entry["install_dir"])
        # Safety: must live under download root
        try:
            path.resolve().relative_to(root.resolve())
        except (ValueError, OSError):
            errors.append(f"refuse prune outside root: {path}")
            continue
        if dry_run:
            removed.append(ver)
            continue
        try:
            shutil.rmtree(path)
            removed.append(ver)
            logger.info("Pruned Logstash version tree %s", path)
        except OSError as e:
            errors.append(f"{ver}: {e}")
            logger.warning("Failed to prune %s: %s", path, e)

    return {"removed": removed, "kept": kept, "errors": errors, "download_root": str(root)}


def format_versions_table(versions: list[dict]) -> str:
    if not versions:
        return "(no Logstash versions installed under download root)"
    lines = [
        f"{'VERSION':<16} {'SIZE':>12}  BINARY",
        "-" * 72,
    ]
    for v in versions:
        size = v.get("size_bytes")
        if size is None:
            size_s = "?"
        elif size >= 1024**3:
            size_s = f"{size / 1024**3:.1f} GiB"
        elif size >= 1024**2:
            size_s = f"{size / 1024**2:.0f} MiB"
        else:
            size_s = f"{size} B"
        lines.append(f"{v.get('version', ''):<16} {size_s:>12}  {v.get('binary', '')}")
    return "\n".join(lines)
