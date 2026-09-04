#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Download and extract official Logstash distributions for simulate agents
when policy logstash_source=VERSION.
"""

from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import logging
import os
import platform
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DOWNLOAD_ROOT = "/opt/logstash-agent/logstash-versions"
_LEGACY_DOWNLOAD_ROOT = "/opt/LogstashAgent/logstash-versions"
ARTIFACTS_BASE = "https://artifacts.elastic.co/downloads/logstash"
VIA_UI_ENV = "LOGSTASH_AGENT_LOGSTASH_VIA_UI"
_TRUTHY_FLAGS = {"1", "true", "yes", "on"}

# --- via-UI artifact proxy tuning -------------------------------------------
# Wall-clock cap on a single ensure. On expiry the download fails and the
# caller (controller._version_download_worker) records status=failed; the next
# check-in re-triggers a fresh attempt, and the .part file is kept for resume.
ARTIFACT_DEADLINE_ENV = "LOGSTASH_AGENT_ARTIFACT_DEADLINE_SEC"
DEFAULT_ARTIFACT_DEADLINE_SEC = 3600.0
# Matches the server's 256 KiB streaming chunk.
_DOWNLOAD_CHUNK = 256 * 1024
# Cold cache (503), serve-cap back-pressure (429), upstream failure (502).
_RETRYABLE_STATUSES = frozenset({429, 502, 503})
# Bad key / wrong connection_id, unknown filename, wrong method. Never retry.
_FATAL_STATUSES = frozenset({401, 404, 405})
# Own backoff when the server sends no Retry-After (spec §6).
_BACKOFF_START_SEC = 15.0
_BACKOFF_CEILING_SEC = 300.0
# Discard .part files nobody resumed within this window.
_PARTIAL_MAX_AGE_SEC = 86400.0


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


def _flag_is_true(value) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUTHY_FLAGS


def _agent_state() -> dict:
    try:
        from logstashagent import agent_state as _as

        return _as.get_state() or {}
    except Exception:
        return {}


def logstash_via_ui_enabled(state: Optional[dict] = None) -> bool:
    """Env ``LOGSTASH_AGENT_LOGSTASH_VIA_UI`` wins over state ``logstash_via_ui``."""
    if VIA_UI_ENV in os.environ:
        return _flag_is_true(os.environ.get(VIA_UI_ENV))
    if state is None:
        state = _agent_state()
    return _flag_is_true((state or {}).get("logstash_via_ui"))


def artifact_url(
    version: str,
    platform_arch: Optional[str] = None,
    *,
    via_ui: Optional[bool] = None,
    logstash_ui_url: Optional[str] = None,
    connection_id: Optional[int | str] = None,
    state: Optional[dict] = None,
) -> str:
    """
    Artifact URL for ``version``.

    Elastic: ``{ARTIFACTS_BASE}/{filename}``.
    Via-UI:  ``{logstash_ui_url}/ConnectionManager/LogstashArtifact/{connection_id}/{filename}``

    ``connection_id`` is in the path because a GET carries no body and the agent
    API key is a bare PBKDF2 hash with no lookup column — the server needs it to
    narrow to one row before check_password runs.
    """
    name = artifact_filename(version, platform_arch)
    if via_ui is None:
        via_ui = logstash_via_ui_enabled(state)
    if not via_ui:
        return f"{ARTIFACTS_BASE}/{name}"
    base = (logstash_ui_url or "").strip()
    if not base:
        st = state if state is not None else _agent_state()
        base = ((st or {}).get("logstash_ui_url") or "").strip()
    if not base:
        raise LogstashDownloadError(
            "logstash_via_ui is enabled but logstash_ui_url is missing"
        )
    cid = connection_id
    if cid in (None, ""):
        st = state if state is not None else _agent_state()
        cid = (st or {}).get("connection_id")
    if cid in (None, ""):
        raise LogstashDownloadError(
            "logstash_via_ui is enabled but connection_id is missing"
        )
    return f"{base.rstrip('/')}/ConnectionManager/LogstashArtifact/{cid}/{name}"


def _via_ui_auth_headers(
    api_key: Optional[str] = None, state: Optional[dict] = None
) -> dict:
    key = (api_key or "").strip()
    if not key:
        st = state if state is not None else _agent_state()
        key = ((st or {}).get("api_key") or "").strip()
    if not key:
        raise LogstashDownloadError(
            "logstash_via_ui is enabled but api_key is missing"
        )
    if key.startswith("lsui_"):
        # ApiTokenCsrfMiddleware classifies lsui_-prefixed values as admin tokens
        # and 401s before the artifact view ever runs.
        raise LogstashDownloadError(
            "api_key has an lsui_ prefix (admin token); the artifact proxy needs "
            "the raw enrollment key"
        )
    return {"Authorization": f"ApiKey {key}"}


def _ssl_context():
    from logstashagent.tls_trust import build_ssl_context

    return build_ssl_context()


def _artifact_deadline_sec() -> float:
    """Wall-clock cap for one ensure, overridable via env."""
    raw = os.environ.get(ARTIFACT_DEADLINE_ENV)
    if not raw:
        return DEFAULT_ARTIFACT_DEADLINE_SEC
    try:
        val = float(raw)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid %s=%r; using %.0f s", ARTIFACT_DEADLINE_ENV, raw,
            DEFAULT_ARTIFACT_DEADLINE_SEC,
        )
        return DEFAULT_ARTIFACT_DEADLINE_SEC
    return val if val > 0 else DEFAULT_ARTIFACT_DEADLINE_SEC


def _retry_after_seconds(headers) -> Optional[float]:
    """
    Parse ``Retry-After`` (delta-seconds form) from a response.

    The server's values are tunable constants, so they are honoured verbatim
    rather than hardcoded here. Returns None when absent or unparseable, in
    which case the caller falls back to its own backoff.
    """
    if headers is None:
        return None
    try:
        raw = headers.get("Retry-After")
    except AttributeError:
        return None
    if raw is None:
        return None
    try:
        val = float(str(raw).strip())
    except (TypeError, ValueError):
        # HTTP-date form: not emitted by this server, and guessing is worse
        # than falling back to our own schedule.
        return None
    if val < 0:
        return None
    return min(val, _BACKOFF_CEILING_SEC * 2)


def _own_backoff(attempt: int) -> float:
    """Exponential from 15 s, hard ceiling 300 s (spec §6)."""
    return min(_BACKOFF_START_SEC * (2**max(0, attempt)), _BACKOFF_CEILING_SEC)


def _partial_dir(download_root: str) -> Path:
    return Path(download_root) / ".partial"


def _sweep_stale_partials(
    download_root: str, max_age_sec: float = _PARTIAL_MAX_AGE_SEC
) -> None:
    """Drop .part files nobody resumed — orphans from a killed agent."""
    pdir = _partial_dir(download_root)
    if not pdir.is_dir():
        return
    now = time.time()
    try:
        entries = list(pdir.iterdir())
    except OSError:
        return
    for path in entries:
        if not path.name.endswith(".part"):
            continue
        try:
            age = now - path.stat().st_mtime
        except OSError:
            continue
        if age > max_age_sec:
            try:
                path.unlink()
                logger.info(
                    "Swept stale partial download %s (%.0f h old)", path.name, age / 3600
                )
            except OSError as e:
                logger.debug("Could not sweep %s: %s", path, e)


def _http_error_body(exc: urllib.error.HTTPError, limit: int = 200) -> str:
    """Best-effort short body read for logging. Consumes the error stream."""
    try:
        return exc.read().decode("utf-8", errors="replace").strip()[:limit]
    except Exception:
        return ""


def _log_retryable(code: int, name: str, delay: float, exc: urllib.error.HTTPError) -> None:
    """
    Log a retryable artifact response.

    503 is the *normal* cold-cache answer, so it stays at debug and carries the
    server's real fetch progress. 502 means the upstream fetch failed and is
    logged loudly — retrying also re-triggers the fetch server-side.
    """
    if code == 502:
        logger.error(
            "Artifact proxy upstream fetch failed (502) for %s; retrying in %.0fs: %s",
            name, delay, _http_error_body(exc),
        )
        return
    if code == 503:
        percent = None
        try:
            percent = json.loads(exc.read() or b"{}").get("percent")
        except Exception:
            pass
        if percent is not None:
            logger.debug(
                "Artifact %s not cached yet (server %s%% fetched); retrying in %.0fs",
                name, percent, delay,
            )
        else:
            logger.debug(
                "Artifact %s not cached yet; retrying in %.0fs", name, delay
            )
        return
    logger.debug(
        "Artifact proxy at serve cap (429) for %s; retrying in %.0fs", name, delay
    )


def version_dir_name(version: str) -> str:
    """Directory name for an extracted release (matches Elastic tarball top-level)."""
    v = (version or "").strip()
    if v.startswith("logstash-"):
        return v
    return f"logstash-{v}"


def version_from_dir_name(name: str) -> Optional[str]:
    """
    Map a directory under download_root back to a version string.

    Canonical: ``logstash-9.4.4`` → ``9.4.4``
    Legacy:    ``9.4.4`` → ``9.4.4``
    """
    name = (name or "").strip()
    if not name or name.startswith(".") or name.startswith("ls-download-"):
        return None
    if name.startswith("logstash-"):
        ver = name[len("logstash-") :]
        return ver or None
    # Legacy bare version directory
    if name[0].isdigit():
        return name
    return None


def version_install_dir(version: str, download_root: str = DEFAULT_DOWNLOAD_ROOT) -> Path:
    """
    Canonical install dir: ``<download_root>/logstash-<version>``.

    (No extra ``<version>/`` wrapper — the tarball already names the tree.)
    """
    return Path(download_root) / version_dir_name(version)


def resolve_logstash_binary(
    version: str, download_root: str = DEFAULT_DOWNLOAD_ROOT
) -> Path:
    """
    Path to bin/logstash inside an extracted version tree.

    Layouts accepted (first match wins):
      - canonical: ``<root>/logstash-<ver>/bin/logstash``
      - legacy:    ``<root>/<ver>/logstash-<ver>/bin/logstash``
      - legacy:    ``<root>/<ver>/bin/logstash``
    """
    root = Path(download_root)
    ver = (version or "").strip()
    candidates = [
        version_install_dir(ver, download_root) / "bin" / "logstash",
        root / ver / f"logstash-{ver}" / "bin" / "logstash",
        root / ver / "bin" / "logstash",
        root / f"logstash-{ver}" / "bin" / "logstash",
    ]
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    # Non-executable is still usable if present (perms fixed later)
    for path in candidates:
        if path.is_file():
            return path
    raise LogstashDownloadError(
        f"Logstash binary not found under {download_root} for version {ver}"
    )


def version_is_present(version: str, download_dir: str) -> bool:
    """True if ``resolve_logstash_binary`` finds a file; False on LogstashDownloadError."""
    try:
        resolve_logstash_binary(version, download_dir)
        return True
    except LogstashDownloadError:
        return False


def chown_tree_to_logstash(path: Path | str) -> None:
    """
    Recursively chown a VERSION tree (or download root) to logstash:logstash.

    Logstash runs as the logstash user and must read its own install tree.
    Downloads run as root during agent install/ensure-version.
    """
    path = Path(path)
    if not path.exists():
        return
    try:
        import grp
        import pwd

        if os.geteuid() != 0:
            return
        uid = pwd.getpwnam("logstash").pw_uid
        gid = grp.getgrnam("logstash").gr_gid
    except (AttributeError, KeyError, OSError, ImportError):
        logger.debug("Skipping chown of %s (no logstash user or not root)", path)
        return
    for walk_root, dirs, files in os.walk(path):
        try:
            os.chown(walk_root, uid, gid)
        except OSError as e:
            logger.debug("chown %s: %s", walk_root, e)
        for name in dirs + files:
            try:
                os.chown(os.path.join(walk_root, name), uid, gid)
            except OSError:
                pass
    logger.info("✓ Ownership set to logstash on %s", path)


def _download_file(
    url: str,
    dest: Path,
    timeout: int = 600,
    headers: Optional[dict] = None,
    *,
    via_ui: bool = False,
    download_root: Optional[str] = None,
) -> None:
    """
    Download ``url`` to ``dest``.

    Elastic (``via_ui=False``): single-shot stream, as before.

    Via-UI: resumable and retrying. Bytes land in ``<download_root>/.partial/
    <name>.part`` — a stable path that survives an agent restart, so a death at
    440/450 MB resumes with ``Range`` instead of re-pulling everything. 503/429/
    502 are retried honouring ``Retry-After``; 401/404/405 fail immediately; 416
    means the partial is wrong, so it is discarded and restarted from zero.

    There is deliberately no fallback to ``artifacts.elastic.co``: a visible
    retry loop is correct, and reaching the internet would defeat both the
    bandwidth saving and air-gapped operation.
    """
    if not via_ui or not download_root:
        logger.info("Downloading %s -> %s", url, dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        target: str | urllib.request.Request = (
            urllib.request.Request(url, headers=headers) if headers else url
        )
        try:
            with urllib.request.urlopen(
                target, timeout=timeout, context=_ssl_context()
            ) as resp, open(dest, "wb") as out:
                shutil.copyfileobj(resp, out)
        except Exception as exc:
            raise LogstashDownloadError(f"Download failed for {url}: {exc}") from exc
        return

    pdir = _partial_dir(download_root)
    pdir.mkdir(parents=True, exist_ok=True)
    part = pdir / f"{dest.name}.part"
    dest.parent.mkdir(parents=True, exist_ok=True)

    deadline = time.monotonic() + _artifact_deadline_sec()
    attempt = 0
    discard_partial = False
    logger.info("Downloading %s -> %s (via UI artifact proxy)", url, dest)

    while True:
        if time.monotonic() >= deadline:
            raise LogstashDownloadError(
                f"Artifact download deadline exceeded for {dest.name}; "
                f"partial retained at {part} for resume"
            )

        if discard_partial:
            try:
                part.unlink()
            except OSError:
                pass
            discard_partial = False
            attempt = 0

        try:
            offset = part.stat().st_size
        except OSError:
            offset = 0

        req_headers = dict(headers or {})
        if offset > 0:
            # Single range only — multi-range is answered with a full 200.
            req_headers["Range"] = f"bytes={offset}-"

        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(
                req, timeout=timeout, context=_ssl_context()
            ) as resp:
                status = getattr(resp, "status", 200)
                if status == 206:
                    logger.info(
                        "Resuming %s from byte %d", dest.name, offset
                    )
                    mode = "ab"
                else:
                    # 200: whole file, whether or not we asked for a range.
                    if offset > 0:
                        logger.debug(
                            "Server sent 200 for a ranged request; restarting %s from 0",
                            dest.name,
                        )
                    mode = "wb"
                with open(part, mode) as out:
                    while True:
                        chunk = resp.read(_DOWNLOAD_CHUNK)
                        if not chunk:
                            break
                        out.write(chunk)
        except urllib.error.HTTPError as exc:
            code = exc.code

            if code == 416:
                logger.warning(
                    "Range past EOF for %s (partial was %d B) — discarding and restarting",
                    dest.name,
                    offset,
                )
                discard_partial = True
                continue

            if code in _FATAL_STATUSES:
                raise LogstashDownloadError(
                    f"HTTP {code} from artifact proxy for {url}: "
                    f"{_http_error_body(exc)}"
                ) from exc

            if code in _RETRYABLE_STATUSES:
                delay = _retry_after_seconds(exc.headers)
                if delay is None:
                    delay = _own_backoff(attempt)
                _log_retryable(code, dest.name, delay, exc)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    continue
                time.sleep(min(delay, remaining))
                attempt += 1
                continue

            raise LogstashDownloadError(
                f"HTTP {code} from artifact proxy for {url}: "
                f"{_http_error_body(exc)}"
            ) from exc
        except (OSError, http.client.IncompleteRead) as exc:
            # Connection reset / timeout / truncated read mid-transfer. The bytes
            # already in .part are kept, so this resumes rather than re-pulling.
            # Narrowly typed on purpose: a TypeError here must not loop for an
            # hour. (URLError, ConnectionError and TimeoutError are all OSError.)
            delay = _own_backoff(attempt)
            logger.warning(
                "Transfer of %s interrupted (%s); resuming in %.0fs",
                dest.name, exc, delay,
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                continue
            time.sleep(min(delay, remaining))
            attempt += 1
            continue
        except Exception as exc:
            raise LogstashDownloadError(f"Download failed for {url}: {exc}") from exc

        # The .part lives under download_root; dest is usually a tmpfs temp dir,
        # so copy rather than os.replace (which cannot cross filesystems).
        try:
            shutil.copy2(part, dest)
        except OSError as exc:
            raise LogstashDownloadError(
                f"Could not stage downloaded {dest.name}: {exc}"
            ) from exc
        try:
            part.unlink()
        except OSError:
            pass
        return


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_sha512(
    tarball: Path,
    sha_url: str,
    timeout: int = 60,
    headers: Optional[dict] = None,
    required: bool = False,
) -> None:
    """
    Verify tarball against the .sha512 sidecar at ``sha_url`` (same origin as the artifact).

    When ``required`` is False (Elastic), sidecar fetch failure is non-fatal.
    When True (via-UI), fetch failure raises LogstashDownloadError, and a cold
    cache (503/502) is retried honouring ``Retry-After``. Sidecars are exempt
    from the server's serve semaphore, so 429 is unlikely but handled anyway.

    The server always has a .sha512 to serve once the row is READY — stored
    verbatim when upstream published one, otherwise written from the digest the
    server computed — so verification is never skipped on the via-UI path.
    """
    def _fetch() -> str:
        target: str | urllib.request.Request = (
            urllib.request.Request(sha_url, headers=headers) if headers else sha_url
        )
        with urllib.request.urlopen(
            target, timeout=timeout, context=_ssl_context()
        ) as resp:
            return resp.read().decode("utf-8", errors="replace").strip()

    if not required:
        try:
            text = _fetch()
        except Exception as exc:
            logger.warning(
                "Could not fetch checksum %s: %s (skipping verify)", sha_url, exc
            )
            return
    else:
        deadline = time.monotonic() + _artifact_deadline_sec()
        attempt = 0
        while True:
            if time.monotonic() >= deadline:
                raise LogstashDownloadError(
                    f"Deadline exceeded fetching checksum {sha_url}"
                )
            try:
                text = _fetch()
                break
            except urllib.error.HTTPError as exc:
                if exc.code not in _RETRYABLE_STATUSES:
                    raise LogstashDownloadError(
                        f"Could not fetch checksum {sha_url}: {exc}"
                    ) from exc
                delay = _retry_after_seconds(exc.headers)
                if delay is None:
                    delay = _own_backoff(attempt)
                _log_retryable(exc.code, f"{tarball.name}.sha512", delay, exc)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    continue
                time.sleep(min(delay, remaining))
                attempt += 1
            except Exception as exc:
                raise LogstashDownloadError(
                    f"Could not fetch checksum {sha_url}: {exc}"
                ) from exc

    # Format is typically: "<hex>  filename" or just hex
    expected = text.split()[0].lower()
    actual = _sha512_file(tarball).lower()
    if expected != actual:
        raise LogstashDownloadError(
            f"SHA-512 mismatch for {tarball.name}: expected {expected[:16]}… got {actual[:16]}…"
        )
    logger.info("✓ Verified SHA-512 for %s", tarball.name)


def version_lock_path(download_root: str, version: str) -> Path:
    safe = (version or "").strip().replace("/", "_").replace("..", "_")
    return Path(download_root) / f".lock-logstash-{safe}"


@contextmanager
def _exclusive_version_lock(download_root: str, version: str):
    """Exclusive flock for one Logstash version tree. Released on process death."""
    root = Path(download_root)
    root.mkdir(parents=True, exist_ok=True)
    lock_path = version_lock_path(download_root, version)
    fh = open(lock_path, "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        fh.close()


def ensure_logstash_version(
    version: str,
    download_root: str = DEFAULT_DOWNLOAD_ROOT,
    *,
    platform_arch: Optional[str] = None,
    force: bool = False,
    logstash_ui_url: Optional[str] = None,
    api_key: Optional[str] = None,
    connection_id: Optional[int | str] = None,
) -> Path:
    """
    Ensure Logstash ``version`` is present under download_root.

    Returns path to the logstash binary.
    Idempotent: skips download if binary already resolves.
    """
    version = (version or "").strip()
    if not version:
        raise LogstashDownloadError("logstash_version is empty")

    download_root = normalize_download_dir(download_root or DEFAULT_DOWNLOAD_ROOT)
    with _exclusive_version_lock(download_root, version):
        return _ensure_logstash_version_locked(
            version,
            download_root,
            platform_arch=platform_arch,
            force=force,
            logstash_ui_url=logstash_ui_url,
            api_key=api_key,
            connection_id=connection_id,
        )


def _ensure_logstash_version_locked(
    version: str,
    download_root: str = DEFAULT_DOWNLOAD_ROOT,
    *,
    platform_arch: Optional[str] = None,
    force: bool = False,
    logstash_ui_url: Optional[str] = None,
    api_key: Optional[str] = None,
    connection_id: Optional[int | str] = None,
) -> Path:
    root = Path(download_root)
    install_dir = version_install_dir(version, download_root)

    if not force:
        try:
            binary = resolve_logstash_binary(version, download_root)
            # Heal ownership on already-present trees (root-owned downloads)
            chown_tree_to_logstash(binary.parent.parent)
            logger.info("Logstash %s already present at %s", version, binary)
            return binary
        except LogstashDownloadError:
            pass

    platform_arch = platform_arch or detect_platform_arch()
    via_ui = logstash_via_ui_enabled()
    state = _agent_state() if via_ui else None
    if via_ui:
        _sweep_stale_partials(download_root)
    url = artifact_url(
        version,
        platform_arch,
        via_ui=via_ui,
        logstash_ui_url=logstash_ui_url,
        connection_id=connection_id,
        state=state,
    )
    sha_url = url + ".sha512"
    headers = _via_ui_auth_headers(api_key, state=state) if via_ui else None
    sha_timeout = 600 if via_ui else 60

    # Extract into download_root so the tarball top-level becomes
    #   logstash-versions/logstash-<version>/
    # (not logstash-versions/<version>/logstash-<version>/)
    root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ls-download-") as tmp:
        tmp_path = Path(tmp)
        tarball = tmp_path / artifact_filename(version, platform_arch)
        _download_file(
            url,
            tarball,
            headers=headers,
            via_ui=via_ui,
            download_root=download_root,
        )
        _verify_sha512(
            tarball,
            sha_url,
            timeout=sha_timeout,
            headers=headers,
            required=via_ui,
        )

        # Remove partial/legacy trees for this version before extract
        legacy_nested = root / version
        for stale in (install_dir, legacy_nested):
            if stale.is_dir() and force:
                shutil.rmtree(stale, ignore_errors=True)

        logger.info("Extracting %s into %s (flat logstash-%s/ layout)", tarball.name, root, version)
        try:
            with tarfile.open(tarball, "r:gz") as tar:
                # Python 3.12+ filter= for safer extract; fall back if unavailable
                try:
                    tar.extractall(path=root, filter="data")
                except TypeError:
                    tar.extractall(path=root)
        except Exception as exc:
            raise LogstashDownloadError(f"Failed to extract {tarball}: {exc}") from exc

    binary = resolve_logstash_binary(version, download_root)
    try:
        os.chmod(binary, 0o755)
    except OSError:
        pass
    # Entire version tree must be readable by the logstash service user
    chown_tree_to_logstash(binary.parent.parent)
    chown_tree_to_logstash(root)
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
        ver = version_from_dir_name(name)
        if not ver:
            continue
        vdir = root / name
        if not vdir.is_dir():
            continue
        try:
            binary = resolve_logstash_binary(ver, str(root))
        except LogstashDownloadError:
            nested = list(vdir.glob("logstash-*/bin/logstash"))
            if nested and nested[0].is_file():
                binary = nested[0]
                # Prefer nested dir as install_dir when legacy wrapper present
                vdir = nested[0].parent.parent
            else:
                continue
        size = None
        try:
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
                "version": ver,
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
                            # .../logstash-versions/logstash-<ver>/bin/logstash
                            # or legacy .../logstash-versions/<ver>/...
                            parts = Path(b).parts
                            if "logstash-versions" in parts:
                                i = parts.index("logstash-versions")
                                if i + 1 < len(parts):
                                    ver = version_from_dir_name(parts[i + 1])
                                    if ver:
                                        used.add(ver)
                                    else:
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
