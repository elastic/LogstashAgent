#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

import logging
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# Note: This module encrypts agent-local credentials (e.g. api_key, optional
# keystore_password in state.json). It is not related to Logstash PKCS#12
# keystore cryptography. Unauthenticated Logstash keystores simply omit
# keystore_password from agent state; encrypt_credential/decrypt_credential
# pass through empty/None values unchanged.


def _logstash_uid_gid() -> tuple[int, int] | None:
    """
    Resolve logstash:logstash without importing installer (avoids circular imports
    that previously caused silent chown skips during enroll/install).
    """
    try:
        import grp
        import pwd

        if os.geteuid() != 0:
            return None
        pw = pwd.getpwnam("logstash")
        gr = grp.getgrnam("logstash")
        return int(pw.pw_uid), int(gr.gr_gid)
    except (AttributeError, KeyError, OSError, ImportError):
        return None


def _chown_to_logstash(path: Path) -> bool:
    """
    Chown path (and parent dir) to logstash:logstash when running as root.

    Returns True if ownership was applied (or already non-root process).
    """
    ids = _logstash_uid_gid()
    if ids is None:
        return False
    uid, gid = ids
    ok = True
    for target in (path, path.parent):
        try:
            if target.exists():
                os.chown(target, uid, gid)
        except OSError as e:
            logger.warning("Could not chown %s to logstash (%s:%s): %s", target, uid, gid, e)
            ok = False
    return ok


def _write_secret_key_file(key_file: Path, key: bytes) -> None:
    """
    Atomically write ``.secret_key`` as mode 0600 owned by logstash when root.

    Pattern: temp file in the same directory → fchmod/fchown → os.replace.
    That way a root-owned 0600 key is never left behind for the logstash service.
    """
    key_file = Path(key_file)
    parent = key_file.parent
    parent.mkdir(parents=True, exist_ok=True)

    ids = _logstash_uid_gid()
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=".secret_key.",
            dir=str(parent),
        )
        os.write(fd, key)
        os.fchmod(fd, 0o600)
        if ids is not None:
            os.fchown(fd, ids[0], ids[1])
        os.close(fd)
        fd = None
        os.replace(tmp_path, key_file)
        tmp_path = None
        # Final assert on the durable path (replace preserves inode on some FS)
        os.chmod(key_file, 0o600)
        if ids is not None:
            os.chown(key_file, ids[0], ids[1])
            try:
                os.chown(parent, ids[0], ids[1])
            except OSError:
                pass
        logger.info(
            "Generated new encryption key and saved to %s (owner=%s)",
            key_file,
            "logstash" if ids else "current-user",
        )
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def get_encryption_key():
    """
    Get or generate the encryption key for credential storage.

    Priority:
    1. Environment variable CREDENTIAL_KEY
    2. Key file in state dir /.secret_key
    3. Generate new key and save to state dir /.secret_key

    Returns:
        bytes: The encryption key

    Raises:
        RuntimeError: If key cannot be loaded or generated
    """
    try:
        # Check for environment variable first
        env_key = os.environ.get("CREDENTIAL_KEY")
        if env_key:
            try:
                Fernet(env_key.encode())
                return env_key.encode()
            except Exception as e:
                logger.error(f"Invalid CREDENTIAL_KEY in environment: {e}")
                raise RuntimeError(f"Invalid CREDENTIAL_KEY format: {e}")

        # Prefer the active agent state directory (packaged or per-instance)
        try:
            from logstashagent import agent_state as _agent_state

            key_file = _agent_state.resolve_state_dir() / ".secret_key"
        except Exception:
            if os.path.isdir("/opt/logstash-agent/state"):
                key_file = Path("/opt/logstash-agent/state") / ".secret_key"
            elif os.path.isdir("/var/lib/logstash-agent"):
                key_file = Path("/var/lib/logstash-agent") / ".secret_key"
            else:
                base_dir = Path(__file__).resolve().parent
                key_file = base_dir / "data" / ".secret_key"

        if key_file.exists():
            # Self-heal root-owned keys left by install/enroll as root (only works as root)
            _chown_to_logstash(key_file)
            try:
                with open(key_file, "rb") as f:
                    key = f.read()
                Fernet(key)
                return key
            except PermissionError:
                # Still unreadable (e.g. service already running as logstash) — surface clearly
                st = None
                try:
                    st = key_file.stat()
                except OSError:
                    pass
                owner = f"uid={st.st_uid} mode={oct(st.st_mode & 0o777)}" if st else "unknown"
                logger.error(
                    "Permission denied reading encryption key file: %s (%s). "
                    "Fix with: sudo chown logstash:logstash %s && sudo chmod 600 %s",
                    key_file,
                    owner,
                    key_file,
                    key_file,
                )
                raise RuntimeError(
                    f"Cannot read encryption key file: Permission denied ({key_file}). "
                    f"Run as root: chown logstash:logstash {key_file} && chmod 600 {key_file}"
                )
            except Exception as e:
                logger.error(f"Error reading or validating encryption key from {key_file}: {e}")
                raise RuntimeError(f"Invalid encryption key in file: {e}")

        # Generate + write with correct ownership in one step
        key = Fernet.generate_key()
        try:
            _write_secret_key_file(key_file, key)
        except PermissionError:
            logger.error(f"Permission denied writing to key file: {key_file}")
            raise RuntimeError("Cannot write encryption key: Permission denied")
        except Exception as e:
            logger.error(f"Error writing encryption key: {e}")
            raise RuntimeError(f"Cannot write encryption key: {e}")

        return key
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in get_encryption_key: {e}")
        raise RuntimeError(f"Failed to get encryption key: {e}")


def ensure_secret_key_ownership(state_dir: str | Path | None = None) -> None:
    """
    Chown every ``.secret_key`` under a state dir (or all instance trees).

    Call from install/setup after enroll-as-root so the logstash service can read keys.
    """
    ids = _logstash_uid_gid()
    if ids is None:
        return
    uid, gid = ids
    roots: list[Path] = []
    if state_dir is not None:
        roots.append(Path(state_dir))
    else:
        try:
            from logstashagent import agent_state as _agent_state

            roots.append(Path(_agent_state.resolve_state_dir()))
        except Exception:
            pass
        opt = Path("/opt/logstash-agent")
        if opt.is_dir():
            roots.append(opt / "state")
            for child in opt.iterdir():
                if child.is_dir() and (
                    child.name.startswith("simulate-") or child.name.startswith("managed-")
                ):
                    roots.append(child / "state")

    seen: set[Path] = set()
    for root in roots:
        try:
            root = root.resolve()
        except OSError:
            continue
        if root in seen or not root.is_dir():
            continue
        seen.add(root)
        key = root / ".secret_key"
        if not key.is_file():
            continue
        try:
            os.chown(key, uid, gid)
            os.chmod(key, 0o600)
            os.chown(root, uid, gid)
            logger.info("Fixed ownership on %s → logstash:%s", key, gid)
        except OSError as e:
            logger.warning("Could not fix ownership on %s: %s", key, e)


def encrypt_credential(plaintext):
    """
    Encrypt a credential string.

    Args:
        plaintext (str): The plaintext credential to encrypt

    Returns:
        str: Base64-encoded encrypted credential, or None if encryption fails

    Raises:
        ValueError: If plaintext is not a string
        RuntimeError: If encryption fails
    """
    if not plaintext:
        return plaintext

    if not isinstance(plaintext, str):
        raise ValueError(f"plaintext must be a string, got {type(plaintext).__name__}")

    try:
        key = get_encryption_key()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(plaintext.encode())
        return encrypted.decode()
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(f"Error encrypting credential: {e}")
        raise RuntimeError(f"Encryption failed: {e}")


def decrypt_credential(encrypted_text):
    """
    Decrypt a credential string.

    Args:
        encrypted_text (str): The encrypted credential

    Returns:
        str: Decrypted plaintext credential, or None if decryption fails

    Raises:
        ValueError: If encrypted_text is not a string or is invalid
        RuntimeError: If decryption fails
    """
    if not encrypted_text:
        return encrypted_text

    if not isinstance(encrypted_text, str):
        raise ValueError(f"encrypted_text must be a string, got {type(encrypted_text).__name__}")

    try:
        key = get_encryption_key()
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()
    except InvalidToken:
        logger.error("Failed to decrypt credential: Invalid token or wrong encryption key")
        raise ValueError("Cannot decrypt credential: Invalid token or wrong encryption key")
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(f"Error decrypting credential: {e}")
        raise RuntimeError(f"Decryption failed: {e}")
