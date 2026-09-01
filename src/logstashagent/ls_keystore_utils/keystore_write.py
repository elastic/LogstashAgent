#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Pure-Python PKCS#12 writers for Logstash keystores.

Produces files compatible with Logstash's ``JavaKeyStore`` backend
(OpenJDK PKCS#12 secret bags + SHA-256 MAC), so secrets written here can be
listed, retrieved, added to, and removed by ``logstash-keystore`` / Logstash.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Union

from asn1crypto import keys, pkcs12
from asn1crypto.core import Integer, ObjectIdentifier, OctetString
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .crypto import read_keystore, valid_keystore
from .exceptions import LogstashKeystoreException
from .settings import (
    KEY_NAME_PATTERN,
    KEY_NAME_PATTERN_DESCRIPTION,
    KEYSTORE_SEED,
    MAC_ITERATIONS,
    MAC_SALT_LENGTH,
    PBE_WITH_MD5_AND_DES,
    PBES2_ITERATIONS,
    PBES2_IV_LENGTH,
    PBES2_KEY_LENGTH,
    PBES2_SALT_LENGTH,
    PKCS8_SHROUDED_KEY_BAG,
    URN_PREFIX,
)
from .utils import (
    ascii_bytes_to_chars,
    ascii_chars_to_bytes,
    deobfuscate,
    obfuscate,
    read_file_bytes,
)

logger = logging.getLogger(__name__)

_KEY_NAME_RE = re.compile(KEY_NAME_PATTERN)


def _bmp_password(password: str) -> bytes:
    """Encode password as BMPString with terminating null (PKCS#12 KDF input)."""
    return password.encode("utf-16-be") + b"\x00\x00"


def _pkcs12_kdf(
    password_bmp: bytes,
    salt: bytes,
    iterations: int,
    key_len: int,
    id_byte: int,
    hash_alg: hashes.HashAlgorithm,
) -> bytes:
    """RFC 7292 Appendix B PKCS#12 key-derivation function."""

    def hash_fn(data: bytes) -> bytes:
        digest = hashes.Hash(hash_alg)
        digest.update(data)
        return digest.finalize()

    u = hash_alg.digest_size
    v = 64 if u <= 32 else 128
    diversifier = bytes([id_byte]) * v

    s_block = b""
    if salt:
        s_len = v * ((len(salt) + v - 1) // v)
        while len(s_block) < s_len:
            s_block += salt
        s_block = s_block[:s_len]

    p_block = b""
    if password_bmp:
        p_len = v * ((len(password_bmp) + v - 1) // v)
        while len(p_block) < p_len:
            p_block += password_bmp
        p_block = p_block[:p_len]

    i_block = bytearray(s_block + p_block)
    cycles = (key_len + u - 1) // u
    result = b""
    for _ in range(cycles):
        a_i = hash_fn(diversifier + bytes(i_block))
        for _ in range(1, iterations):
            a_i = hash_fn(a_i)
        result += a_i
        b_block = (a_i * ((v // len(a_i)) + 1))[:v]
        new_i = bytearray()
        for offset in range(0, len(i_block), v):
            chunk = bytes(i_block[offset : offset + v])
            total = int.from_bytes(chunk, "big") + int.from_bytes(b_block, "big") + 1
            new_i += (total % (1 << (v * 8))).to_bytes(v, "big")
        i_block = new_i
    return result[:key_len]


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    raise ValueError(f"DER length too large: {n}")


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _build_private_key_info(base64_secret: bytes) -> bytes:
    """Build PKCS#8 PrivateKeyInfo matching Java PBE SecretKey encoding.

    Structure::

        SEQUENCE {
            INTEGER 0,
            SEQUENCE { OID pbeWithMD5AndDES-CBC },
            OCTET STRING <base64(secret)>
        }
    """
    oid = ObjectIdentifier(PBE_WITH_MD5_AND_DES).dump()
    alg_id = _der_tlv(0x30, oid)
    version = Integer(0).dump()
    privkey = OctetString(base64_secret).dump()
    return _der_tlv(0x30, version + alg_id + privkey)


def _encrypt_pbes2(plaintext: bytes, password: str) -> bytes:
    """Encrypt plaintext with PBES2 (PBKDF2-SHA256 + AES-256-CBC).

    Returns:
        DER-encoded EncryptedPrivateKeyInfo.
    """
    salt = secrets.token_bytes(PBES2_SALT_LENGTH)
    iv = secrets.token_bytes(PBES2_IV_LENGTH)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBES2_KEY_LENGTH,
        salt=salt,
        iterations=PBES2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    epki = keys.EncryptedPrivateKeyInfo(
        {
            "encryption_algorithm": {
                "algorithm": "pbes2",
                "parameters": {
                    "key_derivation_func": {
                        "algorithm": "pbkdf2",
                        "parameters": {
                            "salt": {"specified": salt},
                            "iteration_count": PBES2_ITERATIONS,
                            "key_length": PBES2_KEY_LENGTH,
                            "prf": {"algorithm": "sha256", "parameters": None},
                        },
                    },
                    "encryption_scheme": {
                        "algorithm": "aes256_cbc",
                        "parameters": iv,
                    },
                },
            },
            "encrypted_data": ciphertext,
        }
    )
    return epki.dump()


def _validate_key_name(key_name: str) -> str:
    """Validate and normalize a Logstash secret key name to lowercase."""
    if not isinstance(key_name, str) or not key_name:
        raise ValueError("Key name must be a non-empty string")
    if not _KEY_NAME_RE.match(key_name):
        raise ValueError(
            f"Invalid secret key name `{key_name}`. {KEY_NAME_PATTERN_DESCRIPTION}"
        )
    return key_name.lower()


def _validate_secret_value(value: str, key_name: str) -> str:
    """Validate a secret value (non-empty ASCII, matching CLI rules)."""
    if not isinstance(value, str):
        raise TypeError(f"Secret value for `{key_name}` must be a string")
    if value == "":
        raise ValueError(f"Secret value for `{key_name}` cannot be empty")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"Secret value for `{key_name}` must contain only ASCII characters"
        ) from exc
    return value


def _validate_password(password: str) -> str:
    if not isinstance(password, str) or password == "":
        raise ValueError("Keystore password must be a non-empty string")
    return password


def _make_safe_bag(
    key_name: str,
    secret_value: str,
    password: str,
    timestamp_ms: Optional[int] = None,
) -> pkcs12.SafeBag:
    """Build one Logstash secret SafeBag."""
    key_name = _validate_key_name(key_name)
    secret_value = _validate_secret_value(secret_value, key_name)
    alias = f"{URN_PREFIX}:{key_name}"
    b64_secret = base64.b64encode(secret_value.encode("utf-8"))
    private_key_info = _build_private_key_info(b64_secret)
    encrypted = _encrypt_pbes2(private_key_info, password)
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    secret_bag = pkcs12.SecretBag(
        {
            "secret_type_id": PKCS8_SHROUDED_KEY_BAG,
            "secret_value": encrypted,
        }
    )
    return pkcs12.SafeBag(
        {
            "bag_id": "secret_bag",
            "bag_value": secret_bag,
            "bag_attributes": [
                {"type": "friendly_name", "values": [alias]},
                {
                    "type": "local_key_id",
                    "values": [f"Time {timestamp_ms}".encode("utf-8")],
                },
            ],
        }
    )


def build_keystore_bytes(
    password: str, secrets_map: Optional[Mapping[str, str]] = None
) -> bytes:
    """Build a complete Logstash PKCS#12 keystore as bytes.

    Always includes the ``keystore.seed`` marker bag required by Logstash.

    Args:
        password: Keystore password (non-empty).
        secrets_map: Optional mapping of key name -> secret value.

    Returns:
        DER-encoded PKCS#12 bytes with integrity MAC.
    """
    password = _validate_password(password)
    secrets_map = secrets_map or {}

    all_secrets: Dict[str, str] = {KEYSTORE_SEED: KEYSTORE_SEED}
    for key_name, value in secrets_map.items():
        normalized = _validate_key_name(key_name)
        if normalized == KEYSTORE_SEED:
            raise ValueError(f"Key name `{KEYSTORE_SEED}` is reserved")
        all_secrets[normalized] = _validate_secret_value(value, normalized)

    bags = [
        _make_safe_bag(name, value, password) for name, value in all_secrets.items()
    ]
    safe_contents = pkcs12.SafeContents(bags)
    auth_safe = pkcs12.AuthenticatedSafe(
        [{"content_type": "data", "content": safe_contents.dump()}]
    )
    auth_safe_der = auth_safe.dump()

    mac_salt = secrets.token_bytes(MAC_SALT_LENGTH)
    mac_key = _pkcs12_kdf(
        _bmp_password(password),
        mac_salt,
        MAC_ITERATIONS,
        32,
        3,
        hashes.SHA256(),
    )
    mac_digest = hmac.new(mac_key, auth_safe_der, hashlib.sha256).digest()

    pfx = pkcs12.Pfx(
        {
            "version": "v3",
            "auth_safe": {"content_type": "data", "content": auth_safe_der},
            "mac_data": {
                "mac": {
                    "digest_algorithm": {"algorithm": "sha256", "parameters": None},
                    "digest": mac_digest,
                },
                "mac_salt": mac_salt,
                "iterations": MAC_ITERATIONS,
            },
        }
    )
    return pfx.dump()


def _atomic_write(path: Path, data: bytes) -> None:
    """Write bytes to ``path`` atomically via a same-directory temp file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp_path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o644)
        except OSError:
            # Best-effort; Windows or restricted FS may not support chmod.
            logger.debug("Could not set permissions on %s", path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def generate_default_keystore_password() -> str:
    """Generate a Logstash-style default keystore password.

    Matches ``JavaKeyStore``: 32 random bytes, Base64-encoded to ASCII.

    Returns:
        A 44-character Base64 password string.
    """
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def append_password_trailer(pkcs12_bytes: bytes, password: str) -> bytes:
    """Append Logstash default-password trailer to PKCS#12 bytes.

    Layout (matches ``JavaKeyStore.saveKeyStore`` when ``useDefaultPass``)::

        <pkcs12> || obfuscated_password_bytes || uint8(length)

    Args:
        pkcs12_bytes: DER-encoded PKCS#12 keystore body.
        password: Plain keystore password to embed.

    Returns:
        Full file bytes including trailer.

    Raises:
        ValueError: If the obfuscated password cannot fit in a single length byte.
    """
    password = _validate_password(password)
    obfuscated_chars = obfuscate(password)
    obfuscated_bytes = ascii_chars_to_bytes(obfuscated_chars)
    if len(obfuscated_bytes) > 255:
        raise ValueError(
            "Obfuscated password too long to store in Logstash trailer "
            f"({len(obfuscated_bytes)} > 255)"
        )
    return pkcs12_bytes + obfuscated_bytes + bytes([len(obfuscated_bytes)])


def _verify_pkcs12_mac(pkcs12_bytes: bytes, password: str) -> bool:
    """Return True if the PKCS#12 MAC validates for ``password``."""
    try:
        pfx = pkcs12.Pfx.load(pkcs12_bytes)
    except (ValueError, TypeError):
        return False
    mac_data = pfx["mac_data"]
    if mac_data is None or mac_data.native is None:
        return False
    try:
        mac_salt = mac_data["mac_salt"].native
        iterations = mac_data["iterations"].native
        expected = mac_data["mac"]["digest"].native
        alg = mac_data["mac"]["digest_algorithm"]["algorithm"].native
        auth_safe_der = pfx["auth_safe"]["content"].native
    except (KeyError, TypeError, AttributeError):
        return False

    if alg != "sha256":
        logger.debug("Unsupported PKCS#12 MAC algorithm: %s", alg)
        return False

    mac_key = _pkcs12_kdf(
        _bmp_password(password),
        mac_salt,
        iterations,
        32,
        3,
        hashes.SHA256(),
    )
    actual = hmac.new(mac_key, auth_safe_der, hashlib.sha256).digest()
    return hmac.compare_digest(actual, expected)


def extract_embedded_password(path_or_data: Union[str, Path, bytes]) -> Optional[str]:
    """Extract the default password from a Logstash keystore trailer, if present.

    Unauthenticated Logstash keystores (created without ``LOGSTASH_KEYSTORE_PASS``)
    append an obfuscated password after the PKCS#12 body. This function recovers
    that password when the trailer is valid and the PKCS#12 MAC verifies.

    Args:
        path_or_data: Filesystem path or raw keystore file bytes.

    Returns:
        The plain keystore password if a valid trailer is present, else None.
    """
    if isinstance(path_or_data, (str, Path)):
        data = read_file_bytes(Path(path_or_data))
    else:
        data = path_or_data

    if not data or len(data) < 3:
        return None

    try:
        pfx = pkcs12.Pfx.load(data)
        pkcs12_len = len(pfx.dump())
    except (ValueError, TypeError) as exc:
        logger.debug("Cannot parse PKCS#12 while extracting trailer: %s", exc)
        return None

    if pkcs12_len >= len(data):
        return None

    trailing = data[pkcs12_len:]
    if len(trailing) < 2:
        return None

    length_byte = trailing[-1]
    if length_byte != len(trailing) - 1:
        logger.debug(
            "Trailing data length byte mismatch: byte=%s actual=%s",
            length_byte,
            len(trailing) - 1,
        )
        return None

    obfuscated_bytes = trailing[:-1]
    if len(obfuscated_bytes) % 2 != 0:
        return None

    try:
        password = deobfuscate(ascii_bytes_to_chars(obfuscated_bytes))
    except ValueError as exc:
        logger.debug("Failed to deobfuscate trailer password: %s", exc)
        return None

    pkcs12_bytes = data[:pkcs12_len]
    if not _verify_pkcs12_mac(pkcs12_bytes, password):
        logger.debug("Trailer password failed PKCS#12 MAC verification")
        return None

    return password


def has_embedded_password(path_or_data: Union[str, Path, bytes]) -> bool:
    """Return True if the keystore has a valid default-password trailer."""
    return extract_embedded_password(path_or_data) is not None


def resolve_keystore_password(
    path: Union[str, Path],
    password: Optional[str] = None,
) -> tuple[str, bool]:
    """Resolve the password for a keystore file.

    Args:
        path: Path to the keystore.
        password: Explicit password. When provided, it is used as-is and
            ``embedded`` is False (authenticated write mode).

    Returns:
        Tuple of ``(password, embedded)`` where ``embedded`` is True when the
        password was recovered from the file trailer.

    Raises:
        ValueError: If no password is provided and no valid trailer is found.
        FileNotFoundError: If the keystore path does not exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Keystore not found: {path}")

    if password is not None:
        return _validate_password(password), False

    embedded = extract_embedded_password(path)
    if embedded is not None:
        return embedded, True

    raise ValueError(
        "Password required: keystore has no valid embedded default-password "
        "trailer. Provide password=... or use an unauthenticated keystore."
    )


def _finalize_keystore_bytes(
    pkcs12_bytes: bytes, password: str, *, embed_password: bool
) -> bytes:
    if embed_password:
        return append_password_trailer(pkcs12_bytes, password)
    return pkcs12_bytes


def create_keystore_file(
    path: Union[str, Path],
    password: Optional[str] = None,
    *,
    exist_ok: bool = False,
    embed_password: Optional[bool] = None,
) -> tuple[Path, str, bool]:
    """Create a new empty Logstash keystore (seed marker only).

    Args:
        path: Destination path for ``logstash.keystore``.
        password: Keystore password. If None, a default password is generated
            and embedded in the file trailer (unauthenticated / default-password
            mode, matching ``logstash-keystore create`` without
            ``LOGSTASH_KEYSTORE_PASS``).
        exist_ok: If False (default), raise FileExistsError when path exists.
        embed_password: Whether to append the default-password trailer. Defaults
            to True when ``password`` is None, otherwise False. Pass True with an
            explicit password to force trailer embedding.

    Returns:
        Tuple of ``(path, password_used, embedded)``.

    Raises:
        FileExistsError: If the keystore already exists and exist_ok is False.
        ValueError: If password is invalid.
    """
    path = Path(path)
    if path.exists() and not exist_ok:
        raise FileExistsError(f"Keystore already exists: {path}")

    if password is None:
        password = generate_default_keystore_password()
        if embed_password is None:
            embed_password = True
    else:
        password = _validate_password(password)
        if embed_password is None:
            embed_password = False

    data = _finalize_keystore_bytes(
        build_keystore_bytes(password, {}),
        password,
        embed_password=bool(embed_password),
    )
    _atomic_write(path, data)
    logger.info(
        "Created Logstash keystore at %s (embedded_password=%s)",
        path.resolve(),
        bool(embed_password),
    )
    return path, password, bool(embed_password)


def write_keystore_secrets(
    path: Union[str, Path],
    password: str,
    secrets_map: Mapping[str, str],
    *,
    embed_password: bool = False,
) -> None:
    """Replace all user secrets in the keystore (seed is always rewritten).

    Args:
        path: Path to the keystore file.
        password: Keystore password.
        secrets_map: Full set of user secrets to store (seed added automatically).
        embed_password: If True, append the Logstash default-password trailer so
            the keystore remains usable without ``LOGSTASH_KEYSTORE_PASS``.
    """
    path = Path(path)
    password = _validate_password(password)
    data = _finalize_keystore_bytes(
        build_keystore_bytes(password, secrets_map),
        password,
        embed_password=embed_password,
    )
    _atomic_write(path, data)
    logger.debug(
        "Wrote keystore %s with %d secret(s) (embedded_password=%s)",
        path,
        len(secrets_map),
        embed_password,
    )


def _load_existing_secrets(path: Path, password: str) -> Dict[str, str]:
    """Load existing user secrets (uppercase keys from reader -> lowercase)."""
    if not path.exists():
        raise FileNotFoundError(f"Keystore not found: {path}")
    if not valid_keystore(path):
        raise LogstashKeystoreException(f"Invalid keystore file: {path}")
    existing = read_keystore(path, password)
    return {key.lower(): value for key, (value, _ts) in existing.items()}


def upsert_secrets(
    path: Union[str, Path],
    password: str,
    updates: Mapping[str, str],
    *,
    embed_password: bool = False,
) -> None:
    """Add or overwrite secrets in an existing keystore (or create if missing).

    Args:
        path: Path to the keystore file.
        password: Keystore password.
        updates: Secrets to add or overwrite.
        embed_password: Preserve/write default-password trailer when True.
    """
    path = Path(path)
    password = _validate_password(password)
    if not updates:
        raise ValueError("Cannot add empty dict of keys")

    normalized_updates: Dict[str, str] = {}
    for key_name, value in updates.items():
        normalized = _validate_key_name(key_name)
        if normalized == KEYSTORE_SEED:
            raise ValueError(f"Key name `{KEYSTORE_SEED}` is reserved")
        normalized_updates[normalized] = _validate_secret_value(value, normalized)

    if path.exists():
        secrets_map = _load_existing_secrets(path, password)
    else:
        secrets_map = {}
    secrets_map.update(normalized_updates)
    write_keystore_secrets(
        path, password, secrets_map, embed_password=embed_password
    )
    logger.info(
        "Upserted %d secret(s) in keystore %s", len(normalized_updates), path
    )


def delete_secrets(
    path: Union[str, Path],
    password: str,
    key_names: Iterable[str],
    *,
    embed_password: bool = False,
) -> None:
    """Remove secrets from an existing keystore.

    Args:
        path: Path to the keystore file.
        password: Keystore password.
        key_names: Keys to remove.
        embed_password: Preserve/write default-password trailer when True.

    Raises:
        ValueError: If key_names is empty or a key is not present.
        FileNotFoundError: If the keystore does not exist.
    """
    path = Path(path)
    password = _validate_password(password)
    names = list(key_names)
    if not names:
        raise ValueError("Cannot remove empty list of keys")

    normalized = [_validate_key_name(name) for name in names]
    secrets_map = _load_existing_secrets(path, password)

    missing = [name for name in normalized if name not in secrets_map]
    if missing:
        raise ValueError(
            f"Key(s) not found in keystore: {', '.join(sorted(missing))}"
        )

    for name in normalized:
        del secrets_map[name]

    write_keystore_secrets(
        path, password, secrets_map, embed_password=embed_password
    )
    logger.info("Removed %d secret(s) from keystore %s", len(normalized), path)


def migrate_keystore_password(
    path: Union[str, Path],
    current_password: str,
    new_password: str,
    *,
    embed_password: bool = False,
) -> Dict[str, str]:
    """Re-encrypt a keystore under a new password (optionally drop the trailer).

    Args:
        path: Path to the keystore file.
        current_password: Current keystore password (explicit or from trailer).
        new_password: New password to apply.
        embed_password: If True, write a default-password trailer with
            ``new_password``. If False (default), produce an authenticated
            keystore with no trailer.

    Returns:
        The secrets that were rewritten (lowercase keys).
    """
    path = Path(path)
    current_password = _validate_password(current_password)
    new_password = _validate_password(new_password)
    secrets_map = _load_existing_secrets(path, current_password)
    write_keystore_secrets(
        path, new_password, secrets_map, embed_password=embed_password
    )
    logger.info(
        "Migrated keystore %s to new password (embedded_password=%s, secrets=%d)",
        path,
        embed_password,
        len(secrets_map),
    )
    return secrets_map
