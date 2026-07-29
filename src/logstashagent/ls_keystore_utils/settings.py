#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""
Common location for settings and constants used across the ls-keystore-utils package.

Install / environment topology lives here (single source of truth). Resolution
behavior is in :mod:`ls_keystore_utils.resolve`. Cryptographic and keystore
format constants follow below.
"""

# ---------------------------------------------------------------------------
# Environment variable names
# ---------------------------------------------------------------------------

ENV_LOGSTASH_HOME = "LOGSTASH_HOME"
ENV_LOGSTASH_KEYSTORE_BIN = "LOGSTASH_KEYSTORE_BIN"
ENV_LOGSTASH_PATH_SETTINGS = "LOGSTASH_PATH_SETTINGS"
ENV_PATH_SETTINGS_ALIAS = "PATH_SETTINGS"
ENV_LOGSTASH_ENV_FILE = "LOGSTASH_ENV_FILE"
ENV_LOGSTASH_KEYSTORE_PASS = "LOGSTASH_KEYSTORE_PASS"

# ---------------------------------------------------------------------------
# Package / tarball install defaults (strings; convert with Path at use site)
# ---------------------------------------------------------------------------

DEFAULT_PACKAGE_HOME = "/usr/share/logstash"
DEFAULT_PACKAGE_KEYSTORE_BIN = f"{DEFAULT_PACKAGE_HOME}/bin/logstash-keystore"
# RPM/DEB path.settings (not $LOGSTASH_HOME/config)
DEFAULT_PACKAGE_PATH_SETTINGS = "/etc/logstash"
# Tarball / share layout config dir
DEFAULT_SHARE_CONFIG = f"{DEFAULT_PACKAGE_HOME}/config"
# RPM/DEB: systemd EnvironmentFile= order (later files override earlier keys).
# Matches: EnvironmentFile=-/etc/default/logstash then -/etc/sysconfig/logstash
DEFAULT_PACKAGE_ENV_FILES = (
    "/etc/default/logstash",
    "/etc/sysconfig/logstash",
)
# Last file in the systemd order (common Red Hat path); prefer DEFAULT_PACKAGE_ENV_FILES.
DEFAULT_PACKAGE_ENV_FILE = DEFAULT_PACKAGE_ENV_FILES[-1]

# ---------------------------------------------------------------------------
# Homebrew layout
# ---------------------------------------------------------------------------

HOME_BREW_LS_PATH = "/opt/homebrew/Cellar/logstash"
HOME_BREW_LS_CFG = "/opt/homebrew/etc/logstash"
HOME_BREW_PATTERN = f"{HOME_BREW_LS_PATH}/*/libexec/bin/logstash-keystore"

# ---------------------------------------------------------------------------
# Derived search lists (built from the primitives above — do not hardcode paths)
# ---------------------------------------------------------------------------

PATTERNS = [DEFAULT_PACKAGE_KEYSTORE_BIN, HOME_BREW_PATTERN]
CANDIDATES = [DEFAULT_PACKAGE_PATH_SETTINGS, DEFAULT_SHARE_CONFIG]
ALTERNATE_LS_PATHS = {HOME_BREW_LS_PATH: HOME_BREW_LS_CFG}

# ---------------------------------------------------------------------------
# Cryptographic constants for PKCS#12 parsing and generation
# ---------------------------------------------------------------------------

# OID constants for better readability
PBES2 = "pbes2"
AES128 = "2.16.840.1.101.3.4.1.2"
AES192 = "2.16.840.1.101.3.4.1.22"
AES256 = "2.16.840.1.101.3.4.1.42"

# Bag type OIDs
KEY_BAG = "1.2.840.113549.1.12.10.1.1"
PKCS8_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2"
SECRET_BAG = "1.2.840.113549.1.12.10.1.3"
CERT_BAG = "1.2.840.113549.1.12.10.1.5"

# Attribute type constants
FRIENDLY_NAME = "friendly_name"
FRIENDLY_NAME_OID = "1.2.840.113549.1.9.20"
LOCAL_KEY_ID = "local_key_id"
LOCAL_KEY_ID_OID = "1.2.840.113549.1.9.21"

ATTR_TYPES = (FRIENDLY_NAME, FRIENDLY_NAME_OID, LOCAL_KEY_ID, LOCAL_KEY_ID_OID)

# AES key length mapping
AES_KEY_LENGTHS = {
    AES128: 16,
    AES192: 24,
    AES256: 32,
}

# Salt/IV filename
SALT_IV_FILENAME = ".salt-iv"

# Password obfuscation heuristic
OBFUSCATION_KEY = b"logstash_keystore_obfuscation_key"
PASSWORD_OBFUSCATED_LENGTH = 32

# Bag alias constants
URN_PREFIX = "urn:logstash:secret:v1"
KEYSTORE_SEED = "keystore.seed"
KEYSTORE_ALIAS = URN_PREFIX + ":" + KEYSTORE_SEED

# Attribute subsets: friendlyName is the bag alias; localKeyId holds timestamps.
FRIENDLY_NAME_ATTR_TYPES = (FRIENDLY_NAME, FRIENDLY_NAME_OID)
LOCAL_KEY_ID_ATTR_TYPES = (LOCAL_KEY_ID, LOCAL_KEY_ID_OID)

# Pure-Python write constants (match OpenJDK / Logstash 9.x PKCS#12 output)
PBE_WITH_MD5_AND_DES = "1.2.840.113549.1.5.3"
PBES2_ITERATIONS = 10000
PBES2_KEY_LENGTH = 32
PBES2_SALT_LENGTH = 20
PBES2_IV_LENGTH = 16
MAC_ITERATIONS = 10000
MAC_SALT_LENGTH = 20

# Logstash key-name rules (ConfigVariableExpander.KEY_PATTERN)
KEY_NAME_PATTERN = r"^[a-zA-Z_.][a-zA-Z0-9_.]*$"
KEY_NAME_PATTERN_DESCRIPTION = (
    "Key names are limited to ASCII letters (a-z, A-Z), numbers (0-9), "
    "underscores (_), and dots (.); they must be at least one character long "
    "and cannot begin with a number"
)

# ### Not apparently needed for Logstash keystore operations
# ### May be useful if the keystore standard changes
# PBE_WITH_SHA1_3DES = "1.2.840.113549.1.12.1.3"
