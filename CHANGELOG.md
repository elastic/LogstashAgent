## [0.5.1] - Pure-Python keystore writes and unauthenticated keystores

### Added

- Added pure-Python PKCS#12 keystore create, add, update, and remove support via the vendored `ls_keystore_utils` package (default path; no JVM startup for routine keystore writes).
- Added support for unauthenticated Logstash keystores (default-password trailer mode), matching native `logstash-keystore create` without `LOGSTASH_KEYSTORE_PASS`.
- Added policy and SNMP keystore set/delete when the agent has no stored keystore password (unauthenticated mode).
- Added `set_keystore_password` to upgrade an unauthenticated keystore to authenticated mode when the server provisions a password, preferring secret-preserving migrate over wipe-and-recreate.
- Added `ensure_keystore` and `clear_keystore_password` helpers so future LogstashUI flows can switch keystore password modes without another library redesign (`clear_keystore_password` is not yet wired to check-in).
- Added env-file handling so `LOGSTASH_KEYSTORE_PASS` can be set or cleared in `/etc/default/logstash`.
- Added unit coverage for pure-Python keystore write, unauthenticated keystores, env resolution, and controller password migrate paths.

### Changed

- Synced vendored `ls_keystore_utils` with ls-keystore-utils dockertests (v0.4.0), including `keystore_write.py` and `resolve.py`.
- Keystore write operations default to pure-Python PKCS#12 construction; optional `use_cli=True` retains `logstash-keystore` binary fallback.
- Keystore bag timestamps are tracked in milliseconds for reliable change detection during pure-Python updates.

### Fixed

- Corrected controller comments that incorrectly described merged keystore apply as a single `logstash-keystore add` invocation.

## [0.3.2] - SNMP compatibility

### Added

- Added SNMP management compatibility to Logstash Agent.
- Added support for applying multiple managed solution configurations in a single agent update cycle.
- Added ±10-second jitter to agent check-ins to reduce synchronized polling across large deployments.
- Added logging when Logstash keystore values are cleared.
- Added a post-installation `configure` command for environments where Logstash is installed after the initial Logstash Agent setup.
- Added support for Logstash source installations and other nonstandard installation layouts.
- Added further test coverage for newly introduced SNMP and Logstash Agent functionality.

### Changed

- Updated Logstash compatibility to 9.4.3 for LogstashUI 0.5.x.
- Changed policy application so agent and network policies are combined before being applied, preventing multiple Logstash restarts.
- Refactored policy application to support future solutions managed by Logstash Agent.
- Changed keystore handling so removing values no longer restarts Logstash.
- Keystore changes now restart Logstash only when values are created or updated.
- Normalized keystore key casing to prevent values from being rewritten continuously.
- Updated the installer to repair `/var/log` permissions when Logstash is not installed.
- Removed the requirement for Logstash to be installed and managed through `systemd` during initial setup.
- Updated installation behavior to support source builds and nonstandard Logstash installations.
- Moved controller logger initialization to the top of the module.

### Fixed

- Fixed an incorrect default port in the agent configuration and updated the related documentation.
- Fixed agent policies being applied before network policies, which caused Logstash to restart twice.
- Fixed repeated keystore writes caused by inconsistent key-name casing.
- Fixed installation failures caused by incorrect `/var/log` permissions when Logstash was not already installed.

## [0.3.1] - Simulation Slot Fixes and Port Update - 06/07/2026

### Added

### Changed

- Updated the default LogstashAgent port from `9600` to `9650` to avoid conflicts with Logstash monitoring APIs.

### Fixed

- Fixed an import issue that could occur when simulation slots were being deallocated.
- Fixed an issue where simulation slots were not properly evicted when a new pipeline needed to take over an existing slot.
- Fixed simulation flow so slot eviction properly waits for the new pipeline to be backfilled before continuing.

## [0.3.0] - Logstash Agent - ARM Compatibility - 05/14/2026

### Added

- Added ARM Docker image builds to the GitHub Actions workflow after successful test completion.

### Changed

- Incremented the application version number.
- Updated the preferred Logstash Agent version preemptively for the next release.