## [0.5.1] - Agent roles, multi-instance, TLS, pure-Python keystores - 08/31/2026

Package version is **0.5.1**. Pair with **LogstashUI 0.5.1**.

### Roles and multi-instance

- Modes: **`packaged`** (production; legacy `default` / `agent` / `host` map here), **`managed`**, **`simulate`**, **`embedded`**.
- Controller waits for enrollment state on start (avoids permanent Offline when the unit starts before state relocate finishes); `get_or_create_agent_id` no longer wipes enrolled fields.
- Simulate **N:** `/opt/logstash-agent/simulate-N/`, units `lsagent-simulate@N` / `ls-simulate@N`, ports **9500+N** / **9560+N**.
- Managed **N:** `/opt/logstash-agent/managed-N/`, units `logstash-agent@N` / `logstash-managed@N`, ports **9600+N** / **9700+N**.
- **Host coexistence:** per-instance state (`LOGSTASH_AGENT_STATE_DIR`) and config (`LOGSTASH_AGENT_CONFIG`); multi-instance yml lives under the instance tree so Packaged `/etc` + `/var/lib` stay untouched.
- Install registry (`/opt/logstash-agent/state/install-registry.json`); CLI `list-instances`; `uninstall --instance simulate-N|managed-N` removes one role (units + path tree); full `uninstall --purge` wipes `/opt/logstash-agent` and the CLI symlink.
- Agent-owned paths consolidated under `/opt/logstash-agent/{bin,config,state,logs,cache}` (no more `/etc`, `/var/lib`, `/var/log`, `/var/cache` for agent data).
- `logstash-agent-ctl` for sudo-rs-safe systemctl (packaged + multi-instance units, numeric instance ids only).
- Install is a full deploy (enable+start agent unit). Distro **`logstash` is enable-only** (never bounced at install).
- Non-root enroll + `setup-simulate` for deferred multi-instance materialize; bare simulate recovery / watchdog for enrolled sim.

### VERSION Logstash pins

- Policy `logstash_source=VERSION` downloads Elastic artifacts into `/opt/logstash-agent/logstash-versions/`.
- Applied on check-in without re-enroll; updates instance `env` `LOGSTASH_BINARY` (simulate and managed) and restarts Logstash when the binary changes.
- CLI: `list-versions`, `ensure-version`, `prune-versions` (keeps pins still in use).

### TLS

- Product-CA trust pin from enrollment fingerprint / well-known `ca.crt` bootstrap (embedded retry loop).
- Agent API served over **HTTPS** with product-CA-signed leaf (CSR at enroll/check-in; SAN drift re-issue).
- **Callback host defaults to non-loopback IPv4** (check-in/enroll `host` + `callback_ip`) so containerized LogstashUI can reach the agent without host DNS. Override with `LOGSTASH_AGENT_CALLBACK_HOST`.

### Keystores

- Pure-Python PKCS#12 keystore create/add/update/remove (default path; optional CLI fallback).
- Unauthenticated keystores; password set/clear/migrate on check-in; env file set/clear for `LOGSTASH_KEYSTORE_PASS`.
- Pre-simulation keystore sync API with compare-and-skip.

### Upgrade notes

- **Production agents do not need to re-enroll.** Upgrade package, restart the unit, confirm `mode=packaged` or `mode=default` in logs.
- Add Simulate/Managed instances with a new policy token (`install --enroll` or enroll + `setup-simulate`); existing Packaged service is left alone.
- Day-2: `logstash-agent list-instances` for a host map.

### Scale testing

- Added `scripts/scale_test.py` — end-to-end scale test that enrolls N agents, collects timing metrics, and generates a markdown report.
- Report includes average, median, min, and max enrollment and check-in latencies per batch.
- Automated mode: iterates over increasing agent counts and accumulates results across runs.
- Batch enrollment is resilient — test continues with however many agents successfully enrolled.

### Fixed

- Fixed additional edge cases in cold-start sequencing that could cause the agent controller to report Offline on fresh installs.


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