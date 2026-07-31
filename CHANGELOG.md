## [0.5.2] - Packaged / Managed modes, install registry, host coexistence - 07/30/2026

### Added

- First-class **`packaged`** and **`managed`** modes (alongside `simulate` / `embedded`). Legacy `default` remains accepted; `agent`/`host` map to **packaged**.
- Systemd templates **`logstash-agent@.service`** and **`logstash-managed@.service`** for Managed instance **N** (paths under `/opt/logstash-agent/managed-N/`; ports **9600+N** / **9700+N**).
- **Install registry** at `/var/lib/logstash-agent/install-registry.json` — package + instance inventory (units, path_root, ports).
- CLI: `list-instances`, `list-versions`, `ensure-version <ver>`, `prune-versions` (VERSION cache; keeps pins in use).
- Uninstall uses the registry: stop multi-instance units, optional `--instance ID`, `--purge` removes trees + state.
- **Host coexistence**: per-instance `LOGSTASH_AGENT_STATE_DIR` / `LOGSTASH_AGENT_CONFIG` in `agent.env`; multi-instance config under the instance tree (does not clobber packaged `/etc` or `/var/lib` state). Packaged install still ships multi-instance unit templates for later enrolls.
- VERSION apply updates **managed** as well as simulate instance `env` (`LOGSTASH_BINARY`); check-in `status_blob` reports resolved version/binary.
- `logstash-agent-ctl` allowlist includes `logstash-agent@N` and `logstash-managed@N` (numeric ids; sudo-rs safe).
- Offline E2E smoke suite (`tests/test_e2e_agent_modes_smoke.py`) for isolation, registry, materialize, VERSION prune.

### Changed

- Install config writes `mode: packaged` (or `managed` / `simulate`) instead of only `default` / `simulate`.
- Multi-instance materialize writes isolation env vars and relocates enrollment state into the instance tree when coexisting with Packaged.
- PyInstaller ships all four multi-instance unit templates (simulate + managed).

### Upgrade notes

- Pair with **LogstashUI 0.5.2** (Packaged/Managed policies, migration 0025).
- **Existing production agents:** upgrade package and restart `logstash-agent` — **no re-enroll** required. Look for `mode=packaged` or `mode=default` in logs.
- Adding Managed/Simulate on a host that already has Packaged: enroll the new policy token with `install --enroll` (or non-root enroll + `setup-simulate`); packaged service and state are left in place.
- Day-2: `logstash-agent list-instances` for a host map; `sudo logstash-agent uninstall --instance managed-N` to drop one multi-instance role only.

## [0.5.1] - Agent roles (default / simulate / embedded) and pure-Python keystores

### Added

- Added first-class agent **roles/modes**: `default` (production), `simulate` (enrolled simulation instances), and `embedded` (Docker-local sim).
- Added simulate instance layout under `/opt/logstash-agent/simulate-N/` with isolated `--path.settings|config|logs|data`.
- Added systemd templates `lsagent-simulate@.service` and `ls-simulate@.service` for numbered simulate instances.
- Added enrollment `policy_config` fields for simulate: `instance_id`, ports (`9500+N` / `9560+N`), path bundle, units, `logstash_source` / version download dir.
- Added `logstash_download.py` to fetch pinned Logstash versions from Elastic artifacts when policy `logstash_source=VERSION`.
- Added `POST /_logstash/keystore/sync` and `GET /_logstash/keystore` for pre-simulation keystore clone with **compare-and-skip** (no write/restart when secrets already match).
- Added CLI `--mode` and `--instance` for simulate runtime.
- Added startup log lines such as `mode=default (legacy 'agent' mapped)` so upgraded installs confirm mapping without re-enroll.
- Added pure-Python PKCS#12 keystore create, add, update, and remove support via the vendored `ls_keystore_utils` package (default path; no JVM startup for routine keystore writes).
- Added support for unauthenticated Logstash keystores (default-password trailer mode), matching native `logstash-keystore create` without `LOGSTASH_KEYSTORE_PASS`.
- Added policy and SNMP keystore set/delete when the agent has no stored keystore password (unauthenticated mode).
- Added `set_keystore_password` to upgrade an unauthenticated keystore to authenticated mode when the server provisions a password, preferring secret-preserving migrate over wipe-and-recreate.
- Added `ensure_keystore` and `clear_keystore_password` helpers; **check-in applies clear** when GetConfigChanges returns `keystore_password: null` (policy has no password, agent still reported a hash).
- Added env-file handling so `LOGSTASH_KEYSTORE_PASS` can be set or cleared in `/etc/default/logstash` (and per-instance env for simulate).
- Added unit coverage for pure-Python keystore write, unauthenticated keystores, env resolution, controller password migrate paths, simulate install, and keystore sync compare-and-skip.
- Added controller apply for `logstash_runtime` (SYSTEM vs VERSION): downloads pinned Logstash releases on policy change without re-enroll, updates simulate `LOGSTASH_BINARY` env, and restarts when the binary path changes.
- Added `logstash-agent setup-simulate` for finishing privileged simulate materialization after non-root `--enroll`; non-root enroll tries passwordless sudo, then partial tree write, then clear deferred instructions (`simulate_setup_pending` in state).
- Added **bare simulate recovery**: quarantine `slot*-filter*` pipelines, re-seed static `simulate-start` / `simulate-end` harness, write harness-only `pipelines.yml`, clear in-memory slots, then `systemctl restart ls-simulate@N`. CLI: `recover-simulate`; auto path on sim failure restart and a background watchdog for enrolled simulate.
- Added **TLS trust pin** for LogstashUI: enrollment token optional `fingerprint` triggers fetch of `{logstash_ui_url}/.well-known/logstashui/ca.crt`, SHA-256(DER) verify, persist product CA; enroll/check-in use system CAs ∪ product CA (`verify` no longer always false when pinned).
- Added **UI CA bootstrap loop** for embedded agents: retry-fetch well-known CA with verify=False until UI is up (TOFU or optional `LOGSTASHUI_CA_FINGERPRINT`), then full trust; `/_logstash/tls-status` and health `tls` block for online/secure indicators.
- Added **agent server TLS** (`tls_server.py`): local key + CSR, product-CA leaf from enroll/check-in/`IssueServerCert`, uvicorn HTTPS on the agent API port; re-issue on check-in without re-enroll; compose secret `LOGSTASHUI_AGENT_CSR_SECRET` for embedded bootstrap.
- Agent server CSR SANs include hostname, FQDN, non-loopback local IPs, and `LOGSTASH_AGENT_TLS_SANS`; re-issue when SANs drift.
- PyInstaller bundle includes **`lsagent-simulate@.service`** and **`ls-simulate@.service`** under `logstashagent/systemd/` for install.
- **sudo-rs compatible sudoers** (Ubuntu 26+): install `/opt/logstash-agent/bin/logstash-agent-ctl` to run validated `systemctl` actions (no `ls-simulate@*` wildcards in sudoers). Restarts go through this helper.
- **Install is a full deploy:** enables and starts the agent unit (`logstash-agent` or `lsagent-simulate@N`). Distro **`logstash` is enable-only** (never started/restarted at install) so live systems are not bounced; the agent restarts Logstash when policy requires.
### Changed

- Normalized legacy config: `agent`/`host` → `default`; `simulation`+`embedded` → `embedded`; `simulation`+`host` → `simulate`.
- Dev `config/logstashagent.yml` aligned to `default|simulate|embedded` vocabulary (`mode: embedded` for local FastAPI).
- Archived abandoned `simulation_mode: target` plan under `docs/archive/abandoned/` (not for implementation).
- **LogstashSupervisor is embedded-only process ownership** (`Popen` + monitor). Enrolled simulate uses systemctl + bare recovery/watchdog. Legacy `simulation_mode: host` only seeds layout / optional `run_as_logstash_user`; `setup_host_mode` is a deprecated alias for `ensure_sim_layout`.
- Install config now writes `mode: default` or `mode: simulate` (no longer `mode: agent`).
- Simulate agents restart Logstash via `systemctl restart ls-simulate@N` instead of the package `logstash` unit.
- Simulate layout root is **`/opt/logstash-agent/simulate-N/`** (was `/opt/LogstashAgent/simulate-N/`).
- `update_logstash_env_file` accepts a policy/instance `keystore_env_file` path (simulate uses instance env, not only `/etc/default/logstash`).
- Embedded / simulate-style Logstash HTTP API default is **9560** (was often 9650 in docker).
- Synced vendored `ls_keystore_utils` with ls-keystore-utils dockertests (v0.4.0), including `keystore_write.py` and `resolve.py`.
- Keystore write operations default to pure-Python PKCS#12 construction; optional `use_cli=True` retains `logstash-keystore` binary fallback.
- Keystore bag timestamps are tracked in milliseconds for reliable change detection during pure-Python updates.

### Fixed

- Corrected controller comments that incorrectly described merged keystore apply as a single `logstash-keystore add` invocation.
- Enrolled simulate FastAPI no longer starts Logstash via the in-process supervisor (avoids double JVM / wrong paths); health, sim queue, and recovery restarts use the Logstash HTTP API and `systemctl restart ls-simulate@N`. Legacy UI host/embedded supervisor paths are unchanged.
- Keystore password clear is applied on check-in (`keystore_password: null` → unauthenticated migrate + env clear), not left as a no-op when the policy password is removed.
- Simulate crash recovery no longer restart-loops the same bad slot config: recovery rewrites to a bare harness `pipelines.yml` before restarting the unit.

### Upgrade notes

- **Existing production (default) agents do not need to re-enroll.** Check-in identity (`api_key`, `connection_id`) is unchanged. Migrate LogstashUI, upgrade the agent package, restart the service.
- On first start after upgrade, look for `mode=default (legacy '…' mapped)` or `mode=default [state|config]`.
- To run pipeline simulation on a dedicated instance, enroll against a **Simulate** policy (new system policy in LogstashUI) rather than reusing the production agent.

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