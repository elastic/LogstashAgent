## [0.5.2] - CLI modes, gated --help, env-vs-yml precedence - 09/02/2026

Package version is **0.5.2**. Works with **LogstashUI 0.5.1 & 0.5.2**.

### Added

- Check-in `status_blob` includes `runtime_download` (`pending|running|ready|failed`, version, error). No progress bars.
- Optional `LOGSTASH_AGENT_LOGSTASH_VIA_UI` (default false; env wins over state `logstash_via_ui`): tarball + `.sha512` from `{logstash_ui_url}/ConnectionManager/LogstashArtifact/{connection_id}/{filename}` with `Authorization: ApiKey` (raw enrollment key — never an `lsui_` admin token), product-CA trust, and **no Elastic fallback when on**. `connection_id` is in the path because a GET carries no body to narrow the API-key lookup.
- Via-UI downloads handle the proxy's cache semantics: `503` (cold cache — the normal first response), `429` (serve cap) and `502` (upstream failed, logged loudly) are retried honouring `Retry-After`, falling back to exponential 15s→300s when the header is absent. `401`/`404`/`405` fail immediately. Bounded by `LOGSTASH_AGENT_ARTIFACT_DEADLINE_SEC` (default 3600); on expiry the next check-in retries.
- Via-UI downloads resume: bytes land in `<download_dir>/.partial/<name>.part`, which survives an agent restart, so a death at 440/450 MB continues with `Range: bytes=<n>-` instead of re-pulling. `416` discards the partial and restarts from zero; orphans older than 24h are swept.
- Agents report `logstash_via_ui` in the `GetConfigChanges` body, so toggling the proxy checkbox alone produces a `logstash_runtime` delta. The **persisted state** value is sent, not the env override, which would otherwise disagree with policy permanently. Check-in drift detection compares it too, since a checkbox flip does not move the revision number.
- `logstash_via_ui` is now read from all three server channels: enrollment `policy_config` (previously dropped), check-in, and the config delta's `logstash_runtime.via_ui`.

### Changed

- First-class CLI `--mode` values: **packaged**, **managed**, **simulate**, **embedded**. Aliases rewritten on load and argparse: `default`|`agent` → packaged, `host` → managed.
- `--help`, admin commands, and `--enroll` no longer load agent yml or create `/etc/logstash` pipeline dirs.
- Documented config precedence: systemd `agent.env` / Logstash env win over `logstash-agent.yml` when set (example yml, installer templates, README).
- `resolve_path_settings_from_env(require_writable=True)`: missing directories are skipped; an explicit env path that exists but is not writable no longer falls back to `/etc/logstash`.
- Missing VERSION tree: start a **background** download (per-version flock still in ensure) and **hold the whole policy revision** (no yml/jvm/log4j2/keystore/pipelines, no revision bump) until the tree exists. Next check-in after ready: snapshot → apply → flip `LOGSTASH_BINARY` immediately before the single restart.
- Packaged/embedded: VERSION pin is a no-op (log once, no download). UI policy should not attach VERSION pins to those roles.

### Fixed

- **Policy `jvm.options` was written but never applied on managed/simulate instances.** JVM settings were absent from the `java` command line. `logstash.lib.sh` finds jvm.options by scanning `"$@"` for an argv entry *equal to* `--path.settings` and reading the next one; both Logstash units passed the equals form (`--path.settings=<dir>`), which never matches, so `LS_JVM_OPTS` was never exported and Logstash silently used the stock jvm.options from `LOGSTASH_HOME`. `logstash.yml` and `log4j2.properties` were unaffected because the Java settings loader accepts either form — which is why this was the only setting that went missing. Present since multi-instance units were introduced, so managed/simulate JVM tuning had never worked. Packaged (distro `logstash.service`) and embedded (Popen argv) already used the two-argument form and were never affected.
- Both Logstash units now pass `--path.settings` as two arguments, **and** the per-instance env file exports `LS_JVM_OPTS` outright, so correctness no longer rests on that argv scan. The env line is written only when jvm.options exists — naming a missing file makes `JvmOptionsParser` fail and Logstash refuse to start — and is added/removed as policy starts or stops supplying the file. A test asserts no shipped unit uses the equals form.
- jvm.options is now written mode `0644` by both writers. `logstash.lib.sh` requires `[ -r ]` to pass **for the logstash user**, so under a restrictive umask a root-owned `0600` file reproduced this exact bug — and, with `LS_JVM_OPTS` set, would turn it into a start failure. Newly relevant now that Logstash actually runs as `logstash` rather than root.
- Already-enrolled managed/simulate hosts self-heal: on controller start a stale unit (still equals-form) or an env file lacking `LS_JVM_OPTS` triggers a repair. The env half needs no privileges and **on its own fixes the bug**; refreshing `ExecStart` needs root and goes through the existing root → `sudo -n … setup-simulate` escalation, falling back to a warning pointing at `sudo logstash-agent configure`. The Logstash unit must still be restarted — `daemon-reload` does not re-exec a running process.
- **Install never created the `logstash` user.** The account was only ever *looked up* — it existed solely as a side effect of installing the Logstash DEB/RPM. On a host without the package, install silently produced root-owned directories, systemd units with **no `User=`** (so both the agent and Logstash ran as root), and a sudoers file granting rights to a nonexistent user. `install`/`configure`/`setup-simulate` now create the system group and user the way the package scriptlets do (`--system`, `--gid logstash`, home `/usr/share/logstash`, `--no-create-home`, nologin shell), before any directory is chowned. Idempotent: a host that already has the Logstash package runs no commands. If the account cannot be created the install **aborts** with the manual `groupadd`/`useradd` commands rather than continuing as root.
- All five systemd units now declare `User=logstash`/`Group=logstash` unconditionally. The packaged unit used to omit them when the account was missing, and the four multi-instance templates shipped with them commented out and uncommented only if the account happened to resolve.
- `sudo logstash-agent configure` is now a one-shot repair for hosts installed before the above: it creates the account, re-applies ownership to `config`/`state`/`logs`/`cache`/`logstash-versions` and every `managed-*`/`simulate-*` tree, fixes `state/.secret_key`, and rewrites all unit files — including the four multi-instance templates, which `configure` previously never touched. `bin/` is deliberately left root-owned, since sudoers grants `logstash` NOPASSWD on `bin/logstash-agent`. Units must be restarted for `User=` to take effect.
- `create_directories()` and `configure_logstash()` no longer log `✓ ... (owned by logstash)` when ownership actually fell back to root — the false success message that hid the missing account.
- `verify_logstash_installed()` no longer counts the `logstash` account as evidence that Logstash is installed, since the installer now creates it.
- systemd `logstash-agent@N` failed immediately: argparse rejected `--mode managed` (`invalid choice`). Units already passed managed; CLI validation had not.
- `--mode host` now maps to **managed** (0.5.1 mapped it to packaged). Same rewrite in argv peek, controller startup logs, and Logstash unit name (`logstash-managed@N`).
- `--enroll` no longer creates pipeline dirs; packaged/managed are included in simulation-style Logstash restart dispatch.
- Embedded supervisor records `_healthy_since` on first healthy API response and clears it on restart / sustained unresponsive (pipeline-bus warmup). Tests existed; the field never landed.
- `restart_logstash` unit tests mock `systemctl_via_sudo` so they do not need a host `systemctl` (macOS/Windows).
- Logstash pin changes (`VERSION` X→Y and `SYSTEM` ↔ `VERSION`) snapshot instance config+env, wait 180s for the API after restart, and restore the snapshot plus the previous binary if the new process never answers. Incomplete snapshots roll back on controller start / next check-in.


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