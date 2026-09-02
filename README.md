# LogstashAgent

> A control-plane agent for LogstashUI that fully manages the Logstash instance it runs alongside.
>
> Warning: **Beta Release** - This project is under active development. Features may change.
>
> **Current package version: 0.5.1** — see [CHANGELOG.md](CHANGELOG.md).

## Overview

LogstashAgent is the host-side runtime for LogstashUI-managed instances.

It enrolls with LogstashUI, persists local agent state, checks in for policy and configuration changes, and applies those changes directly to the local Logstash installation.

Product documentation (roles, ports, coexistence, VERSION CLI) lives in the LogstashUI docs tree:

- **[Agent roles, ports, coexistence, and VERSION](https://github.com/elastic/LogstashUI/blob/main/docs/docs/logstashagent/general/roles.md)** (or your local `LogstashUI/docs/docs/logstashagent/general/roles.md`)

## Agent roles

| Mode | Policy type | Role |
|------|-------------|------|
| `packaged` | PACKAGED | Production agent (enrolled). Manages package Logstash via `systemctl` (`logstash` + `logstash-agent`). |
| `managed` | MANAGED | Multi-instance agent **N**. Tree under `/opt/logstash-agent/managed-N/`; units `logstash-agent@N` / `logstash-managed@N`. Ports **9600+N** / **9700+N**. |
| `simulate` | SIMULATE | Simulation agent **N**. Isolated under `/opt/logstash-agent/simulate-N/`; units `lsagent-simulate@N` / `ls-simulate@N`. Ports **9500+N** / **9560+N**. |
| `embedded` | EMBEDDED | Docker/local sim without enrollment (FastAPI + supervisor). Ports **9500** / **9560**. |
| `default` | (legacy) | Alias of packaged (still accepted). |

Legacy aliases (rewritten on load / CLI): `default` and `agent` → **packaged**; `host` → **managed**.

**Host coexistence:** Packaged + Managed + Simulate can share one machine. Multi-instance state/config live under the instance tree (`LOGSTASH_AGENT_STATE_DIR` / `LOGSTASH_AGENT_CONFIG` in `agent.env`), not under packaged `/var/lib` or `/etc`.

**Precedence** (multi-instance): systemd `agent.env` / Logstash env win when set.

| Concern | Preferred (multi-instance) | Fallback |
|---------|----------------------------|----------|
| State dir | `LOGSTASH_AGENT_STATE_DIR` (`agent.env`) | `--mode` + `--instance` tree |
| Agent yml path | `LOGSTASH_AGENT_CONFIG` (`agent.env`) | instance / packaged path |
| Mode | CLI `--mode` / state / `AGENT_MODE` | yml `mode` |
| Agent API port | `AGENT_API_PORT` / `LOGSTASH_AGENT_PORT` | yml `port` / state |
| Logstash API port | `LOGSTASH_API_PORT` | state / yml |
| Logstash binary & paths | Logstash env (`LOGSTASH_BINARY`, `LOGSTASH_PATH_*`) | yml / state |
| UI URL | state / `LOGSTASH_UI_URL` | yml `logstash_ui_url` |

**Upgrade:** Existing production agents keep working **without re-enroll** after package upgrade. Use a **Simulate** or **Managed** policy token when adding multi-instance roles.

## Features

<details>
<summary><b>Enrollment + Reconciliation Loop</b> - Enroll with LogstashUI and continuously reconcile desired state to the local Logstash instance.</summary>

- Install + enroll (root): `sudo logstash-agent install --enroll=<TOKEN> --logstash-ui-url=<URL>`
- Non-root enroll (token only): `logstash-agent --enroll=<TOKEN> --logstash-ui-url=<URL>` — enrollment always succeeds; for multi-instance policies the agent tries passwordless sudo, then a partial tree write, otherwise leaves setup pending and prints `sudo logstash-agent setup-simulate`
- Finish multi-instance host setup: `sudo logstash-agent setup-simulate` (materialize tree, install units)
- Controller: `logstash-agent --run` (or systemd unit for the role)
- Host map: `logstash-agent list-instances`

</details>

<details>
<summary><b>VERSION Logstash pins</b> - Download Elastic distributions for Managed/Simulate policies.</summary>

- Policy source `VERSION` + `logstash_version` (e.g. `9.4.3`) → download under `/opt/logstash-agent/logstash-versions/`
- Applied on check-in (binary-only changes do not require Deploy)
- CLI: `list-versions`, `ensure-version <ver>`, `prune-versions`

</details>

<details>
<summary><b>Pipeline Management API</b> - Create, update, delete, validate, and inspect Logstash pipelines.</summary>

- Endpoints include `/_logstash/pipeline`, `/_logstash/pipeline/{pipeline_id}`, `/_logstash/pipeline/{pipeline_id}/logs`, and `/_logstash/pipelines/status`.
- Config persistence is backed by `pipelines.yml`, `conf.d`, and metadata files.

</details>

<details>
<summary><b>Host Configuration Management</b> - Apply managed configuration to local Logstash runtime files and secure settings.</summary>

- Controller updates `logstash.yml`, `jvm.options`, `log4j2.properties`, and keystore entries.
- Supports reconciliation and service restart flows for managed updates.

</details>

<details>
<summary><b>Local State + Credential Protection</b> - Persist agent identity and encrypted sensitive fields.</summary>

- Packaged state: `/opt/logstash-agent/state/state.json`
- Packaged config: `/opt/logstash-agent/config/logstash-agent.yml`
- Packaged logs: `/opt/logstash-agent/logs/`
- CLI symlink (only path outside `/opt`): `/usr/local/bin/logstash-agent`
- Multi-instance state: `/opt/logstash-agent/{managed,simulate}-N/state/state.json`
- Dev/source default: `src/logstashagent/data/state.json`
- Encryption key and logs under the same state parent (or package log dir)

</details>

## Requirements

### Software

#### For Packaged / Managed / Simulate (enrolled)
- Linux (x86-64) for the installer
- [Logstash 8.x, 9.x](https://www.elastic.co/docs/reference/logstash/installing-logstash) for **SYSTEM** source, or network access for **VERSION** download
- Root / sudo for install and systemd
- Network reachability to your LogstashUI instance

#### For local development
- [Python 3.12+](https://www.python.org/downloads/)
- `uv` (recommended) or `pip`

## Quick Start - Agent Mode
> [!TIP]
> Use `--run` only after successful enrollment, because controller mode requires persisted enrollment state.

### Install (from source for development)
```bash
cd LogstashAgent
uv sync
```

### Configure
Copy and adjust the example config:
```bash
cp src/logstashagent/config/logstashagent.example.yml src/logstashagent/config/logstashagent.yml
```

### Run agent process
```bash
python src/logstashagent/main.py
```

By default this starts the agent service (including management API) on `0.0.0.0:9600` unless overridden in config.

---
## Enroll And Run Controller

### 1. Enroll the agent
```bash
python src/logstashagent/main.py --enroll=<BASE64_TOKEN> --logstash-ui-url=http://localhost:8080
```

Prefer root install for production:
```bash
sudo logstash-agent install --enroll=<BASE64_TOKEN> --logstash-ui-url=https://logstashui.example
```

### Simulate / Managed policy, non-root enroll
If you enroll without root, enrollment still saves state. Finish privileged setup with:
```bash
sudo logstash-agent setup-simulate
# then (example):
sudo systemctl start lsagent-simulate@N
# or managed:
sudo systemctl start logstash-agent@N
```

### 2. Start controller mode
```bash
python src/logstashagent/main.py --run
# multi-instance:
python src/logstashagent/main.py --run --mode managed --instance 1
```

### 3. Host inventory
```bash
logstash-agent list-instances
logstash-agent list-versions
```

## Day-2 operations (by role)

```bash
# Packaged
sudo systemctl status logstash-agent

# Managed N
sudo systemctl status logstash-agent@N
sudo logstash-agent-ctl status logstash-agent@N

# Simulate N
sudo systemctl status lsagent-simulate@N

# Drop one multi-instance role only
sudo logstash-agent uninstall --instance managed-1
```

## Updating

Pull latest source and resync dependencies:

```bash
git pull
uv sync
```

Then restart the running agent process (or the appropriate systemd unit).

## Limitations
- Controller behavior depends on available host service managers (`systemctl`) for restart operations.
- Host filesystem permissions must allow managed writes to Logstash settings and metadata paths.
- Installer is Linux-only.

## Reporting Issues

Found a bug or have a feature request? [Open an issue](https://github.com/elastic/LogstashUI/issues/new?template=issue.md).

## Contributing

Contributions are welcome.

Please open an issue to discuss large changes before submitting a pull request.

## License

Copyright 2024-2026 Elasticsearch and contributors.

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE.txt) for details.
