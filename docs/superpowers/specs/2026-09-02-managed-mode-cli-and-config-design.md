# Design: Managed mode CLI, gated help, config precedence

**Date:** 2026-09-02  
**Branch:** `fix/modes`  
**Status:** Approved for implementation planning

## Problem

1. **Managed units fail at argparse.** `logstash-agent@.service` runs  
   `--run --mode managed --instance %i`, but CLI `choices` are still  
   `default | simulate | embedded`. Journal shows:  
   `invalid choice: 'managed' (choose from default, simulate, embedded)`.  
   Runtime, installer, README, and CHANGELOG already treat  
   `packaged | managed | simulate | embedded` as first-class. The CLI list  
   was never updated when modes landed — not a bad merge of later slot work.

2. **`--help` probes the filesystem.** Importing `main` refreshes state,  
   loads config (fallback defaults `logstash_settings: /etc/logstash/`),  
   and `makedirs` under `conf.d` / `pipeline-metadata`. On hosts without  
   `/etc/logstash` (macOS, minimal Linux), help is fragile. Help must not  
   need any Logstash directories.

3. **yml vs env overlap is unclear.** Multi-instance install writes  
   `logstash-agent.yml`, `agent.env`, and Logstash `env`. Operators need a  
   clear precedence story and a thinner example config.

## Goals

- Accept `--mode packaged|managed|simulate|embedded` on the CLI.
- Aliases: `default` → `packaged`, `agent` → `packaged`, `host` → `managed`.
- Prefer rewriting aliases to canonical names on load so logs show  
  `mode=packaged` / `mode=managed`.
- `--help` and admin CLI parse with no state write, no yml requirement,  
  no `makedirs` under `/etc/logstash`.
- Document and lightly thin yml vs `agent.env` vs Logstash `env` precedence.
- Align example yml and leftover `default`-only branches with `packaged`.

## Non-goals

- Env-only config (yml optional) for multi-instance.
- Full lazy FastAPI app construction (unless required to avoid FS).
- Deploy/push to production hosts (follow-up after code lands).
- Simulate bus-storm / slot work already done elsewhere.

## Design

### 1. CLI mode normalization

Add a small normalizer used as argparse `type=` (or equivalent):

| Input | Stored / effective mode |
|-------|-------------------------|
| `packaged`, `managed`, `simulate`, `embedded` | unchanged |
| `default`, `agent` | `packaged` |
| `host` | `managed` |
| anything else | argparse error |

`--help` should list the four first-class choices. Aliases remain accepted  
on the command line.

`normalize_agent_mode()` must match: today `host` maps to `packaged`; change  
to **`host` → `managed`**. Prefer rewriting `default` → `packaged` on load  
for consistent logs/state.

Update `--instance` help: applies to **managed and simulate**.

Sweep dispatch branches that check only `'default'` so `'packaged'` works;  
keep accepting legacy `default` during transition.

### 2. Gated import-time initialization

Extend the existing argv hints (`_ADMIN_CLI`, `_SKIP_SIMULATION_IMPORTS`,  
`_argv_mode_hint`) so a **lightweight CLI** path includes `--help` / `-h`  
and non-`--run` admin commands.

**Defer until `--run` (or another path that truly needs them):**

- Agent id creation / version writes into state
- `load_agent_config()` / `AGENT_CONFIG` normalization
- `get_logstash_paths()` + `os.makedirs(PIPELINES_DIR|METADATA_DIR)`
- Slots import / cleanup thread (already skipped for many admin paths;  
  ensure `--help` alone never imports slots)

**Allowed at import for help:** cheap module imports, argparse setup,  
FastAPI `app = FastAPI(...)` if it performs no filesystem work. If route  
registration requires path globals, initialize those globals lazily at  
`--run` entry or on first use (empty/safe defaults until then).

`agent_state.refresh_state_paths()` must not create directories when running  
help; either skip refresh for lightweight CLI or make refresh no-create.

**Success:** with no `/etc/logstash` and no local agent yml,  
`python -m logstashagent.main --help` exits 0, mentions `managed`, and does  
not create `/etc/logstash/conf.d` (or equivalent).

### 3. Config precedence (yml vs env)

Document in `logstashagent.example.yml` and a short README note:

| Concern | Preferred (multi-instance) | Fallback |
|---------|----------------------------|----------|
| State dir | `LOGSTASH_AGENT_STATE_DIR` (`agent.env`) | `--mode` + `--instance` tree |
| Agent yml path | `LOGSTASH_AGENT_CONFIG` (`agent.env`) | instance / packaged path |
| Mode | CLI `--mode` / state / `AGENT_MODE` | yml `mode` |
| Agent API port | `AGENT_API_PORT` / `LOGSTASH_AGENT_PORT` | yml `port` / state |
| Logstash API port | `LOGSTASH_API_PORT` | state / yml |
| Logstash binary & paths | Logstash `env` (`LOGSTASH_BINARY`, `LOGSTASH_PATH_*`) | yml / state |
| UI URL | state / `LOGSTASH_UI_URL` | yml `logstash_ui_url` |

**Keep in yml:** `mode`, `instance_id`, path trio, ports, `host`,  
`logstash_ui_url`, VERSION pin fields when used.

**Thin:** example uses `mode: packaged` and documents aliases; installer  
generated yml adds a comment that runtime prefers `agent.env` / `env` when  
set. Do not strip multi-instance yml to env-only in this change.

### 4. Testing

- Mode normalizer / argparse: four modes accepted; aliases map as above;  
  unknown rejected; help text lists first-class set including `managed`.
- Help side effects: lightweight path does not call `makedirs` for  
  `/etc/logstash/...` (patch or isolated run).
- Existing unit/coexistence/e2e assertions that unit files contain  
  `--mode managed` continue to pass.
- Update any tests that expected `host` → `packaged` / `simulate`.

## Critical files

- `src/logstashagent/main.py` — CLI, gating, mode branches
- `src/logstashagent/config/logstashagent.example.yml`
- `src/logstashagent/installer.py` — generated yml comments
- `README.md` (short precedence blurb); optional `CHANGELOG.md` note
- `tests/` — mode aliases, help gating, `host` → `managed`

## Verification (definition of done)

- [ ] `--help` works without `/etc/logstash` or local yml; lists packaged/managed/simulate/embedded
- [ ] `--mode managed|packaged|default` accepted; default→packaged, agent→packaged, host→managed
- [ ] Unit templates still use `--mode managed`; related tests pass
- [ ] No import-time `makedirs` under `/etc/logstash` for `--help`
- [ ] Example yml + docs describe env vs yml precedence
