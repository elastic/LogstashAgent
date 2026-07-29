# Simulation Mode: target Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add support for `simulation_mode: target` in LogstashAgent so it can act as the control plane for a dedicated (custom-path) Logstash instance used in simulation by LogstashUI (without requiring enrollment token for now). Support CLI overrides for paths and --logstash-ui-url (boilerplate for now), extend install for target setup (skip enroll, sim-style config, non--run service), reuse existing "host" simulation_mode logic for LS management per clarifications. Full sim API parity. Minimal additive changes, TDD, no unrelated refactors.

**Architecture:** Mirror the approved design doc (Approach 1). Plumb new CLI flags in main.py (top-level for runtime + install). Update config loading to accept "target" (no embedded forcing). In supervisor, normalize "target" -> "host" so it behaves exactly like current host sim (custom paths, setup_host_mode, sudo Popen, monitoring). Extend installer.perform_installation (new optional params), conditionalize steps (skip enroll for target, write sim config with mode:simulation + simulation_mode:target + url/paths, use variant systemd ExecStart without --run, minimal sudoers/chowns). Update example yml. Update parser to relax --enroll requirement for target install (but require --logstash-ui-url). --logstash-ui-url stored but unused in logic. Reuse all host sim code paths.

**Tech Stack:** Python 3.12+, argparse, yaml, subprocess (for sudo in supervisor/install), pytest for tests.

---

### Task 1: Update example config and add target documentation (non-code change, but foundation)

**Files:**
- Modify: src/logstashagent/config/logstashagent.example.yml
- Modify: src/logstashagent/config/logstashagent.yml (the live dev one for consistency)

- [ ] **Step 1: Write/update the example to document target**
Use search_replace or edit to change the simulation_mode comment and add target section (after the existing host comments).

Current in example (from read):
```
mode: simulation # simulation | host

# Only applies if mode 'mode' is set to simulation
simulation_mode: embedded # embedded | host
```

New:
```
mode: simulation # simulation | host

# Only applies if mode 'mode' is set to simulation
simulation_mode: embedded # embedded | host | target
# target - Use for a dedicated Logstash (custom paths from tarball vs package) managed by this agent for LogstashUI simulation.
#          See CLI --simulation-mode target and --logstash-* overrides. Behaves like 'host' for LS management.
#          --logstash-ui-url can be provided (boilerplate, stored but unused until token support).
```

Run to verify:
```bash
cat src/logstashagent/config/logstashagent.example.yml | head -20
```
Expected: updated comments with target.

- [ ] **Step 2: Do same for the dev yml**
```bash
# same edit for src/logstashagent/config/logstashagent.yml
```

- [ ] **Step 3: Commit**
```bash
git add src/logstashagent/config/logstashagent*.yml
git commit -m "docs: document simulation_mode: target in example and dev configs (boilerplate for --logstash-ui-url, like host sim)"
```

### Task 2: Add CLI flags and relax install requirements for target in main.py (TDD)

**Files:**
- Modify: src/logstashagent/main.py (argparse section ~1640-1725, install call ~1759, load_agent_config for overrides, main dispatch)
- Test: tests/test_main.py (add tests for new args and target parse)

- [ ] **Step 1: Write failing test for new argparse flags (add to test_main.py or new)**
First, run to see current tests.

```bash
python -m pytest tests/test_main.py -q --tb=no -k "argparse or parse or cli" | cat
```

Create/add test code that will fail until parser updated.

Use cat to append a test function (or use search_replace later).

For plan, we'll show the test code to insert.

Test idea: use parser directly.

```python
# In tests/test_main.py , add:
def test_install_target_cli_parses_paths_and_url_without_enroll():
    # this will fail until we relax required and add flags
    from logstashagent.main import parse_arguments
    import sys
    old = sys.argv
    try:
        sys.argv = ['main.py', 'install', '--simulation-mode', 'target', '--logstash-ui-url', 'http://ui:8080', '--logstash-binary', '/opt/ls/bin/logstash', '--yes']
        args = parse_arguments()
        assert args.command == 'install'
        assert args.simulation_mode == 'target'  # we'll add
        assert args.logstash_ui_url == 'http://ui:8080'
        assert args.logstash_binary == '/opt/ls/bin/logstash'
    finally:
        sys.argv = old
```

To write the test (failing):

```bash
python -m pytest tests/test_main.py::test_install_target_cli_parses_paths_and_url_without_enroll -q --tb=line
```
Expected: FAIL (no such test or AttributeError on args.simulation_mode)

(Assume we add the def to the test file using edit in next steps; for now the run shows collection fail or name error.)

- [ ] **Step 2: Update argparse to add the flags and --simulation-mode for install (make not required for target)**
Edit the parser.

First, add to install_parser after the --yes:

```python
    install_parser.add_argument(
        '--simulation-mode',
        type=str,
        choices=['simulation', 'target'],  # or just str, validate later
        default=None,
        help='For target sim installs: use "target" (skips enrollment, custom paths)'
    )
    # the paths flags
    for flag, help_text in [
        ('--logstash-ui-url', 'logstashui URL (required for target; for enroll otherwise)'),
        ('--logstash-binary', 'path to logstash binary (for target/custom)'),
        ('--logstash-settings', 'path to logstash settings dir'),
        ('--logstash-log-path', 'path to logstash logs'),
    ]:
        install_parser.add_argument(flag, type=str, metavar='VALUE', required=False, help=help_text)
```

For legacy parser.add_argument for --logstash-ui-url, keep, and add the three path flags at top level too (after --yes):

```python
    parser.add_argument('--logstash-binary', type=str, metavar='PATH', help='Override logstash binary path (for target sim mode etc)')
    # similarly for --logstash-settings, --logstash-log-path
```

Remove required=True from install's --enroll and --logstash-ui-url.

Add after parse:

In the install block:

if args.command == 'install':

    sim_mode = getattr(args, 'simulation_mode', None)

    if sim_mode == 'target':

        if not args.logstash_ui_url:

            logger.error("--logstash-ui-url is required for --simulation-mode target")

            sys.exit(1)

        # enroll optional

    else:

        if not args.enroll or not args.logstash_ui_url:

            ... error

Then, pass to call:

installer.perform_installation(

    enroll_token=args.enroll,

    logstash_ui_url=args.logstash_ui_url,

    agent_id=AGENT_ID,

    enrollment_func=...,

    simulation_mode=getattr(args, 'simulation_mode', None),

    logstash_binary=getattr(args, 'logstash_binary', None),

    logstash_settings=getattr(args, 'logstash_settings', None),

    logstash_log_path=getattr(args, 'logstash_log_path', None),

)

Also, update the help text in epilog and parser.

For load_agent_config, add support for CLI overrides? Or handle in __main__ before, but for simplicity, since paths are in AGENT_CONFIG, we can set os.environ or patch, but better: after parse, if paths, set into config later.

For now, in main, before load? Load is global.

We can modify load_agent_config to accept overrides, but to minimal, after AGENT_CONFIG = load... , then:

if args.logstash_binary:

    AGENT_CONFIG['logstash_binary'] = args.logstash_binary

Similarly for others, and 'logstash_ui_url'

But for install, the args are before the normal load? The load is at top level.

The parse is in if __name__.

For direct run with flags, we can override after load.

For install, the call uses the args directly.

Also need to handle --simulation-mode for normal run? Per design, mainly for install, but flags for runtime too.

Add:

simulation_mode = getattr(args, 'simulation_mode', None)

if simulation_mode:

    AGENT_CONFIG['simulation_mode'] = simulation_mode

But for target, set mode simulation too?

Anyway.

Run the test after edit to see pass.

- [ ] **Step 3: Run test to verify passes after minimal parser + override changes**

```bash
python -m pytest tests/test_main.py::test_install_target_cli_parses_paths_and_url_without_enroll -q --tb=short
```
Expected: PASS

- [ ] **Step 4: Commit the CLI changes**
```bash
git add src/logstashagent/main.py tests/test_main.py
git commit -m "feat: add --logstash-ui-url --logstash-binary etc CLI flags; support --simulation-mode target in install (relax enroll req, pass to installer); boilerplate plumbing"
```

### Task 3: Update installer to support target simulation_mode (TDD)

**Files:**
- Modify: src/logstashagent/installer.py (sig of perform_installation, write_config_file, install_systemd_service, the perform logic with ifs for target, add target_service_template perhaps)
- Test: tests/test_installer.py (add tests for target path)

- [ ] **Step 1: Add/update failing test for target install**
Similar to existing installer tests.

```python
# e.g. in test_installer.py
@patch('installer.perform_enrollment')
def test_perform_installation_target_skips_enroll_writes_sim_config(mock_enroll, ...):
    # setup mocks for root etc
    installer.perform_installation(
        enroll_token=None,
        logstash_ui_url='http://ui',
        agent_id='id',
        enrollment_func=mock_enroll,
        simulation_mode='target',
        logstash_binary='/opt/custom/bin/logstash',
        ...
    )
    mock_enroll.assert_not_called()
    # assert config written has mode: simulation , simulation_mode: target , the paths
    # assert service template has no --run
```

Run to fail:

```bash
python -m pytest tests/test_installer.py -q -k "target" --tb=line
```
Expected: FAIL (no test or TypeError on extra kwargs, or still calls enroll)

- [ ] **Step 2: Update the function signature and write_config_file to support target**
First, change def:

def perform_installation(

    enroll_token: str = None,

    logstash_ui_url: str,

    agent_id: str,

    enrollment_func,

    simulation_mode: str = None,

    logstash_binary: str = None,

    logstash_settings: str = None,

    logstash_log_path: str = None,

) -> None:

Then, in body, pass the paths to write_config_file(logstash_ui_url, simulation_mode=..., **paths)

Update write_config_file:

def write_config_file(logstash_ui_url: str, simulation_mode: str = None, logstash_binary=None, logstash_settings=None, logstash_log_path=None):

    if simulation_mode == 'target':

        mode_line = "mode: simulation"

        sim_line = "simulation_mode: target"

        bin_line = logstash_binary or "/usr/share/logstash/bin/logstash"

        # etc

        config_content = f"""...

{mode_line}

{sim_line}

logstash_binary: {bin_line}

...

logstash_ui_url: {logstash_ui_url}

"""

    else:

        ... original "mode: agent"

    ...

Then, in perform, after step 4:

write_config_file( logstash_ui_url, simulation_mode=simulation_mode, logstash_binary=..., ...)

For step 6:

install_systemd_service(simulation_mode=simulation_mode)  # we'll update it to conditional template

For step 7:

if simulation_mode != 'target':

    logger.info("\nStep 7: Enrolling...")

    enrollment_func(...)

    ...

else:

    logger.info("\nStep 7: Skipping enrollment for target simulation mode (per design)")

Similar for step 8,9: if simulation_mode != 'target': do full chowns and sudoers

For sudoers, in target we can write a minimal one focused on systemctl logstash.

Add a target_systemd template:

TARGET_SYSTEMD_SERVICE_TEMPLATE = """[Unit]

Description=LogstashAgent (target sim mode) - Control plane for dedicated Logstash in LogstashUI sim

After=network.target

[Service]

Type=simple

User=logstash  # or root? but keep similar

...

ExecStart=/opt/logstash-agent/bin/logstash-agent   # no --run, starts server

...

"""

Then, in install_systemd_service(simulation_mode=None):

    if simulation_mode == 'target':

        template = TARGET_...

    else:

        template = SYSTEMD...

    with open(...) as f: f.write(template)

Also, update calls in perform.

For lighter chowns in target: still do agent dirs, but conditional the logstash chowns.

- [ ] **Step 3: Run the installer target test to verify it now skips enroll, writes correct config, etc. (after the edits)**

```bash
python -m pytest tests/test_installer.py -q -k "target" --tb=short
```
Expected: PASS

- [ ] **Step 4: Commit installer changes**
```bash
git add src/logstashagent/installer.py tests/test_installer.py
git commit -m "feat: support simulation_mode=target in installer (skip enroll, sim-style config with custom paths/ui_url, non--run systemd, minimal sudoers/chowns for dedicated LS)"
```

### Task 4: Support 'target' in supervisor by normalizing to host behavior (minimal)

**Files:**
- Modify: src/logstashagent/logstash_supervisor.py (in __init__, add 2 lines to map target -> host)

- Test: tests/test_logstash_supervisor.py (add or extend test that target uses host paths/setup)

- [ ] **Step 1: Write failing test asserting target maps to host logic**
E.g. 

def test_supervisor_target_behaves_as_host():

    sup = LogstashSupervisor(config={'simulation_mode': 'target', 'logstash_binary': '/custom/bin/logstash', ...})

    assert sup.simulation_mode_type == 'host'  # after map

    # or check it calls setup etc.

Run to fail (before change).

- [ ] **Step 2: Add the mapping code (minimal add)**
After:

self.simulation_mode_type = self.config.get(

    "simulation_mode", "embedded"

)  

Add:

if self.simulation_mode_type == "target":

    self.simulation_mode_type = "host"

    logger.info("[Supervisor] Treating simulation_mode=target as host (per design: identical LS management for dedicated instance)")

Update the comment: # 'embedded' or 'host' (target normalized to host)

This makes all existing if self.simulation_mode_type == 'host':  work for target too, using the custom paths from config.

- [ ] **Step 3: Run test to pass**

- [ ] **Step 4: Commit**
```bash
git add src/logstashagent/logstash_supervisor.py tests/test_logstash_supervisor.py
git commit -m "feat: normalize simulation_mode=target to host in supervisor (so exactly like host sim for custom paths/setup/sudo Popen per clarification; minimal change)"
```

### Task 5: Update slots defaults / main logging / other small accepts for target (additive)

**Files:**
- Modify: src/logstashagent/slots.py (the _load_config defaults and comments)
- Modify: src/logstashagent/main.py (a few logging and force ifs to handle 'target' like 'host', e.g. don't force embedded paths for target)

- [ ] **Step 1: Test for slots default accepts target**
Run pytest ... will fail until.

- [ ] **Step 2: Update the dicts to use 'host' or comment, or if 'target' treat as host in _load.**

Since slots uses for background thread start: if mode=="simulation" (target will have mode sim), fine.

Update comments and default example.

In main force if: change to if == 'embedded' (target won't match, good, like host).

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**

### Task 6: Add/update tests for full parity, integration, docs

**Files:**
- Modify: tests/test_main.py , test_installer.py, test_logstash_supervisor.py (already in prior tasks)
- Perhaps tests/test_integration.py or new for target config
- Modify: README.md (add note under quickstart or limitations)
- Commit

- [ ] **Step 1: Write a failing integration-ish test for target config load + supervisor**
- [ ] **Step 2: Implement minimal (the previous changes cover)**
- [ ] **Step 3: Run full relevant tests**
```bash
python -m pytest tests/ -q --tb=no -k "install or supervisor or main or simulation or target or slots" | cat
```
Expected: all pass (or the new ones)

- [ ] **Step 4: Update README with target mention (e.g. in requirements or quickstart for sim)**
- [ ] **Step 5: Commit**
```bash
git add tests/ README.md
git commit -m "test: add coverage for target simulation_mode CLI/install/supervisor; docs: mention target in README"
```

### Task 7: Final verification and commit any loose ends

- Run full test suite?
```bash
python -m pytest -q --tb=no | cat
```
Expected: PASS (or note skips)

- git status clean-ish

- Perhaps update CHANGELOG.md

- Commit
```bash
git add CHANGELOG.md
git commit -m "chore: finalize simulation_mode target support; update changelog"
```

**Verification commands throughout (from design):**
- After each: python -m pytest ... -q
- Manual: python src/logstashagent/main.py install --help (see new flags)
- python -c "from src.logstashagent.main import parse_arguments; ..." or direct run with flags (but needs mocks for full)
- For install target (in test env with mocks)

This plan produces working increments at each commit. All per approved design, user clarifications, existing patterns (TDD, atomic, etc.), YAGNI.

After all tasks, the agent supports the requested target mode for dedicated LS sim with UI. 

**Next after this plan:** Use subagent-driven or executing-plans, but only after this plan is executed/verified. 

(End of plan per writing-plans skill. Now hand off for execution.)