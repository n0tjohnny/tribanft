# TRIBANFT AGENT v3.3 — S4.5 OPTIMIZED

## REMEMBER
- tribanFT runs on remote server (not this machine)
- For server commands → provide for user to execute and paste output
- **XDG compliance MANDATORY** (never suggest /var/lib, /root, or other non-XDG paths)
- For plugins/rules reference: docs/RULE_SYNTAX.md, docs/API_REFERENCE.md, docs/PARSER_EVENTTYPES_MAPPING.md, docs/PLUGIN_DEVELOPMENT.md
- For docs updates reference: docs/DOCUMENTATION_AGENT.md, docs/DOCUMENTATION_GUIDE.md
- ALWAYS respect config.template.conf paths (never suggest alternatives)
- No formal test suite exists → validate via scripts/analyze_and_tune.sh or manual --verbose runs

## MODE: FULL | ANALYSIS | LIGHT | PLUGIN
**FULL** = code edits | **ANALYSIS** = review only | **LIGHT** = docs/format | **PLUGIN** = YAML rules + plugin code

## PRIMITIVES
```
VIEW(path) → content | ABORT
RAG(target, depth=2) → deps[≥1] | ABORT
EDIT(path, old, new, why) → ok | ABORT
  # Pre: old unique in file, why ≤50 chars
  # Post: single logical change
  # Example: EDIT("managers/blacklist.py", "if x >", "if x >=", "inclusive check")
CMD(command, reason) → user_executes
  # Pre: reason explains necessity
  # Example: CMD("grep ERROR /var/log/tribanft.log", "verify error pattern")
VALID(file, type) → {security:bool, deps:bool, yaml:bool}
  # Pre: file viewed + RAG complete
  # yaml: validates YAML syntax for detector/parser rules
  # Post: all checks pass or ABORT with specific failure
BACKUP(target) → snapshot_created
  # Pre: modifying critical state (blacklist, database)
  # Automatic via BackupManager, verify retention policy
```

## WORKFLOW
```
1. Request → classify task + MODE
2. PRE-FLIGHT → run prevention checklist
3. VIEW target files (include YAML if plugin work)
4. RAG dependencies (parsers/detectors use base classes)
5. IF bug → add DEBUG logging BEFORE fix
6. VALID → abort if security/deps/yaml fail
7. EDIT (one logical change per call)
8. IF plugin → validate YAML with CMD
9. CMD to verify (user executes)
10. DOC change (docs/DOCUMENTATION_AGENT.md workflow)

ANALYSIS: VIEW → RAG → tag facts → zero mods
LIGHT: VIEW → EDIT (docs/format only) → DOC
PLUGIN: VIEW yaml + code → VALID yaml → EDIT → CMD validate → DOC
```

## PREVENTION CHECKLIST
```
Before any code change:
[ ] Config: Log loaded values at INFO level (see config.py pattern)
[ ] Updates: "if new and new != old" pattern (prevents None overwrites)
[ ] External data: .get() + isinstance() checks (never direct dict access)
[ ] Locks: Context managers only (with file_lock(...): pattern)
[ ] Parsers: Fallback chains + log missing fields at WARNING
[ ] Atomic writes: temp file → os.rename() for state/blacklist
[ ] Whitelist check: ALWAYS before blacklist operations
[ ] Backup: Verify BackupManager handles critical files
[ ] Storage backend: File <10k IPs, SQLite ≥10k (check config[storage])
[ ] XDG paths: Use ${state_dir}, ${data_dir} from config (no hardcoded paths)
```

## SECURITY INVARIANTS (code-verified only)
- **Whitelist precedence** (NEVER block whitelisted IPs - check before ALL operations)
- **Atomic operations** on blacklist/state modifications (temp → rename pattern)
- **Corruption protection** (blacklist_writer: abort if >50% IP loss detected)
- **Input validation** on all external data (ipaddress.ip_address() for IPs)
- **Thread-safe** critical paths (file_lock with advisory locking via fcntl)
- **Backup before modify** (BackupManager: 7-day retention, compress >1 day old)
- **Verify through code inspection** (no assumptions, VIEW first)

## PLUGIN PATTERNS
```
Detectors:
  1. Extend BaseDetector (bruteforce_detector/detectors/base.py)
  2. Define METADATA = {'name': str, 'version': str, 'enabled_by_default': bool}
  3. Implement detect(event: dict) → dict|None
  4. Place YAML rules in bruteforce_detector/rules/detectors/
  5. Register via PluginManager auto-discovery

Parsers:
  1. Extend BaseLogParser (bruteforce_detector/parsers/base.py)
  2. Define METADATA + event_type mapping
  3. Implement parse(line: str) → dict|None
  4. Place YAML patterns in bruteforce_detector/rules/parsers/
  5. Patterns loaded via ParserPatternLoader singleton (cached)

YAML validation:
  CMD("python3 -c \"import yaml; yaml.safe_load(open('path'))\"", "validate YAML syntax")
```

## STATE MANAGEMENT
```
Atomic write pattern (state.py, blacklist_writer.py):
  1. Write to temp file (tempfile.NamedTemporaryFile)
  2. os.rename(temp, target) → atomic swap
  3. Auto-backup via BackupManager before modifications
  4. Corruption recovery: try primary → fallback to latest backup

Storage backend selection (managers/database.py, managers/blacklist_writer.py):
  - File backend: <10k IPs (blacklist_ipv4.txt, blacklist_ipv6.txt)
  - SQLite backend: ≥10k IPs (blacklist.db with WAL mode)
  - Config: [storage] backend = file|sqlite|auto (auto switches at 10k)
  - Migration: handled automatically by BlacklistAdapter

Backup retention (utils/backup_manager.py):
  - retention_days=7, min_keep=5
  - Compress after compress_age_days=1
  - Auto-cleanup on rotation
```

## PROHIBITED
- Rewrites for single-line changes
- Assume behavior without VIEW
- Skip RAG on dependencies
- Batch unrelated edits
- Non-XDG paths (/var/lib, /root, hardcoded /home)
- Emojis in code or docs
- Direct dict access for external data (use .get())
- OR logic in update conditions (use "if new and new != old")
- Locks without context managers
- Modify state without atomic write pattern

## CRITICAL FILES (actual paths)
```
Core:
  bruteforce_detector/main.py              # BruteForceDetectorEngine entry point
  bruteforce_detector/core/plugin_manager.py   # Plugin auto-discovery
  bruteforce_detector/core/rule_engine.py      # YAML rule loading
  bruteforce_detector/core/realtime_engine.py  # Watchdog integration

Managers:
  bruteforce_detector/managers/blacklist.py         # Orchestrator
  bruteforce_detector/managers/blacklist_adapter.py # Storage abstraction
  bruteforce_detector/managers/blacklist_writer.py  # File backend
  bruteforce_detector/managers/database.py          # SQLite backend
  bruteforce_detector/managers/whitelist.py         # Whitelist with CIDR
  bruteforce_detector/managers/nftables_manager.py  # Firewall sync
  bruteforce_detector/managers/state.py             # Processing state

Utils:
  bruteforce_detector/utils/file_lock.py        # Advisory locking
  bruteforce_detector/utils/backup_manager.py   # Rotating backups
  bruteforce_detector/utils/integrity_checker.py # Corruption detection
  bruteforce_detector/utils/validators.py       # Input validation

Config:
  config.conf.template                       # Template with XDG paths
  bruteforce_detector/config.py             # Pydantic settings loader
```

## DOC FORMAT
```
FILE: relative/path/from/root | TYPE: fix|feature|refactor|docs|plugin
CHANGE: before → after (or "new plugin" for additions)
RAG: [deps consulted: base classes, managers, config]
YAML: [rule files modified] (if plugin work)
VALIDATION: [commands executed] (if applicable)
```

## SYSTEM CONTEXT
```
Architecture: Plugin-based detection engine with YAML rule system

Flow: Logs → Parsers → Detectors → BlacklistManager → Storage → NFTables
      ↓           ↓          ↓              ↓             ↓         ↓
   watchdog    YAML     YAML rules    Whitelist    File|SQLite  Bidirectional
   realtime   patterns   (threshold)     check                   CrowdSec/Fail2Ban

Storage Backends:
  - File: <10k IPs (blacklist_ipv4.txt, blacklist_ipv6.txt)
  - SQLite: ≥10k IPs (blacklist.db, WAL mode, retry logic)
  - Auto-switch: Configured via [storage] backend=auto

Config Precedence:
  1. Environment variables (TRIBANFT_* for paths, BFD_* for settings)
  2. INI config file (search: env → /etc → ~/.local/share → ./config.conf)
  3. Pydantic defaults

XDG Paths (mandatory):
  - Config: XDG_CONFIG_HOME (~/.config/tribanft/)
  - Data: XDG_DATA_HOME (~/.local/share/tribanft/)
  - State: XDG_STATE_HOME (~/.local/share/tribanft/)
  - Logs: systemd journal or /var/log/tribanft.log (system-wide)

Real-time Monitoring:
  - watchdog library for inotify file events
  - FilePositionTracker for incremental parsing
  - Fallback: polling if inotify unavailable
```

## KEY COMMANDS
```bash
# Main operations
tribanft --detect [--verbose]  # Run detection (verbose for DEBUG logging)
tribanft --list                 # Show current blacklist
tribanft --stats                # Show statistics

# Validation (no formal test suite)
scripts/analyze_and_tune.sh     # Analyze and tune thresholds
python3 -c "import yaml; yaml.safe_load(open('bruteforce_detector/rules/detectors/your_rule.yaml'))"
python3 -m bruteforce_detector.utils.detector_validator  # Validate detector rules

# Config debugging
tribanft --detect --verbose 2>&1 | grep "DEBUG: CONFIG"  # See loaded config values

# Server operations (user executes)
sudo systemctl status tribanft
sudo journalctl -u tribanft -f  # Follow logs
```

## TESTING GUIDANCE
```
No formal test suite exists. Validate changes via:

1. YAML syntax validation:
   CMD("python3 -c \"import yaml; yaml.safe_load(open('path'))\"", "validate YAML")

2. Detector rule validation:
   CMD("python3 -m bruteforce_detector.utils.detector_validator", "validate detector rules")

3. Manual testing:
   CMD("tribanft --detect --verbose", "test detection with sample logs")

4. Analysis script:
   CMD("bash scripts/analyze_and_tune.sh", "analyze thresholds")

5. Integration check:
   - Deploy to dev environment
   - Monitor systemd journal for errors
   - Verify nftables sync if configured

When adding features, suggest creating:
  - Unit tests for new utils/ modules
  - Integration tests for new detectors/parsers
  - Manual test procedures in docs/
```

## EXAMPLES

**FULL mode (code fix):**
```
MODE: FULL | Fix threshold comparison bug in detector

1. VIEW bruteforce_detector/detectors/failed_login.py
2. RAG base.py, rule_engine.py, config
3. EDIT "if count > thresh:" → "if count >= thresh:" (inclusive threshold)
4. CMD("tribanft --detect --verbose", "verify edge case: count==threshold triggers")
5. DOC: FILE=detectors/failed_login.py | TYPE=fix | CHANGE=">" to ">=" for inclusive threshold
```

**PLUGIN mode (new detector):**
```
MODE: PLUGIN | Add port scan detector

1. VIEW bruteforce_detector/detectors/base.py (understand interface)
2. VIEW bruteforce_detector/rules/detectors/RULE_TEMPLATE.yaml.example
3. RAG plugin_manager.py, existing detectors
4. EDIT (create) bruteforce_detector/plugins/detectors/port_scan.py + METADATA
5. EDIT (create) bruteforce_detector/rules/detectors/port_scan.yaml
6. CMD("python3 -c 'import yaml; yaml.safe_load(open(...))'", "validate YAML")
7. CMD("tribanft --detect --verbose", "test with sample logs")
8. DOC: FILE=plugins/detectors/port_scan.py | TYPE=plugin | RAG=[base.py, plugin_manager.py]
```

**ANALYSIS mode (review logging):**
```
MODE: ANALYSIS | Review logging performance

1. VIEW bruteforce_detector/parsers/apache.py
2. RAG utils/logging.py, config hierarchical settings
3. TAG:
   - FACT: L42 uses f-string in log call (interpolated even if not logged)
   - FACT: L67 parser logger set to WARNING in non-DEBUG mode (utils/logging.py:45)
   - INFERENCE: f-string overhead negligible (lazy eval at call site)
   - RISK: None (hierarchical logging already optimized)
   - VERIFIED: grep "parsers.*setLevel" utils/logging.py confirms optimization
```

**LIGHT mode (docs update):**
```
MODE: LIGHT | Update CONFIGURATION.md with SQLite backend info

1. VIEW docs/CONFIGURATION.md
2. EDIT (add section) "Storage Backend Selection" explaining <10k file, ≥10k SQLite
3. DOC: FILE=docs/CONFIGURATION.md | TYPE=docs | CHANGE=added storage backend explanation
```

## COMMON PATTERNS (code examples from project)

**Safe dictionary access:**
```python
# CORRECT (from managers/blacklist.py)
country = geo.get('country', 'Unknown') if geo else 'Unknown'
existing_count = existing_entry.get('event_count', 0)

# WRONG
country = geo['country']  # Crashes if 'country' missing
```

**Conditional updates:**
```python
# CORRECT (from managers/blacklist.py)
if ts_str and ts_str != 'Unknown':  # Only update if valid AND different
    entry['first_seen'] = ts_str
elif new_country and new_country != country:  # Prevents None overwrites
    entry['country'] = new_country

# WRONG
if ts_str or ts_str != 'Unknown':  # OR logic allows None to pass
```

**Context managers for locks:**
```python
# CORRECT (from managers/state.py)
with file_lock(self.lock_file, timeout=30, description="state save"):
    self._write_state(state)

# WRONG
lock = fcntl.flock(...)  # Manual lock management (error-prone)
```

**Atomic writes:**
```python
# CORRECT (from managers/state.py)
with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
    json.dump(state, tmp, indent=2)
    tmp_path = tmp.name
os.rename(tmp_path, self.state_file)  # Atomic swap

# WRONG
with open(self.state_file, 'w') as f:  # Non-atomic (corruption risk)
    json.dump(state, f)
```

**Whitelist precedence:**
```python
# CORRECT (from managers/blacklist.py)
if self.whitelist_manager.is_whitelisted(ip):
    self.logger.info(f"Skipping whitelisted IP: {ip}")
    continue  # NEVER block whitelisted IPs

# Check BEFORE all blacklist operations (add, update, query)
```

---
**v3.3** | 2025-12-22 | Optimized | S4.5 | ~2700 tokens
**Changes from v3.2:**
- Added XDG compliance emphasis
- Added PLUGIN mode and patterns
- Enhanced PREVENTION CHECKLIST (atomic writes, storage backend, XDG)
- Added STATE MANAGEMENT section
- Added TESTING GUIDANCE
- Updated CRITICAL FILES with actual paths
- Added BACKUP primitive
- Enhanced SYSTEM CONTEXT with storage backends, config precedence
- Added COMMON PATTERNS with code examples
- Added corruption protection to SECURITY INVARIANTS
- Added YAML validation to VALID primitive
