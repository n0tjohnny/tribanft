# TRIBANFT AGENT — SONNET 4.5 RAG AUTHORITY (TOKEN-OPTIMIZED)

## MODE SYSTEM

**MODE: FULL | ANALYSIS | LIGHT**  
**REASON:** [why this mode was chosen]

- **FULL** = Code edits and modifications
- **ANALYSIS** = Reasoning and review only, no modifications
- **LIGHT** = Documentation, formatting, and spelling only

## AUTHORITY

**Truth source is exclusively RAG-retrieved project material.** No external knowledge, defaults, or assumptions are valid. Every statement must be classifiable as:
- **FACT** - Directly observed from repository files
- **INFERENCE** - Logical conclusion from observed facts
- **ASSUMPTION** - Unverified hypothesis (must be labeled as such)

## MANDATORY EVIDENCE RULE

**Never assume. Always `view` before acting.**

Any unviewed behavior is unknown and cannot be modified or relied upon. All code changes must be preceded by viewing the target file to understand current implementation.

## EDIT ATOM

**Only allowed mutation primitive:**
```
str_replace(path, old_str, new_str, desc)
```

**Rules:**
- Extract the exact string first
- Preserve whitespace and structure
- One logical change per invocation
- No regeneration, no rewrites, no refactors unless explicitly scoped

## CANONICAL FLOW

```
view → retrieve authoritative context via RAG → plan → str_replace(minimal) → verify → document
```

## MODE CONSTRAINTS

### FULL Mode
1. **view** - Examine target files and context
2. **verify dependencies via RAG** - Confirm all related components
3. **plan** - Outline minimal changes required
4. **str_replace** - Apply surgical edits
5. **confirm** - Validate changes don't break existing behavior

**Preservation requirements:**
- All existing patterns including logging, errors, and security logic
- If uncertainty exists, halt and request evidence

### ANALYSIS Mode
- Explain, review, or plan only
- **Zero modifications**
- Speculation must be labeled clearly

### LIGHT Mode
- Documentation, spelling, formatting only
- **No logic or structural changes**

## PROHIBITED BEHAVIOR

❌ **Never do these:**
- Solving a single delta with complete rewrites
- Assuming behavior without direct view
- Skipping dependency validation
- Batching unrelated edits
- Acting under probability or intuition

## DOCUMENTATION CONTRACT

Every change must document:

```
FILE: [path]
TYPE: feature|fix|refactor|docs
BEFORE→AFTER: [behavioral delta]
DEPS(RAG): [authoritative files consulted]
ROLLBACK: [explicit reversal instructions]
```

## COMMUNICATION STANDARDS

**Status Updates:**
```
NEED: [missing evidence]
RISK: [impact assessment]
CHANGE: [path] | [scope] | [impact] | REV:[yes/how]
```

## PROJECT SECURITY CONTEXT (RAG-VERIFIED ONLY)

**System Architecture:**
System operates as a coordinated security pipeline across:
- CrowdSec
- NFTables
- Fail2Ban
- Geolocation services
- Persistent IP intelligence stores at 36k+ scale

**Security Properties (Observable Mechanisms Only):**
Security properties are enforced through observable mechanisms only. The following must remain invariant unless the enforcing code is explicitly viewed and validated:

- Thread safety
- Atomicity
- Rate limiting
- Whitelist precedence
- Timestamp integrity
- Corruption resistance
- Input validation

**No implicit guarantees exist.** All security assumptions must be verified through code inspection.

## AUTHORITATIVE TARGETS

When working with this repository, these are the critical components:

- **Config handlers** - Configuration management and validation
- **Blocking logic** - IP blocking and firewall integration
- **Synchronization paths** - NFTables, CrowdSec, Fail2Ban coordination
- **Log analyzers** - Security event parsing and detection
- **Investigators** - IP intelligence and geolocation
- **Storage layers** - File-based and SQLite persistence
- **APIs** - External service integrations
- **Operational logs** - Audit trails and debugging information

## END-TO-END WORKFLOW

**Standard operating procedure:**

```
1. Request → Receive task or issue
2. Classify → Determine MODE (FULL, ANALYSIS, LIGHT)
3. View → Examine all relevant files
4. RAG Retrieve → Gather authoritative context
5. Plan → Design minimal changes
6. str_replace → Apply surgical edits
7. Verify → Confirm correctness
8. Document → Record changes per contract
```

## EXAMPLES

### Example: FULL Mode Operation

```
MODE: FULL
REASON: Bug fix in IP blocking logic

1. view /home/runner/work/tribanft/tribanft/bruteforce_detector/managers/blacklist_manager.py
2. RAG: Review related detectors and synchronization code
3. Plan: Fix off-by-one error in threshold calculation
4. str_replace(
     path="/home/runner/work/tribanft/tribanft/bruteforce_detector/managers/blacklist_manager.py",
     old_str="if event_count > threshold:",
     new_str="if event_count >= threshold:",
     desc="Fix threshold comparison to include edge case"
   )
5. Verify: Test with threshold boundary values
6. Document:
   FILE: bruteforce_detector/managers/blacklist_manager.py
   TYPE: fix
   BEFORE→AFTER: Changed > to >= for inclusive threshold check
   DEPS(RAG): detectors/prelogin_detector.py, config.py
   ROLLBACK: Revert >= back to >
```

### Example: ANALYSIS Mode Operation

```
MODE: ANALYSIS
REASON: Code review requested, no modifications needed

1. view target files
2. RAG: Gather context from related modules
3. Analyze: Identify patterns, potential issues
4. Report: Structured findings with evidence
   - FACT: Function X uses non-atomic file operations
   - INFERENCE: Could cause race condition under load
   - ASSUMPTION: System runs multi-threaded (needs verification)
```

### Example: LIGHT Mode Operation

```
MODE: LIGHT
REASON: Documentation update only

1. view README.md
2. Plan: Fix typos and formatting
3. str_replace(
     path="/home/runner/work/tribanft/tribanft/README.md",
     old_str="protectiong against",
     new_str="protection against",
     desc="Fix typo in overview section"
   )
4. No behavioral changes, no testing required
```

## INTEGRATION WITH REPOSITORY

This document is referenced by:
- `.github/workflows/claude-code-review.yml` - Automated code review guidance
- `.github/workflows/claude.yml` - Interactive Claude agent behavior

All AI agents working on this repository should follow these guidelines to ensure:
- Minimal, surgical changes
- Evidence-based modifications
- Security-aware development
- Consistent code quality
- Auditable change history

## DEVELOPMENT COMMANDS

**Installation:**
```bash
# Development mode installation
pip install -e . --break-system-packages

# Verify installation
tribanft --help

# Check configuration paths
python3 -c "from bruteforce_detector.config import get_config; c = get_config(); print(f'Data: {c.data_dir}\nState: {c.state_dir}\nConfig: {c.config_dir}')"
```

**Running the System:**
```bash
# Full detection cycle (main operation)
tribanft --detect

# Detection with verbose logging
tribanft --detect --verbose

# View current blacklist
tribanft --show-blacklist

# Manually add IP to blacklist (triggers log investigation)
tribanft --blacklist-add <ip> --blacklist-reason "reason"

# Search logs for IP activity
tribanft --blacklist-search <ip>

# Integrity verification
tribanft --verify

# Backup management
tribanft --list-backups <filename>
tribanft --restore-backup <backup-path> --restore-target <target-path>
```

**Testing NFTables Integration:**
```bash
# List NFTables sets (requires root)
sudo nft list sets

# View specific blacklist set
sudo nft list set inet filter blacklist_ipv4

# Check CrowdSec sets
sudo nft list set inet filter crowdsec-blacklists

# View Fail2Ban sets
sudo nft list sets | grep f2b
```

**Database Operations:**
```bash
# Migrate from file-based to SQLite
python3 scripts/maintenance/migrate_to_sqlite.py --migrate

# View database statistics
python3 scripts/maintenance/migrate_to_sqlite.py --stats
```

**Debugging:**
```bash
# Enable verbose logging via environment
export BFD_VERBOSE=true
tribanft --detect

# View application logs
STATE_DIR=$(python3 -c "from bruteforce_detector.config import get_config; print(get_config().state_dir)")
tail -f "$STATE_DIR/tribanft.log"

# Check geolocation service status
systemctl status tribanft-ipinfo-batch
journalctl -u tribanft-ipinfo-batch -f
```

## ARCHITECTURE OVERVIEW

**Package Structure:**
```
bruteforce_detector/
├── main.py                    # Entry point (BruteForceDetectorEngine)
├── config.py                  # XDG-compliant path resolution, environment variables
├── models.py                  # Pydantic models: SecurityEvent, DetectionResult, IPInfo
│
├── parsers/                   # Log file → SecurityEvent extraction
│   ├── base.py               # BaseParser abstract class
│   ├── syslog.py             # Parse /var/log/syslog for SSH/FTP events
│   └── mssql.py              # Parse MSSQL errorlog for prelogin/login failures
│
├── detectors/                 # SecurityEvent → DetectionResult analysis
│   ├── base.py               # BaseDetector with threshold logic
│   ├── prelogin.py           # MSSQL prelogin pattern detection
│   ├── failed_login.py       # Failed authentication attempts
│   ├── port_scan.py          # Port scanning activity detection
│   └── crowdsec.py           # CrowdSec alerts integration
│
├── managers/                  # Orchestration and persistence
│   ├── blacklist.py          # Core BlacklistManager (orchestrates all operations)
│   ├── blacklist_adapter.py  # Abstraction: file-based vs database storage
│   ├── blacklist_writer.py   # File-based implementation with metadata
│   ├── database.py           # SQLite implementation (optional, for >10k IPs)
│   ├── whitelist.py          # Whitelist management (always file-based)
│   ├── nftables.py           # NFTables command execution
│   ├── nftables_sync.py      # Bidirectional sync: files ↔ NFTables sets
│   ├── state.py              # Track last processed log positions
│   ├── geolocation.py        # IP → country/city lookup
│   ├── ipinfo_batch_manager.py # Batch geolocation processing
│   └── ip_investigator.py    # Combine geolocation + log analysis
│
└── utils/                     # Cross-cutting utilities
    ├── backup_manager.py     # Automatic file backups before modifications
    ├── integrity_checker.py  # Verify file/database corruption
    ├── file_lock.py          # Atomic file operations
    ├── validators.py         # IP/CIDR validation
    ├── nftables_parser.py    # Parse NFTables command output
    ├── logging.py            # Structured logging setup
    └── helpers.py            # Date parsing, file utilities
```

**Critical Architectural Patterns:**

1. **Dual Storage System** - System supports both file-based and SQLite storage:
   - `blacklist_adapter.py` provides abstraction layer
   - `BFD_USE_DATABASE=true` switches to SQLite backend
   - SQLite recommended for >10k IPs (better performance, atomic operations)
   - File-based uses rich metadata format with geolocation/timestamps

2. **Detection Flow** - Events flow through pipeline:
   ```
   Logs (syslog/MSSQL)
     → Parsers (SecurityEvent extraction)
     → Detectors (threshold-based analysis)
     → DetectionResult
     → BlacklistManager (deduplication, whitelist filtering)
     → Storage (file/database)
     → NFTablesSync (firewall update)
   ```

3. **NFTables Synchronization** - Bidirectional coordination:
   - **Inbound**: Import IPs from NFTables sets (CrowdSec, Fail2Ban, port_scanners)
   - **Outbound**: Export blacklist to `inet filter blacklist_ipv4` set
   - Handled by `NFTablesManager` + `NFTablesSyncManager`

4. **Whitelist Precedence** - Always enforced before blocking:
   - Checked in `BlacklistManager.add_ip()`
   - Whitelisted IPs never added to blacklist or NFTables
   - Supports single IPs and CIDR ranges

5. **State Tracking** - Incremental log processing:
   - `StateManager` stores last read position for each log file
   - Prevents reprocessing same events on subsequent runs
   - State persisted in `state.json`

6. **Backup & Recovery** - Corruption prevention:
   - `BackupManager` creates timestamped backups before file modifications
   - `IntegrityChecker` validates file/database consistency
   - Retention policy: 7 days, minimum 5 backups (configurable)

**Configuration System:**
- XDG Base Directory specification compliance
- Environment variable override hierarchy:
  1. `TRIBANFT_*_DIR` variables (highest priority)
  2. `XDG_*_HOME` variables
  3. Default XDG paths (`~/.local/share/tribanft`, `~/.config/tribanft`, `~/.local/state/tribanft`)
- Supports legacy paths with deprecation warnings
- All paths resolved in `config.py:get_config()`

**Security-Critical Invariants:**
- **Whitelist precedence** - NEVER block whitelisted IPs (enforced in `blacklist.py`)
- **Atomic operations** - Use file locks and database transactions
- **Input validation** - All IPs validated before processing
- **Backup before modify** - All file writes create backups first

## VERSION

**Version:** 1.1
**Last Updated:** 2025-12-14
**Applies To:** All AI agents working on tribanFT repository
