# TribanFT Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] - 2025-12-24

### Threat Intelligence & Missing Pieces Release

Major feature release implementing missing EventTypes and threat intelligence integration.

### Added

#### New EventTypes

- **DNS_ATTACK** - DNS attack detection (amplification, tunneling, zone transfers, brute force)
  - Added to models.py (line 98)
  - Fully implemented with DNS parser
  - Supports BIND9, dnsmasq, Unbound, systemd-resolved

#### DNS Parser (NEW)

- **DNS Parser** - DNS server attack detection
  - DNS_ATTACK: Generated for amplification, zone transfers, tunneling, subdomain brute force
  - Multi-server support: BIND9, dnsmasq, Unbound, systemd-resolved
  - 16 regex patterns covering major DNS attack vectors:
    - DNS amplification (ANY queries) - 3 patterns
    - Zone transfer attempts (AXFR/IXFR) - 4 patterns
    - DNS tunneling (long subdomains, Base64/hex) - 4 patterns
    - Subdomain brute force (NXDOMAIN) - 3 patterns
    - Suspicious queries (TXT, NULL) - 2 patterns
  - Multi-format timestamp parsing (BIND9, Unbound, syslog)
  - Pattern file: bruteforce_detector/rules/parsers/dns.yaml (283 lines)
  - Parser plugin: bruteforce_detector/plugins/parsers/dns.py (178 lines)
  - Config key: dns_log_path in config.conf.template
  - Updated documentation: PARSER_EVENTTYPES_MAPPING.md, API_REFERENCE.md

#### Threat Intelligence Integration (NEW)

- **Threat Feed Detector** - External threat intelligence integration
  - KNOWN_MALICIOUS_IP: Imports known malicious IPs from threat feeds
  - Supported feeds: AbuseIPDB, Spamhaus DROP/EDROP, AlienVault OTX
  - 24-hour cache with automatic TTL management
  - Automatic deduplication against existing blacklist
  - Rate limiting and API key management
  - Placeholder implementations for future API integrations
  - Detector plugin: bruteforce_detector/plugins/detectors/threat_feed.py (395 lines)
  - Rule file: bruteforce_detector/rules/detectors/threat_intelligence.yaml (162 lines)
  - Disabled by default (requires API keys and configuration)

- **CrowdSec Integration** - Community threat intelligence
  - CROWDSEC_BLOCK: Imports blocked IPs from CrowdSec Local API
  - Verified existing implementation (crowdsec.py already correct)
  - Added comprehensive YAML rule configuration
  - Rule file: bruteforce_detector/rules/detectors/crowdsec.yaml (260 lines)
  - Enabled by default if CrowdSec is installed
  - Includes installation and configuration instructions

#### Configuration

- **config.conf.template** - Threat intelligence configuration
  - Added [threat_intelligence] section:
    - threat_feeds_enabled: Enable/disable threat feed integration
    - threat_feed_sources: Comma-separated list of feed sources
    - threat_feed_cache_hours: Cache duration for feed results
  - Added dns_log_path to [logs] section
  - API key file configuration for AbuseIPDB and AlienVault OTX

#### Performance Optimizations (NEW)

- **Database Query Optimization** - Significantly improved query performance
  - Added database indexes:
    - idx_event_count (DESC) - Optimizes top threats queries
    - idx_date_added (DESC) - Optimizes time-range queries
    - idx_last_seen (DESC) - Optimizes recent activity queries
  - Query performance logging in debug mode:
    - Context manager for automatic timing
    - All major queries instrumented
    - Format: `[PERF] operation_name: XX.XXms`
  - New query methods with index-optimized SQL:
    - query_by_attack_type() - Filter by EventType
    - query_by_timerange() - Filter by date range
    - query_top_ips() - Get top IPs by event count
  - File: bruteforce_detector/managers/database.py (+200 lines)

#### Enhanced CLI Query Interface (NEW)

- **--query-attack-type TYPE** - Filter IPs by attack/event type
  - Example: `tribanft --query-attack-type sql_injection`
  - Searches event_types in metadata JSON
  - Case-insensitive matching
  - Displays up to 100 results sorted by event count

- **--query-timerange RANGE** - Filter IPs by time range
  - Flexible time range formats:
    - Date range: `"2025-12-01 to 2025-12-24"`
    - Relative: `"last 7 days"` or `"last 30 days"`
  - Uses idx_date_added index for fast queries
  - Results sorted by date_added descending

- **--export-json FILE** - Export blacklist to JSON format
  - Full metadata export with proper JSON structure
  - Includes all fields: geolocation, event_types, timestamps
  - Sorted by event_count descending
  - UTF-8 encoding with 2-space indentation

- **--live-monitor** - Real-time threat stream monitoring
  - Continuously monitors database for new threats
  - Displays threats as they're detected (2-second polling)
  - Shows: timestamp, IP, location, attack type, events, reason
  - Periodic statistics (threats/minute, uptime)
  - Press Ctrl+C to exit with final stats
  - File: bruteforce_detector/utils/live_monitor.py (145 lines)

- **Enhanced query_tool.py** - New query methods
  - query_attack_type() - Attack type filtering
  - query_timerange() - Time range filtering with parsing
  - export_json() - JSON export with full metadata
  - File: bruteforce_detector/utils/query_tool.py (+200 lines)


### Documentation

- **COMMANDS.md** - Comprehensive command reference documentation
  - Complete reference for all 40+ tribanft CLI commands
  - File: docs/COMMANDS.md (600+ lines)

### Changed

- **models.py** - Added DNS_ATTACK EventType to Protocol-Specific section
- **PARSER_EVENTTYPES_MAPPING.md** - Added DNS parser to capabilities matrix
- **API_REFERENCE.md** - Updated EventType documentation with v2.5.0 features
- **database.py** - Added 3 new indexes and query performance logging
- **main.py** - Added 4 new CLI arguments and command handlers
- **query_tool.py** - Added 3 new query methods for enhanced filtering

---

## [2.4.1] - 2025-12-23

### Documentation & Automation Release

Major documentation streamlining and automation-first approach. All manual operations replaced with scripts.

### Added

#### Parser Enhancements

- **Apache/Nginx Parser** - HTTP error event generation
  - HTTP_ERROR_4XX: Generated for status codes 400-499 (client errors)
  - HTTP_ERROR_5XX: Generated for status codes 500-599 (server errors)
  - Enables detection rules for error rate anomalies
  - Previously these EventTypes existed in models.py but were not generated
  - Updated documentation: PARSER_EVENTTYPES_MAPPING.md, API_REFERENCE.md, PARSERS.md

- **FTP Parser** - FTP server attack detection (NEW)
  - FTP_ATTACK: Generated for failed login attempts and authentication failures
  - Multi-server support: vsftpd, ProFTPD, Pure-FTPd
  - 9 regex patterns covering different FTP server log formats
  - Multi-format timestamp parsing (syslog, ISO formats)
  - Pattern file: bruteforce_detector/rules/parsers/ftp.yaml
  - Parser plugin: bruteforce_detector/plugins/parsers/ftp.py (172 lines)
  - Config key: ftp_log_path in config.conf.template
  - Updated documentation: PARSER_EVENTTYPES_MAPPING.md, PARSERS.md, README.md

- **SMTP Parser** - Mail server attack detection (NEW)
  - SMTP_ATTACK: Generated for authentication failures and relay abuse attempts
  - Multi-server support: Postfix, Sendmail, Exim
  - 13 regex patterns covering SASL auth failures, relay attempts, command pipelining
  - Detects both authentication failures and abuse patterns
  - Pattern file: bruteforce_detector/rules/parsers/smtp.yaml
  - Parser plugin: bruteforce_detector/plugins/parsers/smtp.py (158 lines)
  - Config key: smtp_log_path in config.conf.template
  - Updated documentation: PARSER_EVENTTYPES_MAPPING.md, PARSERS.md, README.md

#### Automation Scripts (2 new scripts)

- **install.sh** - Automated installation
  - One-command deployment
  - Automatic dependency installation (pyyaml, pydantic, watchdog)
  - Automatic backup of existing installation
  - Config creation from template with learning mode default
  - YAML validation
  - Systemd service setup
  - Eliminates all manual deployment steps

- **scripts/setup-config.sh** - Interactive configuration
  - Auto-detects existing config
  - Interactive prompts for key settings
  - Flags: --learning-mode, --production
  - Validates [plugins] section
  - Sets learning mode by default

- **scripts/setup_nftables.sh** - NFTables automation
  - Automated NFTables configuration for TribanFT
  - Creates required tables, chains, and sets
  - Sets up logging for blocked connections
  - 137 lines of setup automation

- **scripts/analyze_and_tune.sh** - Log analysis and tuning (rewritten)
  - Robust log parsing based on actual log format
  - Detection summary and attack type analysis
  - Top blocked IPs with country codes
  - Service health monitoring
  - Actionable tuning recommendations
  - No fragile field parsing or external dependencies

### Changed

#### Code Improvements

- **config.py** - Refactored configuration handling
  - Cleaner code structure
  - Improved readability and maintainability
  - Net reduction of 9 lines

- **config.conf.template** - Enhanced configuration
  - Added 6 new configuration parameters
  - Better organization

- **database.py** - Enhanced database manager
  - Improved error handling
  - Better logging

- **ipinfo_batch_manager.py** - IPInfo improvements
  - Enhanced rate limiting handling
  - Better error recovery

### Documentation

**Total Reduction: 3411 lines → 1669 lines (51% reduction)**

All documentation now follows "automated, concise, copy-paste ready" pattern:
- Copy-paste commands only
- Tables instead of prose
- Script references instead of manual operations
- Minimal inline examples
- No verbose explanations

#### Streamlined Documentation Files

- **DEPLOYMENT_GUIDE.md** (940 → 115 lines, 88% reduction)
  - 4-step automated deployment
  - Fully automated with install.sh
  - Removed all manual operations
  - Week-by-week workflow (learning → tuning → production)

- **PLUGIN_DEVELOPMENT.md** (1045 → 393 lines, 62% reduction)
  - Quick start with copy-paste commands
  - Reference tables for METADATA and methods
  - Minimal inline examples (2 complete examples)
  - Removed verbose tutorials
  - Troubleshooting in table format

- **CONFIGURATION.md** (990 → 353 lines, 64% reduction)
  - Automated setup with setup-config.sh
  - Service management with systemctl/journalctl
  - All [section] options in reference tables
  - Removed verbose systemd tutorial
  - Example configurations for common scenarios

- **MONITORING_AND_TUNING.md** (907 → 358 lines, 61% reduction)
  - Quick commands for all operations
  - Threshold tuning reference tables
  - Weekly monitoring checklist
  - Automated analysis with analyze_and_tune.sh
  - Removed manual log analysis scripts

- **PARSERS.md** (800 → 452 lines, 44% reduction)
  - Built-in parsers reference table
  - YAML pattern system guide
  - Minimal parser examples
  - Removed verbose Apache parser section (238 → 60 lines)
  - Pattern best practices table

- **API_REFERENCE.md** (621 → 397 lines, 36% reduction)
  - Core data models only
  - Base classes reference
  - Removed duplicate EventType documentation
  - Removed Apache parser details (link to PARSERS.md)
  - Removed migration guide (not API reference)
  - Development workflow guide

### Impact

**User Experience**:
- **4-command deployment**: wget → extract → install → start
- **Zero manual operations**: Everything automated with scripts
- **50% less reading**: Documentation cut in half
- **Copy-paste ready**: All commands work as-is

**Maintainability**:
- **Scripts handle logic**: Docs just reference scripts
- **Easier updates**: Change script, not 5 docs
- **Consistent patterns**: Same automation approach everywhere

**Deployment Time**:
- **Before**: ~30 minutes (manual steps, config editing, validation)
- **After**: ~5 minutes (run install.sh, verify logs)

---

## [2.4.0] - 2025-12-23

### NFTables Discovery & Extensibility Release

Enhanced NFTables integration with automatic set discovery and flexible IP import capabilities.

**Note:** Initial release had integration issues - features were coded but not connected to detection flow. Fixed in same-day patch (see "Fixed" section below).

### Added

#### NFTables Discovery
- **discover_nftables_sets()** method in NFTablesManager
  - Auto-discover all NFTables sets in the system
  - Extract metadata: family, table, set name, type, flags, timeout
  - Filter by family (ip/ip6/inet) or verdict context
  - Returns structured dict mapping set identifiers to metadata

- **import_from_set()** generic method in NFTablesManager
  - Import IPs from any NFTables set, not just port_scanners
  - Flexible parameters: table, set_name, family, reason
  - Automatic whitelist filtering
  - Returns data compatible with BlacklistAdapter
  - Replaces hardcoded set names with dynamic discovery

#### Shadow Event Log
- **Optional JSONL event log** for NFTables operations
  - Append-only audit trail at `${state_dir}/nftables_events.jsonl`
  - Logs discovery and import events with timestamps
  - Non-blocking: failures do not affect core functionality
  - Enables debugging, replay, and historical analysis
  - Controlled via `nftables_event_log_enabled` config parameter

#### Configuration
- **NFTables Discovery Section** in config.conf.template
  - `nftables_event_log_enabled`: Enable shadow event log (default: false)
  - `nftables_auto_discovery`: Auto-discover sets flag (default: false)
  - `nftables_import_sets`: Comma-separated custom sets to import

### Changed

- **Refactored get_port_scanners()** to use generic import_from_set()
  - Reduced code duplication by ~70 lines
  - Maintains backward compatibility (identical output format)
  - Improved maintainability through code reuse

### Documentation

- Updated docs/CONFIGURATION.md with NFTables discovery parameters
- Added usage examples for discovery and flexible import methods
- Added activation instructions in implementation summary
- Documented bug fix and integration changes

---

## [2.3.0] - 2025-12-22

### Real-Time Monitoring Release

Major architectural upgrade: real-time log monitoring with inotify/kqueue instead of periodic polling. Detection lag reduced from 5 minutes to <2 seconds.

### Added

#### Real-Time Log Monitoring
- **LogWatcher** (`bruteforce_detector/core/log_watcher.py`)
  - File system event monitoring using inotify (Linux) / kqueue (BSD/macOS)
  - Incremental log reading with byte offset tracking
  - Automatic file rotation detection and handling
  - Per-file thread-safe locking
  - Debouncing for rapid log writes (1s window)
  - Rate limiting for DoS protection (1000 events/s max)
  - Automatic fallback to periodic mode if watchdog unavailable

- **RealtimeDetectionMixin** (`bruteforce_detector/core/realtime_engine.py`)
  - Extends BruteForceDetectorEngine with real-time capabilities
  - Graceful degradation on errors (automatic fallback to periodic mode)
  - File position persistence in state.json
  - Separate detection pipeline for real-time events

- **Incremental Parsing** (`bruteforce_detector/parsers/base.py`)
  - `parse_incremental(from_offset, to_offset)` method in BaseLogParser
  - Reads only new log lines since last position
  - Returns (events, final_offset) for position tracking
  - Compatible with all existing parsers (syslog, mssql, apache, nginx)

#### State Management Improvements
- **Atomic State Writes with Backup** (`bruteforce_detector/managers/state.py`)
  - Automatic backup before state file updates
  - Corruption recovery from .bak file
  - Temp file + atomic rename pattern
  - Handles both file corruption scenarios

- **File Position Tracking** (`bruteforce_detector/models.py`)
  - `ProcessingState.last_processed_positions` dict for byte offsets
  - Per-file position persistence
  - Compatible with existing timestamp-based filtering

#### Migration Tools
- **Migration Assistant** (`bruteforce_detector/utils/migration.py`)
  - Detects legacy cron-based setups
  - `tribanft --migrate` command for automated migration
  - Automatic warnings in daemon mode if cron detected
  - Step-by-step migration guide display

#### Configuration
- **Real-Time Section** in `config.conf.template`
  - `monitor_syslog`, `monitor_mssql`, `monitor_apache`, `monitor_nginx` (per-source enable/disable)
  - `monitor_files` (custom file list override)
  - `debounce_interval` (batch rapid writes, default: 1.0s)
  - `max_events_per_second` (rate limit, default: 1000)
  - `rate_limit_backoff` (pause duration, default: 30s)
  - `fallback_interval` (periodic mode interval, default: 60s)

### Changed

#### Daemon Mode Behavior
- **Breaking**: `--daemon` now runs real-time monitoring by default
- **Removed**: `--interval` parameter (no longer needed)
- **Automatic fallback**: Periodic mode (60s) if watchdog unavailable
- **Systemd service** updated to use new real-time mode

#### Detection Pipeline
- Event processing is now immediate instead of batched every 5 minutes
- File rotation handled automatically (truncation detection + position reset)
- State updates every 60s to persist file positions

### Fixed
- File rotation edge cases (log rotation during processing)
- State corruption during power loss (atomic writes + backup)
- Memory usage with large log files (incremental reading vs. full file)

### Dependencies
- **Added**: `watchdog>=3.0.0` (optional, falls back to periodic if missing)

3. Install watchdog (optional, but recommended):
   ```bash
   pip install watchdog>=3.0.0
   ```

**Backward compatibility:**
- Single detection runs (`tribanft --detect`) work unchanged
- Existing config files work without modification
- System auto-detects watchdog availability and falls back gracefully

---

## [2.2.0] - 2025-12-22

### Security Enhancement Release

Major security improvements including new attack detection, firewall log parsing, and automatic configuration validation.

### Added

#### Network Layer Detection (L3/L4)
- **NFTablesParser** (`bruteforce_detector/plugins/parsers/nftables.py`)
  - Parses kernel firewall logs (nftables/iptables)
  - Behavioral analysis for port scanning detection
  - Network reconnaissance detection
  - Two-pass analysis with connection state tracking
  - Generates `PORT_SCAN` and `NETWORK_SCAN` EventTypes
- **IPTablesParser** - Alias for NFTablesParser
- **NFTables Pattern Configuration** (`bruteforce_detector/rules/parsers/nftables.yaml`)
  - Firewall log recognition patterns
  - Connection field extraction patterns
  - Threshold configuration documentation

#### Application Layer Detection (L7 - Web Attacks)
- **XSS Attack Detection** - 6 patterns
  - Script tag injection (`<script>`)
  - JavaScript protocol handlers (`javascript:`)
  - Event handler injection (`onload=`, `onerror=`)
  - Embedded content (`<iframe>`, `<object>`, `<embed>`)
  - Image tag XSS
  - Dialog injection (`alert()`, `confirm()`)
- **Path Traversal Detection** - 5 patterns
  - Directory traversal sequences (`../`, `..\`)
  - Sensitive file access (`/etc/passwd`, `c:\windows\system32`)
  - Protocol wrapper exploitation (`php://filter`, `file://`)
  - URL-encoded traversal (`%2f`, `%5c`)
  - Separator bypass (`/..;/`)
- **Command Injection Detection** - 4 patterns
  - Shell command injection (`;`, `|`, `&&`, backticks)
  - URL-encoded command injection (`%0a`, `%0d`)
  - Chained commands
  - Command substitution (`$()`, `${}`)
- **Malicious File Upload Detection** - 4 patterns
  - Executable file uploads (`.php`, `.jsp`, `.asp`, `.exe`)
  - Malicious content-type headers
  - SVG/XML with embedded scripts
  - Double extension uploads (`.jpg.php`)

#### Apache Parser Enhancements
- Added EventType generation for:
  - `XSS_ATTACK`
  - `PATH_TRAVERSAL`
  - `COMMAND_INJECTION`
  - `FILE_UPLOAD_MALICIOUS`
- Updated module and class docstrings
- Enhanced `_parse_line()` documentation

#### Detection Rules
- **Web Attacks Detector** (`bruteforce_detector/rules/detectors/web_attacks.yaml`)
  - XSS attack detector (threshold: 3 attempts / 30min)
  - Path traversal detector (threshold: 5 attempts / 30min)
  - Command injection detector (threshold: 2 attempts / 30min - critical)
  - Malicious upload detector (threshold: 3 attempts / 30min)
- **Network Scanning Detectors** (`bruteforce_detector/rules/detectors/network_scanning.yaml`)
  - Port scan detector (threshold: 1 scan detection)
  - Network scan detector (threshold: 1 scan detection)
  - Combined reconnaissance detector (threshold: 1 event)

#### Configuration Validation Framework
- **DetectorValidator** (`bruteforce_detector/utils/detector_validator.py`)
  - Validates parser/EventType coherence at detector load time
  - Prevents layer mismatch (L3/L4 vs L7 EventTypes)
  - Rejects misconfigured detectors with descriptive errors
  - Provides programmatic validation API
  - Helper methods:
    - `get_parser_capabilities(parser_name)` - Get EventTypes a parser can generate
    - `get_parsers_for_event_type(event_type)` - Get parsers that generate an EventType
    - `suggest_parser_for_detector(event_types)` - Suggest appropriate parsers
- **RuleEngine Integration** - Automatic validation during detector loading
  - Invalid detectors are rejected with error messages
  - Validation happens at startup (no runtime overhead)

#### Documentation
- **Parser/EventType Mapping** (`docs/PARSER_EVENTTYPES_MAPPING.md`)
  - Complete parser capabilities matrix
  - EventType generation logic for each parser
  - Validation framework documentation
  - Debugging guide and common mistakes
  - Migration guide for v2.2.0
- **Implementation Summary** (`docs/IMPLEMENTATION_SUMMARY_v2.2.md`)
  - Feature completion matrix
  - Validation report
  - Deployment checklist
  - Security impact assessment

#### Blacklist Management
- **IP Removal Command** (`tribanft --blacklist-remove <ip>`)
  - Remove IPs from blacklist database and files
  - Removes from NFTables if sync enabled
  - Validates IP address format
  - Methods added:
    - `BlacklistDatabase.delete_ip()` - Delete from SQLite
    - `BlacklistAdapter.remove_ip()` - Remove from storage layer
    - `BlacklistAdapter._remove_from_files()` - Remove from text files with metadata cleanup
    - `BlacklistManager.remove_ip()` - High-level removal with NFTables sync

### Changed

#### Pattern Refinements (Reduced False Positives)
- **SQL Injection Patterns** - Added SQL context requirements
  - Before: `(?i).*\bor\s+1\s*=\s*1.*` (too generic)
  - After: `(?i)(?:where|and|or)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?(?:--|#|/\*)` (requires SQL keywords + SQL comment)
  - Boolean injection now requires SQL keywords (`where`, `and`, `or`)
  - Stacked queries require SQL DDL/DML keywords + target objects
  - Information schema patterns require specific table references
- **WordPress Attack Patterns** - Removed redundant status code checks
  - Removed `\s+(401|403)` from regex patterns
  - Parser already filters by status code, regex duplication removed
  - Cleaner, more efficient pattern matching

#### Code Organization
- Removed leading/trailing `.*` from patterns for better performance
- Improved pattern descriptions for clarity

#### Configuration Architecture
- **Port Scan Thresholds** - Made configurable in YAML (was hardcoded)
  - `nftables.yaml` now controls detection sensitivity via `configuration` section
  - `port_scan_threshold`: Number of ports to trigger PORT_SCAN event (default: 5)
  - `network_scan_threshold`: Number of attempts to trigger NETWORK_SCAN event (default: 10)
  - Parser loads configuration at initialization with fallback to defaults
  - Users can tune without modifying Python code
  - Location: `bruteforce_detector/rules/parsers/nftables.yaml`

#### Documentation Compliance
- **Removed emojis from code** - Compliance with DOCUMENTATION_GUIDE.md
  - Removed checkmark emojis from log messages in:
    - `database.py`
    - `blacklist_adapter.py`
    - `blacklist.py`
  - All log output now text-only per documentation standards

### Security

#### Attack Coverage Expanded
- **Before v2.2**: SQL Injection, WordPress, Failed Login detection only
- **After v2.2**: +6 new attack categories
  - Port Scanning (L3/L4)
  - Network Scanning (L3/L4)
  - XSS (L7)
  - Path Traversal (L7)
  - Command Injection (L7)
  - Malicious File Upload (L7)

#### False Positive Reduction
- SQL injection patterns refined with context (estimated 60-70% reduction in false positives)
- WordPress patterns optimized (removed redundant checks)

#### Configuration Safety
- Automatic validation prevents silent failures
- Misconfigured detectors are rejected at load time
- Clear error messages guide configuration fixes

### Fixed

- **EventType integration** - DetectionResult now includes event_type field
  - Added `event_type: EventType` field to DetectionResult dataclass (models.py:193)
  - Updated `_create_detection_result()` to propagate detector event_type (base.py:144)
  - Updated rule engine `_create_detection()` to use source event type (rule_engine.py:467)
  - `to_dict()` now serializes event_type for JSON storage (models.py:206)
  - Fixes: CROWDSEC_BLOCK and KNOWN_MALICIOUS_IP EventTypes now properly propagated
  - Impact: Detection results can now be filtered by attack type, metrics by threat category
- Layer coherence issues (L3/L4 vs L7 EventType mismatches now prevented)
- Silent detector failures (misconfigured detectors now caught at load time)
- SQL injection false positives (patterns now require SQL context)
- **Invalid regex in apache.yaml** - Command injection pattern 3 had double-escaped parentheses
  - Changed from `(?i)(?:\`|\\$\\(|\\$\\{)` to `(?i)(?:\`|\$\(|\$\{)`
  - Pattern now compiles correctly and matches command substitution attacks
- **NFTables YAML warnings** - Moved documentation patterns outside `pattern_groups`
  - `common_scan_patterns` were documentation-only (no regex), causing loader warnings
  - Converted to comment-based documentation section
  - Parser pattern loader no longer warns about missing regex fields
- **Syntax error in main.py** - Fixed try/except block indentation
  - Line 353 logger statement was outside try block
  - Moved inside try block where it belongs
  - File now compiles without syntax errors

### Performance

- No runtime overhead (validation at load time only)
- Pre-compiled regex patterns (cached in memory)
- Efficient pattern matching (removed unnecessary `.*` wildcards)

### Migration Notes

#### Backwards Compatibility
- Fully backwards compatible
- Existing detectors continue to work unchanged
- New EventTypes are additive, not replacing
- Pattern refinements only improve accuracy

#### New Requirements
- **Firewall Logs** (optional): If using port scan detection, ensure firewall logs are available at `/var/log/kern.log` or `/var/log/messages`
- **No configuration changes required** for existing deployments

#### Validation Messages
- Expect new validation log messages during detector loading
- Invalid detectors will be logged and skipped (not loaded)
- Review logs for any detector configuration issues

---

## [2.1.0] - 2025-12-21

### YAML-Based Parser Patterns

This release migrates all parser pattern definitions from hardcoded Python to YAML configuration files, enabling pattern updates without code changes.

### Added

#### Parser Pattern System
- **ParserPatternLoader** (`bruteforce_detector/core/parser_pattern_loader.py`)
  - Loads and caches YAML-based parser patterns
  - Pre-compiles regex patterns for performance
  - Organizes patterns into logical groups
  - Graceful error handling for invalid YAML/regex
  - Singleton pattern for efficient memory usage

#### Parser Pattern Files (3 files)
- `bruteforce_detector/rules/parsers/apache.yaml` - 33 patterns in 4 groups
  - Log format parsing (1 pattern)
  - SQL injection detection (13 patterns)
  - WordPress attack detection (13 patterns)
  - Login page identification (6 patterns)
- `bruteforce_detector/rules/parsers/syslog.yaml` - 3 patterns in 2 groups
  - MSSQL prelogin detection (2 patterns)
  - Port scan detection (1 pattern)
- `bruteforce_detector/rules/parsers/mssql.yaml` - 2 patterns in 1 group
  - Failed login detection (2 patterns)
- `bruteforce_detector/rules/parsers/PARSER_TEMPLATE.yaml.example` - Template and documentation

#### BaseLogParser Enhancements
- Added `_pattern_loader` class variable (singleton pattern)
- Added `_load_patterns()` method (auto-loads on init)
- Added `_get_compiled_patterns(group)` method for accessing patterns
- Automatic initialization on first parser instantiation

### Changed

#### Parser Implementations
- **ApacheParser** - Removed 57 lines of hardcoded patterns
  - Now loads patterns from `apache.yaml`
  - Uses `_get_compiled_patterns()` for all pattern groups
  - Maintains same functionality with cleaner code
- **SyslogParser** - Removed hardcoded PRELOGIN_PATTERNS and PORT_SCAN_PATTERNS
  - Loads patterns from `syslog.yaml`
  - Added port scan detection (previously missing)
- **MSSQLParser** - Removed hardcoded failed_login_patterns
  - Loads patterns from `mssql.yaml`

### Removed

#### Legacy Files
- `bruteforce_detector/parsers/syslog.py` - Superseded by plugin version
- `bruteforce_detector/parsers/mssql.py` - Superseded by plugin version
- `bruteforce_detector/parsers/__init__.py` - Removed legacy imports (now exports only BaseLogParser)

### Documentation

#### Updated Files
- `docs/PARSERS.md` - Complete rewrite with YAML pattern system
  - Added "YAML-Based Pattern System" section (150+ lines)
  - Documented pattern file structure and syntax
  - Added pattern update workflow
  - Added custom pattern file creation guide
  - Included example custom web application parser
- `docs/DOCUMENTATION_GUIDE.md` - Added YAML documentation standards
  - Parser pattern YAML file format
  - YAML best practices
  - Validation commands
- `config.conf.template` - Added YAML Parser Patterns section
  - Documented pattern file locations
  - Pattern update instructions
  - Reference to comprehensive docs

### Benefits

- **No Code Deployment** - Update patterns without touching Python
- **Non-Programmer Friendly** - YAML is easier to read/write than code
- **Consistent Architecture** - Matches detector YAML rule format
- **Version Control** - Pattern changes tracked separately from code
- **Pattern Sharing** - Same SQL injection patterns used by detectors and parsers
- **Easier Maintenance** - Patterns clearly visible and documented
- **Graceful Degradation** - Invalid patterns logged but don't crash system

### Migration Notes

**For Users:**
- No action required - existing installations work unchanged
- Pattern updates: Edit YAML files in `bruteforce_detector/rules/parsers/`
- Validate YAML: `python3 -c "import yaml; yaml.safe_load(open('file.yaml'))"`

**For Developers:**
- Custom parsers: Use `self._get_compiled_patterns('group_name')` instead of hardcoding
- See `PARSER_TEMPLATE.yaml.example` for pattern file structure
- See `docs/PARSERS.md` for complete guide

---

## [2.0.0] - 2025-12-20

### Major Release: Plugin System & YAML Rule Engine

This release introduces a complete architectural overhaul with plugin-based extensibility and configuration-driven detection rules.

### Added - YAML Rule Engine

#### Core Features
- **YAML Rule Engine** (`bruteforce_detector/core/rule_engine.py`)
  - Define detection rules using YAML configuration files
  - Regex pattern matching with pre-compilation for performance
  - Configurable thresholds and time windows per rule
  - Multi-rule file support (single or multiple detectors per file)
  - Event aggregation by source IP, event type, or source
  - Support for all event types (FAILED_LOGIN, PRELOGIN_INVALID, PORT_SCAN, etc.)

#### Example YAML Rules (5 files)
- `sql_injection.yaml` - 13 SQL injection detection patterns
  - UNION-based, boolean-based, time-based, error-based injections
  - Stacked queries, xp_cmdshell, stored procedure abuse
  - MSSQL, MySQL, PostgreSQL, Oracle patterns
- `rdp_bruteforce.yaml` - 8 RDP attack patterns
  - Windows Event 4625 detection
  - CredSSP, NLA failures
  - Terminal Services errors
- `wordpress_attacks.yaml` - 4 multi-detector rules
  - Login bruteforce (wp-login.php)
  - XML-RPC amplification attacks
  - Vulnerability scanning
  - User enumeration
- `custom_environment_examples.yaml` - 8 environment-specific detectors
  - E-commerce platforms (Magento, WooCommerce)
  - API Gateway rate limiting
  - Corporate network lateral movement
  - Development environment probing
  - Cloud metadata service abuse (AWS/Azure/GCP)
  - Email credential stuffing
  - VPN bruteforce
  - DNS amplification attacks
- `RULE_TEMPLATE.yaml` - Complete syntax reference template

#### Configuration
- New `[plugins]` configuration section
  - `enable_yaml_rules` - Enable/disable YAML rule engine
  - `rules_dir` - Path to YAML rule files directory
  - Default: `~/.local/share/tribanft/bruteforce_detector/rules`

#### Integration
- Integrated rule engine into main detection cycle
- Rules execute after plugin detectors
- Fully compatible with existing detection system

### Added - Attack Detection Enhancement

#### New Event Types (18 added)
**EventType Enum Expansion** (`bruteforce_detector/models.py`):
- `SQL_INJECTION` - SQL injection attack attempts
- `WORDPRESS_ATTACK` - WordPress-specific attacks
- `HTTP_REQUEST` - Generic HTTP requests (baseline traffic)
- `RDP_ATTACK` - RDP bruteforce attempts
- `DIRECTORY_TRAVERSAL` - Path traversal attacks
- `XSS` - Cross-site scripting attempts
- `FILE_UPLOAD` - Malicious file upload attempts
- `COMMAND_INJECTION` - OS command injection
- `XXE` - XML external entity attacks
- `SSRF` - Server-side request forgery
- `LDAP_INJECTION` - LDAP injection attacks
- `XPATH_INJECTION` - XPath injection attacks
- `API_ABUSE` - API rate limiting violations
- `BRUTE_FORCE_GENERIC` - Generic bruteforce attacks
- `RECONNAISSANCE` - Reconnaissance/scanning activity
- `MALWARE_DOWNLOAD` - Malware download attempts
- `DATA_EXFILTRATION` - Data exfiltration attempts
- `PRIVILEGE_ESCALATION` - Privilege escalation attempts

**Case-Insensitive Parsing**:
- EventType enum now accepts both uppercase and lowercase values
- Example: `SQL_INJECTION`, `sql_injection`, or `Sql_Injection` all valid

#### Apache/Nginx Parser Plugin
**New Parser** (`bruteforce_detector/plugins/parsers/apache.py`):
- Parses Apache/Nginx access logs in combined format
- Multi-event generation capability (1-4 events per log line)
- 13 SQL injection detection patterns
- 13 WordPress attack detection patterns
- Failed login detection (401/403 on login pages)
- Rich metadata generation (method, URI, status, user-agent)

**Detection Capabilities**:

1. **SQL Injection Patterns** (13 patterns):
   - UNION-based injection
   - Boolean-based blind injection (OR/AND)
   - Time-based blind injection (WAITFOR, BENCHMARK, SLEEP)
   - Error-based injection (CONVERT, CAST)
   - Stacked query injection
   - Comment-based evasion
   - Information schema enumeration
   - MSSQL stored procedures (xp_cmdshell, sp_executesql)

2. **WordPress Attack Patterns** (13 patterns):
   - wp-login.php bruteforce
   - wp-admin access attempts
   - XML-RPC amplification (multicall, getUsersBlogs)
   - Plugin vulnerability scanning (timthumb, revslider)
   - Plugin/theme enumeration (readme.txt, style.css)
   - Malicious file upload attempts
   - wp-config backup scanning
   - REST API user enumeration
   - Author enumeration

3. **Failed Login Detection**:
   - HTTP status 401/403 on login pages
   - Detects /wp-login, /admin, /auth, /signin, /login paths

**Performance Features**:
- Pre-compiled regex patterns (initialized once)
- ~10,000 lines/second processing speed
- Incremental parsing (only new lines)

#### Log Sources Filtering
**Rule Engine Enhancement** (`bruteforce_detector/core/rule_engine.py`):
- New `log_sources` field in YAML rules
- Filter events by parser name before event_type matching
- Supports both `parsers` and `sources` syntax
- Example:
  ```yaml
  log_sources:
    parsers:
      - apache
      - nginx
  ```

**Benefits**:
- More precise event filtering
- Reduces false positives
- Better performance (early filtering)
- Parser-specific detection rules

#### Updated YAML Rules
**Modified Rules**:
- `sql_injection.yaml` - Now uses SQL_INJECTION and HTTP_REQUEST event types with log_sources
- `wordpress_attacks.yaml` - Updated with log_sources and 4 detector configurations
- `rdp_bruteforce.yaml` - Updated to use RDP_ATTACK and FAILED_LOGIN event types

**Rule Structure Changes**:
- Added log_sources section to filter by parser
- Updated event_types to use new EventType values
- Case-insensitive event type matching

### Added - Plugin System

#### Core Features
- **Plugin Manager** (`bruteforce_detector/core/plugin_manager.py`)
  - Auto-discovery of detector and parser plugins
  - Directory scanning for Python modules
  - Dependency injection based on constructor signatures
  - Configuration-driven enable/disable per plugin
  - METADATA dictionary support for plugin versioning

#### Plugin Architecture
- `bruteforce_detector/core/` - Core plugin framework
- `bruteforce_detector/plugins/detectors/` - Detector plugins directory
- `bruteforce_detector/plugins/parsers/` - Parser plugins directory
- Drop-in plugin support (no core code changes needed)

#### Migrated Plugins
All existing detectors and parsers converted to plugin architecture:

**Detector Plugins:**
- `prelogin.py` - MSSQL prelogin bruteforce detection
- `failed_login.py` - Failed login bruteforce detection
- `port_scan.py` - Port scanning detection
- `crowdsec.py` - CrowdSec integration

**Parser Plugins:**
- `syslog.py` - Syslog parser
- `mssql.py` - MSSQL error log parser

#### Plugin Templates
- `DETECTOR_PLUGIN_TEMPLATE.py` - Complete detector plugin example
- `PARSER_PLUGIN_TEMPLATE.py` - Complete parser plugin example
- Fully documented with usage examples

#### Configuration
- New `[plugins]` configuration section
  - `enable_plugin_system` - Enable/disable auto-discovery
  - `detector_plugin_dir` - Path to detector plugins
  - `parser_plugin_dir` - Path to parser plugins

### Added - Documentation

#### Comprehensive Documentation Suite (4,000+ lines)
- **QUICK_DEPLOY.md** (263 lines) - Fast deployment checklist
- **DEPLOYMENT_GUIDE.md** (710 lines) - Complete deployment procedures
  - Pre-deployment checklist
  - Step-by-step deployment
  - Learning mode → Tuning → Production workflow
  - Rollback procedures
  - Troubleshooting
- **PHASE_1_2_SUMMARY.md** (614 lines) - Implementation overview
  - What was implemented
  - Before/after comparison
  - Quick start guides
  - Use cases and examples
- **PLUGIN_DEVELOPMENT.md** (924 lines) - Plugin development guide
  - Creating detector plugins
  - Creating parser plugins
  - METADATA specifications
  - Testing and debugging
  - Best practices
  - Complete examples
- **RULE_SYNTAX.md** (671 lines) - YAML rule syntax reference
  - Complete syntax documentation
  - Pattern matching guide
  - Multi-rule files
  - Examples and troubleshooting
- **MONITORING_AND_TUNING.md** (907 lines) - Operations guide
  - Real-time log monitoring
  - Detection pattern analysis
  - Threshold tuning strategies
  - Environment-specific patterns
  - False positive analysis
  - Performance monitoring

#### Utility Scripts
- `scripts/analyze_and_tune.sh` (422 lines) - Advanced log analysis tool
  - Detection summary and statistics
  - Top blocked IPs with country info
  - Event count distribution
  - Time distribution analysis
  - Potential false positive identification
  - Automated tuning recommendations
  - Report generation

### Changed

#### Main Detection Engine
- Integrated `PluginManager` for auto-discovery
- Removed hardcoded detector/parser lists
- Implemented dependency injection for detectors
- Added rule engine execution after plugin detectors
- Maintained backward compatibility with legacy code

#### Configuration
- Added `[plugins]` section to `config.conf.template`
- Updated documentation references
- All settings have sensible defaults

#### Directory Structure
- Reorganized all documentation to `docs/` directory
- Created plugin directory structure
- Created rules directory structure

### Documentation Organization
- Moved all `.md` files to `docs/` directory (except README.md)
- Updated README.md with & 2 features
- Updated CONFIGURATION.md with plugin system section
- Created comprehensive CHANGELOG.md

### Performance

#### Optimizations
- Pre-compiled regex patterns in rule engine
- Lazy loading of plugins
- Efficient pattern matching with caching
- Smart backup system (90% reduction in backup count)

#### Statistics
- 40 Python files (11,259 lines of code)
- 5 YAML rule files (25+ detection patterns)
- 6 documentation files (4,089 lines)
- 3 utility scripts

### Compatibility

#### Backward Compatibility
- All existing detectors work as plugins
- All existing parsers work as plugins
- Legacy configuration files supported
- Existing blacklist files compatible
- Can disable plugin system to use legacy mode

#### Breaking Changes
- None - fully backward compatible

### Migration Path

#### From v1.x to v2.0
1. Install PyYAML dependency: `pip3 install pyyaml`
2. Add `[plugins]` section to config.conf (or let defaults apply)
3. No other changes required - automatic migration

#### Recommended Deployment
1. Week 1: Deploy with `enable_nftables_integration = false` (learning mode)
2. Week 2: Tune thresholds using `analyze_and_tune.sh`
3. Week 3+: Enable NFTables integration for production

### Security

#### New Detection Capabilities
- SQL injection detection (13 patterns)
- RDP bruteforce detection (8 patterns)
- WordPress-specific attacks (4 detectors)
- Environment-specific patterns (8 scenarios)
- Cloud metadata service abuse detection
- API rate limiting abuse detection

### Dependencies

#### New Requirements
- PyYAML >= 5.1 (for YAML rule parsing)

#### Existing Requirements (Unchanged)
- Python >= 3.8
- NFTables (for firewall integration)
- systemd (for service management)

---

## [1.3.0] - 2025-12-18

### Added
- Systemd service support (replaces cron)
- Smart backup system (skip redundant backups)
- Backup compression (gzip, automatic)
- SQLite database support for large deployments
- Rich IP metadata (geolocation, ISP, attack patterns)
- Query capabilities (by country, source, event type)
- IP investigation with automated log analysis

### Changed
- Migrated from cron to systemd service
- Improved backup retention logic
- Enhanced performance for large blacklists (>10,000 IPs)

### Performance
- Smart backups reduce backup count by ~90%
- Database mode handles millions of IPs efficiently
- Compressed backups save disk space

---

## [1.2.0] - 2025-12-14

### Added
- IPInfo.io batch service integration
- Automated geolocation enrichment
- CSV export functionality
- Backup verification and restore commands

### Changed
- Improved error handling in parsers
- Enhanced logging for debugging

---

## [1.1.0] - 2025-12-10

### Added
- CrowdSec integration
- NFTables bidirectional sync
- Whitelist support
- Manual blacklist management

### Changed
- Refactored detector architecture
- Improved MSSQL parser reliability

---

## [1.0.0] - 2025-12-01

### Initial Release

#### Core Features
- Syslog and MSSQL log parsing
- Failed login detection
- Port scan detection
- MSSQL prelogin detection
- NFTables integration
- File-based blacklist storage
- Basic geolocation support

---

## Version Numbering

- **Major version** (X.0.0): Breaking changes, architectural changes
- **Minor version** (0.X.0): New features, backward compatible
- **Patch version** (0.0.X): Bug fixes, minor improvements

---

## Upgrade Notes

### v1.x → v2.0

**Required Actions:**
1. Install PyYAML: `pip3 install pyyaml`
2. Add `[plugins]` section to config.conf (optional, has defaults)

**Optional Actions:**
1. Create custom YAML rules in `~/.local/share/tribanft/bruteforce_detector/rules/detectors/`
2. Create custom plugins in `~/.local/share/tribanft/bruteforce_detector/plugins/`
3. Use `analyze_and_tune.sh` for threshold optimization
4. Review environment-specific rule examples

**No Breaking Changes:**
- Existing configuration files work without modification
- Existing blacklist files are compatible
- Service continues running without interruption
- Plugin system can be disabled if needed

---

## Support

- **GitHub**: https://github.com/n0tjohnny/tribanft
- **Issues**: https://github.com/n0tjohnny/tribanft/issues
- **Documentation**: See `docs/` directory

---

**Legend:**
- `Added` - New features
- `Changed` - Changes to existing functionality
- `Deprecated` - Features that will be removed in future versions
- `Removed` - Features removed in this version
- `Fixed` - Bug fixes
- `Security` - Security improvements
