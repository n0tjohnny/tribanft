# TribanFT YAML Rule Syntax Reference

Complete reference for creating YAML-based detection rules.

**Author**: TribanFT Project
**License**: GNU GPL v3
**Last Updated**: 2025-12-21 (Phase 1 updates)

---

## Table of Contents

1. [Overview](#overview)
2. [Rule File Format](#rule-file-format)
3. [Metadata Section](#metadata-section)
4. [Log Sources Section](#log-sources-section)
5. [Detection Section](#detection-section)
6. [Pattern Syntax](#pattern-syntax)
7. [Aggregation Section](#aggregation-section)
8. [Output Section](#output-section)
9. [Multi-Rule Files](#multi-rule-files)
10. [Best Practices](#best-practices)
11. [Examples](#examples)

---

## Overview

YAML rules allow you to define threat detection logic without writing Python code. Rules are automatically discovered and loaded from `bruteforce_detector/rules/detectors/`.

### Benefits

1. **No Coding Required**: Define patterns using regex and thresholds
2. **Easy to Share**: YAML files can be version controlled and shared
3. **Hot Reload**: Update rules without code changes (restart required)
4. **Community Driven**: Share rule packs for specific attack types
5. **Rapid Prototyping**: Test detection logic quickly

### How It Works

1. **Load**: RuleEngine scans `rules/detectors/*.yaml`
2. **Parse**: YAML files parsed into DetectionRule objects
3. **Apply**: Rules applied to SecurityEvents from log parsers
4. **Match**: Events matching patterns are counted
5. **Detect**: When threshold reached, DetectionResult created
6. **Block**: Malicious IPs added to blacklist and NFTables

---

## Rule File Format

### Basic Structure

```yaml
metadata:
  name: rule_name
  version: 1.0.0
  description: What this rule detects
  enabled: true

log_sources:         # Optional (Phase 1)
  parsers:           # Filter by parser name
    - apache
    - nginx

detection:
  event_types:
    - FAILED_LOGIN
  threshold: 10
  time_window_minutes: 60
  confidence: high

  patterns:
    - regex: "pattern here"
      description: "What pattern matches"

aggregation:
  group_by: source_ip

output:
  reason_template: "Detection message"
```

### File Location

- **Single Rule**: `bruteforce_detector/rules/detectors/my_rule.yaml`
- **Multi-Rule**: `bruteforce_detector/rules/detectors/attack_pack.yaml`

### File Extension

- Use `.yaml` or `.yml`
- Both are supported

---

## Metadata Section

Provides information about the rule.

### Required Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `name` | string | Unique rule identifier (lowercase, underscores) | `sql_injection_detector` |
| `version` | string | Semantic version (MAJOR.MINOR.PATCH) | `1.0.0` |
| `enabled` | boolean | Whether rule is active | `true` |

### Optional Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `author` | string | Rule author/maintainer | `Security Team` |
| `description` | string | What the rule detects | `Detects SQL injection attempts` |
| `priority` | string | Execution priority | `high` (critical/high/medium/low) |

### Example

```yaml
metadata:
  name: rdp_bruteforce
  version: 2.1.0
  author: TribanFT Project
  description: Detects RDP bruteforce attacks
  enabled: true
  priority: high
```

---

## Log Sources Section

Filters which events are analyzed by this rule based on their source.

**Added in**: Phase 1 (v2.0)
**Purpose**: Improve performance by filtering events before pattern matching
**Optional**: If omitted, all events matching event_types are analyzed

### parsers

List of parser names to accept events from.

**Type**: List of strings
**Format**: Parser names from plugin METADATA
**Default**: None (accept all parsers)

**Available Parsers**:
- `apache` - Apache/Nginx access logs
- `nginx` - Nginx access logs (alias for apache)
- `syslog` - System authentication logs
- `mssql` - Microsoft SQL Server error logs
- `windows_security` - Windows Security Event Log
- Custom parsers (check your installation)

**How It Works**:
1. Rule engine receives events from all parsers
2. If `log_sources.parsers` is defined, only events where `event.source` matches are kept
3. Remaining events are then filtered by `event_types`
4. Pattern matching only runs on filtered events

**Performance Benefit**:
- Filtering by parser is faster than regex pattern matching
- Reduces unnecessary pattern evaluations
- Example: SQL injection rule only analyzes HTTP logs, not MSSQL logs

### Example: Web Application Attacks

```yaml
log_sources:
  parsers:
    - apache
    - nginx

detection:
  event_types:
    - SQL_INJECTION
    - WORDPRESS_ATTACK
    - HTTP_REQUEST
```

This rule only analyzes events from Apache/Nginx parsers, ignoring MSSQL, syslog, etc.

### Example: RDP Attacks

```yaml
log_sources:
  parsers:
    - windows_security
    - syslog

detection:
  event_types:
    - RDP_ATTACK
    - FAILED_LOGIN
```

This rule only analyzes events from Windows Security logs and syslog.

### Example: No Filter (Accept All)

```yaml
# log_sources section omitted

detection:
  event_types:
    - FAILED_LOGIN
```

This rule analyzes FAILED_LOGIN events from all parsers (apache, syslog, mssql, etc.).

### Best Practices

1. **Always specify parsers** for attack-specific rules:
   ```yaml
   # SQL injection only comes from web logs
   log_sources:
     parsers: [apache, nginx]
   ```

2. **Omit for generic rules** that apply to all sources:
   ```yaml
   # Failed logins can come from anywhere
   # log_sources: not specified
   ```

3. **Use correct parser names** from plugin METADATA:
   ```python
   # In parser plugin
   METADATA = {
       'name': 'apache',  # Use this name in YAML
   }
   ```

4. **Check available parsers**:
   ```bash
   # View loaded parsers in logs
   sudo journalctl -u tribanft | grep "Discovered parser"
   ```

---

## Detection Section

Defines what to detect and how.

### event_types

List of EventType enums to analyze.

**Type**: List of strings (case-insensitive as of Phase 1)
**Format**: Uppercase with underscores (e.g., `SQL_INJECTION`)
**Required**: Yes (at least one event type)

**Available Types** (22 total as of Phase 1):

#### Authentication Events
- `PRELOGIN_INVALID` - MSSQL reconnaissance (malformed prelogin packets)
- `FAILED_LOGIN` - Failed authentication (SSH, FTP, HTTP, MSSQL, RDP)
- `SUCCESSFUL_LOGIN` - Successful authentication (for anomaly detection)

#### Network Events
- `PORT_SCAN` - Port scanning activity (Nmap, Masscan)
- `NETWORK_SCAN` - Network reconnaissance

#### HTTP/Web Events (Phase 1)
- `HTTP_REQUEST` - Generic HTTP request (all web traffic)
- `HTTP_ERROR_4XX` - Client errors (400, 401, 403, 404)
- `HTTP_ERROR_5XX` - Server errors (500, 502, 503)

#### Attack Events (Phase 1)
- `SQL_INJECTION` - SQL injection attempts (UNION, blind, time-based)
- `XSS_ATTACK` - Cross-site scripting attempts
- `PATH_TRAVERSAL` - Directory traversal attacks (`../`)
- `COMMAND_INJECTION` - OS command injection
- `FILE_UPLOAD_MALICIOUS` - Malicious file upload attempts

#### Application-Specific (Phase 1)
- `WORDPRESS_ATTACK` - WordPress attacks (wp-login, xmlrpc, plugin scanning)
- `DRUPAL_ATTACK` - Drupal attacks
- `JOOMLA_ATTACK` - Joomla attacks

#### Protocol-Specific (Phase 1)
- `RDP_ATTACK` - RDP bruteforce/exploitation (Windows Event 4625)
- `SSH_ATTACK` - SSH bruteforce/exploitation
- `FTP_ATTACK` - FTP bruteforce
- `SMTP_ATTACK` - SMTP abuse/attacks

#### Threat Intelligence
- `CROWDSEC_BLOCK` - CrowdSec community blocks
- `KNOWN_MALICIOUS_IP` - Known bad IPs from threat feeds

**Case-Insensitive Matching** (Phase 1):
```yaml
# All of these are equivalent:
event_types:
  - SQL_INJECTION   # Recommended
  - sql_injection   # Also works
  - Sql_Injection   # Also works
```

**Multiple Event Types**:
```yaml
detection:
  event_types:
    - SQL_INJECTION
    - HTTP_REQUEST  # Analyze both types
```

**Example: Web Application Security**:
```yaml
detection:
  event_types:
    - SQL_INJECTION
    - WORDPRESS_ATTACK
    - XSS_ATTACK
```

**Example: Authentication Monitoring**:
```yaml
detection:
  event_types:
    - FAILED_LOGIN
    - RDP_ATTACK
    - SSH_ATTACK
```

**See Also**: [API_REFERENCE.md](API_REFERENCE.md#eventtype-enum) for complete EventType documentation

### threshold

Minimum number of matching events required to trigger detection.

**Type**: Integer
**Range**: 1-1000
**Default**: 10

**Guidelines**:
- **Low threshold (1-5)**: Very sensitive, more false positives
- **Medium threshold (10-20)**: Balanced detection
- **High threshold (50+)**: Conservative, fewer false positives

**Example**:
```yaml
detection:
  threshold: 15  # Trigger after 15 matching events
```

### time_window_minutes

Time window in minutes for event aggregation.

**Type**: Integer
**Range**: 1-1440 (24 hours)
**Default**: 60

**Guidelines**:
- **Short window (5-30 min)**: Fast/targeted attacks
- **Medium window (60-120 min)**: Balanced detection
- **Long window (1440 min/24 hr)**: Slow/distributed attacks

**Example**:
```yaml
detection:
  time_window_minutes: 30  # 30-minute window
```

### confidence

Confidence level of detection.

**Type**: String (enum)
**Options**: `high`, `medium`, `low`
**Default**: `medium`

**Impact**:
- Affects blacklist priority
- Used for alert severity
- Determines response actions

**Example**:
```yaml
detection:
  confidence: high  # High-confidence detection
```

### patterns

List of regex patterns to match against log lines.

See [Pattern Syntax](#pattern-syntax) for details.

**Example**:
```yaml
detection:
  patterns:
    - regex: "(?i).*failed.*login.*"
      description: "Failed authentication"
      severity: high
```

---

## Pattern Syntax

Patterns use Python regex with optional flags.

### Pattern Structure

```yaml
patterns:
  - regex: "your regex pattern"
    description: "What this matches"
    severity: high  # Optional
    flags: []       # Optional
```

### Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `regex` | Yes | string | Python regex pattern |
| `description` | No | string | Human-readable description |
| `severity` | No | string | critical/high/medium/low |
| `flags` | No | list | Regex flags (see below) |

### Regex Flags

```yaml
patterns:
  - regex: "pattern"
    flags:
      - IGNORECASE   # Case-insensitive matching
      - MULTILINE    # ^ and $ match line boundaries
      - DOTALL       # . matches newlines
```

### Common Patterns

#### Case-Insensitive Matching

```yaml
# Option 1: Use (?i) flag in regex
- regex: "(?i).*failed.*login.*"

# Option 2: Use flags list
- regex: ".*failed.*login.*"
  flags: [IGNORECASE]
```

#### IP Address Extraction

```yaml
- regex: ".*from\\s+(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*"
  description: "Extract IPv4 address"
```

#### Multiple Alternatives

```yaml
- regex: "(?i).*(union|select|drop|insert|delete).*"
  description: "SQL keywords"
```

#### Word Boundaries

```yaml
- regex: "\\berror\\b"
  description: "Match 'error' as whole word"
```

#### Special Characters

Escape these characters with backslash:
- `.` `*` `+` `?` `^` `$` `(` `)` `[` `]` `{` `}` `|` `\`

```yaml
- regex: "/wp-login\\.php"  # Dot is literal
- regex: "\\$_POST\\['user'\\]"  # Dollar and brackets escaped
```

### Pattern Testing

Before deploying, test patterns at:
- **https://regex101.com** (select Python flavor)
- **https://regexr.com**

---

## Aggregation Section

Defines how matching events are grouped.

### group_by

Field to group events by before applying threshold.

**Type**: String (enum)
**Options**:
- `source_ip` - Group by attacker IP address (most common)
- `event_type` - Group by attack type
- `source` - Group by log source

**Default**: `source_ip`

**Example**:
```yaml
aggregation:
  group_by: source_ip  # Count events per IP
```

### condition

Condition for triggering detection (for future use).

**Currently Supported**: `count >= threshold` only

**Example**:
```yaml
aggregation:
  condition: count >= threshold
```

---

## Output Section

Configures detection result formatting.

### reason_template

Template for detection reason message.

**Type**: String with variables
**Variables**:
- `{rule_name}` - Name of matched rule
- `{event_count}` - Number of events matched
- `{pattern_description}` - Description from matched pattern
- `{ip}` - Source IP address
- `{threshold}` - Configured threshold

**Example**:
```yaml
output:
  reason_template: "SQL injection: {pattern_description} - {event_count} attempts from {ip}"
```

**Result**:
```
SQL injection: UNION-based injection - 25 attempts from 1.2.3.4
```

---

## Multi-Rule Files

Define multiple related rules in a single file.

### Format

```yaml
detectors:
  - metadata:
      name: rule_one
      ...
    detection:
      ...
    output:
      ...

  - metadata:
      name: rule_two
      ...
    detection:
      ...
    output:
      ...
```

### Example

See `bruteforce_detector/rules/detectors/wordpress_attacks.yaml` for a complete example with 4 rules in one file.

---

## Best Practices

### Performance

**Specific Patterns**: Use specific patterns to reduce false matches
**Reasonable Thresholds**: Avoid threshold=1 (too sensitive)
**Test Regex**: Validate patterns before deployment
**Limit Patterns**: <20 patterns per rule for performance

### Security

**Validate Patterns**: Avoid ReDoS (regex denial of service)
**Document Examples**: Include test log lines in comments
**Version Control**: Track changes to rules
**Peer Review**: Have rules reviewed before production

### Maintenance

**Descriptive Names**: Use clear rule/pattern names
**Comments**: Document why patterns exist
**Versioning**: Increment version on changes
**Disable vs Delete**: Disable rules instead of deleting

### Organization

**One Attack Type**: One rule file per attack category
**Related Rules**: Group related patterns in multi-rule files
**Naming Convention**: `attack_type_detector.yaml`

---

## Examples

### Example 1: Simple Threshold Rule

Detect IPs with >10 failed SSH logins in 30 minutes.

```yaml
metadata:
  name: ssh_bruteforce
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - FAILED_LOGIN
  threshold: 10
  time_window_minutes: 30
  confidence: high

  patterns:
    - regex: "(?i).*sshd.*failed.*password.*"
      description: "SSH password failure"

aggregation:
  group_by: source_ip

output:
  reason_template: "SSH bruteforce - {event_count} failed logins"
```

### Example 2: Multiple Pattern Rule

Detect various SQL injection techniques.

```yaml
metadata:
  name: sql_injection
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - SQL_INJECTION
  threshold: 5
  time_window_minutes: 60
  confidence: high

  patterns:
    - regex: "(?i).*\\bunion\\s+select.*"
      description: "UNION-based injection"
      severity: critical

    - regex: "(?i).*\\bor\\s+1=1.*"
      description: "Boolean injection"
      severity: critical

    - regex: "(?i).*sleep\\(\\d+\\).*"
      description: "Time-based injection"
      severity: high

aggregation:
  group_by: source_ip

output:
  reason_template: "SQL injection: {pattern_description} ({event_count} attempts)"
```

### Example 3: Low Threshold / High Confidence

Detect critical attacks with few attempts.

```yaml
metadata:
  name: xp_cmdshell_exploit
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - FAILED_LOGIN
    - PRELOGIN_INVALID
  threshold: 1  # Single attempt is enough
  time_window_minutes: 1440  # 24 hours
  confidence: high

  patterns:
    - regex: "(?i).*xp_cmdshell.*"
      description: "xp_cmdshell exploitation"
      severity: critical

aggregation:
  group_by: source_ip

output:
  reason_template: "CRITICAL: xp_cmdshell exploitation attempt detected"
```

### Example 4: Multi-Rule File

Multiple related rules in one file.

```yaml
detectors:
  # Rule 1: WordPress login bruteforce
  - metadata:
      name: wp_login_bruteforce
      version: 1.0.0
      enabled: true

    detection:
      event_types: [FAILED_LOGIN]
      threshold: 15
      time_window_minutes: 30
      confidence: high

      patterns:
        - regex: "(?i).*/wp-login\\.php.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "WordPress login bruteforce"

  # Rule 2: WordPress XML-RPC abuse
  - metadata:
      name: wp_xmlrpc_abuse
      version: 1.0.0
      enabled: true

    detection:
      event_types: [PORT_SCAN]
      threshold: 5
      time_window_minutes: 15
      confidence: high

      patterns:
        - regex: "(?i).*/xmlrpc\\.php.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "WordPress XML-RPC abuse"
```

---

## Troubleshooting

### Rule Not Loading

**Problem**: Rule not discovered by RuleEngine

**Solutions**:
1. Check file extension (`.yaml` or `.yml`)
2. Verify file in `bruteforce_detector/rules/detectors/`
3. Check YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('rule.yaml'))"`
4. Enable debug: `verbose = true` in config.conf
5. Check logs: `sudo journalctl -u tribanft | grep "Loaded rule"`

### Rule Not Triggering

**Problem**: Rule loads but doesn't create detections

**Solutions**:
1. Check `enabled: true` in metadata
2. Verify `event_types` match parser output
3. Lower `threshold` for testing
4. Test patterns against actual log lines
5. Add debug logging to patterns
6. Check `enable_yaml_rules = true` in config.conf

### Pattern Not Matching

**Problem**: Pattern doesn't match expected log lines

**Solutions**:
1. Test regex at regex101.com
2. Check for escaped special characters
3. Use `(?i)` for case-insensitive
4. Verify log format matches pattern
5. Check raw_message field content

### Performance Issues

**Problem**: Rules slow down detection

**Solutions**:
1. Reduce number of patterns per rule
2. Use more specific patterns
3. Optimize regex (avoid backtracking)
4. Increase threshold
5. Disable unused rules

---

## Reference

### Complete Rule Schema

```yaml
metadata:
  name: string (required)
  version: string (required)
  author: string (optional)
  description: string (optional)
  enabled: boolean (required)
  priority: string (optional, critical|high|medium|low)

detection:
  event_types: list<EventType> (required)
  threshold: integer (required, 1-1000)
  time_window_minutes: integer (required, 1-1440)
  confidence: string (required, high|medium|low)

  patterns: list (required)
    - regex: string (required)
      description: string (optional)
      severity: string (optional, critical|high|medium|low)
      flags: list<string> (optional, IGNORECASE|MULTILINE|DOTALL)

aggregation:
  group_by: string (required, source_ip|event_type|source)
  condition: string (optional, "count >= threshold")

output:
  reason_template: string (required)
```

---

**For more examples, see:**
- `bruteforce_detector/rules/detectors/sql_injection.yaml`
- `bruteforce_detector/rules/detectors/rdp_bruteforce.yaml`
- `bruteforce_detector/rules/detectors/wordpress_attacks.yaml`
- `bruteforce_detector/rules/detectors/RULE_TEMPLATE.yaml`

**Need help?** Check PLUGIN_DEVELOPMENT.md or create an issue on GitHub.
