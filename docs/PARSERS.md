# TribanFT Log Parsers Reference

Complete reference for built-in and custom log parsers.

**Author**: TribanFT Project
**License**: GNU GPL v3
**Last Updated**: 2025-12-21
**Version**: 2.1 (YAML-based patterns)

---

## Table of Contents

1. [Overview](#overview)
2. [YAML-Based Pattern System](#yaml-based-pattern-system)
3. [Built-in Parsers](#built-in-parsers)
4. [Parser Configuration](#parser-configuration)
5. [Creating Custom Parsers](#creating-custom-parsers)
6. [Creating Custom Pattern Files](#creating-custom-pattern-files)

---

## Overview

Log parsers extract security events from log files. Each parser is responsible for:
- Reading log files in a specific format
- Identifying security-relevant events
- Creating SecurityEvent objects with appropriate metadata
- Supporting incremental parsing (only process new lines)

### YAML Pattern Architecture

**NEW in v2.1**: Parsers now use YAML-based pattern definitions instead of hardcoded patterns.

**Benefits**:
- ✓ Update patterns without changing Python code
- ✓ Non-programmers can add/modify patterns
- ✓ Consistent with detector YAML rules
- ✓ Pattern versioning and documentation
- ✓ No code deployment needed for pattern updates

### Parser Discovery

Parsers are automatically discovered from:
```
~/.local/share/tribanft/bruteforce_detector/plugins/parsers/
```

**Configuration**:
```ini
[plugins]
enable_plugin_system = true
parser_plugin_dir = ~/.local/share/tribanft/bruteforce_detector/plugins/parsers
```

---

## YAML-Based Pattern System

### Pattern File Location

Parser patterns are stored in YAML files at:
```
bruteforce_detector/rules/parsers/
├── apache.yaml        # Apache/Nginx patterns
├── syslog.yaml        # Syslog patterns
├── mssql.yaml         # MSSQL patterns
└── PARSER_TEMPLATE.yaml.example  # Template for custom patterns
```

### Pattern File Structure

```yaml
metadata:
  name: parser_name          # Must match parser's METADATA['name']
  version: 1.0.0
  author: TribanFT Project
  description: Parser description
  log_format: format_name
  enabled: true

pattern_groups:
  # Group patterns by purpose
  sql_injection:
    - regex: '(?i).*\bunion\s+select'
      description: 'UNION-based SQL injection'

  wordpress:
    - regex: '(?i)/wp-login\.php'
      description: 'wp-login.php access'

  login_pages:
    - regex: '(?i)/login'
      description: 'Generic login'
```

### How Patterns Work

1. **Load Time**: Patterns loaded once at parser initialization
2. **Pre-Compilation**: All regex patterns compiled with `re.compile()`
3. **Caching**: Compiled patterns cached for performance
4. **Grouping**: Patterns organized by logical groups (sql_injection, wordpress, etc.)
5. **Usage**: Parser code calls `self._get_compiled_patterns('group_name')`

### Pattern Groups

Pattern groups organize related patterns:

**Apache Parser Groups**:
- `log_format` - Log line parsing regex (1 pattern)
- `sql_injection` - SQL injection detection (13 patterns)
- `wordpress` - WordPress attack detection (13 patterns)
- `login_pages` - Login page identification (6 patterns)

**Syslog Parser Groups**:
- `prelogin` - MSSQL prelogin detection (2 patterns)
- `port_scan` - Port scan detection (1 pattern)

**MSSQL Parser Groups**:
- `failed_login` - Failed login detection (2 patterns)

### Updating Patterns

**Add a new pattern**:
```yaml
# Edit bruteforce_detector/rules/parsers/apache.yaml
pattern_groups:
  sql_injection:
    # ... existing patterns ...
    - regex: '(?i).*\bselect\s+.*\bfrom\s+.*\bwhere'
      description: 'Basic SELECT statement'
```

**Test the pattern**:
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('bruteforce_detector/rules/parsers/apache.yaml'))"

# Test detection
tribanft --detect --verbose
```

**No restart required** - patterns are loaded at parser initialization.

### Pattern Syntax

**Regex Field** (required):
```yaml
regex: '(?i).*\bunion\s+select'
```
- Use Python regex syntax
- Case-insensitive: `(?i)` prefix
- Capture groups: Use `(\w+)` for IP extraction
- Named groups: `(?P<ip>[\d.]+)` for field extraction

**Description Field** (required):
```yaml
description: 'UNION-based SQL injection'
```
- Human-readable explanation
- Used in logs and debugging
- Keep concise (1-5 words)

**Optional Fields** (future enhancement):
```yaml
severity: critical         # Severity level
event_type: SQL_INJECTION  # Override event type
flags: [MULTILINE]         # Regex flags
```

### Error Handling

**Missing YAML file**:
- Parser logs warning
- Returns empty pattern list
- Parser continues with no pattern matching

**Invalid YAML syntax**:
- Error logged with file name
- Pattern group skipped
- Other patterns still load

**Invalid regex**:
- Error logged with pattern details
- Pattern skipped
- Other patterns in group still load

**All errors are non-fatal** - system continues running.

---

## Built-in Parsers

### Apache/Nginx Parser (Phase 1)

**Module**: `bruteforce_detector.plugins.parsers.apache`
**Class**: `ApacheParser`
**Log Format**: Apache/Nginx Combined Log Format
**Added**: Phase 1 (v2.0)

#### Supported Log Format

```
1.2.3.4 - - [20/Jan/2025:14:30:00 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"
```

**Format Components**:
- IP address (IPv4/IPv6)
- Identity (usually `-`)
- User (usually `-`)
- Timestamp with timezone
- HTTP method (GET, POST, etc.)
- Request URI
- HTTP protocol version
- Status code (200, 404, 500, etc.)
- Response size in bytes
- Referer header
- User-Agent header

#### Detection Capabilities

**Multi-Event Generation**:
- Parser generates 1-4 events per log line
- Base event: `HTTP_REQUEST` (always generated)
- Conditional events based on pattern matching

**Event Types Generated**:

| Event Type | Trigger | Description |
|------------|---------|-------------|
| `HTTP_REQUEST` | Always | All HTTP requests (baseline traffic) |
| `SQL_INJECTION` | Pattern match | SQL injection attempts detected in URI |
| `WORDPRESS_ATTACK` | Pattern match | WordPress-specific attack patterns |
| `FAILED_LOGIN` | 401/403 on login pages | Failed authentication attempts |

#### SQL Injection Detection

**Pattern Count**: 13 patterns
**Detection Method**: Regex matching on request URI

**Pattern Categories**:

1. **UNION-based Injection**:
   ```regex
   (?i).*\bunion\s+(all\s+)?select
   ```
   Detects: `UNION SELECT`, `UNION ALL SELECT`

2. **Boolean-based Blind Injection**:
   ```regex
   (?i).*\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1
   (?i).*\band\s+['\"]?1['\"]?\s*=\s*['\"]?1
   ```
   Detects: `OR 1=1`, `AND 1=1`, `OR '1'='1'`

3. **Time-based Blind Injection**:
   ```regex
   (?i).*\bwaitfor\s+delay\s+['\"]
   (?i).*\bbenchmark\s*\(
   (?i).*\bsleep\s*\(\s*\d+\s*\)
   ```
   Detects: `WAITFOR DELAY`, `BENCHMARK()`, `SLEEP()`

4. **Error-based Injection**:
   ```regex
   (?i).*\bconvert\s*\(.*\busing\s+
   (?i).*\bcast\s*\(.*\bas\s+
   ```
   Detects: `CONVERT()`, `CAST()` exploitation

5. **Stacked Queries**:
   ```regex
   (?i).*;.*\s*(drop|insert|update|delete|exec|execute)\s+
   ```
   Detects: Multiple SQL statements in one request

6. **Comment-based Evasion**:
   ```regex
   (?i).*(/\*|\*/|--|#).*\b(select|union|insert|drop)
   ```
   Detects: SQL comments used for evasion

7. **Information Schema Enumeration**:
   ```regex
   (?i).*\binformation_schema\b
   ```
   Detects: Database structure enumeration

8. **MSSQL Stored Procedures**:
   ```regex
   (?i).*\bxp_cmdshell\b
   (?i).*\bsp_executesql\b
   ```
   Detects: Dangerous MSSQL procedures

**Example SQL Injection Events**:

```python
# Request: /admin?id=1' UNION SELECT NULL,NULL,NULL--
SecurityEvent(
    source_ip="1.2.3.4",
    event_type=EventType.SQL_INJECTION,
    source="apache",
    metadata={
        "method": "GET",
        "uri": "/admin?id=1' UNION SELECT NULL,NULL,NULL--",
        "status": 200,
        "attack_type": "UNION-based SQL injection",
        "user_agent": "sqlmap/1.0"
    }
)
```

#### WordPress Attack Detection

**Pattern Count**: 13 patterns
**Detection Method**: Regex matching on request URI

**Pattern Categories**:

1. **Login Bruteforce**:
   ```regex
   (?i)/wp-login\.php
   (?i)/wp-admin/
   (?i)POST.*wp-login.*log=.*pwd=
   ```
   Detects: wp-login.php access, wp-admin access, login POST requests

2. **XML-RPC Abuse**:
   ```regex
   (?i)POST.*/xmlrpc\.php
   (?i)/xmlrpc\.php.*system\.multicall
   (?i)/xmlrpc\.php.*wp\.getUsersBlogs
   ```
   Detects: XML-RPC amplification, multicall abuse, user enumeration

3. **Plugin/Theme Vulnerability Scanning**:
   ```regex
   (?i)/wp-content/plugins/.*(timthumb|revslider|revolution)
   (?i)/wp-content/plugins/.*readme\.txt
   (?i)/wp-content/themes/.*style\.css
   ```
   Detects: Vulnerable plugin scanning, version enumeration

4. **Malicious File Upload**:
   ```regex
   (?i)/wp-content/uploads/.*\.php
   ```
   Detects: PHP files in upload directory

5. **Configuration File Access**:
   ```regex
   (?i)/wp-config\.php\.(bak|backup|old|~)
   ```
   Detects: wp-config.php backup file scanning

6. **REST API Abuse**:
   ```regex
   (?i)/wp-json/wp/v2/users
   ```
   Detects: User enumeration via REST API

7. **Author Enumeration**:
   ```regex
   (?i)\?author=\d+
   ```
   Detects: Username enumeration via author parameter

**Example WordPress Attack Events**:

```python
# Request: POST /wp-login.php
SecurityEvent(
    source_ip="1.2.3.4",
    event_type=EventType.WORDPRESS_ATTACK,
    source="apache",
    metadata={
        "method": "POST",
        "uri": "/wp-login.php",
        "status": 401,
        "attack_type": "wp-login.php access",
        "user_agent": "WPScan/3.8.0"
    }
)

# Request: POST /xmlrpc.php (multicall)
SecurityEvent(
    source_ip="1.2.3.4",
    event_type=EventType.WORDPRESS_ATTACK,
    source="apache",
    metadata={
        "method": "POST",
        "uri": "/xmlrpc.php",
        "status": 200,
        "attack_type": "XML-RPC POST request",
        "user_agent": "python-requests/2.28.0"
    }
)
```

#### Failed Login Detection

**Trigger**: HTTP status 401 or 403 on login pages
**Login Pages Detected**:
- `/login`
- `/login.php`
- `/admin/login`
- `/wp-login.php`
- `/auth`
- `/signin`
- `/user/login`

**Example Failed Login Event**:

```python
# Request: POST /wp-login.php (status 401)
SecurityEvent(
    source_ip="1.2.3.4",
    event_type=EventType.FAILED_LOGIN,
    source="apache",
    metadata={
        "method": "POST",
        "uri": "/wp-login.php",
        "status": 401,
        "user_agent": "Mozilla/5.0"
    }
)
```

#### Event Metadata

All events include comprehensive metadata:

```python
{
    "method": "POST",                    # HTTP method
    "uri": "/api/users?id=1",           # Full request URI with query string
    "status": 404,                       # HTTP status code
    "user_agent": "Mozilla/5.0...",     # User-Agent header
    "referer": "https://example.com",   # Referer header (if available)
    "size": 1234,                        # Response size in bytes
    "attack_type": "..."                 # Pattern description (for attacks)
}
```

#### Log File Configuration

**Apache Configuration**:
```apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
CustomLog /var/log/apache2/access.log combined
```

**Nginx Configuration**:
```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log combined;
```

**TribanFT Configuration**:
```ini
[logs]
# Apache/Nginx logs are not configured separately
# Parser automatically processes access.log files found by file monitoring
# Or specify custom log path in parser configuration
```

#### Performance Characteristics

**Multi-Event Overhead**:
- Each log line parsed once
- Regex patterns compiled at parser initialization
- Pattern matching runs on all lines (1-4 events per line)
- Average: 2-3 events per line for typical web traffic

**Processing Speed**:
- ~10,000 lines/second on typical hardware
- Pre-compiled regex patterns for performance
- Incremental parsing (only new lines)

#### Usage in YAML Rules

**SQL Injection Detection**:
```yaml
log_sources:
  parsers:
    - apache
    - nginx

detection:
  event_types:
    - SQL_INJECTION
    - HTTP_REQUEST
  threshold: 5
  time_window_minutes: 60
```

**WordPress Attack Detection**:
```yaml
log_sources:
  parsers:
    - apache

detection:
  event_types:
    - WORDPRESS_ATTACK
  threshold: 10
  time_window_minutes: 120
```

---

### Syslog Parser

**Module**: `bruteforce_detector.plugins.parsers.syslog`
**Class**: `SyslogParser`
**Log Format**: Standard syslog format

#### Supported Events

- `FAILED_LOGIN` - SSH, FTP authentication failures
- `PORT_SCAN` - Port scanning detection
- `RDP_ATTACK` - RDP bruteforce (from Windows logs forwarded to syslog)

#### Log File Configuration

```ini
[logs]
syslog_path = /var/log/syslog
```

---

### MSSQL Parser

**Module**: `bruteforce_detector.plugins.parsers.mssql`
**Class**: `MSSQLParser`
**Log Format**: Microsoft SQL Server error log

#### Supported Events

- `PRELOGIN_INVALID` - Invalid prelogin packets (reconnaissance)
- `FAILED_LOGIN` - SQL authentication failures

#### Log File Configuration

```ini
[logs]
mssql_error_log_path = /var/opt/mssql/log/errorlog
```

---

## Parser Configuration

### Global Settings

```ini
[plugins]
enable_plugin_system = true
parser_plugin_dir = ~/.local/share/tribanft/bruteforce_detector/plugins/parsers
```

### Per-Parser Configuration

Disable specific parsers:

```ini
[plugin:apache]
enabled = false

[plugin:syslog]
enabled = true
```

---

## Creating Custom Parsers

See [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) for complete guide.

### Quick Start

1. **Create parser file**:
   ```bash
   cd bruteforce_detector/plugins/parsers/
   cp PARSER_PLUGIN_TEMPLATE.py custom_parser.py
   ```

2. **Implement parser logic**:
   ```python
   class CustomParser(BaseLogParser):
       METADATA = {
           'name': 'custom',
           'version': '1.0.0',
           'description': 'Custom log format parser',
           'enabled_by_default': True
       }

       def parse(self, log_file_path, state):
           events = []
           # Your parsing logic
           return events
   ```

3. **Restart service**:
   ```bash
   sudo systemctl restart tribanft
   ```

### Multi-Event Generation Pattern

**Best Practice** (from Apache parser):

```python
def parse(self, log_file_path, state):
    events = []

    for line in self._read_new_lines(log_file_path, state):
        # Always generate base event
        events.append(SecurityEvent(
            event_type=EventType.HTTP_REQUEST,
            source=self.METADATA['name']
        ))

        # Conditionally generate attack-specific events
        if self._detect_sql_injection(line):
            events.append(SecurityEvent(
                event_type=EventType.SQL_INJECTION,
                source=self.METADATA['name'],
                metadata={"attack_type": "SQL injection"}
            ))

        if self._detect_wordpress_attack(line):
            events.append(SecurityEvent(
                event_type=EventType.WORDPRESS_ATTACK,
                source=self.METADATA['name'],
                metadata={"attack_type": "WordPress attack"}
            ))

    return events
```

**Benefits**:
- Single log line can generate multiple event types
- Enables more specific YAML rules
- Better log source filtering
- Richer threat detection

### Parser Metadata

**Required Fields**:
```python
METADATA = {
    'name': 'parser_name',           # Must match event.source in YAML rules
    'version': '1.0.0',
    'description': 'What this parser does',
    'enabled_by_default': True
}
```

**Optional Fields**:
```python
METADATA = {
    # ... required fields ...
    'author': 'Your Name',
    'log_format': 'apache_combined',
    'dependencies': ['config'],
}
```

---

---

## Creating Custom Pattern Files

### Step 1: Copy Template

```bash
cd bruteforce_detector/rules/parsers/
cp PARSER_TEMPLATE.yaml.example custom_parser.yaml
```

### Step 2: Define Metadata

```yaml
metadata:
  name: custom_parser  # Must match your parser's METADATA['name']
  version: 1.0.0
  author: Your Name
  description: Custom log parser for XYZ format
  log_format: custom_format
  enabled: true
```

### Step 3: Define Pattern Groups

```yaml
pattern_groups:
  # Main log format parsing
  log_format:
    - name: main_pattern
      regex: '^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<message>.*)'
      description: Main log format

  # Attack detection patterns
  attack_detection:
    - regex: '(?i).*(malicious|attack|exploit).*'
      description: 'Generic attack keywords'

    - regex: '(?i).*authentication\s+failed.*from\s+([0-9a-fA-F\.:]+)'
      description: 'Authentication failure with IP'
```

### Step 4: Test Patterns

```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('custom_parser.yaml'))"

# Test with tribanft
tribanft --detect --verbose
```

### Step 5: Use Patterns in Parser Code

```python
class CustomParser(BaseLogParser):
    METADATA = {
        'name': 'custom_parser',  # Matches YAML metadata.name
        'version': '1.0.0',
        'enabled_by_default': True
    }

    def _parse_line(self, line: str):
        # Load attack patterns from YAML
        attack_patterns = self._get_compiled_patterns('attack_detection')

        for pattern, description in attack_patterns:
            match = pattern.search(line)
            if match:
                # Pattern matched!
                self.logger.debug(f"Matched: {description}")
                # Create SecurityEvent...
                break
```

### Pattern Development Tips

1. **Start Simple**: Begin with 1-2 patterns, test, then expand
2. **Test Regex**: Use https://regex101.com/ to test patterns
3. **Performance**: Avoid `.* at start of patterns when possible
4. **Capture Groups**: Use `(pattern)` to extract IPs, usernames, etc.
5. **Case Insensitive**: Most security patterns should use `(?i)`
6. **Validation**: Always validate YAML before deploying

### Example: Custom Web Application Parser

```yaml
metadata:
  name: webapp_parser
  version: 1.0.0
  description: Custom web application log parser

pattern_groups:
  log_format:
    - regex: '^\[(?P<timestamp>[^\]]+)\]\s+(?P<level>\w+)\s+(?P<message>.*)'
      description: 'Bracketed log format'

  sql_injection:
    - regex: '(?i).*\bunion\s+select'
      description: 'UNION SQL injection'
    - regex: "(?i).*\\bor\\s+1=1"
      description: 'Boolean injection'

  xss_attacks:
    - regex: '(?i).*<script[^>]*>.*</script>'
      description: 'Script tag XSS'
    - regex: '(?i).*javascript:'
      description: 'JavaScript protocol XSS'

  path_traversal:
    - regex: '\.\./\.\./'
      description: 'Directory traversal'
    - regex: '%2e%2e%2f'
      description: 'URL-encoded traversal'
```

---

## See Also

- [API_REFERENCE.md](API_REFERENCE.md) - EventType enum reference
- [RULE_SYNTAX.md](RULE_SYNTAX.md) - Log source filtering in YAML rules
- [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) - Creating custom parsers
- [CONFIGURATION.md](CONFIGURATION.md) - Parser configuration
- **NEW**: `bruteforce_detector/rules/parsers/PARSER_TEMPLATE.yaml.example` - Pattern file template
