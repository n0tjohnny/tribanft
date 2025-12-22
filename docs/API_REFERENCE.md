# TribanFT API Reference

Technical reference for TribanFT core modules and data structures.

**Author**: TribanFT Project
**License**: GNU GPL v3
**Last Updated**: 2025-12-21

---

## Table of Contents

1. [Data Models](#data-models)
2. [Core Modules](#core-modules)
3. [Plugin Base Classes](#plugin-base-classes)
4. [Type Reference](#type-reference)

---

## Data Models

### EventType Enum

Security event types detected in logs. Expanded in v2.0 Phase 1 from 4 to 22 event types.

**Module**: `bruteforce_detector.models`

**Categories**:

#### Authentication Events
Events related to user authentication attempts.

| Value | Description | Use Case |
|-------|-------------|----------|
| `PRELOGIN_INVALID` | MSSQL reconnaissance attempts | Malformed prelogin packets |
| `FAILED_LOGIN` | Failed authentication | SSH, FTP, HTTP, MSSQL failures |
| `SUCCESSFUL_LOGIN` | Successful authentication | Anomaly detection baseline |

#### Network Events
Network-level attack patterns.

| Value | Description | Use Case |
|-------|-------------|----------|
| `PORT_SCAN` | Port scanning activity | Nmap, Masscan detection |
| `NETWORK_SCAN` | Network reconnaissance | Host discovery attempts |

#### HTTP/Web Events
Web server traffic and errors.

| Value | Description | Use Case |
|-------|-------------|----------|
| `HTTP_REQUEST` | Generic HTTP request | All web traffic monitoring |
| `HTTP_ERROR_4XX` | Client errors | 400, 401, 403, 404 responses |
| `HTTP_ERROR_5XX` | Server errors | 500, 502, 503 responses |

#### Attack Events
Exploitation attempts detected in requests.

| Value | Description | Use Case |
|-------|-------------|----------|
| `SQL_INJECTION` | SQL injection attempts | UNION, boolean-blind, time-based attacks |
| `XSS_ATTACK` | Cross-site scripting | Reflected/stored XSS patterns |
| `PATH_TRAVERSAL` | Directory traversal | `../` patterns in URIs |
| `COMMAND_INJECTION` | OS command injection | Shell metacharacters in inputs |
| `FILE_UPLOAD_MALICIOUS` | Malicious file uploads | PHP/executable uploads to web dirs |

#### Application-Specific Events
CMS-specific attack patterns.

| Value | Description | Use Case |
|-------|-------------|----------|
| `WORDPRESS_ATTACK` | WordPress attacks | wp-login, xmlrpc, plugin scanning |
| `DRUPAL_ATTACK` | Drupal attacks | Core/module vulnerabilities |
| `JOOMLA_ATTACK` | Joomla attacks | Component vulnerabilities |

#### Protocol-Specific Events
Protocol-level bruteforce attacks.

| Value | Description | Use Case |
|-------|-------------|----------|
| `RDP_ATTACK` | RDP bruteforce/exploitation | Windows Event 4625, CredSSP failures |
| `SSH_ATTACK` | SSH bruteforce | SSH authentication failures |
| `FTP_ATTACK` | FTP bruteforce | FTP login failures |
| `SMTP_ATTACK` | SMTP abuse | Email relay/spam attempts |

#### Threat Intelligence Events
External threat feed integration.

| Value | Description | Use Case |
|-------|-------------|----------|
| `CROWDSEC_BLOCK` | CrowdSec blocked IPs | Community threat intelligence |
| `KNOWN_MALICIOUS_IP` | Known bad IPs | Custom threat feeds |

**Usage Example**:
```python
from bruteforce_detector.models import EventType

# Create event with new type
event = SecurityEvent(
    source_ip=ipaddress.ip_address("1.2.3.4"),
    event_type=EventType.SQL_INJECTION,
    timestamp=datetime.now(),
    source="apache",
    metadata={"uri": "/admin?id=1' OR '1'='1"}
)
```

**YAML Rule Usage**:
```yaml
detection:
  event_types:
    - SQL_INJECTION
    - HTTP_REQUEST
```

**Migration Notes**:
- EventType names in YAML are case-insensitive (SQL_INJECTION = sql_injection)
- Rule engine automatically converts uppercase to enum values
- Backward compatible with existing rules using lowercase names

---

### SecurityEvent Dataclass

Represents a single security event extracted from logs.

**Module**: `bruteforce_detector.models`

**Attributes**:

| Field | Type | Description |
|-------|------|-------------|
| `source_ip` | `IPAddress` | IP address of attacker (IPv4/IPv6) |
| `event_type` | `EventType` | Type of security event (enum) |
| `timestamp` | `datetime` | When the event occurred |
| `source` | `str` | Log source name (e.g., 'apache', 'syslog') |
| `raw_message` | `str` | Original log line for reference |
| `metadata` | `dict` | Additional event-specific data |

**Metadata Examples by Event Type**:

```python
# SQL_INJECTION metadata
{
    "uri": "/admin?id=1' UNION SELECT NULL--",
    "method": "GET",
    "status": 200,
    "attack_type": "UNION-based SQL injection",
    "user_agent": "sqlmap/1.0"
}

# WORDPRESS_ATTACK metadata
{
    "uri": "/wp-login.php",
    "method": "POST",
    "status": 401,
    "attack_type": "wp-login.php access",
    "user_agent": "WPScan/3.8.0"
}

# HTTP_REQUEST metadata
{
    "uri": "/api/users",
    "method": "GET",
    "status": 200,
    "size": 1234,
    "referer": "https://example.com",
    "user_agent": "curl/7.68.0"
}
```

**Methods**:

```python
def to_dict(self) -> dict:
    """Serialize to dictionary for JSON storage."""

def from_dict(cls, data: dict) -> SecurityEvent:
    """Deserialize from dictionary."""
```

---

### DetectionResult Dataclass

Output from a detection algorithm indicating a threat.

**Module**: `bruteforce_detector.models`

**Attributes**:

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `IPAddress` | IP address to block |
| `reason` | `str` | Human-readable explanation |
| `confidence` | `DetectionConfidence` | Detection confidence (LOW/MEDIUM/HIGH) |
| `event_count` | `int` | Number of events that triggered detection |
| `source_events` | `List[SecurityEvent]` | Events that caused detection |
| `first_seen` | `Optional[datetime]` | Timestamp of first event in attack |
| `last_seen` | `Optional[datetime]` | Timestamp of last event in attack |
| `geolocation` | `Optional[Dict]` | Geo data (country, city, ISP) |

**Usage Example**:
```python
result = DetectionResult(
    ip=ipaddress.ip_address("1.2.3.4"),
    reason="SQL injection detected: UNION-based SQL injection - 10 attempts",
    confidence=DetectionConfidence.HIGH,
    event_count=10,
    source_events=matching_events
)
```

---

## Core Modules

### RuleEngine

YAML-based detection rule execution engine (Phase 1 enhancement).

**Module**: `bruteforce_detector.core.rule_engine`

**Class**: `RuleEngine`

#### Constructor

```python
def __init__(self, rules_dir: Path):
    """
    Initialize rule engine.

    Args:
        rules_dir: Directory to scan for YAML rule files
    """
```

#### Key Methods

```python
def apply_rules(self, events: List[SecurityEvent]) -> List[DetectionResult]:
    """
    Apply all enabled rules to security events.

    Args:
        events: List of SecurityEvent objects from parsers

    Returns:
        List of DetectionResult objects for IPs that triggered rules
    """
```

#### DetectionRule Dataclass

Internal representation of parsed YAML rules.

**Attributes** (Phase 1 additions in bold):

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Rule identifier |
| `version` | `str` | Rule version (semantic) |
| `enabled` | `bool` | Whether rule is active |
| `event_types` | `List[EventType]` | Event types to match |
| `threshold` | `int` | Minimum events required |
| `time_window_minutes` | `int` | Time window for event grouping |
| `confidence` | `str` | Detection confidence level |
| `patterns` | `List[Dict]` | Regex patterns to match |
| `reason_template` | `str` | Template for detection reason |
| `metadata` | `Dict` | Additional rule metadata |
| `group_by` | `str` | Field to group events by |
| **`log_sources`** | **`Optional[Dict]`** | **Log source filters (parsers or files)** |

#### Log Source Filtering (Phase 1 Feature)

**Purpose**: Filter events by parser name or log file path before applying rules.

**YAML Syntax**:
```yaml
log_sources:
  parsers:
    - apache
    - nginx
```

**Filter Logic**:
1. If `log_sources.parsers` is defined, only analyze events from those parsers
2. Event source is matched against parser names from parser METADATA
3. Filtering happens before event_type filtering (performance optimization)

**Example**:
```yaml
# sql_injection.yaml
log_sources:
  parsers:
    - apache
    - nginx

detection:
  event_types:
    - SQL_INJECTION
    - HTTP_REQUEST
```

This rule only processes events from Apache/Nginx parsers, ignoring MSSQL/syslog events even if they have SQL_INJECTION type.

**Implementation Details**:
```python
# In _apply_single_rule()
if rule.log_sources and 'parsers' in rule.log_sources:
    allowed_parsers = rule.log_sources['parsers']
    events = [e for e in events if e.source in allowed_parsers]
```

---

### Apache/Nginx Parser (Phase 1 Addition)

Extracts security events from Apache and Nginx access logs.

**Module**: `bruteforce_detector.plugins.parsers.apache`

**Class**: `ApacheParser`

#### METADATA

```python
METADATA = {
    'name': 'apache',
    'version': '1.0.0',
    'author': 'TribanFT Project',
    'description': 'Parses Apache/Nginx combined log format for security events',
    'log_format': 'apache_combined',
    'enabled_by_default': True
}
```

#### Supported Log Format

**Combined log format**:
```
1.2.3.4 - - [20/Jan/2025:14:30:00 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"
```

**Fields**:
- IP address
- Identity (usually `-`)
- User (usually `-`)
- Timestamp
- Request (METHOD URI PROTOCOL)
- Status code
- Response size
- Referer
- User-Agent

#### Detection Capabilities

**Multi-Event Generation**:
- Generates 1-4 events per log line based on content
- All requests generate `HTTP_REQUEST` event
- Conditional events generated when patterns match

**SQL Injection Detection**:
- 13 SQL injection patterns
- Types: UNION, boolean-blind, time-based, error-based, stacked queries
- Events generated with type `SQL_INJECTION`

**SQL Injection Patterns**:
```python
SQL_INJECTION_PATTERNS = [
    (r'(?i).*\bunion\s+(all\s+)?select', 'UNION-based SQL injection'),
    (r"(?i).*\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1", 'Boolean-based blind injection (OR)'),
    (r'(?i).*\bwaitfor\s+delay\s+[\'"]', 'Time-based blind injection (WAITFOR)'),
    (r'(?i).*\bbenchmark\s*\(', 'Time-based blind injection (BENCHMARK)'),
    (r'(?i).*\bsleep\s*\(\s*\d+\s*\)', 'Time-based blind injection (SLEEP)'),
    (r'(?i).*\binformation_schema\b', 'Information schema enumeration'),
    (r'(?i).*\bxp_cmdshell\b', 'xp_cmdshell exploitation'),
    # ... 6 more patterns
]
```

**WordPress Attack Detection**:
- 13 WordPress attack patterns
- Types: Login bruteforce, XML-RPC abuse, plugin/theme scanning, enumeration
- Events generated with type `WORDPRESS_ATTACK`

**WordPress Patterns**:
```python
WORDPRESS_PATTERNS = [
    (r'(?i)/wp-login\.php', 'wp-login.php access'),
    (r'(?i)/wp-admin/', 'wp-admin access'),
    (r'(?i)POST.*/xmlrpc\.php', 'XML-RPC POST request'),
    (r'(?i)/wp-content/plugins/.*readme\.txt', 'Plugin enumeration'),
    (r'(?i)/wp-json/wp/v2/users', 'REST API user enumeration'),
    # ... 8 more patterns
]
```

**Failed Login Detection**:
- HTTP 401/403 on login pages
- Login pages: `/login`, `/wp-login.php`, `/admin/login`, `/auth`, etc.
- Events generated with type `FAILED_LOGIN`

#### Event Metadata

All events include comprehensive metadata:

```python
metadata = {
    "method": "POST",              # HTTP method
    "uri": "/wp-login.php",        # Request URI
    "status": 401,                 # HTTP status code
    "user_agent": "Mozilla/5.0",   # User-Agent header
    "attack_type": "wp-login.php access"  # Matched pattern description
}
```

#### Usage Example

```python
from bruteforce_detector.plugins.parsers.apache import ApacheParser

parser = ApacheParser()
events = parser.parse(log_file_path="/var/log/apache2/access.log")

# Events generated:
# - HTTP_REQUEST for every line
# - SQL_INJECTION when patterns match
# - WORDPRESS_ATTACK when WP patterns match
# - FAILED_LOGIN for 401/403 on login pages
```

#### Configuration

No additional configuration required. Parser is auto-discovered when:
```ini
[plugins]
enable_plugin_system = true
parser_plugin_dir = ~/.local/share/tribanft/bruteforce_detector/plugins/parsers
```

---

## Plugin Base Classes

### BaseLogParser

Abstract base class for log parsers.

**Module**: `bruteforce_detector.parsers.base`

**Required Methods**:

```python
def parse(self, log_file_path: str, state: ProcessingState) -> List[SecurityEvent]:
    """
    Parse log file and extract security events.

    Args:
        log_file_path: Path to log file
        state: Processing state for incremental parsing

    Returns:
        List of SecurityEvent objects
    """
```

**Phase 1 Best Practices**:

1. **Multi-Event Generation**: Generate multiple event types per log line when appropriate
   ```python
   events = []
   # Always generate HTTP_REQUEST
   events.append(SecurityEvent(..., event_type=EventType.HTTP_REQUEST))

   # Conditionally generate attack events
   if sql_injection_detected:
       events.append(SecurityEvent(..., event_type=EventType.SQL_INJECTION))
   ```

2. **Rich Metadata**: Include all available information in metadata
   ```python
   metadata = {
       "method": method,
       "uri": uri,
       "status": status_code,
       "user_agent": user_agent,
       "attack_type": pattern_description
   }
   ```

3. **Source Naming**: Use parser name from METADATA as event source
   ```python
   SecurityEvent(source="apache")  # Matches METADATA['name']
   ```

---

## Type Reference

### Type Aliases

```python
# IP address (IPv4 or IPv6)
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
```

### Enums

**EventType**: See [EventType Enum](#eventtype-enum)

**DetectionConfidence**:
```python
class DetectionConfidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
```

---

## Phase 1 Implementation Summary

### Changes to Existing APIs

#### EventType Enum (bruteforce_detector/models.py)
- **Added**: 18 new event types
- **Categories**: HTTP/Web (3), Attacks (5), Application-Specific (3), Protocol-Specific (4), updated Network (1)
- **Backward Compatibility**: Existing event types unchanged

#### DetectionRule Dataclass (bruteforce_detector/core/rule_engine.py)
- **Added**: `log_sources` field (Optional[Dict])
- **Purpose**: Filter events by parser name before applying rules
- **Default**: None (no filtering)

#### RuleEngine._apply_single_rule() (bruteforce_detector/core/rule_engine.py)
- **Added**: Log source filtering logic
- **Added**: Case-insensitive EventType parsing
- **Behavior**: Filters events by log_sources.parsers before event_type filtering

### New Modules (Phase 1)

#### ApacheParser (bruteforce_detector/plugins/parsers/apache.py)
- **Purpose**: Parse Apache/Nginx combined log format
- **Event Types**: HTTP_REQUEST, SQL_INJECTION, WORDPRESS_ATTACK, FAILED_LOGIN
- **Patterns**: 13 SQL injection, 13 WordPress attack patterns
- **Multi-Event**: Generates 1-4 events per log line

### Updated YAML Rules

#### sql_injection.yaml
- **Added**: log_sources.parsers: [apache, nginx]
- **Changed**: event_types: [SQL_INJECTION, HTTP_REQUEST]

#### wordpress_attacks.yaml
- **Added**: log_sources.parsers: [apache, nginx]
- **Updated**: 4 detectors with correct event_types

#### rdp_bruteforce.yaml
- **Added**: log_sources.parsers: [windows_security, syslog]
- **Changed**: event_types: [RDP_ATTACK, FAILED_LOGIN]

---

## Migration Guide

### For Existing Rules

**Before Phase 1**:
```yaml
detection:
  event_types:
    - FAILED_LOGIN
```

**After Phase 1** (with filtering):
```yaml
log_sources:
  parsers:
    - apache
    - nginx

detection:
  event_types:
    - SQL_INJECTION
    - HTTP_REQUEST
```

### For Custom Parsers

**Generate Multiple Event Types**:
```python
def parse(self, log_file_path, state):
    events = []

    for line in log_file:
        # Base event
        events.append(SecurityEvent(
            event_type=EventType.HTTP_REQUEST,
            source="apache"  # Must match METADATA['name']
        ))

        # Attack-specific events
        if sql_injection_detected:
            events.append(SecurityEvent(
                event_type=EventType.SQL_INJECTION,
                source="apache",
                metadata={"attack_type": "UNION-based SQL injection"}
            ))

    return events
```

---

## See Also

- [RULE_SYNTAX.md](RULE_SYNTAX.md) - YAML rule syntax reference
- [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) - Plugin development guide
- [CONFIGURATION.md](CONFIGURATION.md) - Configuration reference
- [CHANGELOG.md](../CHANGELOG.md) - Version history
