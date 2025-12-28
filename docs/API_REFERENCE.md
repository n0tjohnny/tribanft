# TribanFT API Reference

Core data models and base classes for plugin development.

---

## Data Models

### EventType Enum

Security event categories.

**Module**: `bruteforce_detector.models`

| Category | EventTypes |
|----------|-----------|
| **Authentication** | PRELOGIN_INVALID, FAILED_LOGIN, SUCCESSFUL_LOGIN |
| **Network** | PORT_SCAN, NETWORK_SCAN |
| **HTTP** | HTTP_REQUEST, HTTP_ERROR_4XX*, HTTP_ERROR_5XX* |
| **Web Attacks** | SQL_INJECTION, XSS_ATTACK, PATH_TRAVERSAL, COMMAND_INJECTION, FILE_UPLOAD_MALICIOUS |
| **CMS** | WORDPRESS_ATTACK, DRUPAL_ATTACK, JOOMLA_ATTACK |
| **Protocols** | RDP_ATTACK, SSH_ATTACK, FTP_ATTACK, SMTP_ATTACK, DNS_ATTACK* |
| **Threat Intel** | CROWDSEC_BLOCK, KNOWN_MALICIOUS_IP |

**NEW in v2.5.0**: DNS_ATTACK, CROWDSEC_BLOCK, and KNOWN_MALICIOUS_IP now fully implemented

Full list: `bruteforce_detector/models.py`

### DetectionConfidence Enum

Detection confidence levels.

**Module**: `bruteforce_detector.models`

| Value | Description | Use Case |
|-------|-------------|----------|
| `LOW` | Weak evidence | Single suspicious event |
| `MEDIUM` | Moderate evidence | Port scan patterns detected |
| `HIGH` | Strong evidence | 20+ failed logins in time window |

### SecurityEvent

Security event extracted from logs.

**Module**: `bruteforce_detector.models`

```python
@dataclass
class SecurityEvent:
    source_ip: IPAddress         # IP address object (ipaddress.IPv4Address or IPv6Address)
    event_type: EventType        # Event category (EventType enum)
    timestamp: datetime          # When event occurred
    source: str                  # Parser name (e.g., "apache", "syslog")
    raw_message: str             # Original log line
    metadata: dict               # Additional event-specific data (optional)
```

**Example**:
```python
import ipaddress
from datetime import datetime

event = SecurityEvent(
    source_ip=ipaddress.ip_address("1.2.3.4"),  # IPAddress object, NOT string
    event_type=EventType.SQL_INJECTION,
    timestamp=datetime.now(),
    source="apache",
    raw_message="GET /search?q=' UNION SELECT...",
    metadata={"method": "GET", "uri": "/search", "status": 200}
)
```

### DetectionResult

Detection result from a detector.

**Module**: `bruteforce_detector.models`

```python
@dataclass
class DetectionResult:
    ip: IPAddress                           # IP to block (IPv4Address or IPv6Address)
    reason: str                             # Human-readable explanation
    confidence: DetectionConfidence         # Detection confidence level
    event_count: int                        # Number of events that triggered detection
    event_type: EventType                   # Primary event type
    source_events: List[SecurityEvent]      # Events that caused this detection
    first_seen: Optional[datetime]          # Timestamp of first event
    last_seen: Optional[datetime]           # Timestamp of last event
    geolocation: Optional[Dict]             # Geo data (enriched by BlacklistManager)
```

**Example**:
```python
import ipaddress
from datetime import datetime

result = DetectionResult(
    ip=ipaddress.ip_address("1.2.3.4"),     # IPAddress object, NOT string
    reason="SQL injection: 15 attempts in 5 minutes",
    confidence=DetectionConfidence.HIGH,    # NOT Severity
    event_count=15,
    event_type=EventType.SQL_INJECTION,
    source_events=matching_events,          # List[SecurityEvent]
    first_seen=datetime.now(),
    last_seen=datetime.now(),
    geolocation=None
)
```

**NEW in v2.8.0**: All timestamps are now timezone-aware (timezone.utc)
- first_seen, last_seen use datetime.now(timezone.utc)
- Detectors automatically create timezone-aware timestamps
- Database and state files use timezone-aware timestamps
- Prevents timezone confusion in distributed environments

---

## File Formats

### Blacklist File Format

Enhanced blacklist files with comprehensive metadata for forensic analysis.

**Location**: `~/.local/share/tribanft/data/blacklist_ipv4.txt`, `blacklist_ipv6.txt` (v2.9.0+, organized structure)

**Structure**:

```
# ======================================================================================================================
# ENHANCED BLACKLIST - COMPREHENSIVE THREAT INTELLIGENCE
# ======================================================================================================================
# Last Updated: 2025-12-27 21:35:16
#
# STATISTICS:
#   Total IPs: 102450 (New: 0)
#   High Confidence: 67017 | Medium: 3
#   Total Events: 1084407811762428500000000000000000000000
#   With Geolocation: 53319 (52.0%)
# ======================================================================================================================

# ----------------------------------------------------------------------------------------------------------------------
# SOURCE: AUTOMATIC (31450 IPs)
# ----------------------------------------------------------------------------------------------------------------------

# IP: 1.2.3.4 | US, New York | Acme ISP Inc
#   Reason: SQL injection: 15 attempts in 5 minutes
#   Events: 15
#   EventTypes: sql_injection,http_error_4xx
#   First: 2025-12-27 10:30 | Last: 2025-12-27 10:35 | Added: 2025-12-27 10:35
#   Source: automatic
1.2.3.4
```

**Metadata Fields**:

| Field | Description | Example |
|-------|-------------|---------|
| IP | IP address with geolocation and ISP | `1.2.3.4 \| US, New York \| Acme ISP` |
| Reason | Human-readable block reason | `SQL injection: 15 attempts` |
| Events | Total event count | `15` |
| **EventTypes** | Comma-separated attack types | `sql_injection,port_scan` |
| First | First detection timestamp | `2025-12-27 10:30` |
| Last | Last detection timestamp | `2025-12-27 10:35` |
| Added | Date added to blacklist | `2025-12-27 10:35` |
| Source | Detection source | `automatic`, `manual`, `crowdsec_csv_import` |

**NEW in v2.8.3**: EventTypes field now written to files for forensic analysis

**EventTypes Values**: See [EventType Enum](#eventtype-enum) table above

**Sources**:
- `automatic` - Detected by TribanFT detectors/rules
- `manual` - Manually added via `--blacklist-add`
- `crowdsec_csv_import` - Imported from CrowdSec CSV
- `nftables_import` - Imported from existing NFTables sets
- `legacy` - Pre-existing entries without metadata

**Reading**: Use `BlacklistWriter.read_blacklist()` to parse with full metadata preservation

**Writing**: Use `BlacklistWriter.write_blacklist()` with corruption protection and automatic backups

---

## Base Classes

### BaseDetector

Base class for all detector plugins.

**Module**: `bruteforce_detector.detectors.base`

**Required Methods**:

```python
class MyDetector(BaseDetector):
    def __init__(self, config, event_type: EventType):
        """Constructor - config and event_type injected by PluginManager"""
        super().__init__(config, event_type)

    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """Main detection logic - process events, return detections"""
        detections = []
        # Your detection logic here
        return detections
```

**Optional Methods**:

```python
def initialize(self) -> bool:
    """Called once at startup - load resources, validate config"""
    return True

def cleanup(self):
    """Called at shutdown - release resources"""
    pass
```

**Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| config | Config | Configuration object |
| event_type | EventType | Event type this detector handles |
| logger | Logger | Logger instance |
| enabled | bool | Whether detector is enabled (based on config) |
| name | str | Detector class name |

**Helper Methods**:

```python
def _create_detection_result(
    ip_str: str,
    reason: str,
    confidence: str,  # "low", "medium", or "high" - converted to DetectionConfidence
    event_count: int,
    source_events: List[SecurityEvent],
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None
) -> Optional[DetectionResult]:
    """Helper to create DetectionResult with proper timestamps extracted from source_events"""
```

See: `bruteforce_detector/detectors/base.py`

### BaseLogParser

Base class for all parser plugins.

**Module**: `bruteforce_detector.parsers.base`

**Required Methods**:

```python
class MyParser(BaseLogParser):
    def __init__(self, log_path: str):
        """Constructor - log file path injected by PluginManager"""
        super().__init__(log_path)

    def _parse_line(self, line: str, line_number: int) -> Optional[List[SecurityEvent]]:
        """Parse single log line - return SecurityEvent(s) or None"""
        # Your parsing logic here
        return [event] if event else None
```

**Optional Methods**:

```python
def _initialize_patterns(self):
    """Load regex patterns from YAML or define inline"""
    self.patterns = [re.compile(r'pattern'), ...]

def parse_incremental(self, from_offset: int, to_offset: int) -> Tuple[List[SecurityEvent], int]:
    """Parse only new log lines (for real-time monitoring)"""
    pass
```

**Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| config | Config | Configuration object |
| logger | Logger | Logger instance |
| log_file_path | str | Path to log file |
| last_offset | int | Last read position |

**Helper Methods**:

```python
def _get_compiled_patterns(self, group_name: str) -> List[Pattern]:
    """Get pre-compiled patterns from YAML pattern file"""

def _extract_ip(self, line: str) -> str:
    """Extract IP address from log line"""

def _parse_timestamp(self, timestamp_str: str) -> datetime:
    """Parse timestamp string to datetime"""
```

**YAML Pattern Integration**:

```python
# In parser __init__
self._initialize_patterns()

# In _parse_line
for pattern in self._get_compiled_patterns('sql_injection'):
    if pattern.search(line):
        # Create SecurityEvent
```

See: `bruteforce_detector/parsers/base.py`

---

## Core Modules

### RuleEngine

YAML-based detection rule engine.

**Module**: `bruteforce_detector.core.rule_engine`

**Methods**:

```python
class RuleEngine:
    def load_rules(self, rules_dir: str) -> int:
        """Load YAML rules from directory - returns count loaded"""

    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """Run all enabled rules against events"""
```

See: docs/RULE_SYNTAX.md for YAML rule format

### PluginManager

Auto-discovers and loads detector/parser plugins.

**Module**: `bruteforce_detector.core.plugin_manager`

**Methods**:

```python
class PluginManager:
    def discover_detectors(self, plugin_dir: str) -> List[BaseDetector]:
        """Discover and instantiate detector plugins"""

    def discover_parsers(self, plugin_dir: str) -> List[BaseLogParser]:
        """Discover and instantiate parser plugins"""
```

Plugins must have METADATA dictionary:

```python
METADATA = {
    "name": "plugin_name",
    "version": "1.0.0",
    "author": "Author Name",
    "description": "Short description",
    "enabled": True
}
```

### Config

Configuration management with precedence: env vars > config.conf > defaults.

**Module**: `bruteforce_detector.config`

**Usage**:

```python
from bruteforce_detector.config import get_config

config = get_config()

# Access settings
data_dir = config.data_dir
syslog_path = config.syslog_path
enable_nftables = config.enable_nftables_update
```

**Common Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| data_dir | Path | Base data directory |
| syslog_path | str | Syslog file path |
| enable_nftables_update | bool | Enable NFTables blocking |
| use_database | bool | Use SQLite database |

Full reference: docs/CONFIGURATION.md

### BlacklistManager

Manages IP blacklist and NFTables integration.

**Module**: `bruteforce_detector.managers.blacklist`

**Methods**:

```python
class BlacklistManager:
    def add_ip(self, ip: str, reason: str, event_type: EventType):
        """Add IP to blacklist"""

    def remove_ip(self, ip: str):
        """Remove IP from blacklist"""

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
```

---

## Type Hints Reference

Common type hints used in TribanFT:

```python
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
import re

# Common patterns
List[SecurityEvent]          # List of events
List[DetectionResult]        # List of detections
Optional[SecurityEvent]      # Event or None
Dict[str, Any]              # Metadata dictionary
Tuple[List[SecurityEvent], int]  # Events + offset
Pattern                      # Compiled regex (re.Pattern)
```

---

## Development Workflow

### Creating a Detector

1. Copy template: `bruteforce_detector/plugins/detectors/DETECTOR_PLUGIN_TEMPLATE.py`
2. Implement `detect()` method
3. Set METADATA
4. Test and deploy

### Creating a Parser

1. Copy template: `bruteforce_detector/plugins/parsers/PARSER_PLUGIN_TEMPLATE.py`
2. Copy pattern template: `bruteforce_detector/rules/parsers/PARSER_TEMPLATE.yaml.example`
3. Implement `_parse_line()` method
4. Define patterns in YAML
5. Add log path to config
6. Test and deploy

### Testing

```bash
# Syntax check
python3 -c "import bruteforce_detector.plugins.detectors.my_detector"

# Run with service
sudo systemctl restart tribanft
sudo journalctl -u tribanft -f

# Verify loaded
sudo journalctl -u tribanft | grep "Loaded.*my_detector"
```

---

## Related Documentation

- **Plugin Development**: docs/PLUGIN_DEVELOPMENT.md
- **Parser Reference**: docs/PARSERS.md
- **Rule Syntax**: docs/RULE_SYNTAX.md
- **Configuration**: docs/CONFIGURATION.md
- **EventTypes Mapping**: docs/PARSER_EVENTTYPES_MAPPING.md
