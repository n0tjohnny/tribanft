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

### Severity Enum

Event severity levels.

**Module**: `bruteforce_detector.models`

| Value | Description | Use Case |
|-------|-------------|----------|
| `INFO` | Informational | Normal activity logging |
| `WARNING` | Suspicious activity | Failed login attempts |
| `CRITICAL` | Active attack | SQL injection, port scans |

### SecurityEvent

Security event extracted from logs.

**Module**: `bruteforce_detector.models`

```python
@dataclass
class SecurityEvent:
    timestamp: datetime          # When event occurred
    source_ip: str              # Source IP address
    event_type: EventType        # Event category
    severity: Severity           # Event severity
    message: str                 # Human-readable description
    raw_log: str                 # Original log line
    source: str                  # Parser name (e.g., "apache")
    metadata: Dict[str, Any]     # Additional data (optional)
```

**Example**:
```python
event = SecurityEvent(
    timestamp=datetime.now(),
    source_ip="1.2.3.4",
    event_type=EventType.SQL_INJECTION,
    severity=Severity.CRITICAL,
    message="SQL injection attempt",
    raw_log="GET /search?q=' UNION SELECT...",
    source="apache",
    metadata={"method": "GET", "uri": "/search", "status": 200}
)
```

### DetectionResult

Detection result from a detector.

**Module**: `bruteforce_detector.models`

```python
@dataclass
class DetectionResult:
    ip_address: str              # Detected IP
    reason: str                  # Human-readable reason
    event_count: int             # Number of events
    time_window: int             # Time window in seconds
    severity: Severity           # Detection severity
    event_type: EventType        # Primary event type
    detector_name: str           # Detector that created this
```

**Example**:
```python
result = DetectionResult(
    ip_address="1.2.3.4",
    reason="SQL injection: 15 attempts in 5 minutes",
    event_count=15,
    time_window=300,
    severity=Severity.CRITICAL,
    event_type=EventType.SQL_INJECTION,
    detector_name="sql_injection_detector"
)
```

---

## Base Classes

### BaseDetector

Base class for all detector plugins.

**Module**: `bruteforce_detector.detectors.base`

**Required Methods**:

```python
class MyDetector(BaseDetector):
    def __init__(self, config, blacklist_manager):
        """Constructor - dependencies injected by PluginManager"""
        super().__init__(config, blacklist_manager)

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
| blacklist_manager | BlacklistManager | Blacklist management |
| logger | Logger | Logger instance |

**Helper Methods**:

```python
def _create_detection_result(
    ip: str,
    reason: str,
    event_count: int,
    time_window: int,
    severity: Severity,
    event_type: EventType
) -> DetectionResult:
    """Helper to create DetectionResult with detector name"""
```

See: `bruteforce_detector/detectors/base.py`

### BaseLogParser

Base class for all parser plugins.

**Module**: `bruteforce_detector.parsers.base`

**Required Methods**:

```python
class MyParser(BaseLogParser):
    def __init__(self, config):
        """Constructor - config injected by PluginManager"""
        super().__init__(config, "my_parser")

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
