# TribanFT Plugin Development

Quick reference for creating custom detectors and parsers.

---

## Quick Start

### Create Detector Plugin

```bash
# Copy template
cp bruteforce_detector/plugins/detectors/DETECTOR_PLUGIN_TEMPLATE.py.example \
   bruteforce_detector/plugins/detectors/my_detector.py

# Edit plugin
vim bruteforce_detector/plugins/detectors/my_detector.py

# Restart service
sudo systemctl restart tribanft
```

### Create Parser Plugin

```bash
# Copy template
cp bruteforce_detector/plugins/parsers/PARSER_PLUGIN_TEMPLATE.py.example \
   bruteforce_detector/plugins/parsers/my_parser.py

# Edit plugin
vim bruteforce_detector/plugins/parsers/my_parser.py

# Restart service
sudo systemctl restart tribanft
```

---

## Plugin System

### How It Works

1. PluginManager scans `plugins/detectors/` and `plugins/parsers/`
2. Auto-discovers classes inheriting from BaseDetector/BaseLogParser
3. Injects dependencies (config, managers) via constructor
4. Loads enabled plugins only

### Directory Structure

```
bruteforce_detector/plugins/
├── detectors/
│   ├── prelogin.py (built-in example)
│   ├── my_detector.py (your plugin)
│   └── DETECTOR_PLUGIN_TEMPLATE.py (copy this)
└── parsers/
    ├── syslog.py (built-in example)
    ├── my_parser.py (your plugin)
    └── PARSER_PLUGIN_TEMPLATE.py (copy this)
```

---

## Detector Plugin Reference

### Required METADATA

```python
METADATA = {
    "name": "My Detector",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Short description",
    "event_types": [EventType.FAILED_LOGIN],  # Events this detector handles
    "enabled": True
}
```

| Field | Required | Description |
|-------|----------|-------------|
| name | Yes | Plugin display name |
| version | Yes | Semantic version (e.g., "1.0.0") |
| author | Yes | Author name or organization |
| description | Yes | One-line description |
| event_types | Yes | List of EventTypes this detector processes |
| enabled | Yes | True to enable, False to disable |

### Required Methods

```python
class MyDetector(BaseDetector):
    def __init__(self, config, event_type: EventType):
        """Constructor - dependencies injected by PluginManager"""
        super().__init__(config, event_type)

    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """Main detection logic - process events, return detections"""
        detections = []
        # Your logic here
        return detections
```

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `__init__` | config, event_type: EventType | None | Constructor with config and EventType |
| `detect` | List[SecurityEvent] | List[DetectionResult] | Main detection logic |

### Optional Methods

```python
def initialize(self) -> bool:
    """Called once at startup - load resources, validate config"""
    return True

def cleanup(self):
    """Called at shutdown - release resources"""
    pass
```

---

## Parser Plugin Reference

### Required METADATA

```python
METADATA = {
    "name": "My Parser",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Parses custom log format",
    "log_file_path_key": "my_app_log_path",  # Config key for log path
    "enabled": True
}
```

| Field | Required | Description |
|-------|----------|-------------|
| name | Yes | Plugin display name |
| version | Yes | Semantic version |
| author | Yes | Author name |
| description | Yes | One-line description |
| log_file_path_key | Yes | Config key for log path (e.g., "apache_log_path") |
| enabled | Yes | True to enable, False to disable |

### Required Methods

```python
class MyParser(BaseLogParser):
    def __init__(self, log_path: str):
        """Constructor - log path injected by PluginManager"""
        super().__init__(log_path)

    def _parse_line(self, line: str, line_number: int) -> Optional[List[SecurityEvent]]:
        """Parse single log line - return SecurityEvent(s) or None"""
        if not self._matches_pattern(line):
            return None

        # Extract data
        event = SecurityEvent(
            source_ip=ipaddress.ip_address(ip_str),  # IPAddress object
            event_type=EventType.FAILED_LOGIN,
            timestamp=datetime.now(),
            source="my_parser",
            raw_message=line,
            metadata={}
        )
        return [event]
```

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `__init__` | log_path: str | None | Constructor with log file path |
| `_parse_line` | line: str, line_number: int | Optional[List[SecurityEvent]] | Parse single line |

### Optional Methods

```python
def _initialize_patterns(self):
    """Load regex patterns from YAML or define inline"""
    self.patterns = [re.compile(r'pattern'), ...]
```

---

## SecurityEvent Data Model

```python
SecurityEvent(
    source_ip=ipaddress.ip_address("1.2.3.4"),  # IPAddress object (NOT string)
    event_type=EventType.FAILED_LOGIN,          # EventType enum
    timestamp=datetime.now(),                   # datetime object
    source="parser_name",                       # Parser that generated this
    raw_message="original log line...",         # Original log line (NOT raw_log)
    metadata={}                                 # Optional dict for extra data
)
```

### EventTypes

Common event types:
- `FAILED_LOGIN`, `PRELOGIN_INVALID`, `PORT_SCAN`
- `SQL_INJECTION`, `WORDPRESS_ATTACK`, `XSS_ATTACK`
- `PATH_TRAVERSAL`, `COMMAND_INJECTION`, `FILE_UPLOAD_MALICIOUS`

See: `bruteforce_detector/models.py` for full list

---

## DetectionResult Data Model

```python
DetectionResult(
    ip=ipaddress.ip_address("1.2.3.4"),     # IPAddress object (NOT ip_address)
    reason="Failed login: 10 attempts",     # Human-readable reason
    confidence=DetectionConfidence.HIGH,    # Detection confidence (NOT severity)
    event_count=10,                         # Number of events
    event_type=EventType.FAILED_LOGIN,      # EventType enum
    source_events=[...],                    # List[SecurityEvent] - source events
    first_seen=datetime.now(),              # First event timestamp
    last_seen=datetime.now(),               # Last event timestamp
    geolocation=None                        # Optional geolocation data
)
```

---

## Minimal Example: Custom Detector

```python
from bruteforce_detector.detectors.base import BaseDetector
from bruteforce_detector.models import SecurityEvent, DetectionResult, EventType, DetectionConfidence
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List
import ipaddress

METADATA = {
    "name": "SSH Timing Attack Detector",
    "version": "1.0.0",
    "author": "Security Team",
    "description": "Detects rapid SSH login attempts",
    "event_types": [EventType.FAILED_LOGIN],
    "enabled": True
}

class SSHTimingDetector(BaseDetector):
    def __init__(self, config, event_type: EventType):
        super().__init__(config, event_type)
        self.threshold = 5   # attempts
        self.window = 60     # seconds

    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        # Group by IP
        ip_events = defaultdict(list)
        for event in events:
            if event.event_type == EventType.FAILED_LOGIN:
                ip_events[event.source_ip].append(event)

        # Check thresholds
        detections = []
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= self.threshold:
                # Use helper method from BaseDetector
                detection = self._create_detection_result(
                    ip_str=str(ip),
                    reason=f"SSH timing attack: {len(ip_event_list)} attempts in {self.window}s",
                    confidence="high",  # String converted to DetectionConfidence internally
                    event_count=len(ip_event_list),
                    source_events=ip_event_list
                )
                if detection:
                    detections.append(detection)

        return detections
```

---

## Minimal Example: Custom Parser

```python
from bruteforce_detector.parsers.base import BaseLogParser
from bruteforce_detector.models import SecurityEvent, EventType
from datetime import datetime
from typing import Optional, List
import ipaddress
import re

METADATA = {
    "name": "Custom App Parser",
    "version": "1.0.0",
    "author": "Dev Team",
    "description": "Parses custom application logs",
    "log_file_path_key": "custom_app_log_path",
    "enabled": True
}

class CustomAppParser(BaseLogParser):
    def __init__(self, log_path: str):
        super().__init__(log_path)
        self.login_pattern = re.compile(r'LOGIN_FAILED ip=(\S+)')

    def _parse_line(self, line: str, line_number: int) -> Optional[List[SecurityEvent]]:
        match = self.login_pattern.search(line)
        if not match:
            return None

        ip_str = match.group(1)
        event = SecurityEvent(
            source_ip=ipaddress.ip_address(ip_str),  # IPAddress object
            event_type=EventType.FAILED_LOGIN,
            timestamp=datetime.now(),
            source="custom_app",
            raw_message=line,
            metadata={"ip": ip_str}
        )
        return [event]
```

---

## Testing

```bash
# Syntax check
python3 -c "import bruteforce_detector.plugins.detectors.my_detector"

# Test with service restart
sudo systemctl restart tribanft
sudo journalctl -u tribanft -f

# Verify plugin loaded
sudo journalctl -u tribanft | grep "Loaded plugin.*my_detector"
```

---

## Configuration

Add log path to `~/.local/share/tribanft/config.conf`:

```ini
[logs]
custom_app_log_path = /var/log/myapp.log
```

Enable/disable via METADATA or config:
```python
METADATA = {"enabled": True}  # Always enabled
```

---

## Troubleshooting

| Issue | Check | Solution |
|-------|-------|----------|
| Plugin not loading | Service logs | Verify METADATA, check syntax errors |
| No detections | Event types match | Ensure detector event_types matches parser output |
| Import errors | Dependencies | Install required packages |
| Config key missing | Config file | Add log_file_path_key to [logs] section |

```bash
# Debug plugin loading
sudo journalctl -u tribanft | grep -i "plugin\|error"

# Test imports
python3 -c "from bruteforce_detector.plugins.detectors.my_detector import *"
```

---

## YAML Pattern System

For parsers that use YAML patterns, see:
- **Pattern syntax**: docs/RULE_SYNTAX.md
- **Pattern files**: bruteforce_detector/rules/parsers/
- **Examples**: bruteforce_detector/rules/parsers/apache.yaml

---

## Reference Files

**Built-in Examples**:
- Detector: `bruteforce_detector/plugins/detectors/prelogin.py`
- Parser: `bruteforce_detector/plugins/parsers/syslog.py`

**Templates**:
- `bruteforce_detector/plugins/detectors/DETECTOR_PLUGIN_TEMPLATE.py`
- `bruteforce_detector/plugins/parsers/PARSER_PLUGIN_TEMPLATE.py`

**API Reference**: docs/API_REFERENCE.md
