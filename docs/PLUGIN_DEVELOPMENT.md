# TribanFT Plugin Development Guide

Complete guide for creating custom detector and parser plugins for TribanFT.

**Author**: TribanFT Project
**License**: GNU GPL v3
**Last Updated**: 2025-01-20

---

## Table of Contents

1. [Introduction](#introduction)
2. [Plugin System Overview](#plugin-system-overview)
3. [Creating Detector Plugins](#creating-detector-plugins)
4. [Creating Parser Plugins](#creating-parser-plugins)
5. [Plugin Metadata](#plugin-metadata)
6. [Testing Plugins](#testing-plugins)
7. [Best Practices](#best-practices)
8. [Examples](#examples)
9. [Troubleshooting](#troubleshooting)

---

## Introduction

The TribanFT plugin system allows you to extend threat detection capabilities without modifying core code. Plugins are automatically discovered and loaded at runtime.

### What You Can Build

- **Detector Plugins**: Custom threat detection logic (e.g., detect RDP bruteforce, WordPress attacks)
- **Parser Plugins**: Support for new log formats (e.g., Nginx, Apache, custom applications)

### Why Use Plugins?

- **No Core Code Modification**: Drop plugin file in directory, restart service
- **Auto-Discovery**: PluginManager automatically finds and loads your plugins
- **Dependency Injection**: Framework provides config and managers automatically
- **Configuration-Driven**: Enable/disable plugins via config.conf
- **Community Sharing**: Easy to share detection rules with other users

---

## Plugin System Overview

### Architecture

```
TribanFT Engine
    ├─ PluginManager (discovers plugins)
    │
    ├─ Detectors (analyze events)
    │   ├─ PreloginDetector (built-in)
    │   ├─ PortScanDetector (built-in)
    │   └─ CustomDetector (your plugin)
    │
    └─ Parsers (extract events from logs)
        ├─ SyslogParser (built-in)
        ├─ MSSQLParser (built-in)
        └─ CustomParser (your plugin)
```

### Plugin Discovery Process

1. **Scan**: PluginManager scans `plugins/detectors/` and `plugins/parsers/`
2. **Import**: Dynamically imports Python modules
3. **Validate**: Checks if class inherits from BaseDetector/BaseLogParser
4. **Check Config**: Reads enable flags from config.conf
5. **Inject Dependencies**: Provides config, managers as constructor parameters
6. **Instantiate**: Creates plugin instances

### Directory Structure

```
bruteforce_detector/
├── plugins/
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── prelogin.py                    # Built-in
│   │   ├── failed_login.py                # Built-in
│   │   ├── port_scan.py                   # Built-in
│   │   ├── crowdsec.py                    # Built-in
│   │   ├── my_custom_detector.py          # YOUR PLUGIN
│   │   └── DETECTOR_PLUGIN_TEMPLATE.py    # Copy this to start
│   │
│   └── parsers/
│       ├── __init__.py
│       ├── syslog.py                      # Built-in
│       ├── mssql.py                       # Built-in
│       ├── my_custom_parser.py            # YOUR PLUGIN
│       └── PARSER_PLUGIN_TEMPLATE.py      # Copy this to start
```

---

## Creating Detector Plugins

### Quick Start

1. **Copy Template**:
   ```bash
   cd bruteforce_detector/plugins/detectors/
   cp DETECTOR_PLUGIN_TEMPLATE.py rdp_bruteforce_detector.py
   ```

2. **Edit Plugin**:
   - Update `METADATA` dictionary
   - Implement `detect()` method
   - Set `enabled_by_default = True`

3. **Restart Service**:
   ```bash
   sudo systemctl restart tribanft
   ```

4. **Verify Loading**:
   ```bash
   sudo journalctl -u tribanft -n 50 | grep "Discovered plugin"
   ```

### Detector Plugin Structure

```python
"""
RDP Bruteforce Detector

Detects RDP (Remote Desktop Protocol) bruteforce attacks.

Author: Your Name
License: GNU GPL v3
"""

from ...detectors.base import BaseDetector
from ...models import SecurityEvent, DetectionResult, EventType
from collections import defaultdict


class RDPBruteforceDetector(BaseDetector):
    """Detects RDP bruteforce attacks."""

    # ═══ PLUGIN METADATA (REQUIRED) ═══
    METADATA = {
        'name': 'rdp_bruteforce_detector',
        'version': '1.0.0',
        'author': 'Your Name',
        'description': 'Detects RDP bruteforce attempts',
        'dependencies': ['config'],
        'enabled_by_default': True
    }

    def __init__(self, config):
        """Initialize detector."""
        super().__init__(config, EventType.FAILED_LOGIN)

        # Load configuration
        self.threshold = getattr(config, 'rdp_threshold', 10)
        self.logger.info(f"Initialized RDP detector: threshold={self.threshold}")

    def detect(self, events):
        """
        Detect RDP bruteforce attacks.

        Args:
            events: List of SecurityEvent objects

        Returns:
            List of DetectionResult objects
        """
        detections = []

        # Filter RDP events
        rdp_events = [
            e for e in events
            if e.event_type == EventType.FAILED_LOGIN
            and 'rdp' in e.raw_message.lower()
        ]

        # Group by IP
        events_by_ip = defaultdict(list)
        for event in rdp_events:
            events_by_ip[str(event.source_ip)].append(event)

        # Apply threshold
        for ip_str, ip_events in events_by_ip.items():
            if len(ip_events) >= self.threshold:
                result = self._create_detection_result(
                    ip_str=ip_str,
                    reason=f"RDP bruteforce - {len(ip_events)} failed attempts",
                    confidence='high',
                    event_count=len(ip_events),
                    source_events=ip_events
                )

                if result:
                    detections.append(result)

        return detections
```

### Detector Base Class API

**Constructor Parameters** (auto-injected by PluginManager):
- `config`: Configuration object with all settings
- `blacklist_manager` (optional): Access to blacklist for checking existing IPs

**Inherited Methods**:
- `_create_detection_result()`: Helper to create DetectionResult with proper timestamps

**Methods You Must Implement**:
- `detect(events) -> List[DetectionResult]`: Core detection logic

### EventType Enum

Map your detection to appropriate event type:

```python
from ...models import EventType

EventType.PRELOGIN_INVALID    # MSSQL prelogin reconnaissance
EventType.FAILED_LOGIN        # Authentication failures
EventType.PORT_SCAN           # Port scanning activity
EventType.CROWDSEC_BLOCK      # CrowdSec community blocks
```

### DetectionResult Object

Created using `_create_detection_result()` helper:

```python
result = self._create_detection_result(
    ip_str='1.2.3.4',                     # IP address string
    reason='Attack description',          # Human-readable reason
    confidence='high',                    # 'high', 'medium', or 'low'
    event_count=15,                       # Number of events
    source_events=ip_events               # List of SecurityEvent objects
)
```

---

## Creating Parser Plugins

### Quick Start

1. **Copy Template**:
   ```bash
   cd bruteforce_detector/plugins/parsers/
   cp PARSER_PLUGIN_TEMPLATE.py nginx_access_parser.py
   ```

2. **Edit Plugin**:
   - Update `METADATA` dictionary
   - Define regex patterns for log format
   - Implement `parse()` method
   - Set `enabled_by_default = True`

3. **Update Config**:
   ```ini
   # config.conf
   [logs]
   nginx_log_path = /var/log/nginx/access.log
   ```

4. **Restart Service**:
   ```bash
   sudo systemctl restart tribanft
   ```

### Parser Plugin Structure

```python
"""
Nginx Access Log Parser

Parses Nginx access logs for security events.

Author: Your Name
License: GNU GPL v3
"""

import re
import ipaddress
from datetime import datetime
from ...parsers.base import BaseLogParser
from ...models import SecurityEvent, EventType


class NginxAccessParser(BaseLogParser):
    """Parser for Nginx access logs."""

    # ═══ PLUGIN METADATA (REQUIRED) ═══
    METADATA = {
        'name': 'nginx_access_parser',
        'version': '1.0.0',
        'author': 'Your Name',
        'description': 'Parses Nginx access logs',
        'log_format': 'nginx_combined',
        'enabled_by_default': True
    }

    def __init__(self, log_path, config=None):
        """Initialize parser."""
        super().__init__(log_path)
        self.config = config

        # Define regex patterns
        self.patterns = {
            'path_traversal': re.compile(
                r'(?P<ip>[\d.]+).*"GET (?P<path>.*\.\./.*) HTTP',
                re.IGNORECASE
            ),
            'sql_injection': re.compile(
                r'(?P<ip>[\d.]+).*"(?P<method>GET|POST) (?P<path>.*(?:union|select).*) HTTP',
                re.IGNORECASE
            )
        }

    def parse(self, since_timestamp=None, max_lines=None):
        """
        Parse log file and extract security events.

        Args:
            since_timestamp: Only return events after this time
            max_lines: Maximum lines to process

        Returns:
            List of SecurityEvent objects
        """
        events = []
        lines_processed = 0

        for line in self.read_lines():
            if max_lines and lines_processed >= max_lines:
                break
            lines_processed += 1

            # Try each pattern
            for pattern_name, pattern in self.patterns.items():
                match = pattern.search(line)

                if match:
                    try:
                        ip_str = match.group('ip')
                        source_ip = ipaddress.ip_address(ip_str)

                        event = SecurityEvent(
                            source_ip=source_ip,
                            event_type=EventType.PORT_SCAN,  # Map to appropriate type
                            timestamp=datetime.now(),
                            source='nginx',
                            raw_message=line
                        )

                        events.append(event)

                    except Exception as e:
                        self.logger.debug(f"Failed to parse line: {e}")

        self.logger.info(f"Parsed {len(events)} events from {lines_processed} lines")
        return events
```

### Parser Base Class API

**Constructor Parameters**:
- `log_path`: Path to log file (required)
- `config` (optional): Configuration object

**Inherited Methods**:
- `read_lines()`: Generator that yields lines from log file with error handling

**Methods You Must Implement**:
- `parse(since_timestamp=None, max_lines=None) -> List[SecurityEvent]`: Extract events

### SecurityEvent Object

Create events from parsed log lines:

```python
from ...models import SecurityEvent, EventType
import ipaddress
from datetime import datetime

event = SecurityEvent(
    source_ip=ipaddress.ip_address('1.2.3.4'),
    event_type=EventType.FAILED_LOGIN,
    timestamp=datetime.now(),
    source='custom_parser',
    raw_message='original log line'
)
```

---

## Plugin Metadata

### METADATA Dictionary (Required)

All plugins must define a `METADATA` class variable:

```python
METADATA = {
    # Plugin identifier (lowercase, underscores)
    'name': 'my_plugin_name',

    # Semantic version (MAJOR.MINOR.PATCH)
    'version': '1.0.0',

    # Author/maintainer name
    'author': 'Your Name',

    # Brief description
    'description': 'Brief description of what this plugin does',

    # Required dependencies (for detectors)
    'dependencies': ['config', 'blacklist_manager'],

    # Enable by default?
    'enabled_by_default': True
}
```

### Metadata Fields

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `name` | Yes | Unique plugin identifier | `'rdp_detector'` |
| `version` | Yes | Semantic version | `'1.0.0'` |
| `author` | No | Plugin author | `'Security Team'` |
| `description` | No | Brief description | `'Detects RDP attacks'` |
| `dependencies` | Detector only | Required constructor params | `['config']` |
| `enabled_by_default` | No | Auto-enable plugin? | `True` |
| `log_format` | Parser only | Log format handled | `'nginx_combined'` |

---

## Testing Plugins

### 1. Syntax Check

```bash
python3 -m py_compile bruteforce_detector/plugins/detectors/my_plugin.py
```

### 2. Unit Test

Create `tests/test_my_plugin.py`:

```python
import pytest
from bruteforce_detector.plugins.detectors.my_plugin import MyDetector
from bruteforce_detector.models import SecurityEvent, EventType
from datetime import datetime
import ipaddress

class MockConfig:
    my_plugin_threshold = 10

def test_my_detector():
    """Test detector with mock events."""
    config = MockConfig()
    detector = MyDetector(config)

    # Create test events
    events = [
        SecurityEvent(
            source_ip=ipaddress.ip_address('1.2.3.4'),
            event_type=EventType.FAILED_LOGIN,
            timestamp=datetime.now(),
            source='test',
            raw_message='test attack pattern'
        )
        for _ in range(15)  # Above threshold
    ]

    # Run detection
    detections = detector.detect(events)

    # Verify
    assert len(detections) > 0
    assert str(detections[0].ip) == '1.2.3.4'
```

Run tests:
```bash
pytest tests/test_my_plugin.py -v
```

### 3. Integration Test

```bash
# Run tribanft with your plugin
tribanft --detect --verbose

# Check logs for plugin loading
sudo journalctl -u tribanft | grep "my_plugin"

# Verify detections
tribanft --show-blacklist
```

---

## Best Practices

### Code Quality

**Follow Documentation Standards**: Add docstrings to classes and methods (see DOCUMENTATION_GUIDE.md)
**Use Type Hints**: Annotate function parameters and return types
**Error Handling**: Wrap risky operations in try/except
**Logging**: Use `self.logger` for debug/info/error messages
**PEP 8**: Follow Python style guidelines

### Performance

**Efficient Patterns**: Test regex patterns for performance
**Avoid N+1**: Group operations to reduce iterations
**Memory Usage**: Don't load entire log files into memory
**Lazy Evaluation**: Use generators where possible

### Security

**Validate Input**: Check IP addresses are valid
**Sanitize Logs**: Be careful with log injection attacks
**Safe Defaults**: Use conservative thresholds
**No Hardcoded Secrets**: Use config for sensitive data

### Configuration

**Configurable Thresholds**: Load from `config` with `getattr(config, 'param', default)`
**Descriptive Defaults**: Choose sensible default values
**Document Settings**: Add config examples to plugin docstring

---

## Examples

### Example 1: SSH Timing Attack Detector

Detects rapid SSH connection/disconnection patterns:

```python
from ...detectors.base import BaseDetector
from ...models import EventType
from collections import defaultdict
from datetime import timedelta

class SSHTimingDetector(BaseDetector):
    METADATA = {
        'name': 'ssh_timing_detector',
        'version': '1.0.0',
        'description': 'Detects SSH timing-based attacks'
    }

    def __init__(self, config):
        super().__init__(config, EventType.FAILED_LOGIN)
        self.threshold = getattr(config, 'ssh_timing_threshold', 20)
        self.time_window = timedelta(minutes=5)

    def detect(self, events):
        detections = []

        # Filter SSH events
        ssh_events = [e for e in events if 'sshd' in e.raw_message.lower()]

        # Group by IP
        events_by_ip = defaultdict(list)
        for event in ssh_events:
            events_by_ip[str(event.source_ip)].append(event)

        # Check timing patterns
        for ip_str, ip_events in events_by_ip.items():
            # Sort by timestamp
            sorted_events = sorted(ip_events, key=lambda e: e.timestamp)

            # Count events within time window
            rapid_events = []
            for i, event in enumerate(sorted_events):
                window_events = [
                    e for e in sorted_events[i:]
                    if e.timestamp - event.timestamp <= self.time_window
                ]
                if len(window_events) > len(rapid_events):
                    rapid_events = window_events

            if len(rapid_events) >= self.threshold:
                result = self._create_detection_result(
                    ip_str=ip_str,
                    reason=f"SSH timing attack - {len(rapid_events)} rapid connections",
                    confidence='high',
                    event_count=len(rapid_events),
                    source_events=rapid_events
                )

                if result:
                    detections.append(result)

        return detections
```

### Example 2: Apache Access Log Parser (Multi-Event Generation)

**Real-world example from Phase 1 implementation** (`bruteforce_detector/plugins/parsers/apache.py`):

This parser demonstrates best practices for multi-event generation, pattern pre-compilation, and rich metadata.

```python
from ...parsers.base import BaseLogParser
from ...models import SecurityEvent, EventType
import re
import ipaddress
from datetime import datetime

class ApacheParser(BaseLogParser):
    """
    Parser for Apache/Nginx access logs in combined format.

    Demonstrates:
    - Multi-event generation (1-4 events per log line)
    - Pattern pre-compilation for performance
    - Rich metadata generation
    - Event source naming (must match METADATA['name'])
    """

    METADATA = {
        'name': 'apache',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses Apache/Nginx combined log format for security events',
        'log_format': 'apache_combined',
        'enabled_by_default': True
    }

    # SQL Injection patterns (13 total, showing 3 examples)
    SQL_INJECTION_PATTERNS = [
        (r'(?i).*\bunion\s+(all\s+)?select', 'UNION-based SQL injection'),
        (r"(?i).*\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1", 'Boolean-based blind injection'),
        (r'(?i).*\bsleep\s*\(\s*\d+\s*\)', 'Time-based blind injection (SLEEP)'),
        # ... 10 more patterns
    ]

    # WordPress attack patterns (13 total, showing 3 examples)
    WORDPRESS_PATTERNS = [
        (r'(?i)/wp-login\.php', 'wp-login.php access'),
        (r'(?i)POST.*/xmlrpc\.php', 'XML-RPC POST request'),
        (r'(?i)/wp-json/wp/v2/users', 'REST API user enumeration'),
        # ... 10 more patterns
    ]

    def __init__(self, log_path: str):
        super().__init__(log_path)

        # Pre-compile regex patterns for performance
        self._sql_patterns = [(re.compile(p), desc) for p, desc in self.SQL_INJECTION_PATTERNS]
        self._wp_patterns = [(re.compile(p), desc) for p, desc in self.WORDPRESS_PATTERNS]
        self.logger.info(f"Apache parser initialized: {len(self._sql_patterns)} SQL patterns, "
                        f"{len(self._wp_patterns)} WordPress patterns")

    def _parse_line(self, line: str, since_timestamp) -> List[SecurityEvent]:
        """
        Parse single log line - can generate MULTIPLE events.

        Multi-event generation pattern:
        1. Always generate HTTP_REQUEST (baseline)
        2. Conditionally generate SQL_INJECTION (if pattern matches)
        3. Conditionally generate WORDPRESS_ATTACK (if pattern matches)
        4. Conditionally generate FAILED_LOGIN (if 401/403 on login page)
        """
        events = []

        # Parse log line (combined format)
        match = self.COMBINED_LOG_PATTERN.match(line)
        if not match:
            return []

        fields = match.groupdict()
        ip_address = ipaddress.ip_address(fields['ip'])
        uri = fields['uri']
        status = int(fields['status'])

        # Build metadata
        metadata = {
            'method': fields['method'],
            'uri': uri,
            'status': status,
            'user_agent': fields['user_agent'],
        }

        # 1. Always generate HTTP_REQUEST event (baseline traffic)
        events.append(SecurityEvent(
            source_ip=ip_address,
            event_type=EventType.HTTP_REQUEST,
            timestamp=self._parse_timestamp(fields['timestamp']),
            source='apache',  # Must match METADATA['name']
            raw_message=line,
            metadata=metadata.copy()
        ))

        # 2. Check for SQL injection patterns
        sql_detected = False
        for pattern, description in self._sql_patterns:
            if pattern.search(uri) or pattern.search(line):
                if not sql_detected:  # Only one SQL event per line
                    events.append(SecurityEvent(
                        source_ip=ip_address,
                        event_type=EventType.SQL_INJECTION,
                        timestamp=self._parse_timestamp(fields['timestamp']),
                        source='apache',
                        raw_message=line,
                        metadata={**metadata, 'attack_type': description}
                    ))
                    sql_detected = True
                    self.logger.debug(f"SQL injection detected: {description}")
                break

        # 3. Check for WordPress attack patterns
        wp_detected = False
        for pattern, description in self._wp_patterns:
            if pattern.search(uri) or pattern.search(line):
                if not wp_detected:  # Only one WordPress event per line
                    events.append(SecurityEvent(
                        source_ip=ip_address,
                        event_type=EventType.WORDPRESS_ATTACK,
                        timestamp=self._parse_timestamp(fields['timestamp']),
                        source='apache',
                        raw_message=line,
                        metadata={**metadata, 'attack_type': description}
                    ))
                    wp_detected = True
                    self.logger.debug(f"WordPress attack detected: {description}")
                break

        # 4. Check for failed login attempts (401/403 on login pages)
        if status in [401, 403]:
            for login_pattern in self._login_patterns:
                if login_pattern.search(uri):
                    events.append(SecurityEvent(
                        source_ip=ip_address,
                        event_type=EventType.FAILED_LOGIN,
                        timestamp=self._parse_timestamp(fields['timestamp']),
                        source='apache',
                        raw_message=line,
                        metadata={**metadata, 'login_failure_type': 'HTTP auth failure'}
                    ))
                    self.logger.debug(f"Failed login detected: {status} on {uri}")
                    break

        return events  # Returns 1-4 events
```

**Key Takeaways from Apache Parser:**

1. **Multi-Event Generation**:
   - Single log line generates 1-4 events
   - Base event (HTTP_REQUEST) always created
   - Attack-specific events conditionally added
   - Prevents duplicate events of same type per line

2. **Performance Optimization**:
   - Pre-compile regex patterns in `__init__`
   - Store compiled patterns as instance variables
   - Avoid re-compiling on every line

3. **Rich Metadata**:
   - Include HTTP method, URI, status code, user-agent
   - Add attack-specific fields (`attack_type`)
   - Copy metadata dict to avoid mutations

4. **Event Source Naming**:
   - `source='apache'` must match `METADATA['name']='apache'`
   - Used for log_sources filtering in YAML rules

5. **Error Handling**:
   - Wrap parsing in try/except
   - Log warnings for unparseable lines
   - Continue processing on errors

---

## Troubleshooting

### Plugin Not Loading

**Problem**: Plugin not discovered by PluginManager

**Solutions**:
1. Check file is in correct directory (`plugins/detectors/` or `plugins/parsers/`)
2. Verify class inherits from `BaseDetector` or `BaseLogParser`
3. Check for syntax errors: `python3 -m py_compile your_plugin.py`
4. Enable debug logging: `verbose = true` in config.conf
5. Check logs: `sudo journalctl -u tribanft | grep "Discovered plugin"`

### Import Errors

**Problem**: `ModuleNotFoundError` or `ImportError`

**Solutions**:
1. Use relative imports: `from ...detectors.base import BaseDetector`
2. Don't import from old detector locations
3. Ensure `__init__.py` exists in plugin directories

### Plugin Disabled

**Problem**: Plugin discovered but not running

**Solutions**:
1. Check `METADATA['enabled_by_default'] = True`
2. Verify no disable flag in config: `enable_my_plugin_plugin = false`
3. Check detector's event type is enabled (e.g., `enable_failed_login_detection = true`)

### No Detections

**Problem**: Plugin runs but produces no detections

**Solutions**:
1. Add debug logging: `self.logger.debug(f"Processing {len(events)} events")`
2. Check event filtering logic
3. Verify threshold isn't too high
4. Ensure event type matches what parsers produce
5. Test with known malicious traffic

### Dependency Injection Fails

**Problem**: `TypeError: __init__() missing required positional argument`

**Solutions**:
1. List dependencies in METADATA: `'dependencies': ['config', 'blacklist_manager']`
2. Ensure constructor parameters match dependency names
3. Provide default values: `def __init__(self, config, blacklist_manager=None):`

---

## Support & Contributing

### Getting Help

- **Documentation**: Read DOCUMENTATION_GUIDE.md for code standards
- **Examples**: Check built-in plugins in `plugins/detectors/` and `plugins/parsers/`
- **Templates**: Use DETECTOR_PLUGIN_TEMPLATE.py and PARSER_PLUGIN_TEMPLATE.py
- **Issues**: Report bugs at GitHub repository

### Contributing Plugins

1. Fork TribanFT repository
2. Create plugin following this guide
3. Add tests and documentation
4. Submit pull request

### Sharing Plugins

Share your plugins with the community:
- Create GitHub repository with your plugin
- Tag as `tribanft-plugin`
- Include README with usage instructions
- Provide example config and test cases

---

## YAML-Based Detection Rules

### Quick Start with YAML Rules

**Don't want to write Python code?** Use YAML rules instead!

YAML rules let you define detection logic using simple configuration files:

```yaml
metadata:
  name: my_custom_attack
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - FAILED_LOGIN
  threshold: 10
  time_window_minutes: 30
  confidence: high

  patterns:
    - regex: "(?i).*attack.*pattern.*"
      description: "Custom attack signature"

aggregation:
  group_by: source_ip

output:
  reason_template: "Custom attack detected - {event_count} attempts"
```

### When to Use YAML Rules vs Python Plugins

| Feature | YAML Rules | Python Plugins |
|---------|------------|----------------|
| **Complexity** | Simple pattern matching | Complex logic, algorithms |
| **Skills Required** | Basic regex | Python programming |
| **Development Time** | Minutes | Hours to days |
| **Flexibility** | Limited to patterns | Unlimited |
| **Performance** | Fast (compiled regex) | Fast (optimized code) |
| **Testing** | Quick edit & restart | Full development cycle |

**Use YAML Rules For**:
- Pattern-based detection (regex matching)
- Threshold-based attacks
- Simple bruteforce detection
- Reconnaissance detection
- Rapid prototyping

**Use Python Plugins For**:
- Statistical analysis
- Machine learning integration
- Complex state tracking
- Custom log parsing
- Advanced algorithms

### Creating YAML Rules

**Step 1**: Copy template

```bash
cd ~/.local/share/tribanft/bruteforce_detector/rules/detectors/
cp RULE_TEMPLATE.yaml my_attack.yaml
```

**Step 2**: Edit rule

```yaml
metadata:
  name: ftp_bruteforce
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - FAILED_LOGIN
  threshold: 15
  time_window_minutes: 30
  confidence: high

  patterns:
    - regex: "(?i).*vsftpd.*failed.*login.*"
      description: "FTP login failure"

aggregation:
  group_by: source_ip

output:
  reason_template: "FTP bruteforce - {event_count} failed logins"
```

**Step 3**: Restart service

```bash
sudo systemctl restart tribanft
```

**Step 4**: Verify loading

```bash
sudo journalctl -u tribanft | grep "Loaded rule"
```

### YAML Rule Examples

**Example 1: Custom Port Scanner Detection**

```yaml
metadata:
  name: aggressive_port_scan
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - PORT_SCAN
  threshold: 50  # Many ports
  time_window_minutes: 5  # Very fast
  confidence: high

  patterns:
    - regex: "(?i).*connection.*refused.*"
    - regex: "(?i).*firewall.*drop.*"

aggregation:
  group_by: source_ip

output:
  reason_template: "Aggressive port scan - {event_count} ports in 5 minutes"
```

**Example 2: Database Enumeration**

```yaml
metadata:
  name: database_enumeration
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - FAILED_LOGIN
  threshold: 5
  time_window_minutes: 60
  confidence: medium

  patterns:
    - regex: "(?i).*information_schema.*"
      description: "Information schema query"
    - regex: "(?i).*sys\\.tables.*"
      description: "System table enumeration"

aggregation:
  group_by: source_ip

output:
  reason_template: "Database enumeration: {pattern_description}"
```

### Complete Documentation

For complete YAML rule syntax reference, see **RULE_SYNTAX.md**:

- Pattern syntax (regex)
- Available event types
- Threshold tuning
- Time window guidelines
- Multi-rule files
- Troubleshooting
- Complete examples

### YAML Rules + Python Plugins

**Best of both worlds**: Use YAML rules for simple patterns and Python plugins for complex logic.

Example workflow:
1. Start with YAML rule for quick detection
2. Monitor false positive rate
3. If logic becomes complex, convert to Python plugin
4. Keep YAML rule as fallback/supplement

---

**Happy Plugin Development!**

For more information, visit: https://github.com/n0tjohnny/tribanft
