# TribanFT Log Parsers

Reference for built-in parsers and YAML pattern system.

---

## Built-in Parsers

| Parser | Log Format | EventTypes Generated | Pattern File |
|--------|-----------|---------------------|--------------|
| SyslogParser | Syslog | PRELOGIN_INVALID, PORT_SCAN | syslog.yaml |
| MSSQLParser | MSSQL errorlog | FAILED_LOGIN | mssql.yaml |
| ApacheParser | Combined format | HTTP_REQUEST, HTTP_ERROR_4XX, HTTP_ERROR_5XX, SQL_INJECTION, WORDPRESS_ATTACK, FAILED_LOGIN, XSS_ATTACK, PATH_TRAVERSAL, COMMAND_INJECTION, FILE_UPLOAD_MALICIOUS | apache.yaml |
| FTPParser | FTP logs | FTP_ATTACK | ftp.yaml |
| SMTPParser | Mail logs | SMTP_ATTACK | smtp.yaml |
| DNSParser | DNS logs (BIND9, dnsmasq, Unbound) | DNS_ATTACK | dns.yaml |
| NFTablesParser | Kernel firewall logs | PORT_SCAN, NETWORK_SCAN | nftables.yaml |

---

## YAML Pattern System

### Pattern File Location

```
bruteforce_detector/rules/parsers/
├── apache.yaml     # Apache/Nginx patterns
├── syslog.yaml     # Syslog patterns
├── mssql.yaml      # MSSQL patterns
├── nftables.yaml   # Firewall patterns
└── PARSER_TEMPLATE.yaml.example  # Template
```

### Pattern File Structure

```yaml
metadata:
  name: parser_name
  version: 1.0.0
  author: Your Name
  description: Parser description
  log_format: format_name
  enabled: true

pattern_groups:
  sql_injection:
    - regex: '(?i).*\bunion\s+select'
      description: 'UNION-based SQL injection'
    - regex: '(?i).*\bor\s+1\s*=\s*1'
      description: 'Boolean-based injection'

  wordpress:
    - regex: '(?i)/wp-login\.php'
      description: 'wp-login.php access'

  login_pages:
    - regex: '(?i)/login'
      description: 'Generic login page'
```

### Update Patterns

```bash
# Edit pattern file
vim ~/.local/share/tribanft/bruteforce_detector/rules/parsers/apache.yaml

# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('apache.yaml'))"

# Restart service
sudo systemctl restart tribanft

# Verify patterns loaded
sudo journalctl -u tribanft | grep "Loaded.*patterns"
```

---

## Parser Configuration

### Enable/Disable Parsers

Via YAML metadata:
```yaml
metadata:
  enabled: true  # or false
```

Via log file path (disable by not setting):
```ini
[logs]
# Enabled: set path
apache_access_log_path = /var/log/apache2/access.log

# Disabled: comment out or don't set
# nginx_access_log_path = /var/log/nginx/access.log
```

### Real-Time Monitoring

```ini
[realtime]
monitor_syslog = true    # Monitor /var/log/syslog
monitor_mssql = true     # Monitor MSSQL errorlog
monitor_apache = true    # Monitor Apache access log
monitor_nginx = true     # Monitor Nginx access log
```

Requires: `pip3 install watchdog`

---

## Creating Custom Parsers

### Quick Start

```bash
# Copy template
cp bruteforce_detector/plugins/parsers/PARSER_PLUGIN_TEMPLATE.py \
   bruteforce_detector/plugins/parsers/my_parser.py

# Copy pattern template
cp bruteforce_detector/rules/parsers/PARSER_TEMPLATE.yaml.example \
   bruteforce_detector/rules/parsers/my_parser.yaml

# Edit files
vim bruteforce_detector/plugins/parsers/my_parser.py
vim bruteforce_detector/rules/parsers/my_parser.yaml

# Add log path to config
echo "my_app_log_path = /var/log/myapp.log" >> ~/.local/share/tribanft/config.conf

# Restart
sudo systemctl restart tribanft
```

### Minimal Parser Example

**my_parser.py**:
```python
from bruteforce_detector.parsers.base import BaseLogParser
from bruteforce_detector.models import SecurityEvent, EventType, Severity
from datetime import datetime
from typing import Optional, List

METADATA = {
    "name": "my_parser",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Parses custom app logs",
    "log_file_path_key": "my_app_log_path",
    "enabled": True
}

class MyParser(BaseLogParser):
    def __init__(self, config):
        super().__init__(config, "my_parser")
        self._initialize_patterns()

    def _parse_line(self, line: str, line_number: int) -> Optional[List[SecurityEvent]]:
        # Use patterns from YAML
        for pattern in self._get_compiled_patterns('failed_login'):
            if pattern.search(line):
                return [SecurityEvent(
                    timestamp=datetime.now(),
                    source_ip=self._extract_ip(line),
                    event_type=EventType.FAILED_LOGIN,
                    severity=Severity.WARNING,
                    message="Failed login",
                    raw_log=line,
                    source="my_parser"
                )]
        return None
```

**my_parser.yaml**:
```yaml
metadata:
  name: my_parser
  version: 1.0.0
  author: Your Name
  description: Custom app parser
  log_format: custom
  enabled: true

pattern_groups:
  failed_login:
    - regex: 'LOGIN_FAILED'
      description: 'Failed login attempt'
    - regex: 'AUTHENTICATION_ERROR'
      description: 'Auth error'
```

---

## Parser Reference

### Built-in Parsers Detail

#### SyslogParser

**Log File**: `/var/log/syslog`

**EventTypes**:
- `PRELOGIN_INVALID` - MSSQL prelogin packets
- `PORT_SCAN` - Port scan patterns

**Pattern Groups** (syslog.yaml):
- `mssql_prelogin` - MSSQL prelogin detection
- `port_scan` - Port scan indicators

**Example Log**:
```
Dec 23 10:15:42 host mssql[1234]: PRELOGIN packet from 1.2.3.4
Dec 23 10:15:43 host kernel: PORT_SCAN from 1.2.3.4
```

#### MSSQLParser

**Log File**: `/var/opt/mssql/log/errorlog`

**EventTypes**:
- `FAILED_LOGIN` - Login failures

**Pattern Groups** (mssql.yaml):
- `failed_login` - Failed login patterns

**Example Log**:
```
2025-12-23 10:15:42.12 Logon       Error: 18456, Severity: 14, State: 8.
2025-12-23 10:15:42.12 Logon       Login failed for user 'sa'. [CLIENT: 1.2.3.4]
```

#### ApacheParser

**Log File**: `/var/log/apache2/access.log` or `/var/log/nginx/access.log`

**Log Format**: Combined (Apache/Nginx)

**EventTypes**:
- `HTTP_REQUEST` - All requests (baseline)
- `SQL_INJECTION` - SQL injection attempts
- `WORDPRESS_ATTACK` - WordPress attacks
- `FAILED_LOGIN` - 401/403 on login pages
- `XSS_ATTACK` - XSS attempts
- `PATH_TRAVERSAL` - Directory traversal
- `COMMAND_INJECTION` - OS command injection
- `FILE_UPLOAD_MALICIOUS` - Malicious uploads

**Pattern Groups** (apache.yaml):
- `sql_injection` - 13 SQL injection patterns
- `wordpress` - 13 WordPress attack patterns
- `xss` - 6 XSS patterns
- `path_traversal` - 5 traversal patterns
- `command_injection` - 4 injection patterns
- `file_upload` - 4 upload patterns
- `login_pages` - Login page identification

**Example Patterns**:
```yaml
sql_injection:
  - regex: '(?i)\bunion\s+select'
    description: 'UNION-based injection'

wordpress:
  - regex: '(?i)/wp-login\.php'
    description: 'wp-login.php access'
```

Full patterns: `bruteforce_detector/rules/parsers/apache.yaml`

#### NFTablesParser

**Log File**: `/var/log/kern.log` or `/var/log/messages`

**EventTypes**:
- `PORT_SCAN` - Port scanning detected
- `NETWORK_SCAN` - Network reconnaissance

**Pattern Groups** (nftables.yaml):
- `firewall_logs` - Firewall log recognition
- `connection_fields` - Connection data extraction

**Configuration** (nftables.yaml):
```yaml
configuration:
  port_scan_threshold: 5    # Ports to trigger scan
  network_scan_threshold: 10  # Attempts to trigger scan
```

---

## Creating Custom Pattern Files

### Template Structure

```yaml
metadata:
  name: parser_name              # Must match parser METADATA['name']
  version: 1.0.0
  author: Your Name
  description: Short description
  log_format: format_name        # e.g., "syslog", "json", "custom"
  enabled: true

# Documentation (optional)
documentation:
  log_example: |
    Example log line here
  notes: |
    Any notes about the parser

# Pattern groups
pattern_groups:
  # Group name (used in code: _get_compiled_patterns('group_name'))
  group_name:
    - regex: 'pattern1'
      description: 'Pattern 1 description'
    - regex: 'pattern2'
      description: 'Pattern 2 description'

  another_group:
    - regex: 'pattern3'
      description: 'Pattern 3 description'
```

### Pattern Best Practices

| Do | Don't |
|----|-------|
| Use case-insensitive: `(?i)` | Hardcode case |
| Specific patterns first | Generic patterns first |
| Test with sample logs | Deploy untested |
| Document each pattern | Leave undocumented |
| Group logically | Mix unrelated patterns |

### Common Regex Patterns

```yaml
# IP address extraction
regex: '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

# User agent
regex: '"([^"]+)"$'

# Status code
regex: '\s(\d{3})\s'

# URL path
regex: '"[A-Z]+\s([^\s]+)\s'

# Timestamp
regex: '^\[([^\]]+)\]'
```

---

## Testing Parsers

### Syntax Check

```bash
# Python syntax
python3 -c "import bruteforce_detector.plugins.parsers.my_parser"

# YAML syntax
python3 -c "import yaml; yaml.safe_load(open('my_parser.yaml'))"
```

### Test with Service

```bash
# Restart service
sudo systemctl restart tribanft

# Watch logs
sudo journalctl -u tribanft -f

# Verify parser loaded
sudo journalctl -u tribanft | grep "Loaded.*my_parser"

# Check for parsing errors
sudo journalctl -u tribanft | grep -i "error.*my_parser"
```

### Debug Parsing

Add debug logging to parser:
```python
def _parse_line(self, line: str, line_number: int) -> Optional[List[SecurityEvent]]:
    self.logger.debug(f"Parsing line {line_number}: {line[:100]}")
    # ... parsing logic
```

Enable debug logging:
```ini
[advanced]
verbose = true
log_level = DEBUG
```

---

## Troubleshooting

| Issue | Check | Solution |
|-------|-------|----------|
| Parser not loading | METADATA['name'] matches YAML | Fix name mismatch |
| No events generated | Log file path exists | Verify log path in config |
| Pattern not matching | Test regex separately | Use regex101.com to test |
| YAML syntax error | Validate YAML | Fix indentation/quotes |
| Permission denied | Log file permissions | Check read permissions |

```bash
# Check parser status
sudo journalctl -u tribanft | grep "Parser.*my_parser"

# Test log file access
cat /var/log/myapp.log | head

# Validate patterns
cd ~/.local/share/tribanft/bruteforce_detector/rules/parsers
for f in *.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))" && echo "✓ $f" || echo "✗ $f"
done
```

---

## Performance

### Pattern Optimization

| Slow | Fast |
|------|------|
| `.*pattern.*` | `pattern` |
| `(a\|b\|c\|d)` | `[abcd]` |
| Backtracking | Atomic groups |
| Long alternations | Specific patterns |

### Caching

Parsers cache:
- Compiled regex patterns (load once)
- Pattern group lookups
- Configuration settings

---

## Related Documentation

- **Plugin Development**: docs/PLUGIN_DEVELOPMENT.md
- **Rule Syntax**: docs/RULE_SYNTAX.md
- **EventTypes Mapping**: docs/PARSER_EVENTTYPES_MAPPING.md
- **Configuration**: docs/CONFIGURATION.md
