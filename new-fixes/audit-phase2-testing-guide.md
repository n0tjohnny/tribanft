# TribanFT Phase 2 - Testing & Verification Guide

**Date**: 2025-12-27
**Version**: v2.8.0 (Phase 2)
**Scope**: 9 MEDIUM priority fixes + 1 LOW bonus fix

---

## Quick Reference

### Files Modified (7 files)

```bash
# View all changes
git diff HEAD~9 HEAD bruteforce_detector/detectors/base.py
git diff HEAD~9 HEAD bruteforce_detector/managers/nftables_manager.py
git diff HEAD~9 HEAD bruteforce_detector/managers/blacklist.py
git diff HEAD~9 HEAD bruteforce_detector/parsers/base.py
git diff HEAD~9 HEAD bruteforce_detector/managers/database.py
git diff HEAD~9 HEAD bruteforce_detector/core/realtime_engine.py
git diff HEAD~9 HEAD bruteforce_detector/core/log_watcher.py
```

### Fixes to Test

| Fix | Priority | File | Lines | Risk |
|-----|----------|------|-------|------|
| #27 | MEDIUM | detectors/base.py | +2 | Very Low |
| #4 | MEDIUM | nftables_manager.py | +1 | Low |
| #9+#10 | MEDIUM | blacklist.py | +17 | Medium |
| #26 | MEDIUM | parsers/base.py | +7 | Low |
| #14+#11 | MEDIUM | database.py | +48 | Low |
| #21 | MEDIUM | realtime_engine.py | +18 | Low |
| #13 | MEDIUM | database.py | +8 | Low |
| #20 | MEDIUM | log_watcher.py | +58 | Low |

---

## Section 1: Code Review Checklist

### 1.1 General Review

```bash
# Check for syntax errors
python3 -m py_compile bruteforce_detector/detectors/base.py
python3 -m py_compile bruteforce_detector/managers/nftables_manager.py
python3 -m py_compile bruteforce_detector/managers/blacklist.py
python3 -m py_compile bruteforce_detector/parsers/base.py
python3 -m py_compile bruteforce_detector/managers/database.py
python3 -m py_compile bruteforce_detector/core/realtime_engine.py
python3 -m py_compile bruteforce_detector/core/log_watcher.py

# Check imports
python3 -c "from bruteforce_detector.detectors.base import BaseDetector; print('✓ detectors/base.py imports OK')"
python3 -c "from bruteforce_detector.managers.nftables_manager import NFTablesManager; print('✓ nftables_manager.py imports OK')"
python3 -c "from bruteforce_detector.managers.blacklist import BlacklistManager; print('✓ blacklist.py imports OK')"
python3 -c "from bruteforce_detector.parsers.base import BaseLogParser; print('✓ parsers/base.py imports OK')"
python3 -c "from bruteforce_detector.managers.database import DatabaseManager; print('✓ database.py imports OK')"
python3 -c "from bruteforce_detector.core.realtime_engine import RealtimeDetectionMixin; print('✓ realtime_engine.py imports OK')"
python3 -c "from bruteforce_detector.core.log_watcher import LogWatcher; print('✓ log_watcher.py imports OK')"
```

**Expected**: All files compile and import without errors.

---

### 1.2 Fix-Specific Code Review

#### ✓ Fix #27: Naive Datetime in BaseDetector

**Review Points**:
- [ ] Import includes `timezone` from datetime
- [ ] `datetime.now(timezone.utc)` used instead of `datetime.now()`
- [ ] Comment mentions timezone-aware

**Verify**:
```bash
grep -n "from datetime import" bruteforce_detector/detectors/base.py
# Expected: from datetime import datetime, timezone

grep -n "datetime.now(timezone.utc)" bruteforce_detector/detectors/base.py
# Expected: Line 125 or similar
```

---

#### ✓ Fix #4: Error Propagation Inconsistency

**Review Points**:
- [ ] `raise` statement added after error logging
- [ ] Comment explains re-raising

**Verify**:
```bash
grep -A3 "ERROR: NFTables update failed" bruteforce_detector/managers/nftables_manager.py
# Expected to see:
#   self.logger.error(f"ERROR: NFTables update failed: {e}")
#   raise  # Re-raise to propagate error to caller
```

---

#### ✓ Fix #9 + #10: IP Removal Consistency

**Review Points**:
- [ ] Two-phase commit: NFTables first, then storage
- [ ] Uses `self.nft_sync.update_blacklists()` (not new instance)
- [ ] Raises exception if NFTables fails
- [ ] Comments mention Fix #9 and Fix #10

**Verify**:
```bash
# Check for two-phase commit pattern
grep -A10 "TWO-PHASE COMMIT" bruteforce_detector/managers/blacklist.py

# Verify no NFTablesSync instance creation
grep -n "NFTablesSync" bruteforce_detector/managers/blacklist.py
# Expected: Should NOT find "NFTablesSync(" in remove_ip method

# Verify uses existing instance
grep -n "self.nft_sync.update_blacklists" bruteforce_detector/managers/blacklist.py
# Expected: Found in remove_ip method
```

---

#### ✓ Fix #26: Parser Singleton Thread Safety

**Review Points**:
- [ ] `threading` imported
- [ ] `_pattern_loader_lock` class variable exists
- [ ] Double-checked locking pattern used
- [ ] Lock acquired before singleton check

**Verify**:
```bash
grep -n "import threading" bruteforce_detector/parsers/base.py

grep -n "_pattern_loader_lock" bruteforce_detector/parsers/base.py
# Expected: _pattern_loader_lock = threading.Lock()

grep -A10 "with BaseLogParser._pattern_loader_lock" bruteforce_detector/parsers/base.py
# Expected: Double-checked locking pattern visible
```

---

#### ✓ Fix #14 + #11: Backup Atomic + Naive Datetime

**Review Points**:
- [ ] Uses `source.backup(dest, ...)` instead of `shutil.copy2()`
- [ ] Includes `PRAGMA integrity_check`
- [ ] Has `_backup_progress` callback method
- [ ] Uses `datetime.now(timezone.utc)` for timestamp
- [ ] Comment mentions Fix #14

**Verify**:
```bash
grep -n "source.backup" bruteforce_detector/managers/database.py
# Expected: Found in backup() method

grep -n "PRAGMA integrity_check" bruteforce_detector/managers/database.py
# Expected: Found in backup() method

grep -n "_backup_progress" bruteforce_detector/managers/database.py
# Expected: Method defined

grep -n "datetime.now(timezone.utc)" bruteforce_detector/managers/database.py
# Expected: Multiple occurrences (Fix #11 and #14)
```

---

#### ✓ Fix #21: Parser Reuse Thread Safety

**Review Points**:
- [ ] `self.parser_locks` dictionary created
- [ ] Locks created during parser setup
- [ ] Lock acquired in `_on_log_file_modified`
- [ ] Lock released in finally block

**Verify**:
```bash
grep -n "self.parser_locks" bruteforce_detector/core/realtime_engine.py
# Expected: Multiple occurrences (init, setup, callback)

grep -A5 "lock.acquire()" bruteforce_detector/core/realtime_engine.py
# Expected: In _on_log_file_modified method

grep -A3 "finally:" bruteforce_detector/core/realtime_engine.py | grep "lock.release()"
# Expected: Lock released in finally
```

---

#### ✓ Fix #13: UPSERT Overwrites Metadata

**Review Points**:
- [ ] COALESCE order changed: `COALESCE(current, new)` instead of `COALESCE(new, current)`
- [ ] Applied to: reason, confidence, source
- [ ] Comment mentions "FIX #13: Preserve original"
- [ ] Geolocation still enriched if missing

**Verify**:
```bash
grep -A10 "FIX #13" bruteforce_detector/managers/database.py
# Expected: See COALESCE pattern with current first

grep -n "COALESCE(reason, excluded.reason)" bruteforce_detector/managers/database.py
# Expected: Preserves original (current before excluded)
```

---

#### ✓ Fix #20: Rate Limit State Persistence

**Review Points**:
- [ ] `json` and `tempfile` imported
- [ ] `self.state_file` created in `__init__`
- [ ] `_load_rate_limit_state()` called in `__init__`
- [ ] `_save_rate_limit_state()` uses atomic write
- [ ] `_save_rate_limit_state()` called in `_check_rate_limit()`
- [ ] Comment mentions Fix #20

**Verify**:
```bash
grep -n "import json" bruteforce_detector/core/log_watcher.py
grep -n "import tempfile" bruteforce_detector/core/log_watcher.py

grep -n "_load_rate_limit_state" bruteforce_detector/core/log_watcher.py
# Expected: Method defined and called in __init__

grep -n "_save_rate_limit_state" bruteforce_detector/core/log_watcher.py
# Expected: Method defined and called in _check_rate_limit

grep -n "os.replace" bruteforce_detector/core/log_watcher.py
# Expected: Atomic write in _save_rate_limit_state
```

---

## Section 2: Functional Testing

### 2.1 Test Environment Setup

```bash
# Backup current state
cp -r ~/.local/share/tribanft ~/.local/share/tribanft.backup.$(date +%Y%m%d)

# Check Python version
python3 --version
# Expected: Python 3.8+

# Check dependencies
python3 -c "import sqlite3; print(f'SQLite version: {sqlite3.sqlite_version}')"
# Expected: SQLite 3.24+ (3.38+ for full json_patch support)

# Verify NFTables
sudo nft --version
# Expected: nftables v0.9+
```

---

### 2.2 Fix #27: Timezone-Aware Datetime

**Test**: Detector creates timezone-aware timestamps

```bash
# Create test detector
cat > /tmp/test_datetime.py << 'EOF'
import sys
sys.path.insert(0, '/home/jc/Documents/projetos/tribanft')

from bruteforce_detector.detectors.base import BaseDetector
from bruteforce_detector.models import SecurityEvent, EventType, DetectionResult
from datetime import datetime, timezone
from typing import List

class TestDetector(BaseDetector):
    METADATA = {'name': 'test', 'version': '1.0', 'enabled': True}

    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        # Force fallback datetime creation
        result = self._create_detection(
            ip='1.2.3.4',
            events=[],  # Empty events to trigger fallback
            reason='test',
            confidence='high'
        )

        # Check if datetime has timezone
        print(f"first_seen type: {type(result.first_seen)}")
        print(f"first_seen: {result.first_seen}")
        print(f"Has timezone: {result.first_seen.tzinfo is not None}")

        assert result.first_seen.tzinfo is not None, "FAIL: Datetime is naive!"
        print("✓ PASS: Datetime is timezone-aware")
        return [result]

# Test
from bruteforce_detector.config import get_config
detector = TestDetector(get_config())
detector.detect([])
EOF

python3 /tmp/test_datetime.py
```

**Expected Output**:
```
✓ PASS: Datetime is timezone-aware
```

---

### 2.3 Fix #4: Error Propagation

**Test**: NFTables errors are propagated to caller

```bash
# Create test script
cat > /tmp/test_error_propagation.py << 'EOF'
import sys
sys.path.insert(0, '/home/jc/Documents/projetos/tribanft')

from bruteforce_detector.managers.nftables_manager import NFTablesManager
from bruteforce_detector.config import get_config
from unittest.mock import patch, MagicMock
import subprocess

config = get_config()
config.enable_nftables_update = True

nft_manager = NFTablesManager(config)

# Mock subprocess to force failure
with patch('subprocess.run') as mock_run:
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "Test error"
    mock_run.return_value = mock_result

    try:
        nft_manager.update_blacklists({'ipv4': set(), 'ipv6': set()})
        print("✗ FAIL: No exception raised!")
    except RuntimeError as e:
        print(f"✓ PASS: Exception propagated: {e}")
    except Exception as e:
        print(f"✗ FAIL: Wrong exception type: {type(e)}")
EOF

python3 /tmp/test_error_propagation.py
```

**Expected Output**:
```
✓ PASS: Exception propagated: NFTables atomic update failed: ...
```

---

### 2.4 Fix #9 + #10: IP Removal Consistency

**Test**: Two-phase commit and no duplicate instances

```bash
# This requires a running system with NFTables
# Manual test:

# 1. Add an IP to blacklist
tribanft --blacklist-add 198.51.100.1 --reason "Test IP for removal" --no-log-search

# 2. Verify IP in both storage and NFTables
tribanft --query-ip 198.51.100.1
sudo nft list set inet filter blacklist_ipv4 | grep 198.51.100.1

# 3. Remove the IP
tribanft --blacklist-remove 198.51.100.1

# 4. Verify IP NOT in storage AND NOT in NFTables
tribanft --query-ip 198.51.100.1
# Expected: "IP 198.51.100.1 not found in blacklist"

sudo nft list set inet filter blacklist_ipv4 | grep 198.51.100.1
# Expected: No match (IP removed from firewall)

# 5. Check logs for two-phase commit
sudo journalctl -u tribanft -n 50 | grep -E "Removed.*from NFTables|Removed.*from blacklist storage"
# Expected: Both messages appear
```

---

### 2.5 Fix #26: Parser Singleton Thread Safety

**Test**: Concurrent parser creation

```bash
cat > /tmp/test_parser_singleton.py << 'EOF'
import sys
sys.path.insert(0, '/home/jc/Documents/projetos/tribanft')

from bruteforce_detector.parsers.apache import ApacheParser
import threading
import time

instances = []
lock = threading.Lock()

def create_parser(n):
    parser = ApacheParser('/var/log/apache2/access.log')
    with lock:
        instances.append(id(parser._pattern_loader))
    time.sleep(0.01)

# Create 10 parsers concurrently
threads = []
for i in range(10):
    t = threading.Thread(target=create_parser, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# Check if all instances share same pattern loader
unique_loaders = set(instances)
print(f"Pattern loader instances: {len(unique_loaders)}")
print(f"Instance IDs: {unique_loaders}")

if len(unique_loaders) == 1:
    print("✓ PASS: Only one pattern loader instance created")
else:
    print(f"✗ FAIL: Multiple pattern loaders created: {len(unique_loaders)}")
EOF

python3 /tmp/test_parser_singleton.py
```

**Expected Output**:
```
Pattern loader instances: 1
✓ PASS: Only one pattern loader instance created
```

---

### 2.6 Fix #14: SQLite Backup Atomic

**Test**: Backup consistency during active writes

```bash
cat > /tmp/test_backup_atomic.py << 'EOF'
import sys
sys.path.insert(0, '/home/jc/Documents/projetos/tribanft')

from bruteforce_detector.managers.database import DatabaseManager
from bruteforce_detector.config import get_config
import threading
import time
import sqlite3

config = get_config()
db_manager = DatabaseManager(config)

# Function to continuously write to database
def write_data():
    for i in range(100):
        db_manager.add_ip(
            ip=f"192.0.2.{i}",
            reason="Test",
            confidence="high",
            first_seen=time.time(),
            last_seen=time.time(),
            event_count=1
        )
        time.sleep(0.01)

# Start writer thread
writer = threading.Thread(target=write_data)
writer.start()

# Create backup while writes happening
time.sleep(0.2)  # Let some writes happen
print("Creating backup during active writes...")
backup_path = db_manager.backup()

# Wait for writer to finish
writer.join()

if backup_path and backup_path.exists():
    # Verify backup integrity
    try:
        with sqlite3.connect(backup_path) as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()
            if result[0] == 'ok':
                print(f"✓ PASS: Backup integrity verified: {backup_path}")
            else:
                print(f"✗ FAIL: Backup corrupted: {result[0]}")
    except Exception as e:
        print(f"✗ FAIL: Could not verify backup: {e}")
else:
    print("✗ FAIL: Backup not created")
EOF

python3 /tmp/test_backup_atomic.py
```

**Expected Output**:
```
Creating backup during active writes...
✓ PASS: Backup integrity verified: /path/to/backup
```

---

### 2.7 Fix #21: Parser Reuse Thread Safety

**Test**: Concurrent parser access

```bash
# This is tested implicitly by real-time monitoring
# Manual test:

# 1. Enable real-time monitoring
# In config.conf:
# [realtime]
# monitor_syslog = true
# monitor_apache = true

# 2. Start daemon
tribanft --daemon &
DAEMON_PID=$!

# 3. Generate concurrent log writes
for i in {1..10}; do
    echo "$(date) Test log entry $i" | sudo tee -a /var/log/syslog &
done

# 4. Wait for processing
sleep 5

# 5. Check for errors
sudo journalctl -u tribanft -n 100 | grep -i "error\|exception"
# Expected: No parser-related errors

# 6. Stop daemon
kill -TERM $DAEMON_PID
```

---

### 2.8 Fix #13: UPSERT Metadata Preservation

**Test**: Original detection metadata preserved

```bash
cat > /tmp/test_upsert_metadata.py << 'EOF'
import sys
sys.path.insert(0, '/home/jc/Documents/projetos/tribanft')

from bruteforce_detector.managers.database import DatabaseManager
from bruteforce_detector.config import get_config
import time

config = get_config()
db_manager = DatabaseManager(config)

# First detection: SSH brute force
print("First detection: SSH brute force, high confidence")
db_manager.add_ip(
    ip='203.0.113.1',
    reason='SSH brute force attack',
    confidence='high',
    source='ssh_detector',
    first_seen=time.time(),
    last_seen=time.time(),
    event_count=10
)

# Query first detection
ip_info = db_manager.get_ip('203.0.113.1')
print(f"After first detection:")
print(f"  Reason: {ip_info.get('reason')}")
print(f"  Confidence: {ip_info.get('confidence')}")
print(f"  Source: {ip_info.get('source')}")
print(f"  Event count: {ip_info.get('event_count')}")

# Second detection: Port scan (different attack)
print("\nSecond detection: Port scan, medium confidence")
db_manager.add_ip(
    ip='203.0.113.1',
    reason='Port scanning detected',
    confidence='medium',
    source='port_scan_detector',
    first_seen=time.time(),
    last_seen=time.time(),
    event_count=5
)

# Query after second detection
ip_info = db_manager.get_ip('203.0.113.1')
print(f"\nAfter second detection:")
print(f"  Reason: {ip_info.get('reason')}")
print(f"  Confidence: {ip_info.get('confidence')}")
print(f"  Source: {ip_info.get('source')}")
print(f"  Event count: {ip_info.get('event_count')}")

# Verify original metadata preserved
if ip_info.get('reason') == 'SSH brute force attack':
    print("\n✓ PASS: Original reason preserved")
else:
    print(f"\n✗ FAIL: Reason changed to: {ip_info.get('reason')}")

if ip_info.get('confidence') == 'high':
    print("✓ PASS: Original confidence preserved")
else:
    print(f"✗ FAIL: Confidence changed to: {ip_info.get('confidence')}")

if ip_info.get('source') == 'ssh_detector':
    print("✓ PASS: Original source preserved")
else:
    print(f"✗ FAIL: Source changed to: {ip_info.get('source')}")

if ip_info.get('event_count') == 15:  # 10 + 5
    print("✓ PASS: Event count accumulated")
else:
    print(f"✗ FAIL: Event count is: {ip_info.get('event_count')}")
EOF

python3 /tmp/test_upsert_metadata.py
```

**Expected Output**:
```
✓ PASS: Original reason preserved
✓ PASS: Original confidence preserved
✓ PASS: Original source preserved
✓ PASS: Event count accumulated
```

---

### 2.9 Fix #20: Rate Limit State Persistence

**Test**: Rate limit survives restart

```bash
cat > /tmp/test_rate_limit_persistence.py << 'EOF'
import sys
sys.path.insert(0, '/home/jc/Documents/projetos/tribanft')

from bruteforce_detector.core.log_watcher import LogWatcher
from bruteforce_detector.config import get_config
import time
import json
from pathlib import Path

config = get_config()

# Callback (does nothing)
def dummy_callback(file_path, from_offset, to_offset):
    pass

# Create first watcher and trigger rate limit
print("Creating first LogWatcher...")
watcher1 = LogWatcher(config, dummy_callback)

# Manually trigger rate limit
watcher1.event_count = 10000  # Exceed max_events_per_second
result = watcher1._check_rate_limit()

print(f"Rate limit triggered: {not result}")
print(f"Paused until: {watcher1.paused_until}")

# Check state file exists
state_file = Path(config.state_dir) / 'log_watcher_rate_limit.json'
if state_file.exists():
    with open(state_file, 'r') as f:
        state = json.load(f)
    print(f"✓ State file created: {state}")
else:
    print("✗ FAIL: State file not created")
    sys.exit(1)

# Simulate restart - create new watcher
print("\nSimulating restart (creating new LogWatcher)...")
watcher2 = LogWatcher(config, dummy_callback)

print(f"Paused until restored: {watcher2.paused_until}")

if watcher2.paused_until and watcher2.paused_until == watcher1.paused_until:
    print("✓ PASS: Rate limit state persisted across restart")
else:
    print(f"✗ FAIL: State not restored")
    print(f"  Original: {watcher1.paused_until}")
    print(f"  Restored: {watcher2.paused_until}")
EOF

python3 /tmp/test_rate_limit_persistence.py
```

**Expected Output**:
```
Rate limit triggered: True
Paused until: <timestamp>
✓ State file created: {...}

Simulating restart (creating new LogWatcher)...
Paused until restored: <same timestamp>
✓ PASS: Rate limit state persisted across restart
```

---

## Section 3: Regression Testing

### 3.1 Phase 1 Fixes Verification

```bash
# Verify Phase 1 fixes still working

# Fix #1: NFTables race condition (threading.Lock)
grep -n "_nftables_lock" bruteforce_detector/managers/nftables_manager.py
# Expected: Lock declared and used

# Fix #2: Whitelist defense-in-depth
grep -n "is_whitelisted" bruteforce_detector/managers/nftables_manager.py
# Expected: Whitelist check in update_blacklists

# Fix #3: NFTables sets validation
grep -n "_validate_nftables_sets" bruteforce_detector/managers/nftables_manager.py
# Expected: Method exists and called

# Fix #12: UPSERT last_seen MAX
grep -n "MAX(excluded.last_seen" bruteforce_detector/managers/database.py
# Expected: Uses MAX not COALESCE

# Fix #18: Rule reload race condition
grep -n "_reload_lock" bruteforce_detector/core/rule_engine.py
# Expected: Lock exists

# Fix #19: Detector exception tracking
grep -n "failed_detectors" bruteforce_detector/main.py
# Expected: Detector failure tracking

# Fix #31: Whitelist atomic file rewrite
grep -n "tempfile.mkstemp" bruteforce_detector/managers/whitelist.py
# Expected: Atomic write pattern

# Fix #34: Whitelist hot-reload
grep -n "def reload" bruteforce_detector/managers/whitelist.py
# Expected: reload() method exists

# Fix #35: Signal handlers
grep -n "SIGTERM\|SIGINT" bruteforce_detector/main.py
# Expected: Signal handlers registered

# Fix #36: Backup file locking
grep -n "file_lock" bruteforce_detector/utils/backup_manager.py
# Expected: File locking used
```

---

### 3.2 Security Invariants Verification

#### Invariant 1: Whitelist Precedence

```bash
# Check all whitelist checkpoints
grep -rn "is_whitelisted" bruteforce_detector/managers/*.py

# Expected locations:
# - blacklist.py: add_manual_ip, _prepare_detection_ips
# - nftables_manager.py: update_blacklists (defense-in-depth)
```

#### Invariant 2: Atomic Operations

```bash
# Check for locks and transactions
grep -rn "with.*_update_lock" bruteforce_detector/managers/*.py
grep -rn "BEGIN IMMEDIATE" bruteforce_detector/managers/*.py
grep -rn "tempfile.mkstemp" bruteforce_detector/managers/*.py
grep -rn "os.replace" bruteforce_detector/managers/*.py
```

#### Invariant 3: Thread Safety

```bash
# Check for all locks
grep -rn "threading.Lock()" bruteforce_detector/

# Expected: At least 7 locks across different files
```

#### Invariant 4: Input Validation

```bash
# Check validation still present
grep -rn "validate_ip\|validate_cidr" bruteforce_detector/
grep -rn "ipaddress.ip_address" bruteforce_detector/
grep -rn "_sanitize_ip_for_nft" bruteforce_detector/managers/nftables_manager.py
```

#### Invariant 5: Database UPSERT Logic

```bash
# Check UPSERT patterns
grep -rn "ON CONFLICT.*DO UPDATE" bruteforce_detector/managers/database.py
grep -rn "BEGIN IMMEDIATE" bruteforce_detector/managers/database.py

# Check last_seen uses MAX (not COALESCE)
grep -n "last_seen = MAX" bruteforce_detector/managers/database.py
```

---

### 3.3 Integration Testing

```bash
# Full integration test
echo "
=== Integration Test: Full Detection Cycle ===

1. Start fresh
"
rm -rf ~/.local/share/tribanft/blacklist.db
rm -rf ~/.local/share/tribanft/blacklist_*.txt

echo "2. Run detection cycle"
tribanft --detect --verbose 2>&1 | head -50

echo "
3. Check blacklist"
tribanft --show-blacklist | head -10

echo "
4. Test IP add/remove cycle"
tribanft --blacklist-add 198.51.100.100 --reason "Integration test" --no-log-search
tribanft --query-ip 198.51.100.100
tribanft --blacklist-remove 198.51.100.100
tribanft --query-ip 198.51.100.100

echo "
5. Test whitelist"
tribanft --whitelist-add 192.0.2.1
tribanft --blacklist-add 192.0.2.1 --reason "Should fail" --no-log-search
# Expected: Whitelisted IP not added

echo "
6. Check NFTables sync (if enabled)"
if [ "$(sudo nft list sets 2>/dev/null | grep blacklist_ipv4)" ]; then
    sudo nft list set inet filter blacklist_ipv4 | head -20
fi

echo "
=== Integration Test Complete ===
"
```

---

## Section 4: Performance Testing

```bash
# Performance benchmarks
cat > /tmp/test_performance.py << 'EOF'
import sys
sys.path.insert(0, '/home/jc/Documents/projetos/tribanft')

from bruteforce_detector.managers.database import DatabaseManager
from bruteforce_detector.config import get_config
import time

config = get_config()
db_manager = DatabaseManager(config)

# Test 1: Bulk insert performance
print("Test 1: Bulk insert 1000 IPs")
start = time.time()
for i in range(1000):
    db_manager.add_ip(
        ip=f"192.0.2.{i % 256}",
        reason="Performance test",
        confidence="medium",
        first_seen=time.time(),
        last_seen=time.time(),
        event_count=1
    )
elapsed = time.time() - start
print(f"Time: {elapsed:.2f}s ({1000/elapsed:.1f} IPs/sec)")

# Test 2: Backup performance
print("\nTest 2: Database backup")
start = time.time()
backup_path = db_manager.backup()
elapsed = time.time() - start
print(f"Time: {elapsed:.2f}s")
print(f"Backup: {backup_path}")

# Test 3: Query performance
print("\nTest 3: Query 100 IPs")
start = time.time()
for i in range(100):
    db_manager.get_ip(f"192.0.2.{i}")
elapsed = time.time() - start
print(f"Time: {elapsed:.2f}s ({100/elapsed:.1f} queries/sec)")

print("\n✓ Performance tests complete")
EOF

python3 /tmp/test_performance.py
```

---

## Section 5: Final Checklist

### Pre-Deployment Checklist

- [ ] All syntax checks passed
- [ ] All import checks passed
- [ ] All fix-specific code reviews passed
- [ ] All functional tests passed
- [ ] All regression tests passed (Phase 1 fixes intact)
- [ ] All security invariants verified
- [ ] Integration tests passed
- [ ] Performance acceptable (no major degradation)
- [ ] No errors in logs during testing
- [ ] Documentation updated

### Test Results Summary

| Test | Status | Notes |
|------|--------|-------|
| Syntax/Import | ⏳ | |
| Fix #27 (Datetime) | ⏳ | |
| Fix #4 (Error Prop) | ⏳ | |
| Fix #9+#10 (IP Removal) | ⏳ | |
| Fix #26 (Singleton) | ⏳ | |
| Fix #14+#11 (Backup) | ⏳ | |
| Fix #21 (Parser Lock) | ⏳ | |
| Fix #13 (UPSERT) | ⏳ | |
| Fix #20 (Rate Limit) | ⏳ | |
| Regression (Phase 1) | ⏳ | |
| Security Invariants | ⏳ | |
| Integration | ⏳ | |
| Performance | ⏳ | |

---

## Section 6: Known Issues & Limitations

### Non-Critical Issues

1. **Fix #9 Performance**: Full NFTables update for single IP removal
   - **Impact**: Slower for large blacklists (>10k IPs)
   - **Mitigation**: Acceptable for manual operations
   - **Future**: Optimize with incremental updates

2. **Fix #14 Backup Timing**: Includes timestamp in filename
   - **Impact**: Multiple backups per day instead of one
   - **Mitigation**: Backup cleanup handles old backups
   - **Future**: Configurable backup naming

3. **Fix #20 State File**: I/O on every rate limit trigger
   - **Impact**: Minimal (only on rate limit exceeded)
   - **Mitigation**: Rare occurrence in normal operation
   - **Future**: Async state writes

### Testing Limitations

- Concurrent testing requires multiple processes (harder to automate)
- Real-time monitoring tests require actual log writes
- NFTables tests require sudo privileges
- Some tests require specific system state

---

## Section 7: Rollback Procedures

### Quick Rollback (All Phase 2 Fixes)

```bash
# Tag current state first
git tag phase2-tested-$(date +%Y%m%d)

# Identify commits to revert
git log --oneline --grep="Fix #" | head -9

# Revert all Phase 2 fixes
git revert HEAD~8..HEAD

# Or reset to before Phase 2
git reset --hard <commit-before-phase2>

# Restart service
sudo systemctl restart tribanft
```

### Individual Fix Rollback

```bash
# Find specific fix commit
git log --oneline --grep="Fix #27"

# Revert that commit
git revert <commit-hash>

# Restart service
sudo systemctl restart tribanft
```

---

## Section 8: Next Steps After Testing

### If Tests Pass ✅

1. Update CHANGELOG.md with all Phase 2 fixes
2. Create git tag: `v2.8.0-phase2-medium-complete`
3. Proceed with LOW priority fixes (16 remaining)
4. Final integration testing
5. Release v2.8.0

### If Tests Fail ❌

1. Document failure details
2. Analyze root cause
3. Fix issues
4. Re-test
5. Update implementation if needed

---

## Appendix: Quick Test Commands

```bash
# Run all basic checks
cd /home/jc/Documents/projetos/tribanft

echo "=== Syntax Checks ==="
find bruteforce_detector -name "*.py" -type f | xargs -I {} python3 -m py_compile {}

echo "=== Import Checks ==="
python3 -c "from bruteforce_detector.detectors.base import BaseDetector; print('✓ detectors OK')"
python3 -c "from bruteforce_detector.managers.nftables_manager import NFTablesManager; print('✓ nftables OK')"
python3 -c "from bruteforce_detector.managers.blacklist import BlacklistManager; print('✓ blacklist OK')"
python3 -c "from bruteforce_detector.parsers.base import BaseLogParser; print('✓ parsers OK')"
python3 -c "from bruteforce_detector.managers.database import DatabaseManager; print('✓ database OK')"

echo "=== Security Invariants ==="
grep -c "is_whitelisted" bruteforce_detector/managers/*.py
grep -c "threading.Lock()" bruteforce_detector/**/*.py
grep -c "ON CONFLICT" bruteforce_detector/managers/database.py

echo "=== Basic Functionality ==="
tribanft --show-blacklist | head -5
tribanft --show-whitelist | head -5

echo "=== All Checks Complete ==="
```

---

**END OF TESTING GUIDE**

**Status**: Ready for comprehensive testing
**Next**: Execute tests and document results
