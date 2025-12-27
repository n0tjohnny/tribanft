#!/bin/bash
# TribanFT Phase 2 Fixes - Automated Verification Script
# Date: 2025-12-27
# Version: v2.8.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

function print_header() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
}

function test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

function test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
}

function test_warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
    ((WARN++))
}

print_header "TribanFT Phase 2 - Automated Verification"
echo "Date: $(date)"
echo "Project: $PROJECT_ROOT"
echo ""

# =============================================================================
# Section 1: Syntax and Import Checks
# =============================================================================

print_header "Section 1: Syntax and Import Checks"

echo "Checking Python syntax..."
SYNTAX_ERRORS=0

for file in bruteforce_detector/detectors/base.py \
            bruteforce_detector/managers/nftables_manager.py \
            bruteforce_detector/managers/blacklist.py \
            bruteforce_detector/parsers/base.py \
            bruteforce_detector/managers/database.py \
            bruteforce_detector/core/realtime_engine.py \
            bruteforce_detector/core/log_watcher.py; do
    if python3 -m py_compile "$file" 2>/dev/null; then
        test_pass "Syntax OK: $file"
    else
        test_fail "Syntax error: $file"
        ((SYNTAX_ERRORS++))
    fi
done

if [ $SYNTAX_ERRORS -eq 0 ]; then
    test_pass "All files have valid Python syntax"
else
    test_fail "$SYNTAX_ERRORS files have syntax errors"
    exit 1
fi

echo ""
echo "Checking imports..."

if python3 -c "from bruteforce_detector.detectors.base import BaseDetector" 2>/dev/null; then
    test_pass "detectors/base.py imports OK"
else
    test_fail "detectors/base.py import failed"
fi

if python3 -c "from bruteforce_detector.managers.nftables_manager import NFTablesManager" 2>/dev/null; then
    test_pass "nftables_manager.py imports OK"
else
    test_fail "nftables_manager.py import failed"
fi

if python3 -c "from bruteforce_detector.managers.blacklist import BlacklistManager" 2>/dev/null; then
    test_pass "blacklist.py imports OK"
else
    test_fail "blacklist.py import failed"
fi

if python3 -c "from bruteforce_detector.parsers.base import BaseLogParser" 2>/dev/null; then
    test_pass "parsers/base.py imports OK"
else
    test_fail "parsers/base.py import failed"
fi

if python3 -c "from bruteforce_detector.managers.database import DatabaseManager" 2>/dev/null; then
    test_pass "database.py imports OK"
else
    test_fail "database.py import failed"
fi

if python3 -c "from bruteforce_detector.core.realtime_engine import RealtimeDetectionMixin" 2>/dev/null; then
    test_pass "realtime_engine.py imports OK"
else
    test_fail "realtime_engine.py import failed"
fi

if python3 -c "from bruteforce_detector.core.log_watcher import LogWatcher" 2>/dev/null; then
    test_pass "log_watcher.py imports OK"
else
    test_fail "log_watcher.py import failed"
fi

# =============================================================================
# Section 2: Fix-Specific Code Verification
# =============================================================================

print_header "Section 2: Fix-Specific Code Verification"

# Fix #27: Naive Datetime
echo "Checking Fix #27 (Naive Datetime)..."
if grep -q "from datetime import datetime, timezone" bruteforce_detector/detectors/base.py; then
    test_pass "Fix #27: timezone import present"
else
    test_fail "Fix #27: timezone import missing"
fi

if grep -q "datetime.now(timezone.utc)" bruteforce_detector/detectors/base.py; then
    test_pass "Fix #27: timezone-aware datetime used"
else
    test_fail "Fix #27: timezone-aware datetime not used"
fi

# Fix #4: Error Propagation
echo ""
echo "Checking Fix #4 (Error Propagation)..."
if grep -A1 "ERROR: NFTables update failed" bruteforce_detector/managers/nftables_manager.py | grep -q "raise"; then
    test_pass "Fix #4: Exception re-raised"
else
    test_fail "Fix #4: Exception not re-raised"
fi

# Fix #9 + #10: IP Removal
echo ""
echo "Checking Fix #9 + #10 (IP Removal Consistency)..."
if grep -q "TWO-PHASE COMMIT" bruteforce_detector/managers/blacklist.py; then
    test_pass "Fix #9: Two-phase commit pattern present"
else
    test_fail "Fix #9: Two-phase commit pattern missing"
fi

if grep -q "self.nft_sync.update_blacklists" bruteforce_detector/managers/blacklist.py; then
    test_pass "Fix #10: Uses existing NFTables instance"
else
    test_fail "Fix #10: NFTables instance usage not found"
fi

# Check that duplicate instance creation is removed
if grep "remove_ip" -A30 bruteforce_detector/managers/blacklist.py | grep -q "NFTablesSync("; then
    test_fail "Fix #10: Duplicate NFTablesSync instance still created"
else
    test_pass "Fix #10: No duplicate NFTablesSync instance"
fi

# Fix #26: Parser Singleton
echo ""
echo "Checking Fix #26 (Parser Singleton Thread Safety)..."
if grep -q "import threading" bruteforce_detector/parsers/base.py; then
    test_pass "Fix #26: threading module imported"
else
    test_fail "Fix #26: threading module not imported"
fi

if grep -q "_pattern_loader_lock = threading.Lock()" bruteforce_detector/parsers/base.py; then
    test_pass "Fix #26: Pattern loader lock declared"
else
    test_fail "Fix #26: Pattern loader lock not declared"
fi

if grep -q "with BaseLogParser._pattern_loader_lock:" bruteforce_detector/parsers/base.py; then
    test_pass "Fix #26: Double-checked locking pattern present"
else
    test_fail "Fix #26: Double-checked locking pattern missing"
fi

# Fix #14 + #11: Backup Atomic
echo ""
echo "Checking Fix #14 + #11 (Backup Atomic + Datetime)..."
if grep -q "source.backup" bruteforce_detector/managers/database.py; then
    test_pass "Fix #14: SQLite backup API used"
else
    test_fail "Fix #14: SQLite backup API not used"
fi

if grep -q "PRAGMA integrity_check" bruteforce_detector/managers/database.py; then
    test_pass "Fix #14: Integrity check present"
else
    test_fail "Fix #14: Integrity check missing"
fi

if grep -q "_backup_progress" bruteforce_detector/managers/database.py; then
    test_pass "Fix #14: Backup progress callback present"
else
    test_fail "Fix #14: Backup progress callback missing"
fi

# Fix #21: Parser Reuse
echo ""
echo "Checking Fix #21 (Parser Reuse Thread Safety)..."
if grep -q "self.parser_locks" bruteforce_detector/core/realtime_engine.py; then
    test_pass "Fix #21: Parser locks dictionary present"
else
    test_fail "Fix #21: Parser locks dictionary missing"
fi

if grep "lock.acquire()" bruteforce_detector/core/realtime_engine.py | grep -q "_on_log_file_modified" -B5; then
    test_pass "Fix #21: Lock acquired in callback"
else
    test_warn "Fix #21: Lock acquisition pattern may have changed"
fi

if grep "lock.release()" bruteforce_detector/core/realtime_engine.py | grep -q "finally" -B3; then
    test_pass "Fix #21: Lock released in finally block"
else
    test_warn "Fix #21: Lock release pattern may have changed"
fi

# Fix #13: UPSERT Metadata
echo ""
echo "Checking Fix #13 (UPSERT Metadata Preservation)..."
if grep -q "FIX #13" bruteforce_detector/managers/database.py; then
    test_pass "Fix #13: Fix comment present"
else
    test_warn "Fix #13: Fix comment missing (code may still be correct)"
fi

if grep -q "COALESCE(reason, excluded.reason)" bruteforce_detector/managers/database.py; then
    test_pass "Fix #13: UPSERT preserves original reason"
else
    test_fail "Fix #13: UPSERT pattern incorrect for reason"
fi

if grep -q "COALESCE(confidence, excluded.confidence)" bruteforce_detector/managers/database.py; then
    test_pass "Fix #13: UPSERT preserves original confidence"
else
    test_fail "Fix #13: UPSERT pattern incorrect for confidence"
fi

if grep -q "COALESCE(source, excluded.source)" bruteforce_detector/managers/database.py; then
    test_pass "Fix #13: UPSERT preserves original source"
else
    test_fail "Fix #13: UPSERT pattern incorrect for source"
fi

# Fix #20: Rate Limit Persistence
echo ""
echo "Checking Fix #20 (Rate Limit State Persistence)..."
if grep -q "import json" bruteforce_detector/core/log_watcher.py && \
   grep -q "import tempfile" bruteforce_detector/core/log_watcher.py; then
    test_pass "Fix #20: Required modules imported"
else
    test_fail "Fix #20: Missing json or tempfile imports"
fi

if grep -q "_load_rate_limit_state" bruteforce_detector/core/log_watcher.py; then
    test_pass "Fix #20: Load state method present"
else
    test_fail "Fix #20: Load state method missing"
fi

if grep -q "_save_rate_limit_state" bruteforce_detector/core/log_watcher.py; then
    test_pass "Fix #20: Save state method present"
else
    test_fail "Fix #20: Save state method missing"
fi

if grep "_check_rate_limit" -A20 bruteforce_detector/core/log_watcher.py | grep -q "_save_rate_limit_state"; then
    test_pass "Fix #20: State saved on rate limit trigger"
else
    test_fail "Fix #20: State not saved on rate limit"
fi

# =============================================================================
# Section 3: Security Invariants
# =============================================================================

print_header "Section 3: Security Invariants Verification"

echo "Checking Invariant 1: Whitelist Precedence..."
WHITELIST_CHECKS=$(grep -r "is_whitelisted" bruteforce_detector/managers/*.py | wc -l)
if [ "$WHITELIST_CHECKS" -ge 3 ]; then
    test_pass "Invariant 1: Whitelist checks present ($WHITELIST_CHECKS locations)"
else
    test_warn "Invariant 1: Few whitelist checks found ($WHITELIST_CHECKS)"
fi

echo ""
echo "Checking Invariant 2: Atomic Operations..."
LOCK_COUNT=$(grep -r "with.*_update_lock" bruteforce_detector/managers/*.py | wc -l)
TRANSACTION_COUNT=$(grep -r "BEGIN IMMEDIATE" bruteforce_detector/managers/*.py | wc -l)
ATOMIC_WRITE_COUNT=$(grep -r "os.replace" bruteforce_detector/ | wc -l)

if [ "$LOCK_COUNT" -ge 3 ]; then
    test_pass "Invariant 2: Update locks present ($LOCK_COUNT locations)"
else
    test_warn "Invariant 2: Few update locks ($LOCK_COUNT)"
fi

if [ "$TRANSACTION_COUNT" -ge 1 ]; then
    test_pass "Invariant 2: Database transactions present ($TRANSACTION_COUNT)"
else
    test_warn "Invariant 2: No explicit transactions found"
fi

if [ "$ATOMIC_WRITE_COUNT" -ge 3 ]; then
    test_pass "Invariant 2: Atomic file writes present ($ATOMIC_WRITE_COUNT)"
else
    test_warn "Invariant 2: Few atomic writes ($ATOMIC_WRITE_COUNT)"
fi

echo ""
echo "Checking Invariant 3: Thread Safety..."
TOTAL_LOCKS=$(find bruteforce_detector -name "*.py" -exec grep -l "threading.Lock()" {} \; | wc -l)
if [ "$TOTAL_LOCKS" -ge 5 ]; then
    test_pass "Invariant 3: Thread safety locks present ($TOTAL_LOCKS files)"
else
    test_warn "Invariant 3: Few lock declarations ($TOTAL_LOCKS files)"
fi

echo ""
echo "Checking Invariant 4: Input Validation..."
VALIDATION_COUNT=$(grep -r "validate_ip\|validate_cidr\|ipaddress.ip_address" bruteforce_detector/ | wc -l)
if [ "$VALIDATION_COUNT" -ge 10 ]; then
    test_pass "Invariant 4: Input validation present ($VALIDATION_COUNT locations)"
else
    test_warn "Invariant 4: Limited validation found ($VALIDATION_COUNT)"
fi

echo ""
echo "Checking Invariant 5: Database UPSERT Logic..."
if grep -q "ON CONFLICT.*DO UPDATE" bruteforce_detector/managers/database.py; then
    test_pass "Invariant 5: UPSERT logic present"
else
    test_fail "Invariant 5: UPSERT logic missing"
fi

if grep -q "last_seen = MAX" bruteforce_detector/managers/database.py; then
    test_pass "Invariant 5: Uses MAX for last_seen (not COALESCE)"
else
    test_fail "Invariant 5: last_seen not using MAX"
fi

# =============================================================================
# Section 4: Phase 1 Regression Check
# =============================================================================

print_header "Section 4: Phase 1 Regression Check"

echo "Checking Phase 1 fixes still present..."

# Fix #1: NFTables lock
if grep -q "_nftables_lock" bruteforce_detector/managers/nftables_manager.py; then
    test_pass "Phase 1 Fix #1: NFTables lock present"
else
    test_fail "Phase 1 Fix #1: NFTables lock missing"
fi

# Fix #2: Whitelist defense-in-depth
if grep "update_blacklists" -A30 bruteforce_detector/managers/nftables_manager.py | grep -q "is_whitelisted"; then
    test_pass "Phase 1 Fix #2: Whitelist defense-in-depth present"
else
    test_fail "Phase 1 Fix #2: Whitelist defense-in-depth missing"
fi

# Fix #3: NFTables sets validation
if grep -q "_validate_nftables_sets" bruteforce_detector/managers/nftables_manager.py; then
    test_pass "Phase 1 Fix #3: NFTables sets validation present"
else
    test_fail "Phase 1 Fix #3: NFTables sets validation missing"
fi

# Fix #34: Whitelist reload
if grep -q "def reload" bruteforce_detector/managers/whitelist.py; then
    test_pass "Phase 1 Fix #34: Whitelist reload method present"
else
    test_fail "Phase 1 Fix #34: Whitelist reload method missing"
fi

# Fix #35: Signal handlers
if grep -q "SIGTERM\|SIGINT" bruteforce_detector/main.py; then
    test_pass "Phase 1 Fix #35: Signal handlers present"
else
    test_fail "Phase 1 Fix #35: Signal handlers missing"
fi

# =============================================================================
# Final Summary
# =============================================================================

print_header "Verification Summary"

TOTAL=$((PASS + FAIL + WARN))
echo "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo -e "${YELLOW}Warnings: $WARN${NC}"

echo ""
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ ALL CRITICAL CHECKS PASSED${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Run functional tests (see audit-phase2-testing-guide.md Section 2)"
    echo "2. Run integration tests (see audit-phase2-testing-guide.md Section 3)"
    echo "3. Review warnings and address if needed"
    exit 0
else
    echo -e "${RED}✗ $FAIL CRITICAL CHECK(S) FAILED${NC}"
    echo ""
    echo "Review failed checks above before proceeding."
    echo "See audit-phase2-testing-guide.md for detailed testing procedures."
    exit 1
fi
