#!/bin/bash
#
# TribanFT Analysis Script
# Analyzes detection logs and provides tuning recommendations
#
# Usage: ./analyze_and_tune.sh [days]
#

set -euo pipefail

DAYS="${1:-7}"

# Check service
if ! systemctl is-active --quiet tribanft; then
    echo "Error: tribanft service not running"
    echo "Start with: sudo systemctl start tribanft"
    exit 1
fi

# Colors
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
NC='\033[0m'

log() { echo -e "${B}[INFO]${NC} $*"; }
ok() { echo -e "${G}[OK]${NC} $*"; }
warn() { echo -e "${Y}[WARN]${NC} $*"; }
err() { echo -e "${R}[ERROR]${NC} $*"; }

header() {
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "$1"
    echo "═══════════════════════════════════════════════════════════"
}

# Get logs
LOGS=$(sudo journalctl -u tribanft --since "$DAYS days ago" --no-pager 2>/dev/null)

header "TribanFT Analysis - Last $DAYS Days"
echo "Generated: $(date)"
echo "Host: $(hostname)"
echo

# 1. DETECTION SUMMARY
header "1. DETECTION SUMMARY"

BLOCKS=$(echo "$LOGS" | grep -c "Blocking " || echo "0")
echo "Total detections: $BLOCKS"

if [ "$BLOCKS" -eq 0 ]; then
    warn "No detections found"
    echo
    echo "Possible causes:"
    echo "  - No attacks (good!)"
    echo "  - Thresholds too high"
    echo "  - Parsers not finding events"
    echo "  - Service not running continuously"
    echo
    echo "Check: sudo journalctl -u tribanft | grep 'Parser.*found.*events'"
    exit 0
fi

AVG=$((BLOCKS / DAYS))
echo "Average: $AVG detections/day"
echo

if [ "$AVG" -gt 100 ]; then
    warn "High rate (>100/day) - possible false positives"
elif [ "$AVG" -lt 5 ]; then
    ok "Low rate (<5/day) - well-secured"
else
    ok "Normal rate (5-100/day)"
fi

# 2. TOP ATTACK TYPES
header "2. TOP ATTACK TYPES"

echo "$LOGS" | \
    grep "Blocking " | \
    grep -oP 'Blocking \S+ - \K[^-]+' | \
    sed 's/ *$//' | \
    sort | \
    uniq -c | \
    sort -rn | \
    head -10 | \
    awk '{printf "  %4d  %s\n", $1, substr($0, index($0,$2))}'

# 3. TOP BLOCKED IPs
header "3. TOP BLOCKED IPs"

echo "$LOGS" | \
    grep "Blocking " | \
    grep -oP 'Blocking \K[0-9.]+' | \
    sort | \
    uniq -c | \
    sort -rn | \
    head -10 | \
    while read -r count ip; do
        country=$(echo "$LOGS" | grep "Blocking $ip " | head -1 | grep -oP ' - \K[A-Z]{2}' || echo "??")
        printf "  %4d  %-15s  %s\n" "$count" "$ip" "$country"
    done

echo
log "Review suspicious IPs:"
echo "  tribanft --query-ip <IP>"
echo "  whois <IP>"
echo
log "Whitelist if legitimate:"
echo "  tribanft --whitelist-add <IP> --reason \"Description\""

# 4. DETECTION DISTRIBUTION
header "4. DETECTIONS BY HOUR (UTC)"

echo "$LOGS" | \
    grep "Blocking " | \
    awk '{print $3}' | \
    cut -d: -f1 | \
    sort | \
    uniq -c | \
    sort -k2 -n | \
    while read -r count hour; do
        bar=$(printf '█%.0s' $(seq 1 $((count / 2 + 1))))
        printf "  %02d:00  %4d  %s\n" "$hour" "$count" "$bar"
    done

# 5. SERVICE HEALTH
header "5. SERVICE HEALTH"

ERRORS=$(echo "$LOGS" | grep -ci "ERROR" || echo "0")
WARNINGS=$(echo "$LOGS" | grep -ci "WARNING" || echo "0")

echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"
echo

if [ "$ERRORS" -gt 0 ]; then
    warn "Found $ERRORS errors in logs"
    echo
    echo "Recent errors:"
    echo "$LOGS" | grep "ERROR" | tail -5
else
    ok "No errors"
fi

# 6. PARSER STATUS
header "6. PARSER STATUS"

echo "$LOGS" | grep "Parser.*found.*events" | tail -5

# 7. RECOMMENDATIONS
header "7. RECOMMENDATIONS"

# High detection rate
if [ "$AVG" -gt 100 ]; then
    echo "1. HIGH DETECTION RATE ($AVG/day)"
    echo "   Action: Increase thresholds by 50%"
    echo "   Example: threshold: 10 → threshold: 15"
    echo
fi

# Find dominant attack type
DOMINANT=$(echo "$LOGS" | \
    grep "Blocking " | \
    grep -oP 'Blocking \S+ - \K[^-]+' | \
    sed 's/ *$//' | \
    sort | \
    uniq -c | \
    sort -rn | \
    head -1)

DOM_COUNT=$(echo "$DOMINANT" | awk '{print $1}')
DOM_PCT=$((DOM_COUNT * 100 / BLOCKS))

if [ "$DOM_PCT" -gt 80 ]; then
    DOM_TYPE=$(echo "$DOMINANT" | awk '{$1=""; print substr($0,2)}')
    echo "2. SINGLE ATTACK TYPE DOMINANCE ($DOM_PCT%)"
    echo "   Type: $DOM_TYPE"
    echo "   Action: Review threshold for this detector"
    echo "   Files: ~/.local/share/tribanft/bruteforce_detector/rules/detectors/"
    echo
fi

# Repeated IPs
REPEATED=$(echo "$LOGS" | \
    grep "Blocking " | \
    grep -oP 'Blocking \K[0-9.]+' | \
    sort | \
    uniq -c | \
    awk '$1 > 3 {print}' | \
    wc -l)

if [ "$REPEATED" -gt 5 ]; then
    echo "3. REPEATED DETECTIONS"
    echo "   $REPEATED IPs detected multiple times"
    echo "   Action: Review top blocked IPs above"
    echo "   Consider: whitelist if legitimate OR increase ban duration"
    echo
fi

# 8. QUICK COMMANDS
header "8. QUICK COMMANDS"

cat << 'EOF'
# View current blacklist
tribanft --show-blacklist

# Check specific IP
tribanft --query-ip 1.2.3.4

# Whitelist IP
tribanft --whitelist-add 1.2.3.4 --reason "Monitoring server"

# Edit rule thresholds
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/my_rule.yaml

# Restart after changes
sudo systemctl restart tribanft

# Monitor live
sudo journalctl -u tribanft -f | grep "Blocking "
EOF

echo
header "ANALYSIS COMPLETE"
ok "Review recommendations above"
echo
echo "Next steps:"
echo "  1. Investigate top blocked IPs"
echo "  2. Adjust thresholds if needed"
echo "  3. Re-run analysis in 7 days"
echo
log "For detailed tuning: docs/MONITORING_AND_TUNING.md"
