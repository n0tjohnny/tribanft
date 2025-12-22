#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# TribanFT Log Analysis & Threshold Tuning Helper
# ═══════════════════════════════════════════════════════════════════════════
#
# Analyzes TribanFT logs and provides threshold tuning recommendations.
#
# Usage:
#   ./analyze_and_tune.sh [days]
#
# Examples:
#   ./analyze_and_tune.sh        # Analyze last 7 days
#   ./analyze_and_tune.sh 30     # Analyze last 30 days
#   ./analyze_and_tune.sh 1      # Analyze today only
#
# Author: TribanFT Project
# License: GNU GPL v3
#
# ═══════════════════════════════════════════════════════════════════════════

set -e

# Configuration
DAYS="${1:-7}"
REPORT_DIR="$HOME/tribanft_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/analysis_$TIMESTAMP.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create report directory
mkdir -p "$REPORT_DIR"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

header() {
    echo
    echo "═══════════════════════════════════════════════════════════════"
    echo "$1"
    echo "═══════════════════════════════════════════════════════════════"
    echo
}

# Check if tribanft service exists
if ! systemctl list-units --type=service | grep -q tribanft; then
    log_error "TribanFT service not found. Is it installed?"
    exit 1
fi

# Start analysis
clear
header "TribanFT Log Analysis & Tuning Helper"
log_info "Analyzing last $DAYS days of TribanFT logs..."
log_info "Report will be saved to: $REPORT_FILE"
echo

# Execute analysis and save to file
exec > >(tee -a "$REPORT_FILE")

echo "TribanFT Log Analysis Report"
echo "Generated: $(date)"
echo "Analysis Period: Last $DAYS days"
echo "System: $(hostname)"
echo

# ═══════════════════════════════════════════════════════════════════════════
# 1. DETECTION SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
header "1. DETECTION SUMMARY"

total_detections=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep -c "Blacklisted" || echo "0")

echo "Total Detections: $total_detections"

if [ "$total_detections" -eq 0 ]; then
    log_warning "No detections found in the last $DAYS days"
    log_info "This could mean:"
    echo "  - No attacks detected (good!)"
    echo "  - Detection thresholds too high"
    echo "  - Parsers not working correctly"
    echo "  - Service not running continuously"
    echo
    echo "Recommendation: Check service status and logs"
    exit 0
fi

# Detections per day
echo
echo "Detections per day:"
sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted" | \
    awk '{print $1}' | \
    sort | \
    uniq -c | \
    awk '{printf "  %s: %s detections\n", $2, $1}'

# Average per day
avg_per_day=$(echo "$total_detections / $DAYS" | bc)
echo
echo "Average: ~$avg_per_day detections/day"

if [ "$avg_per_day" -gt 100 ]; then
    log_warning "High detection rate (>100/day)"
    echo "  → May indicate:"
    echo "    - Active attack campaign"
    echo "    - Thresholds too low (false positives)"
    echo "    - Misconfigured applications generating auth failures"
elif [ "$avg_per_day" -lt 5 ]; then
    log_info "Low detection rate (<5/day)"
    echo "  → This is normal for well-secured environments"
else
    log_success "Normal detection rate (5-100/day)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 2. DETECTION BY RULE/DETECTOR
# ═══════════════════════════════════════════════════════════════════════════
header "2. DETECTIONS BY RULE/DETECTOR"

echo "Top detection sources:"
sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted" | \
    sed 's/.*(\([^:]*\):.*/\1/' | \
    sort | \
    uniq -c | \
    sort -rn | \
    head -10 | \
    awk '{printf "  %3d  %s\n", $1, $2}'

echo
echo "YAML Rule Engine performance:"
yaml_detections=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "YAML Rule Engine found.*detection" | \
    awk '{sum+=$NF} END {print sum+0}')

echo "  Total YAML rule detections: $yaml_detections"

if [ "$yaml_detections" -gt 0 ]; then
    echo
    echo "  Top YAML rules:"
    sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
        grep "Rule '.*' found.*detection" | \
        sed "s/.*Rule '\([^']*\)' found \([0-9]*\).*/\2 \1/" | \
        awk '{a[$2]+=$1} END {for(i in a) print a[i], i}' | \
        sort -rn | \
        head -5 | \
        awk '{printf "    %3d  %s\n", $1, $2}'
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. TOP BLOCKED IPs
# ═══════════════════════════════════════════════════════════════════════════
header "3. TOP BLOCKED IPs"

echo "Most frequently detected IPs:"
sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted" | \
    awk '{print $9}' | \
    sed 's/[^0-9.]//g' | \
    sort | \
    uniq -c | \
    sort -rn | \
    head -10 | \
    while read count ip; do
        # Try to get country info
        country=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
            grep "$ip" | \
            grep -oP 'Country: \K[^,)]+' | \
            head -1 || echo "Unknown")
        printf "  %3d  %-15s  %s\n" "$count" "$ip" "$country"
    done

echo
log_info "Check if any of these IPs are legitimate services:"
echo "  Use: tribanft --ip-info <IP>"
echo "  Use: whois <IP>"
echo
echo "If legitimate, add to whitelist:"
echo "  tribanft --whitelist-add <IP> --reason \"Service description\""

# ═══════════════════════════════════════════════════════════════════════════
# 4. EVENT COUNT DISTRIBUTION
# ═══════════════════════════════════════════════════════════════════════════
header "4. EVENT COUNT DISTRIBUTION"

echo "How many events triggered each detection:"
sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted.*attempts" | \
    sed 's/.*- \([0-9]*\) attempts.*/\1/' | \
    sort -n | \
    awk '{
        count[$1]++
    }
    END {
        for (events in count) {
            printf "  %3d events: %3d detections\n", events, count[events]
        }
    }' | \
    sort -n

echo
echo "Statistics:"
events=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted.*attempts" | \
    sed 's/.*- \([0-9]*\) attempts.*/\1/')

if [ ! -z "$events" ]; then
    min_events=$(echo "$events" | sort -n | head -1)
    max_events=$(echo "$events" | sort -n | tail -1)
    avg_events=$(echo "$events" | awk '{sum+=$1; n++} END {print int(sum/n)}')

    echo "  Minimum events: $min_events"
    echo "  Maximum events: $max_events"
    echo "  Average events: $avg_events"

    echo
    if [ "$min_events" -eq "$max_events" ]; then
        log_warning "All detections triggered at exactly threshold"
        echo "  → Threshold might be too high"
        echo "  → Consider lowering threshold by 20-30%"
    elif [ "$min_events" -lt 15 ]; then
        log_info "Most detections near threshold (good tuning)"
    else
        log_info "Detections well above threshold"
        echo "  → Threshold could be increased slightly if false positives occur"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. TIME DISTRIBUTION
# ═══════════════════════════════════════════════════════════════════════════
header "5. TIME DISTRIBUTION"

echo "Detections by hour of day (UTC):"
sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted" | \
    awk '{print $3}' | \
    cut -d: -f1 | \
    sort | \
    uniq -c | \
    sort -k2 -n | \
    while read count hour; do
        # Create simple bar chart
        bar=$(printf '█%.0s' $(seq 1 $((count / 2))))
        printf "  %02d:00  %3d  %s\n" "$hour" "$count" "$bar"
    done

echo
log_info "Use this to identify:"
echo "  - Peak attack times"
echo "  - Potential legitimate burst traffic periods"
echo "  - Scheduled tasks that may cause false positives"

# ═══════════════════════════════════════════════════════════════════════════
# 6. POTENTIAL FALSE POSITIVES
# ═══════════════════════════════════════════════════════════════════════════
header "6. POTENTIAL FALSE POSITIVES"

echo "IPs with detections exactly at threshold (may be borderline):"
# Get most common thresholds from config
common_thresholds="10 15 20"

found_borderline=0
for threshold in $common_thresholds; do
    borderline=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
        grep "Blacklisted.*- $threshold attempts" | \
        awk '{print $9}' | \
        sed 's/[^0-9.]//g' | \
        sort -u)

    if [ ! -z "$borderline" ]; then
        echo
        echo "At threshold=$threshold:"
        echo "$borderline" | while read ip; do
            reason=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
                grep "Blacklisted $ip" | \
                head -1 | \
                sed 's/.*(\(.*\))/\1/')
            echo "  $ip - $reason"
        done
        found_borderline=1
    fi
done

if [ "$found_borderline" -eq 0 ]; then
    log_success "No borderline detections found"
else
    echo
    log_warning "Review these IPs manually"
    echo "  Commands:"
    echo "    tribanft --ip-info <IP>       # Check geolocation and ISP"
    echo "    whois <IP>                    # Get registration info"
    echo "    grep <IP> /var/log/...        # Check original logs"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 7. RECOMMENDATIONS
# ═══════════════════════════════════════════════════════════════════════════
header "7. TUNING RECOMMENDATIONS"

# Analyze and provide recommendations
echo "Based on analysis:"
echo

# Check detection rate
if [ "$avg_per_day" -gt 100 ]; then
    echo "1. HIGH DETECTION RATE"
    echo "   Current: $avg_per_day detections/day"
    echo "   Action: Consider increasing thresholds by 50%"
    echo "   Example: threshold: 10 → threshold: 15"
    echo
fi

# Check if all detections are from one rule
dominant_rule=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted" | \
    sed 's/.*(\([^:]*\):.*/\1/' | \
    sort | \
    uniq -c | \
    sort -rn | \
    head -1)

dominant_count=$(echo "$dominant_rule" | awk '{print $1}')
dominant_name=$(echo "$dominant_rule" | awk '{print $2}')
dominant_pct=$((dominant_count * 100 / total_detections))

if [ "$dominant_pct" -gt 80 ]; then
    echo "2. SINGLE RULE DOMINANCE"
    echo "   Rule: $dominant_name ($dominant_pct% of detections)"
    echo "   Action: Review this rule's threshold and patterns"
    echo "   File: ~/.local/share/tribanft/bruteforce_detector/rules/detectors/*.yaml"
    echo "   Or: ~/.local/share/tribanft/bruteforce_detector/plugins/detectors/$dominant_name.py"
    echo
fi

# Check for repeated IPs
repeated_ips=$(sudo journalctl -u tribanft --since "$DAYS days ago" 2>/dev/null | \
    grep "Blacklisted" | \
    awk '{print $9}' | \
    sed 's/[^0-9.]//g' | \
    sort | \
    uniq -c | \
    awk '$1 > 3 {print}' | \
    wc -l)

if [ "$repeated_ips" -gt 5 ]; then
    echo "3. REPEATED DETECTIONS"
    echo "   $repeated_ips IPs detected multiple times"
    echo "   Action: Either persistent attacks OR false positives"
    echo "   Check: Review top blocked IPs above"
    echo "   Consider:"
    echo "     - Whitelist if legitimate"
    echo "     - Increase threshold if too sensitive"
    echo "     - Longer NFTables ban time if real attacks"
    echo
fi

# ═══════════════════════════════════════════════════════════════════════════
# 8. QUICK ACTIONS
# ═══════════════════════════════════════════════════════════════════════════
header "8. QUICK ACTIONS"

echo "Useful commands for next steps:"
echo
echo "# View current blacklist"
echo "tribanft --show-blacklist"
echo
echo "# Check specific IP details"
echo "tribanft --ip-info 1.2.3.4"
echo
echo "# Whitelist an IP"
echo "tribanft --whitelist-add 1.2.3.4 --reason \"Monitoring server\""
echo
echo "# View whitelist"
echo "tribanft --show-whitelist"
echo
echo "# Edit YAML rules"
echo "vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/my_rule.yaml"
echo
echo "# Restart after changes"
echo "sudo systemctl restart tribanft"
echo
echo "# Monitor live"
echo "sudo journalctl -u tribanft -f | grep detection"
echo

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
header "ANALYSIS COMPLETE"

log_success "Report saved to: $REPORT_FILE"
echo
echo "Next steps:"
echo "  1. Review recommendations above"
echo "  2. Investigate top blocked IPs"
echo "  3. Adjust thresholds if needed"
echo "  4. Re-run analysis in 7 days"
echo
log_info "For detailed tuning guide, see: MONITORING_AND_TUNING.md"
