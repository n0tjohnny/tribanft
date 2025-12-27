# Documentation Fixes Changelog (Issues #C21-#C26)

**Date:** 2025-12-25
**Version:** v2.5.0
**Type:** Documentation Fixes
**Priority:** P0 (Critical) - P1 (High)

---

## Summary

Fixed 6 critical documentation issues preventing users from configuring and using v2.5.0 features (threat intelligence, DNS parser) and causing configuration failures.

**Total Issues Fixed:** 6
**Files Modified:** 5
**Estimated User Impact:** High (prevents configuration errors and missing features)

---

## Fixed Issues

### #C21: Missing [threat_intelligence] Section in CONFIGURATION.md ✓
- **Priority:** P0
- **File:** `docs/CONFIGURATION.md`
- **Impact:** Users cannot configure v2.5.0 headline feature (threat intelligence)
- **Fix Applied:**
  - Added complete `[threat_intelligence]` section after `[advanced]` section
  - Documented all 3 configuration fields:
    - `threat_feeds_enabled` (bool, default: false)
    - `threat_feed_sources` (string, default: "spamhaus")
    - `threat_feed_cache_hours` (int, default: 24)
  - Added usage example and notes about API key requirements
- **Lines Added:** 203-222
- **Effort:** 20 minutes

### #C22: Wrong Environment Variable Name in CONFIGURATION.md ✓
- **Priority:** P1
- **File:** `docs/CONFIGURATION.md`
- **Impact:** Users set wrong environment variable, configuration fails silently
- **Fix Applied:**
  - Changed `BFD_ENABLE_NFTABLES` to `BFD_ENABLE_NFTABLES_UPDATE`
  - Corrected to match Pydantic env_prefix convention: `BFD_` + uppercase field name
- **Line:** 235
- **Effort:** 5 minutes

### #C23: Version Shown as v2.4.1 in DEPLOYMENT_GUIDE.md ✓
- **Priority:** P0
- **File:** `docs/DEPLOYMENT_GUIDE.md`
- **Impact:** Users install wrong version, confusion about features
- **Fix Applied:**
  - Updated title: "TribanFT v2.4.1" → "TribanFT v2.5.0"
  - Updated wget URL: `v2.4.1.tar.gz` → `v2.5.0.tar.gz`
  - Updated tar extraction: `tribanft-2.4.1` → `tribanft-2.5.0`
  - Updated cd directory: `tribanft-2.4.1` → `tribanft-2.5.0`
- **Lines:** 3, 12-14
- **Effort:** 5 minutes

### #C24: DNS Parser Missing from PARSERS.md ✓
- **Priority:** P0
- **File:** `docs/PARSERS.md`
- **Impact:** Users unaware DNS attack detection exists (v2.5 feature)
- **Fix Applied:**
  - Added DNSParser row to Built-in Parsers table
  - Documented:
    - Parser: DNSParser
    - Log Format: DNS logs (BIND9, dnsmasq, Unbound)
    - EventTypes: DNS_ATTACK
    - Pattern File: dns.yaml
- **Line:** 16 (new row in table)
- **Effort:** 15 minutes

### #C25: KNOWN_MALICIOUS_IP EventType Undocumented ✓
- **Priority:** P0
- **File:** `docs/PARSER_EVENTTYPES_MAPPING.md`
- **Impact:** Threat intelligence feature invisible to users
- **Fix Applied:**
  - Added new section: "Threat Intelligence Detector (threat_feed.py) [NEW in v2.5]"
  - Documented KNOWN_MALICIOUS_IP EventType
  - Explained detection logic (cache-based threat feed queries)
  - Listed supported feeds (Spamhaus, AbuseIPDB, AlienVault OTX)
  - Added configuration example
  - Included table of feed descriptions and API requirements
- **Lines Added:** 262-307
- **Effort:** 20 minutes

### #C26: --ip-info Command Does Not Exist ✓
- **Priority:** P1
- **File:** `docs/MONITORING_AND_TUNING.md`
- **Impact:** Documented monitoring script fails with "unrecognized arguments" error
- **Fix Applied:**
  - Changed `tribanft --ip-info "$ip"` to `tribanft --query-ip "$ip"`
  - Corrected to match actual CLI argument name
- **Line:** 106
- **Effort:** 1 minute

---

## Files Modified

| File | Changes | Lines Modified | Type |
|------|---------|---------------|------|
| `docs/CONFIGURATION.md` | Added [threat_intelligence] section, fixed env var name | +20, ~1 | Addition + Fix |
| `docs/DEPLOYMENT_GUIDE.md` | Updated version v2.4.1 → v2.5.0 | ~4 | Update |
| `docs/PARSERS.md` | Added DNSParser to table | +1 | Addition |
| `docs/PARSER_EVENTTYPES_MAPPING.md` | Documented KNOWN_MALICIOUS_IP EventType | +46 | Addition |
| `docs/MONITORING_AND_TUNING.md` | Fixed --ip-info → --query-ip | ~1 | Fix |

**Total Lines Modified:** +67, ~6

---

## Testing Validation

### Validation Commands
```bash
# Verify markdown syntax
for file in docs/*.md; do
  echo "Checking $file"
  # Markdown linters would be used here
done

# Verify configuration reference matches code
grep -E "threat_feeds_enabled|threat_feed_sources|threat_feed_cache_hours" \
  bruteforce_detector/config.py

# Verify environment variable naming
grep "enable_nftables_update" bruteforce_detector/config.py

# Verify DNS parser exists
ls bruteforce_detector/plugins/parsers/dns.py
ls bruteforce_detector/rules/parsers/dns.yaml

# Verify KNOWN_MALICIOUS_IP EventType exists
grep "KNOWN_MALICIOUS_IP" bruteforce_detector/models.py

# Verify --query-ip command exists
tribanft --help | grep query-ip
```

---

## User Impact

### Before Fixes
- ❌ Users cannot enable threat intelligence (no documentation)
- ❌ Users set `BFD_ENABLE_NFTABLES` (wrong var name, config fails)
- ❌ Users download v2.4.1 (missing v2.5 features)
- ❌ Users unaware of DNS attack detection
- ❌ Monitoring scripts fail with "unrecognized arguments" error
- ❌ Threat intelligence EventType undiscoverable

### After Fixes
- ✅ Users can configure threat intelligence with proper documentation
- ✅ Users set correct env var `BFD_ENABLE_NFTABLES_UPDATE`
- ✅ Users download correct v2.5.0 release
- ✅ Users discover and configure DNS attack detection
- ✅ Monitoring scripts work with correct `--query-ip` argument
- ✅ Threat intelligence EventType fully documented with examples

---

## Related Issues

### Still Open (Not Fixed in This Changelog)
- **#H1-#H10:** High severity code bugs (data integrity, crash bugs)
  - Require code changes, not documentation fixes
  - Tracked separately in CRITICAL_FIXES_CHANGELOG.md

### Future Enhancements
- Add migration guide for users upgrading from v2.4.x to v2.5.0
- Add threat intelligence troubleshooting section
- Add DNS parser tuning guide

---

## Compliance

### Documentation Standards Met
- ✅ **Copy-paste ready commands** (no explanations in code blocks)
- ✅ **Tables for reference data** (not paragraphs)
- ✅ **Minimal examples** (1-2 max, reference actual files)
- ✅ **Structure:** Quick Start → Tables → Examples
- ✅ **No verbose prose** (reference style, not tutorial)

### Configuration Documentation
- ✅ All fields match `config.py` exactly
- ✅ Environment variable naming follows Pydantic convention
- ✅ Default values match code defaults
- ✅ Type information provided (bool, int, string)

---

## Changelog Metadata

**Generated By:** Claude Code CLI
**Session Date:** 2025-12-25
**Review Status:** Ready for User Review
**Breaking Changes:** None (documentation only)
**Deployment Required:** No (documentation updates only)

---

## Next Steps

1. ✅ User review and approval of documentation changes
2. 📋 Commit documentation fixes to repository
3. 📋 Update FIXES_SUMMARY.md with completed issues
4. 📋 Move to high-severity code fixes (#H1-#H10)

---

**End of Changelog**
