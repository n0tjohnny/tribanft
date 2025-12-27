#!/usr/bin/env python3
"""
TribanFT Real-Time Service Diagnostic Tool

Checks all potential failure points in real-time log monitoring.

This diagnostic tool systematically checks:
1. Watchdog library availability
2. Log file configuration and accessibility
3. Detector enabled flags
4. Rate limiting configuration
5. Systemd service status
6. Application logs for errors

Author: TribanFT Project
License: GNU GPL v3
"""

import sys
import logging
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bruteforce_detector.config import get_config
from bruteforce_detector.core.log_watcher import WATCHDOG_AVAILABLE

def main():
    """Run comprehensive diagnostic checks on real-time service."""
    config = get_config()
    issues = []
    warnings = []

    print("=" * 70)
    print("TribanFT Real-Time Service Diagnostic")
    print("=" * 70)

    # CHECK 1: Watchdog library
    print("\n[1] Checking watchdog library...")
    if not WATCHDOG_AVAILABLE:
        issues.append("Watchdog library not installed")
        print("  ❌ FAILURE: Watchdog not available")
        print("  Fix: pip install watchdog>=3.0.0")
    else:
        try:
            import watchdog
            version = getattr(watchdog, '__version__', 'unknown')
            print(f"  ✓ OK: Watchdog {version} installed")
        except Exception as e:
            print(f"  ✓ OK: Watchdog installed (version check failed: {e})")

    # CHECK 2: Log files configured
    print("\n[2] Checking monitored log files...")
    monitored_count = 0

    if config.monitor_syslog:
        path = Path(config.syslog_path)
        if path.exists():
            print(f"  ✓ syslog: {path} (exists, {path.stat().st_size} bytes)")
            monitored_count += 1
        else:
            warnings.append(f"syslog enabled but file missing: {path}")
            print(f"  ⚠ syslog: {path} (MISSING)")

    if config.monitor_mssql:
        path = Path(config.mssql_error_log_path)
        if path.exists():
            print(f"  ✓ mssql: {path} (exists, {path.stat().st_size} bytes)")
            monitored_count += 1
        else:
            warnings.append(f"mssql enabled but file missing: {path}")
            print(f"  ⚠ mssql: {path} (MISSING)")

    if config.monitor_apache:
        if config.apache_access_log_path:
            path = Path(config.apache_access_log_path)
            if path.exists():
                print(f"  ✓ apache: {path} (exists, {path.stat().st_size} bytes)")
                monitored_count += 1
            else:
                warnings.append(f"apache enabled but file missing: {path}")
                print(f"  ⚠ apache: {path} (MISSING)")
        else:
            warnings.append("apache monitoring enabled but path not configured")
            print("  ⚠ apache: PATH NOT CONFIGURED")

    if config.monitor_nginx:
        if config.nginx_access_log_path:
            path = Path(config.nginx_access_log_path)
            if path.exists():
                print(f"  ✓ nginx: {path} (exists, {path.stat().st_size} bytes)")
                monitored_count += 1
            else:
                warnings.append(f"nginx enabled but file missing: {path}")
                print(f"  ⚠ nginx: {path} (MISSING)")
        else:
            warnings.append("nginx monitoring enabled but path not configured")
            print("  ⚠ nginx: PATH NOT CONFIGURED")

    if monitored_count == 0:
        issues.append("No log files available for monitoring")
        print("  ❌ FAILURE: No monitored log files exist")
    else:
        print(f"\n  ✓ Total monitored files: {monitored_count}")

    # CHECK 3: Detector enabled flags
    print("\n[3] Checking detector enabled flags...")
    if config.enable_prelogin_detection:
        print("  ✓ Prelogin detection: ENABLED")
    else:
        warnings.append("Prelogin detection disabled")
        print("  ⚠ Prelogin detection: DISABLED")

    if config.enable_failed_login_detection:
        print("  ✓ Failed login detection: ENABLED")
    else:
        warnings.append("Failed login detection disabled")
        print("  ⚠ Failed login detection: DISABLED")

    if config.enable_port_scan_detection:
        print("  ✓ Port scan detection: ENABLED")
    else:
        warnings.append("Port scan detection disabled")
        print("  ⚠ Port scan detection: DISABLED")

    # CHECK 4: Rate limiting config
    print("\n[4] Checking rate limiting configuration...")
    print(f"  max_events_per_second: {config.max_events_per_second}")
    print(f"  debounce_interval: {config.debounce_interval}s")
    print(f"  fallback_interval: {config.fallback_interval}s")

    # CHECK 5: Systemd service status
    print("\n[5] Checking systemd service...")
    import subprocess
    try:
        result = subprocess.run(
            ["systemctl", "status", "tribanft.service"],
            capture_output=True, text=True, timeout=5
        )
        if "active (running)" in result.stdout:
            print("  ✓ Service: RUNNING")
        elif "inactive" in result.stdout or "dead" in result.stdout:
            issues.append("Systemd service not running")
            print("  ❌ Service: NOT RUNNING")
            print("  Fix: sudo systemctl start tribanft.service")
        else:
            warnings.append("Cannot determine service status")
            print("  ⚠ Service: UNKNOWN")
    except Exception as e:
        warnings.append(f"Cannot check systemd: {e}")
        print(f"  ⚠ Cannot check systemd: {e}")

    # CHECK 6: Application logs
    print("\n[6] Checking application logs for errors...")
    # Application log is in state_dir/tribanft.log
    app_log = Path(config.state_dir) / 'tribanft.log'
    if app_log.exists():
        print(f"  ✓ Log file: {app_log}")
        # Read last 50 lines for errors
        try:
            with open(app_log, 'r') as f:
                lines = f.readlines()
                recent = lines[-50:] if len(lines) > 50 else lines

                error_keywords = [
                    "Watchdog library not available",
                    "No log files configured",
                    "Rate limit exceeded",
                    "No parser for modified file",
                    "Error processing file modification",
                    "Failed to initialize real-time"
                ]

                found_errors = []
                for line in recent:
                    for keyword in error_keywords:
                        if keyword in line:
                            found_errors.append(line.strip())
                            break

                if found_errors:
                    print(f"\n  ⚠ Found {len(found_errors)} relevant log entries:")
                    for err in found_errors[-5:]:  # Show last 5
                        print(f"    {err[:100]}...")
                else:
                    print("  ✓ No obvious errors in recent logs")
        except Exception as e:
            print(f"  ⚠ Cannot read log file: {e}")
    else:
        warnings.append(f"Application log not found: {app_log}")
        print(f"  ⚠ Log file not found: {app_log}")

    # SUMMARY
    print("\n" + "=" * 70)
    print("DIAGNOSTIC SUMMARY")
    print("=" * 70)

    if issues:
        print(f"\n❌ CRITICAL ISSUES ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")

    if warnings:
        print(f"\n⚠ WARNINGS ({len(warnings)}):")
        for i, warning in enumerate(warnings, 1):
            print(f"  {i}. {warning}")

    if not issues and not warnings:
        print("\n✓ All checks passed!")
        print("\nIf real-time detection still not working, check:")
        print("  1. Pattern files in bruteforce_detector/rules/parsers/")
        print("  2. Manual test: echo 'test log line' >> /var/log/syslog")
        print("  3. Application logs: tail -f", config.app_log_path)

    print("\n" + "=" * 70)
    return 0 if not issues else 1

if __name__ == "__main__":
    sys.exit(main())
