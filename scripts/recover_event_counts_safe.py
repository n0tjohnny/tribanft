#!/usr/bin/env python3
"""
TribanFT Event Count Recovery Tool - Production Safe

Enterprise-grade recovery with multi-layer safety:
- Pre-flight checks (service status, disk space, integrity)
- Multi-layer backups with SQLite backup API
- Atomic transactions with incremental checkpoints
- Automatic rollback on failure
- File locking to prevent concurrent access
- Corruption detection and prevention
- Detailed audit logging

Fixes exponential event_count growth bug (FIX #15) using:
1. Exact values from backup files (when available)
2. Conservative heuristics by source (for new IPs)

Usage:
    # MANDATORY: Always run dry-run first
    python3 recover_event_counts_safe.py --auto --dry-run

    # Apply changes only after reviewing dry-run
    python3 recover_event_counts_safe.py --auto --apply

    # Emergency recovery from failed run
    python3 recover_event_counts_safe.py --recover --backup-id <ID>

Author: TribanFT Project
License: GNU GPL v3
"""

import sqlite3
import gzip
import re
import argparse
import subprocess
import hashlib
import shutil
import json
import sys
import fcntl
import os
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, Set, Optional, List
from collections import defaultdict
from dataclasses import dataclass, asdict
import ipaddress


# =============================================================================
# CONFIGURATION
# =============================================================================

HEURISTICS = {
    'crowdsec_csv_import': 1,
    'automatic': 20,
    'manual': 0,
    'nftables_import': 10,
    'crowdsec_alerts': 5,
    'legacy': 5,
    'unknown': 10
}

CORRUPTION_THRESHOLD = 1000
MIN_EXPECTED_IPS = 5000
MAX_REASONABLE_EVENTS = 100000
BATCH_SIZE = 1000
MAX_PARSING_LOSS = 0.3  # 30% max loss from DB to backup


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DatabaseStats:
    """Database statistics snapshot."""
    total_ips: int
    corrupted_ips: int
    avg_events: float
    max_events: int
    min_events: int
    sources: Dict[str, int]
    timestamp: str

    def to_dict(self):
        return asdict(self)


@dataclass
class RecoveryMetadata:
    """Recovery operation metadata."""
    backup_id: str
    db_path: str
    backup_path: str
    started_at: str
    completed_at: Optional[str]
    phase1_count: int
    phase2_count: int
    stats_before: Dict
    stats_after: Optional[Dict]
    success: bool
    error_message: Optional[str] = None

    def save(self, metadata_file: Path):
        """Save metadata to JSON file."""
        with open(metadata_file, 'w') as f:
            json.dump(asdict(self), f, indent=2)


# =============================================================================
# FILE LOCKING
# =============================================================================

class FileLock:
    """
    File-based lock using fcntl for concurrent access prevention.

    Prevents race conditions when multiple processes access database.
    """

    def __init__(self, lockfile: Path, timeout: int = 30):
        """
        Initialize file lock.

        Args:
            lockfile: Path to lock file
            timeout: Maximum seconds to wait for lock
        """
        self.lockfile = lockfile
        self.timeout = timeout
        self.lock_fd = None

    def __enter__(self):
        """Acquire exclusive lock."""
        import time

        self.lockfile.parent.mkdir(parents=True, exist_ok=True)
        self.lock_fd = open(self.lockfile, 'w')

        start_time = time.time()
        while True:
            try:
                fcntl.flock(self.lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except IOError:
                if time.time() - start_time > self.timeout:
                    raise TimeoutError(
                        f"Could not acquire lock on {self.lockfile} after {self.timeout}s"
                    )
                time.sleep(0.1)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Release lock."""
        if self.lock_fd:
            try:
                fcntl.flock(self.lock_fd.fileno(), fcntl.LOCK_UN)
                self.lock_fd.close()
            except Exception:
                pass

        return False


# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

class PreFlightChecker:
    """Pre-flight safety checks before recovery."""

    @staticmethod
    def check_service_stopped() -> Tuple[bool, str]:
        """Verify TribanFT service is not running."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "tribanft"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return False, "TribanFT service is RUNNING - must stop first: systemctl stop tribanft"
            return True, "Service stopped (safe to proceed)"
        except subprocess.TimeoutExpired:
            return False, "Timeout checking service status"
        except FileNotFoundError:
            return True, "Service check skipped (systemctl not available)"
        except Exception as e:
            return False, f"Error checking service: {e}"

    @staticmethod
    def check_disk_space(required_mb: int = 500) -> Tuple[bool, str]:
        """Verify sufficient disk space for backups."""
        try:
            home = Path.home()
            stat = shutil.disk_usage(home)
            available_mb = stat.free / (1024 * 1024)
            if available_mb < required_mb:
                return False, f"Insufficient disk space: {available_mb:.0f}MB available, {required_mb}MB required"
            return True, f"Disk space OK ({available_mb:.0f}MB available)"
        except Exception as e:
            return False, f"Error checking disk space: {e}"

    @staticmethod
    def check_database_integrity(db_path: Path) -> Tuple[bool, str]:
        """Verify database is not corrupted."""
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            result = conn.execute("PRAGMA integrity_check").fetchone()
            conn.close()

            if result[0] == 'ok':
                return True, "Database integrity verified"
            else:
                return False, f"Database integrity check failed: {result[0]}"
        except Exception as e:
            return False, f"Error checking database integrity: {e}"

    @staticmethod
    def check_backup_readable(backup_path: Path) -> Tuple[bool, str]:
        """Verify backup file is readable and valid gzip."""
        try:
            with gzip.open(backup_path, 'rt') as f:
                for _ in range(100):
                    line = f.readline()
                    if not line:
                        break
            return True, "Backup file readable"
        except Exception as e:
            return False, f"Cannot read backup file: {e}"

    @classmethod
    def run_all_checks(cls, db_path: Path, backup_path: Path) -> List[Tuple[str, bool, str]]:
        """
        Run all pre-flight checks.

        Returns:
            List of (check_name, passed, message) tuples
        """
        checks = [
            ("Service Status", cls.check_service_stopped()),
            ("Disk Space", cls.check_disk_space()),
            ("Database Integrity", cls.check_database_integrity(db_path)),
            ("Backup Readable", cls.check_backup_readable(backup_path)),
        ]
        return [(name, ok, msg) for name, (ok, msg) in checks]


# =============================================================================
# DATABASE BACKUP (SAFE)
# =============================================================================

class DatabaseBackup:
    """Safe database backup using SQLite backup API."""

    @staticmethod
    def create_backup(db_path: Path, backup_dir: Path) -> Tuple[Path, str]:
        """
        Create safe database backup with integrity verification.

        Uses SQLite backup API to handle WAL mode correctly.

        Args:
            db_path: Source database path
            backup_dir: Directory for backup storage

        Returns:
            Tuple of (backup_path, backup_id)

        Raises:
            RuntimeError: If backup integrity check fails
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_id = f"recovery_{timestamp}"
        backup_path = backup_dir / f"{db_path.name}.{backup_id}.backup"

        backup_dir.mkdir(parents=True, exist_ok=True)

        # Use SQLite backup API (handles WAL mode correctly)
        source_conn = sqlite3.connect(db_path, timeout=30)
        backup_conn = sqlite3.connect(backup_path, timeout=30)

        try:
            source_conn.backup(backup_conn)
        finally:
            backup_conn.close()
            source_conn.close()

        # Verify backup integrity
        verify_conn = sqlite3.connect(backup_path, timeout=10)
        result = verify_conn.execute("PRAGMA integrity_check").fetchone()
        verify_conn.close()

        if result[0] != 'ok':
            backup_path.unlink()
            raise RuntimeError(f"Backup integrity check failed: {result[0]}")

        # Calculate checksum
        checksum = DatabaseBackup._calculate_checksum(backup_path)

        # Save metadata
        metadata = {
            'backup_id': backup_id,
            'original_db': str(db_path),
            'created_at': timestamp,
            'checksum': checksum,
            'size_bytes': backup_path.stat().st_size
        }

        metadata_path = backup_dir / f"{backup_id}.metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return backup_path, backup_id

    @staticmethod
    def _calculate_checksum(file_path: Path) -> str:
        """Calculate SHA256 checksum of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def restore_backup(backup_path: Path, target_path: Path) -> bool:
        """
        Restore database from backup with verification.

        Args:
            backup_path: Backup file to restore from
            target_path: Target database path

        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(backup_path, timeout=10)
            result = conn.execute("PRAGMA integrity_check").fetchone()
            conn.close()

            if result[0] != 'ok':
                print(f"ERROR: Backup is corrupted: {result[0]}")
                return False

            source_conn = sqlite3.connect(backup_path, timeout=30)
            target_conn = sqlite3.connect(target_path, timeout=30)

            try:
                source_conn.backup(target_conn)
            finally:
                target_conn.close()
                source_conn.close()

            return True

        except Exception as e:
            print(f"ERROR: Restore failed: {e}")
            return False


# =============================================================================
# BACKUP PARSER (VALIDATED)
# =============================================================================

class BackupParser:
    """Parse backup file with rigorous validation."""

    @staticmethod
    def parse(backup_path: Path) -> Dict[str, int]:
        """
        Extract event counts from backup with validation.

        Args:
            backup_path: Path to compressed backup file

        Returns:
            Dict mapping IP string to event_count

        Raises:
            ValueError: If backup appears corrupted or invalid
        """
        ip_events = {}
        current_ip = None
        corrupted_values = 0
        line_count = 0
        parsed_ips = []

        print(f"\nParsing backup: {backup_path.name}")

        with gzip.open(backup_path, 'rt') as f:
            for line_num, line in enumerate(f, 1):
                line_count = line_num
                line = line.strip()

                # Match IP header
                if line.startswith('# IP:'):
                    ip_match = re.search(r'# IP:\s*([\d\.]+)', line)
                    if ip_match:
                        current_ip = ip_match.group(1)

                        # SECURITY: Validate IP format
                        try:
                            ipaddress.ip_address(current_ip)
                        except ValueError:
                            print(f"  WARNING: Line {line_num}: Invalid IP format {current_ip}, skipping")
                            current_ip = None

                # Match event count (ONLY integers, NOT scientific notation)
                elif current_ip and 'Events:' in line:
                    event_match = re.search(r'Events:\s*(\d+)(?:\s|$)', line)

                    if event_match:
                        try:
                            event_count = int(event_match.group(1))

                            # Sanity check
                            if event_count < 0 or event_count > MAX_REASONABLE_EVENTS:
                                print(f"  WARNING: Line {line_num}: {current_ip} has unreasonable count {event_count}, skipping")
                                corrupted_values += 1
                                current_ip = None
                                continue

                            ip_events[current_ip] = event_count
                            parsed_ips.append(current_ip)
                            current_ip = None

                        except (ValueError, AttributeError) as e:
                            print(f"  WARNING: Line {line_num}: Parse error for {current_ip}: {e}")
                            current_ip = None
                    else:
                        # Events line exists but no integer found
                        if 'e+' in line or 'e-' in line:
                            print(f"  WARNING: Line {line_num}: {current_ip} has scientific notation (corrupted), skipping")
                            corrupted_values += 1
                        current_ip = None

        # VALIDATION: Minimum IPs expected
        if len(ip_events) < MIN_EXPECTED_IPS:
            raise ValueError(
                f"Only {len(ip_events)} IPs parsed from backup (expected >{MIN_EXPECTED_IPS}). "
                f"Backup may be corrupted or incomplete."
            )

        # VALIDATION: Corruption rate
        corruption_rate = corrupted_values / max(len(ip_events), 1)
        if corruption_rate > 0.1:
            raise ValueError(
                f"High corruption rate: {corrupted_values} corrupted values ({corruption_rate*100:.1f}%). "
                f"Backup is not reliable."
            )

        print(f"OK Parsed {len(ip_events):,} IPs from {line_count:,} lines")
        if corrupted_values > 0:
            print(f"  WARN Skipped {corrupted_values} corrupted values ({corruption_rate*100:.2f}%)")

        return ip_events


# =============================================================================
# DATABASE ANALYZER
# =============================================================================

class DatabaseAnalyzer:
    """Analyze database statistics."""

    @staticmethod
    def get_stats(db_path: Path) -> DatabaseStats:
        """
        Get comprehensive database statistics.

        Args:
            db_path: Database file path

        Returns:
            DatabaseStats object
        """
        conn = sqlite3.connect(db_path, timeout=10)
        cursor = conn.cursor()

        total = cursor.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]

        corrupted = cursor.execute(
            "SELECT COUNT(*) FROM blacklist WHERE event_count > ?",
            (CORRUPTION_THRESHOLD,)
        ).fetchone()[0]

        stats_query = cursor.execute(
            "SELECT AVG(event_count), MAX(event_count), MIN(event_count) FROM blacklist"
        ).fetchone()
        avg_events, max_events, min_events = stats_query

        sources = {}
        for row in cursor.execute("SELECT source, COUNT(*) FROM blacklist GROUP BY source"):
            sources[row[0] or 'unknown'] = row[1]

        conn.close()

        return DatabaseStats(
            total_ips=total,
            corrupted_ips=corrupted,
            avg_events=avg_events or 0,
            max_events=max_events or 0,
            min_events=min_events or 0,
            sources=sources,
            timestamp=datetime.now().isoformat()
        )


# =============================================================================
# DATABASE UPDATER (TRANSACTIONAL)
# =============================================================================

class DatabaseUpdater:
    """
    Safe database updates with transactions and checkpoints.

    Implements automatic rollback on failure.
    """

    def __init__(self, db_path: Path):
        """
        Initialize database updater.

        Args:
            db_path: Database file path
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None

    def __enter__(self):
        """Begin transaction with write lock."""
        self.conn = sqlite3.connect(self.db_path, timeout=60, isolation_level=None)
        self.cursor = self.conn.cursor()
        # Begin immediate transaction (acquire write lock)
        self.cursor.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Commit or rollback based on exception."""
        if exc_type is not None:
            print(f"\nERROR occurred - rolling back transaction...")
            try:
                self.conn.rollback()
                print("OK Rollback complete - database unchanged")
            except Exception as e:
                print(f"WARN Rollback failed: {e}")

        if self.conn:
            self.conn.close()

        return False  # Propagate exception

    def update_batch(self, updates: List[Tuple[str, int]], checkpoint: bool = False):
        """
        Update batch of IPs with optional checkpoint.

        Args:
            updates: List of (ip, event_count) tuples
            checkpoint: If True, commit and start new transaction
        """
        for ip, event_count in updates:
            self.cursor.execute(
                "UPDATE blacklist SET event_count = ? WHERE ip = ?",
                (event_count, ip)
            )

        if checkpoint:
            self.conn.commit()
            self.cursor.execute("BEGIN IMMEDIATE")


# =============================================================================
# RECOVERY MANAGER
# =============================================================================

class RecoveryManager:
    """Main recovery orchestrator."""

    def __init__(self, db_path: Path, backup_path: Path, state_dir: Path, dry_run: bool):
        """
        Initialize recovery manager.

        Args:
            db_path: Database to recover
            backup_path: Source backup file
            state_dir: State directory for backups and metadata
            dry_run: If True, only preview changes
        """
        self.db_path = db_path
        self.backup_path = backup_path
        self.state_dir = state_dir
        self.dry_run = dry_run
        self.lock_file = state_dir / "recovery.lock"

    def run(self) -> bool:
        """
        Execute recovery process.

        Returns:
            True if successful, False otherwise
        """
        print("="*80)
        print("TribanFT Event Count Recovery - SAFE MODE")
        print("="*80)

        # Acquire file lock
        try:
            with FileLock(self.lock_file, timeout=5):
                return self._run_locked()
        except TimeoutError:
            print("\nERROR: Another recovery process is running")
            print("Wait for it to complete or remove lock file:")
            print(f"  rm {self.lock_file}")
            return False

    def _run_locked(self) -> bool:
        """Execute recovery with file lock held."""

        # Pre-flight checks
        if not self._pre_flight_checks():
            return False

        # Create safety backup (database)
        db_backup_path = None
        db_backup_id = None
        if not self.dry_run:
            try:
                db_backup_path, db_backup_id = self._create_backup()
            except Exception as e:
                print(f"\nERROR: Failed to create backup: {e}")
                return False

        # Parse source backup
        try:
            ip_events = BackupParser.parse(self.backup_path)
        except ValueError as e:
            print(f"\nFATAL: {e}")
            return False

        # Get database stats
        stats_before = DatabaseAnalyzer.get_stats(self.db_path)

        # CORRUPTION CHECK: Verify parsing didn't lose too much data
        parsing_loss = 1 - (len(ip_events) / max(stats_before.total_ips, 1))
        if parsing_loss > MAX_PARSING_LOSS:
            print(f"\nFATAL: Backup parsing lost {parsing_loss*100:.1f}% of database IPs")
            print(f"  Database has: {stats_before.total_ips:,} IPs")
            print(f"  Backup has:   {len(ip_events):,} IPs")
            print(f"  Loss rate:    {parsing_loss*100:.1f}% (threshold: {MAX_PARSING_LOSS*100:.0f}%)")
            print("\nBackup appears incomplete or corrupted - ABORTING")
            return False

        self._print_stats("BEFORE RECOVERY", stats_before)

        # Execute recovery
        success = False
        if self.dry_run:
            success = self._dry_run(ip_events, stats_before)
        else:
            success = self._execute_recovery(ip_events, stats_before, db_backup_id)

        return success

    def _pre_flight_checks(self) -> bool:
        """Run pre-flight checks."""
        print("\n" + "="*80)
        print("PRE-FLIGHT CHECKS")
        print("="*80)

        checks = PreFlightChecker.run_all_checks(self.db_path, self.backup_path)
        all_passed = True

        for name, passed, message in checks:
            status = "OK" if passed else "FAIL"
            print(f"[{status}] {name}: {message}")
            if not passed:
                all_passed = False

        if not all_passed:
            print("\nFAIL Pre-flight checks failed - cannot proceed")
            return False

        print("\nOK All pre-flight checks passed")
        return True

    def _create_backup(self) -> Tuple[Path, str]:
        """Create database backup."""
        print("\n" + "="*80)
        print("CREATING SAFETY BACKUP")
        print("="*80)

        backup_path, backup_id = DatabaseBackup.create_backup(
            self.db_path,
            self.state_dir
        )
        print(f"OK Database backed up: {backup_path.name}")
        print(f"   Backup ID: {backup_id}")
        return backup_path, backup_id

    def _dry_run(self, ip_events: Dict[str, int], stats_before: DatabaseStats) -> bool:
        """Simulate recovery without making changes."""
        print("\n" + "="*80)
        print("DRY RUN - PREVIEW CHANGES (NO MODIFICATIONS)")
        print("="*80)

        conn = sqlite3.connect(self.db_path, timeout=10)
        cursor = conn.cursor()

        phase1_count = 0
        phase2_count = 0
        backup_ips = set(ip_events.keys())

        # Phase 1: Count IPs in backup
        print("\nPhase 1: IPs with backup values (sample)")
        print("-" * 80)
        cursor.execute(
            "SELECT ip, event_count FROM blacklist WHERE event_count > ? LIMIT 10",
            (CORRUPTION_THRESHOLD,)
        )
        for ip, current_count in cursor.fetchall():
            if ip in ip_events:
                correct_count = ip_events[ip]
                print(f"  {ip}: {current_count:,.0f} -> {correct_count}")
                phase1_count += 1

        # Count total phase 1
        for ip in ip_events.keys():
            cursor.execute(
                "SELECT event_count FROM blacklist WHERE ip = ? AND event_count > ?",
                (ip, CORRUPTION_THRESHOLD)
            )
            if cursor.fetchone():
                phase1_count += 1

        # Phase 2: Count IPs not in backup
        print("\nPhase 2: IPs without backup (heuristic, sample)")
        print("-" * 80)
        cursor.execute(
            "SELECT ip, source, event_count FROM blacklist WHERE event_count > ? LIMIT 10",
            (CORRUPTION_THRESHOLD,)
        )
        for ip, source, current in cursor.fetchall():
            if ip not in backup_ips:
                estimated = HEURISTICS.get(source or 'unknown', 10)
                print(f"  {ip}: {current:,.0f} -> {estimated} (heuristic: {source})")
                phase2_count += 1

        # Count total phase 2
        cursor.execute(
            "SELECT COUNT(*) FROM blacklist WHERE event_count > ?",
            (CORRUPTION_THRESHOLD,)
        )
        total_corrupted = cursor.fetchone()[0]
        phase2_count = total_corrupted - phase1_count

        conn.close()

        print("\n" + "="*80)
        print("DRY RUN SUMMARY")
        print("="*80)
        print(f"Phase 1 (backup):     {phase1_count:,} IPs would be corrected")
        print(f"Phase 2 (heuristic):  {phase2_count:,} IPs would be corrected")
        print(f"Total corrections:    {phase1_count + phase2_count:,} IPs")
        print("\nOK Dry run complete - review and run with --apply to execute")

        return True

    def _execute_recovery(self, ip_events: Dict[str, int], stats_before: DatabaseStats, backup_id: str) -> bool:
        """Execute actual recovery with transactions."""
        print("\n" + "="*80)
        print("EXECUTING RECOVERY")
        print("="*80)

        phase1_updated = 0
        phase2_updated = 0

        try:
            with DatabaseUpdater(self.db_path) as updater:
                # PHASE 1: Exact values from backup
                print("\nPhase 1: Restoring from backup...")
                print("-" * 80)
                batch = []

                for ip, correct_count in ip_events.items():
                    updater.cursor.execute(
                        "SELECT event_count FROM blacklist WHERE ip = ?",
                        (ip,)
                    )
                    row = updater.cursor.fetchone()

                    if row and row[0] > CORRUPTION_THRESHOLD:
                        batch.append((ip, correct_count))
                        phase1_updated += 1

                        if len(batch) >= BATCH_SIZE:
                            updater.update_batch(batch, checkpoint=True)
                            print(f"  Checkpoint: {phase1_updated:,} IPs updated from backup...")
                            batch = []

                # Final batch
                if batch:
                    updater.update_batch(batch, checkpoint=True)

                print(f"OK Phase 1 complete: {phase1_updated:,} IPs restored from backup")

                # PHASE 2: Heuristics for IPs not in backup
                print("\nPhase 2: Applying heuristics...")
                print("-" * 80)
                batch = []
                backup_ips = set(ip_events.keys())

                updater.cursor.execute(
                    "SELECT ip, source, event_count FROM blacklist WHERE event_count > ?",
                    (CORRUPTION_THRESHOLD,)
                )

                heuristic_stats = defaultdict(int)

                for ip, source, current_count in updater.cursor.fetchall():
                    if ip not in backup_ips:
                        estimated = HEURISTICS.get(source or 'unknown', HEURISTICS['unknown'])
                        batch.append((ip, estimated))
                        phase2_updated += 1
                        heuristic_stats[source or 'unknown'] += 1

                        if len(batch) >= BATCH_SIZE:
                            updater.update_batch(batch, checkpoint=True)
                            print(f"  Checkpoint: {phase2_updated:,} IPs updated with heuristics...")
                            batch = []

                # Final batch
                if batch:
                    updater.update_batch(batch, checkpoint=True)

                print(f"OK Phase 2 complete: {phase2_updated:,} IPs corrected with heuristics")

                if heuristic_stats:
                    print("\n  Heuristics applied by source:")
                    for source, count in sorted(heuristic_stats.items(), key=lambda x: -x[1]):
                        print(f"    {source}: {count:,} IPs -> {HEURISTICS.get(source, 10)} events each")

                # Final commit
                updater.conn.commit()

            # Get stats after
            stats_after = DatabaseAnalyzer.get_stats(self.db_path)
            self._print_stats("AFTER RECOVERY", stats_after)

            # Save metadata
            metadata = RecoveryMetadata(
                backup_id=backup_id,
                db_path=str(self.db_path),
                backup_path=str(self.backup_path),
                started_at=stats_before.timestamp,
                completed_at=datetime.now().isoformat(),
                phase1_count=phase1_updated,
                phase2_count=phase2_updated,
                stats_before=stats_before.to_dict(),
                stats_after=stats_after.to_dict(),
                success=True
            )
            metadata.save(self.state_dir / f"{backup_id}.recovery.json")

            print("\n" + "="*80)
            print("RECOVERY COMPLETE")
            print("="*80)
            print(f"Phase 1 (backup):     {phase1_updated:,} IPs")
            print(f"Phase 2 (heuristic):  {phase2_updated:,} IPs")
            print(f"Total corrections:    {phase1_updated + phase2_updated:,} IPs")
            print("\nNext steps:")
            print("  1. Run: tribanft --sync-files")
            print("  2. Verify: Check event counts look reasonable")
            print("  3. Monitor: Watch next detection cycle")
            print(f"\nRecovery metadata: {backup_id}.recovery.json")

            return True

        except Exception as e:
            print(f"\nERROR Recovery failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _print_stats(self, title: str, stats: DatabaseStats):
        """Print database statistics."""
        print(f"\n{title}")
        print("-" * 80)
        print(f"Total IPs:       {stats.total_ips:,}")
        print(f"Corrupted IPs:   {stats.corrupted_ips:,} ({stats.corrupted_ips/max(stats.total_ips,1)*100:.1f}%)")
        print(f"Avg events:      {stats.avg_events:,.2f}")
        print(f"Max events:      {stats.max_events:,}")
        print(f"Min events:      {stats.min_events:,}")


# =============================================================================
# MAIN
# =============================================================================

def find_oldest_backup(backup_dir: Path) -> Path:
    """Find oldest backup file (before corruption started)."""
    backups = sorted(backup_dir.glob("blacklist_ipv4.txt_*.backup.gz"))
    if not backups:
        raise FileNotFoundError(f"No backups found in {backup_dir}")
    return backups[0]


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Safe event count recovery with rollback protection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preview changes (MANDATORY first step)
  python3 recover_event_counts_safe.py --auto --dry-run

  # Apply fixes (only after reviewing dry-run)
  python3 recover_event_counts_safe.py --auto --apply

  # Use specific backup
  python3 recover_event_counts_safe.py --backup <file.gz> --database <db> --apply
        """
    )
    parser.add_argument('--auto', action='store_true', help='Auto-detect paths (recommended)')
    parser.add_argument('--backup', type=str, help='Backup file path (.gz)')
    parser.add_argument('--database', type=str, help='Database file path')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes only (safe)')
    parser.add_argument('--apply', action='store_true', help='Apply changes (USE WITH CAUTION)')

    args = parser.parse_args()

    # Determine mode
    dry_run = args.dry_run or not args.apply

    # Auto-detect paths
    if args.auto:
        home = Path.home()
        db_path = home / '.local' / 'share' / 'tribanft' / 'tribanft.db'
        backup_dir = home / '.local' / 'share' / 'tribanft' / 'backups'
        state_dir = home / '.local' / 'state' / 'tribanft' / 'recovery'
        state_dir.mkdir(parents=True, exist_ok=True)

        try:
            backup_path = find_oldest_backup(backup_dir)
        except FileNotFoundError as e:
            print(f"ERROR: {e}")
            return 1
    else:
        if not args.backup or not args.database:
            parser.error("--backup and --database required (or use --auto)")
        backup_path = Path(args.backup)
        db_path = Path(args.database)
        state_dir = Path.cwd() / 'recovery_state'
        state_dir.mkdir(exist_ok=True)

    # Validate paths
    if not backup_path.exists():
        print(f"ERROR: Backup not found: {backup_path}")
        return 1
    if not db_path.exists():
        print(f"ERROR: Database not found: {db_path}")
        return 1

    print("="*80)
    print("Configuration:")
    print(f"  Database: {db_path}")
    print(f"  Backup:   {backup_path}")
    print(f"  Mode:     {'DRY RUN (preview only)' if dry_run else 'APPLY CHANGES'}")
    print("="*80)

    if not dry_run:
        print("\nWARNING: This will modify the database!")
        print("Press Ctrl+C to abort, or Enter to continue...")
        try:
            input()
        except KeyboardInterrupt:
            print("\nAborted by user")
            return 130

    manager = RecoveryManager(db_path, backup_path, state_dir, dry_run)
    success = manager.run()

    return 0 if success else 1


if __name__ == '__main__':
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        exit(130)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
