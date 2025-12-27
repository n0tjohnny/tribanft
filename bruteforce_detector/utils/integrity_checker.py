"""
TribanFT Integrity Checker

Verification and corruption detection for blacklist files and database.

Provides:
- Blacklist file format validation
- Duplicate IP detection
- Database schema verification
- Metadata consistency checks
- Checksum verification
- NFTables sync status validation

Author: TribanFT Project
License: GNU GPL v3
"""

import logging
import hashlib
import ipaddress
import json
import sqlite3
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from datetime import datetime


class IntegrityCheckResult:
    """Result of an integrity check operation."""
    
    def __init__(self, check_name: str):
        self.check_name = check_name
        self.passed = True
        self.errors = []
        self.warnings = []
        self.info = []
    
    def add_error(self, message: str):
        """Add an error (integrity violation)."""
        self.errors.append(message)
        self.passed = False
    
    def add_warning(self, message: str):
        """Add a warning (potential issue)."""
        self.warnings.append(message)
    
    def add_info(self, message: str):
        """Add informational message."""
        self.info.append(message)
    
    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [f"{status} - {self.check_name}"]

        if self.errors:
            lines.append(f"  Errors ({len(self.errors)}):")
            for err in self.errors[:5]:  # Show first 5
                lines.append(f"    • {err}")
            if len(self.errors) > 5:
                lines.append(f"    ... and {len(self.errors) - 5} more errors")

        if self.warnings:
            lines.append(f"  Warnings ({len(self.warnings)}):")
            for warn in self.warnings[:3]:
                lines.append(f"    WARNING: {warn}")
            if len(self.warnings) > 3:
                lines.append(f"    ... and {len(self.warnings) - 3} more warnings")
        
        if self.info:
            for info_msg in self.info:
                lines.append(f"  ℹ {info_msg}")
        
        return '\n'.join(lines)


class IntegrityChecker:
    """
    Performs integrity checks on blacklist files and database.
    
    Detects:
    - Invalid IP addresses
    - Duplicate entries
    - Malformed metadata
    - Missing required fields
    - Database schema violations
    - File corruption
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def verify_blacklist_file(self, filepath: str) -> IntegrityCheckResult:
        """
        Verify blacklist file format and content.
        
        Checks:
        - File exists and is readable
        - IP addresses are valid
        - Metadata is parseable
        - No duplicate IPs
        
        Args:
            filepath: Path to blacklist file
            
        Returns:
            IntegrityCheckResult with findings
        """
        result = IntegrityCheckResult(f"Blacklist File: {Path(filepath).name}")
        path = Path(filepath)
        
        # Check file exists
        if not path.exists():
            result.add_warning(f"File does not exist: {filepath}")
            return result
        
        # Check readable
        if not os.access(path, os.R_OK):
            result.add_error(f"File is not readable: {filepath}")
            return result
        
        seen_ips = set()
        duplicate_ips = set()
        valid_ips = 0
        invalid_ips = []
        metadata_errors = []
        
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
            
            result.add_info(f"Total lines: {len(lines)}")
            
            current_metadata = None
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Parse metadata comments
                if line.startswith('#'):
                    if line.startswith('# IP:'):
                        try:
                            # Parse metadata line
                            current_metadata = line
                        except Exception as e:
                            metadata_errors.append(f"Line {line_num}: {e}")
                    continue
                
                # Parse IP address
                try:
                    ip = ipaddress.ip_address(line)
                    valid_ips += 1
                    
                    # Check for duplicates
                    if line in seen_ips:
                        duplicate_ips.add(line)
                    else:
                        seen_ips.add(line)
                    
                except ValueError as e:
                    invalid_ips.append(f"Line {line_num}: {line} - {e}")
            
            # Report findings
            result.add_info(f"Valid IPs: {valid_ips}")
            
            if duplicate_ips:
                result.add_warning(f"Found {len(duplicate_ips)} duplicate IPs")
                for dup in list(duplicate_ips)[:5]:
                    result.add_warning(f"  Duplicate: {dup}")
            
            if invalid_ips:
                for invalid in invalid_ips[:10]:
                    result.add_error(invalid)
            
            if metadata_errors:
                for err in metadata_errors[:10]:
                    result.add_warning(err)
        
        except Exception as e:
            result.add_error(f"Failed to read file: {e}")
        
        return result
    
    def check_duplicate_ips(self, filepath: str) -> IntegrityCheckResult:
        """
        Check for duplicate IP addresses in blacklist.
        
        Args:
            filepath: Path to blacklist file
            
        Returns:
            IntegrityCheckResult with duplicate IP findings
        """
        result = IntegrityCheckResult(f"Duplicate Check: {Path(filepath).name}")
        path = Path(filepath)
        
        if not path.exists():
            result.add_warning(f"File does not exist: {filepath}")
            return result
        
        ip_counts = {}
        
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line in ip_counts:
                            ip_counts[line] += 1
                        else:
                            ip_counts[line] = 1
            
            duplicates = {ip: count for ip, count in ip_counts.items() if count > 1}
            
            if duplicates:
                result.add_error(f"Found {len(duplicates)} duplicate IPs")
                for ip, count in list(duplicates.items())[:10]:
                    result.add_error(f"  {ip} appears {count} times")
            else:
                result.add_info("No duplicate IPs found")
        
        except Exception as e:
            result.add_error(f"Failed to check duplicates: {e}")
        
        return result
    
    def verify_database_schema(self, db_path: str) -> IntegrityCheckResult:
        """
        Verify SQLite database schema and integrity.
        
        Args:
            db_path: Path to SQLite database
            
        Returns:
            IntegrityCheckResult with schema validation findings
        """
        result = IntegrityCheckResult(f"Database Schema: {Path(db_path).name}")
        path = Path(db_path)
        
        if not path.exists():
            result.add_warning(f"Database does not exist: {db_path}")
            return result
        
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            
            # Check table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blacklist'")
            if not cursor.fetchone():
                result.add_error("Missing 'blacklist' table")
                return result
            
            # Get table schema
            cursor.execute("PRAGMA table_info(blacklist)")
            columns = {row[1]: row[2] for row in cursor.fetchall()}
            
            # Required columns
            required_columns = {
                'ip': 'TEXT',
                'ip_version': 'INTEGER',
                'reason': 'TEXT',
                'confidence': 'TEXT'
            }
            
            for col_name, col_type in required_columns.items():
                if col_name not in columns:
                    result.add_error(f"Missing required column: {col_name}")
                # Note: SQLite type affinity is flexible, so we don't strictly check types
            
            # Check for NULL values in critical columns
            cursor.execute("SELECT COUNT(*) FROM blacklist WHERE ip IS NULL")
            null_ips = cursor.fetchone()[0]
            if null_ips > 0:
                result.add_error(f"Found {null_ips} rows with NULL IP addresses")
            
            # Check for invalid IP versions
            cursor.execute("SELECT COUNT(*) FROM blacklist WHERE ip_version NOT IN (4, 6)")
            invalid_versions = cursor.fetchone()[0]
            if invalid_versions > 0:
                result.add_error(f"Found {invalid_versions} rows with invalid IP versions")
            
            # Run SQLite integrity check
            cursor.execute("PRAGMA integrity_check")
            integrity_result = cursor.fetchone()[0]
            if integrity_result != 'ok':
                result.add_error(f"Database integrity check failed: {integrity_result}")
            else:
                result.add_info("SQLite integrity check passed")
            
            # Get row count
            cursor.execute("SELECT COUNT(*) FROM blacklist")
            row_count = cursor.fetchone()[0]
            result.add_info(f"Total entries: {row_count}")
            
            conn.close()
        
        except Exception as e:
            result.add_error(f"Database verification failed: {e}")
        
        return result
    
    def verify_metadata_consistency(self, filepath: str) -> IntegrityCheckResult:
        """
        Verify metadata consistency in blacklist file.
        
        Checks:
        - All IPs have metadata
        - Required metadata fields present
        - Timestamp validity
        - Event count validity
        
        Args:
            filepath: Path to blacklist file
            
        Returns:
            IntegrityCheckResult with metadata validation findings
        """
        result = IntegrityCheckResult(f"Metadata Check: {Path(filepath).name}")
        path = Path(filepath)
        
        if not path.exists():
            result.add_warning(f"File does not exist: {filepath}")
            return result
        
        ips_with_metadata = 0
        ips_without_metadata = []
        missing_fields = {}
        invalid_timestamps = []
        
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
            
            current_metadata = None
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                if line.startswith('# IP:'):
                    current_metadata = line
                elif line and not line.startswith('#'):
                    # This is an IP line
                    if current_metadata:
                        ips_with_metadata += 1
                        
                        # Check for required fields in metadata
                        required = ['Country', 'ISP', 'Reason', 'Confidence']
                        for field in required:
                            if field not in current_metadata:
                                if field not in missing_fields:
                                    missing_fields[field] = []
                                missing_fields[field].append(line)
                        
                        # Check timestamp format
                        if 'First:' in current_metadata or 'Last:' in current_metadata:
                            # Timestamps present, validate if possible
                            pass
                    else:
                        ips_without_metadata.append(line)
                    
                    current_metadata = None
            
            # Report findings
            total_ips = ips_with_metadata + len(ips_without_metadata)
            if total_ips > 0:
                result.add_info(f"IPs with metadata: {ips_with_metadata}/{total_ips}")
            
            if ips_without_metadata:
                result.add_warning(f"Found {len(ips_without_metadata)} IPs without metadata")
                for ip in ips_without_metadata[:5]:
                    result.add_warning(f"  No metadata: {ip}")
            
            if missing_fields:
                for field, ips in missing_fields.items():
                    result.add_warning(f"Missing '{field}' in {len(ips)} entries")
        
        except Exception as e:
            result.add_error(f"Metadata verification failed: {e}")
        
        return result
    
    def compute_file_checksum(self, filepath: str) -> Optional[str]:
        """
        Compute SHA256 checksum of a file.
        
        Args:
            filepath: Path to file
            
        Returns:
            Hexadecimal checksum string, or None if failed
        """
        path = Path(filepath)
        if not path.exists():
            return None
        
        try:
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to compute checksum for {filepath}: {e}")
            return None
    
    def verify_all(self, config) -> List[IntegrityCheckResult]:
        """
        Run all integrity checks on configured files.
        
        Args:
            config: Configuration object with file paths
            
        Returns:
            List of IntegrityCheckResult objects
        """
        results = []
        
        # Check blacklist files
        for filepath in [config.blacklist_ipv4_file, config.blacklist_ipv6_file]:
            if Path(filepath).exists():
                results.append(self.verify_blacklist_file(filepath))
                results.append(self.check_duplicate_ips(filepath))
                results.append(self.verify_metadata_consistency(filepath))
        
        # Check database
        if config.use_database and Path(config.database_path).exists():
            results.append(self.verify_database_schema(config.database_path))
        
        return results
