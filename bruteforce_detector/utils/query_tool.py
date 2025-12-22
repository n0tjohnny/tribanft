"""
TribanFT Database Query Tool

Provides rich querying capabilities for the blacklist database.
Replaces the legacy tribanft-ipinfo-query.py with database-backed queries.

Features:
- Query by IP, country, reason, source
- List countries and sources with statistics
- Top threats by event count
- CSV export with full metadata

Author: TribanFT Project
License: GNU GPL v3
"""

import csv
import sqlite3
from typing import Dict, List, Optional
from datetime import datetime


class QueryTool:
    """Database query tool for blacklist analysis and reporting."""

    def __init__(self, db):
        """
        Initialize query tool.

        Args:
            db: BlacklistDatabase instance
        """
        self.db = db

    def query_ip(self, ip: str):
        """
        Query detailed information about a specific IP.

        Args:
            ip: IP address to query
        """
        with sqlite3.connect(self.db.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM blacklist WHERE ip = ?", (ip,)
            ).fetchone()

        if not row:
            print(f"ERROR: IP {ip} not found in blacklist")
            return

        print(f"\nDetailed Information for {ip}")
        print("=" * 80)
        print(f"  IP Address:      {row[0]}")
        print(f"  IP Version:      IPv{row[1]}")

        if row[6]:  # country
            print(f"\nGeolocation:")
            print(f"  Country:         {row[6]}")
            if row[7]:
                print(f"  City:            {row[7]}")
            if row[8]:
                print(f"  ISP:             {row[8]}")
        else:
            print(f"\nGeolocation:    Unknown Location")

        print(f"\nThreat Information:")
        print(f"  Reason:          {row[2] or 'Unknown'}")
        print(f"  Confidence:      {row[3] or 'unknown'}")
        print(f"  Event Count:     {row[4]}")
        print(f"  Source:          {row[5] or 'unknown'}")

        # Parse metadata for event types
        import json
        metadata = {}
        try:
            if row[12]:
                metadata = json.loads(row[12])
        except:
            pass

        event_types = metadata.get('event_types', [])
        if event_types:
            print(f"  Event Types:     {', '.join(event_types)}")

        print(f"\n📅 Timestamps:")
        if row[9]:
            first_seen = datetime.fromisoformat(row[9])
            print(f"  First Seen:      {first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
        if row[10]:
            last_seen = datetime.fromisoformat(row[10])
            print(f"  Last Seen:       {last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
        if row[11]:
            date_added = datetime.fromisoformat(row[11])
            print(f"  Added:           {date_added.strftime('%Y-%m-%d %H:%M:%S')}")

        print("=" * 80)

    def query_country(self, country: str, limit: int = 50):
        """
        List IPs from a specific country.

        Args:
            country: Country name or code
            limit: Maximum number of results to show
        """
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                """
                SELECT ip, city, isp, reason, event_count, first_seen
                FROM blacklist
                WHERE country LIKE ?
                ORDER BY event_count DESC
                LIMIT ?
                """,
                (f"%{country}%", limit)
            ).fetchall()

        if not rows:
            print(f"ERROR: No IPs found for country: {country}")
            return

        print(f"\nIPs from {country} ({len(rows)} results)")
        print("=" * 120)
        print(f"{'IP Address':<18} {'City':<20} {'ISP':<30} {'Reason':<30} {'Events':<8} {'First Seen'}")
        print("-" * 120)

        for row in rows:
            ip = row[0]
            city = row[1] or 'Unknown'
            isp = row[2] or 'Unknown'
            reason = row[3] or 'Unknown'
            events = row[4]
            first_seen = row[5][:16] if row[5] else 'Unknown'

            # Truncate long fields
            city = city[:19]
            isp = isp[:29]
            reason = reason[:29]

            print(f"{ip:<18} {city:<20} {isp:<30} {reason:<30} {events:<8} {first_seen}")

        print("=" * 120)

    def query_reason(self, reason: str, limit: int = 50):
        """
        Search IPs by block reason (partial match).

        Args:
            reason: Reason text to search for
            limit: Maximum number of results
        """
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                """
                SELECT ip, country, city, reason, event_count, confidence
                FROM blacklist
                WHERE reason LIKE ?
                ORDER BY event_count DESC
                LIMIT ?
                """,
                (f"%{reason}%", limit)
            ).fetchall()

        if not rows:
            print(f"ERROR: No IPs found with reason containing: {reason}")
            return

        print(f"\nIPs with reason containing '{reason}' ({len(rows)} results)")
        print("=" * 120)
        print(f"{'IP Address':<18} {'Location':<30} {'Reason':<40} {'Events':<8} {'Confidence'}")
        print("-" * 120)

        for row in rows:
            ip = row[0]
            country = row[1] or 'Unknown'
            city = row[2] or ''
            location = f"{country}, {city}" if city else country
            block_reason = row[3] or 'Unknown'
            events = row[4]
            confidence = row[5] or 'unknown'

            # Truncate
            location = location[:29]
            block_reason = block_reason[:39]

            print(f"{ip:<18} {location:<30} {block_reason:<40} {events:<8} {confidence}")

        print("=" * 120)

    def list_countries(self):
        """List all countries with IP counts and statistics."""
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                """
                SELECT
                    country,
                    COUNT(*) as ip_count,
                    SUM(event_count) as total_events,
                    AVG(event_count) as avg_events
                FROM blacklist
                WHERE country IS NOT NULL
                GROUP BY country
                ORDER BY ip_count DESC
                """
            ).fetchall()

        if not rows:
            print("ERROR: No geolocation data available")
            return

        print(f"\nCountries in Blacklist ({len(rows)} countries)")
        print("=" * 100)
        print(f"{'Country':<30} {'IPs':<12} {'Total Events':<15} {'Avg Events/IP'}")
        print("-" * 100)

        for row in rows:
            country = row[0]
            ip_count = row[1]
            total_events = row[2]
            avg_events = row[3]

            print(f"{country:<30} {ip_count:<12,} {total_events:<15,} {avg_events:.1f}")

        print("=" * 100)
        print(f"Total: {sum(r[1] for r in rows):,} IPs across {len(rows)} countries")

    def list_sources(self):
        """List all detection sources with IP counts."""
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                """
                SELECT
                    source,
                    COUNT(*) as ip_count,
                    SUM(event_count) as total_events
                FROM blacklist
                WHERE source IS NOT NULL
                GROUP BY source
                ORDER BY ip_count DESC
                """
            ).fetchall()

        if not rows:
            print("ERROR: No source data available")
            return

        print(f"\nDetection Sources ({len(rows)} sources)")
        print("=" * 80)
        print(f"{'Source':<40} {'IPs':<15} {'Total Events'}")
        print("-" * 80)

        for row in rows:
            source = row[0]
            ip_count = row[1]
            total_events = row[2]

            print(f"{source:<40} {ip_count:<15,} {total_events:,}")

        print("=" * 80)
        print(f"Total: {sum(r[1] for r in rows):,} IPs")

    def top_threats(self, limit: int = 20):
        """
        Show top N IPs by event count.

        Args:
            limit: Number of top threats to show
        """
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                """
                SELECT ip, country, city, isp, reason, event_count, last_seen
                FROM blacklist
                WHERE event_count > 0
                ORDER BY event_count DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        if not rows:
            print("ERROR: No IPs with events found")
            return

        print(f"\nTop {limit} Threats by Event Count")
        print("=" * 130)
        print(f"{'#':<4} {'IP Address':<18} {'Location':<35} {'Reason':<35} {'Events':<8} {'Last Seen'}")
        print("-" * 130)

        for idx, row in enumerate(rows, 1):
            ip = row[0]
            country = row[1] or 'Unknown'
            city = row[2] or ''
            location = f"{country}, {city}" if city else country
            reason = row[4] or 'Unknown'
            events = row[5]
            last_seen = row[6][:16] if row[6] else 'Unknown'

            # Truncate
            location = location[:34]
            reason = reason[:34]

            print(f"{idx:<4} {ip:<18} {location:<35} {reason:<35} {events:<8,} {last_seen}")

        print("=" * 130)

    def export_csv(self, output_file: str):
        """
        Export full blacklist to CSV with all metadata.

        Args:
            output_file: Output CSV file path
        """
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM blacklist ORDER BY event_count DESC").fetchall()

        if not rows:
            print("ERROR: No data to export")
            return

        # Define CSV fields
        fields = [
            'ip', 'ip_version', 'reason', 'confidence', 'event_count', 'source',
            'country', 'city', 'isp', 'first_seen', 'last_seen', 'date_added'
        ]

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()

                for row in rows:
                    writer.writerow({
                        'ip': row['ip'],
                        'ip_version': row['ip_version'],
                        'reason': row['reason'] or '',
                        'confidence': row['confidence'] or '',
                        'event_count': row['event_count'],
                        'source': row['source'] or '',
                        'country': row['country'] or '',
                        'city': row['city'] or '',
                        'isp': row['isp'] or '',
                        'first_seen': row['first_seen'] or '',
                        'last_seen': row['last_seen'] or '',
                        'date_added': row['date_added'] or ''
                    })

            print(f"Exported {len(rows):,} IPs to {output_file}")
            print(f"   Fields: {', '.join(fields)}")

        except Exception as e:
            print(f"ERROR: Export failed: {e}")
