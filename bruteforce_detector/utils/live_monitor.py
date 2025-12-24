"""
TribanFT Live Threat Monitor

Real-time monitoring of threats being added to the blacklist.
Displays new threats as they are detected and added to the database.

Features:
- Real-time threat stream
- Color-coded output by severity
- Geolocation information
- Event type display
- Periodic statistics summary

Author: TribanFT Project
License: GNU GPL v3
"""

import time
import sqlite3
from datetime import datetime
from typing import Dict, Set


class LiveMonitor:
    """Real-time threat monitoring tool."""

    def __init__(self, db, refresh_interval: int = 2):
        """
        Initialize live monitor.

        Args:
            db: BlacklistDatabase instance
            refresh_interval: Seconds between database checks
        """
        self.db = db
        self.refresh_interval = refresh_interval
        self.seen_ips: Set[str] = set()
        self.start_time = datetime.now()
        self.threat_count = 0

    def run(self):
        """
        Run the live monitor in continuous loop.

        Monitors database for new IPs and displays them as they appear.
        """
        # Get initial state
        self._initialize_seen_ips()

        print(f"Live Threat Monitor Started at {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 130)
        print(f"{'Time':<20} {'IP Address':<18} {'Location':<30} {'Attack Type':<25} {'Events':<8} {'Reason'}")
        print("-" * 130)

        try:
            while True:
                # Check for new threats
                new_threats = self._get_new_threats()

                if new_threats:
                    for ip_str, info in new_threats.items():
                        self._display_threat(ip_str, info)
                        self.threat_count += 1

                # Show periodic stats every 60 seconds
                if (datetime.now() - self.start_time).total_seconds() % 60 < self.refresh_interval:
                    self._show_stats()

                time.sleep(self.refresh_interval)

        except KeyboardInterrupt:
            print("\n" + "=" * 130)
            self._show_final_stats()

    def _initialize_seen_ips(self):
        """Load existing IPs from database to avoid showing old entries."""
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute("SELECT ip FROM blacklist").fetchall()
            self.seen_ips = {row[0] for row in rows}

    def _get_new_threats(self) -> Dict:
        """
        Query database for new IPs added since last check.

        Returns:
            Dict mapping IP to metadata for newly added IPs
        """
        new_threats = {}

        with sqlite3.connect(self.db.db_path) as conn:
            # Get recent additions (last 10 seconds to account for delays)
            query = """
                SELECT *
                FROM blacklist
                WHERE date_added >= datetime('now', '-10 seconds')
                ORDER BY date_added DESC
            """

            rows = conn.execute(query).fetchall()

            for row in rows:
                ip_str = row[0]

                # Skip if already seen
                if ip_str in self.seen_ips:
                    continue

                # Mark as seen
                self.seen_ips.add(ip_str)

                # Parse metadata
                import json
                metadata = {}
                event_types = []

                try:
                    if row[12]:
                        metadata = json.loads(row[12])
                        event_types = metadata.get('event_types', [])
                except json.JSONDecodeError:
                    pass

                # Build info dict
                new_threats[ip_str] = {
                    'reason': row[2],
                    'confidence': row[3],
                    'event_count': row[4],
                    'source': row[5],
                    'country': row[6],
                    'city': row[7],
                    'isp': row[8],
                    'date_added': datetime.fromisoformat(row[11]) if row[11] else datetime.now(),
                    'event_types': event_types
                }

        return new_threats

    def _display_threat(self, ip_str: str, info: Dict):
        """
        Display a single threat to the console.

        Args:
            ip_str: IP address
            info: Threat metadata
        """
        timestamp = info['date_added'].strftime('%Y-%m-%d %H:%M:%S')

        # Build location string
        country = info.get('country', 'Unknown')
        city = info.get('city', '')
        location = f"{country}, {city}" if city else country
        location = location[:29]

        # Get primary attack type
        event_types = info.get('event_types', [])
        attack_type = event_types[0] if event_types else 'unknown'
        attack_type = attack_type.replace('_', ' ').title()
        attack_type = attack_type[:24]

        # Event count
        events = info.get('event_count', 0)

        # Reason
        reason = info.get('reason', 'Unknown')
        reason = reason[:40]

        # Print threat line
        print(f"{timestamp:<20} {ip_str:<18} {location:<30} {attack_type:<25} {events:<8,} {reason}")

    def _show_stats(self):
        """Show periodic statistics summary."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        rate = self.threat_count / max(elapsed / 60, 1)  # Threats per minute

        print()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
              f"Stats: {self.threat_count} threats detected | "
              f"Rate: {rate:.1f}/min | "
              f"Uptime: {int(elapsed / 60)}m {int(elapsed % 60)}s")
        print()

    def _show_final_stats(self):
        """Show final statistics when monitor exits."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        rate = self.threat_count / max(elapsed / 60, 1)

        print()
        print("Monitor Statistics:")
        print(f"   Runtime:         {int(elapsed / 60)} minutes {int(elapsed % 60)} seconds")
        print(f"   Threats Detected: {self.threat_count:,}")
        print(f"   Average Rate:    {rate:.2f} threats/minute")
        print()
