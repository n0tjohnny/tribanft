"""
TribanFT CrowdSec Detector - Fixed JSON Parsing with Historical Alerts

Queries CrowdSec LAPI for:
- Active ban decisions (cscli decisions list)
- Historical alerts (cscli alerts list)

Extracts IP, scenario, events, timestamp, country, and ISP data.
"""

import subprocess
import json
import logging
import ipaddress
import csv
from typing import List, Dict
from datetime import datetime, timezone
from pathlib import Path

from ...detectors.base import BaseDetector
from ...models import DetectionResult, EventType


class CrowdSecDetector(BaseDetector):
    """Detector for IPs banned by CrowdSec."""

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'crowdsec_detector',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Integrates with CrowdSec for community threat intelligence',
        'dependencies': ['config', 'blacklist_manager'],
        'enabled_by_default': True
    }

    # Human-readable scenario name mappings
    SCENARIO_NAMES = {
        'ssh-bf': 'SSH Brute Force',
        'ssh-slow-bf': 'SSH Slow Brute Force',
        'ssh-bf-custom': 'SSH Brute Force (Custom)',
        'mssql-bf': 'MSSQL Brute Force',
        'mysql-bf': 'MySQL Brute Force',
        'http-probing': 'HTTP Probing',
        'http-crawl-non_statics': 'HTTP Crawling (Non-Statics)',
        'http-sensitive-files': 'HTTP Sensitive Files Access',
        'http-bad-user-agent': 'HTTP Bad User Agent',
        'http-admin-interface-probing': 'HTTP Admin Interface Probing',
        'http-dos-swithcing-ua': 'HTTP DoS (Switching UA)',
        'iptables-scan-multi_ports': 'Port Scan (Multiple Ports)',
        'tcp-scan': 'TCP Port Scan',
        'database:bruteforce': 'Database Brute Force',
        'update': 'Community Blocklist Update'
    }

    def __init__(self, config, blacklist_manager=None):
        """
        Initialize CrowdSec detector.
        
        Args:
            config: Configuration object
            blacklist_manager: Optional BlacklistManager for checking existing IPs
        """
        super().__init__(config, EventType.CROWDSEC_BLOCK)
        self.logger = logging.getLogger(__name__)
        self.blacklist_manager = blacklist_manager
    
    def _get_existing_blocked_ips(self) -> set:
        """
        Get set of already-blocked IP addresses to avoid re-detection.
        
        Returns:
            Set of IP address strings currently in blacklist
        """
        if not self.blacklist_manager:
            return set()
        
        try:
            # Get all blocked IPs from blacklist manager
            all_blocked = self.blacklist_manager.get_all_blacklisted_ips()
            
            # Convert IP objects to strings for comparison
            blocked_strs = set()
            for ip in all_blocked.get('ipv4', set()):
                blocked_strs.add(str(ip))
            for ip in all_blocked.get('ipv6', set()):
                blocked_strs.add(str(ip))
            
            return blocked_strs
            
        except Exception as e:
            self.logger.warning(f"Error fetching existing blacklist: {e}")
            return set()
    
    def detect(self, events) -> List[DetectionResult]:
        """Query CrowdSec for active bans and historical alerts, convert to detections."""
        try:
            # Query active decisions
            blocked_ips = self._get_crowdsec_blocked_ips()
            self.logger.debug(f"Found {len(blocked_ips)} IPs from active decisions")
            
            # Query historical alerts
            alert_ips = self._get_crowdsec_alerts()
            self.logger.debug(f"Found {len(alert_ips)} IPs from historical alerts")
            
            # Merge alerts into blocked_ips (decisions take precedence)
            for ip_str, alert_metadata in alert_ips.items():
                if ip_str not in blocked_ips:
                    blocked_ips[ip_str] = alert_metadata
            
            if not blocked_ips:
                self.logger.debug("No CrowdSec decisions or alerts found")
                return []
            
            self.logger.debug(f"Found {len(blocked_ips)} total IPs from CrowdSec (decisions + alerts)")
            
            # Filter out already-blocked IPs to avoid re-detection
            existing_blocked = self._get_existing_blocked_ips()
            if existing_blocked:
                original_count = len(blocked_ips)
                blocked_ips = {
                    ip: meta for ip, meta in blocked_ips.items() 
                    if ip not in existing_blocked
                }
                filtered_count = original_count - len(blocked_ips)
                
                if filtered_count > 0:
                    self.logger.debug(
                        f"Filtered {filtered_count} already-blocked IPs "
                        f"({len(blocked_ips)} new IPs remain)"
                    )
            
            # If all IPs were already blocked, return empty
            if not blocked_ips:
                self.logger.info("All CrowdSec IPs already in blacklist (no new detections)")
                return []
            
            self.logger.info(f"Found {len(blocked_ips)} NEW IPs from CrowdSec to block")
            
            detections = []
            for ip_str, metadata in blocked_ips.items():
                try:
                    result = self._create_detection_result(
                        ip_str=ip_str,
                        reason=self._format_crowdsec_reason(metadata),
                        confidence='high',
                        event_count=metadata.get('events', 1),
                        source_events=[],
                        first_seen=metadata.get('timestamp'),
                        last_seen=metadata.get('timestamp')
                    )
                    
                    if result:
                        # Add geolocation from CrowdSec data if available
                        if metadata.get('country') or metadata.get('as_name'):
                            result.geolocation = {
                                'country': metadata.get('country', 'Unknown'),
                                'isp': metadata.get('as_name', 'Unknown ISP'),
                                'city': ''  # CrowdSec doesn't provide city
                            }
                        detections.append(result)
                        
                except Exception as e:
                    self.logger.warning(f"Error processing CrowdSec IP {ip_str}: {e}")
                    continue
            
            return detections
            
        except Exception as e:
            self.logger.error(f"CrowdSec detection error: {e}")
            return []
    
    def _get_crowdsec_blocked_ips(self) -> Dict[str, Dict]:
        """
        Query CrowdSec LAPI for active ban decisions with metadata.
        
        FIXED: Properly parse the JSON structure from cscli decisions list -o json
        """
        try:
            result = subprocess.run(
                ['cscli', 'decisions', 'list', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                self.logger.error(f"cscli command failed: {result.stderr}")
                return {}
            
            # Parse JSON response
            try:
                decisions_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse cscli JSON output: {e}")
                return {}
            
            if not decisions_data:
                return {}
            
            # Debug: Log structure
            self.logger.debug(f"CrowdSec returned {len(decisions_data)} decision entries")
            
            blocked_ips = {}
            
            # The JSON is an array of decision objects
            for decision_entry in decisions_data:
                try:
                    # Each entry has a 'decisions' array and a 'source' object
                    decisions_list = decision_entry.get('decisions', [])
                    source = decision_entry.get('source', {})
                    
                    # Get IP from source object
                    ip_str = source.get('ip') or source.get('value', '')
                    
                    if not ip_str:
                        self.logger.debug(f"No IP found in entry: {decision_entry.keys()}")
                        continue
                    
                    # Parse creation timestamp from decision entry
                    created_at = decision_entry.get('created_at') or decision_entry.get('start_at')
                    timestamp = datetime.now(timezone.utc)

                    if created_at:
                        try:
                            if created_at.endswith('Z'):
                                timestamp = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            else:
                                parsed = datetime.fromisoformat(created_at)
                                timestamp = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
                        except (ValueError, AttributeError) as e:
                            self.logger.debug(f"Timestamp parse error for {ip_str}: {e}")
                    
                    # Get decision metadata
                    scenario = decision_entry.get('scenario', 'Unknown')
                    events_count = decision_entry.get('events_count', 1)

                    # Get decision type and duration from decisions array
                    decision_type = 'ban'
                    duration = 'Unknown'
                    if decisions_list:
                        first_decision = decisions_list[0]
                        decision_type = first_decision.get('type', 'ban')
                        duration = first_decision.get('duration', 'Unknown')

                    # Extract geolocation from events metadata
                    country = ''
                    as_number = ''
                    as_name = ''

                    events = decision_entry.get('events', [])
                    if events and len(events) > 0:
                        # Parse meta array from first event
                        meta_list = events[0].get('meta', [])
                        for meta in meta_list:
                            key = meta.get('key', '')
                            value = meta.get('value', '')

                            if key == 'IsoCode':
                                country = value
                            elif key == 'ASNNumber':
                                as_number = value
                            elif key == 'ASNOrg':
                                as_name = value

                    # Format AS info (e.g., "14061 DIGITALOCEAN-ASN")
                    if as_number and as_name:
                        as_info = f"{as_number} {as_name}"
                    elif as_name:
                        as_info = as_name
                    else:
                        as_info = 'Unknown ISP'

                    blocked_ips[ip_str] = {
                        'timestamp': timestamp,
                        'reason': scenario,
                        'events': events_count,
                        'scenario': scenario,
                        'type': decision_type,
                        'duration': duration,
                        'country': country,
                        'as_name': as_info
                    }
                    
                    self.logger.debug(
                        f"Parsed CrowdSec decision: {ip_str} ({scenario}, {events_count} events, "
                        f"{country}, {as_info})"
                    )
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing CrowdSec decision entry: {e}")
                    continue
            
            return blocked_ips
            
        except subprocess.TimeoutExpired:
            self.logger.error("cscli command timed out after 10 seconds")
            return {}
        except FileNotFoundError:
            self.logger.error("cscli command not found - is CrowdSec installed?")
            return {}
        except Exception as e:
            self.logger.error(f"Error querying CrowdSec: {e}")
            return {}
    
    def _get_crowdsec_alerts(self) -> Dict[str, Dict]:
        """
        Query CrowdSec for historical alerts with metadata.
        
        Uses: cscli alerts list -o json
        Extracts: IP, scenario, events, timestamp, country, AS/ISP
        """
        try:
            result = subprocess.run(
                ['cscli', 'alerts', 'list', '-a', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=30  # Alerts can take longer than decisions
            )
            
            if result.returncode != 0:
                self.logger.error(f"cscli alerts command failed: {result.stderr}")
                return {}
            
            # Parse JSON response
            try:
                alerts_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse cscli alerts JSON: {e}")
                return {}
            
            if not alerts_data:
                return {}
            
            self.logger.debug(f"CrowdSec returned {len(alerts_data)} alert entries")
            
            alert_ips = {}
            
            # Parse alert JSON structure
            for alert_entry in alerts_data:
                try:
                    # Get IP from source
                    source = alert_entry.get('source', {})
                    ip_str = source.get('ip') or source.get('value', '')
                    
                    if not ip_str:
                        continue
                    
                    # Remove "Ip:" prefix if present
                    ip_str = ip_str.replace('Ip:', '').strip()
                    
                    # Parse creation timestamp
                    created_at = alert_entry.get('created_at') or alert_entry.get('start_at')
                    timestamp = datetime.now(timezone.utc)

                    if created_at:
                        try:
                            if created_at.endswith('Z'):
                                timestamp = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            else:
                                parsed = datetime.fromisoformat(created_at)
                                timestamp = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
                        except (ValueError, AttributeError) as e:
                            self.logger.debug(f"Alert timestamp parse error for {ip_str}: {e}")
                    
                    # Extract metadata
                    scenario = alert_entry.get('scenario', 'Unknown')
                    events_count = alert_entry.get('events_count', 1)
                    
                    # Extract geolocation data
                    country = source.get('cn', '')  # Country code
                    as_number = source.get('as_number', '')
                    as_name = source.get('as_name', '')
                    
                    # Format AS info (e.g., "18779 EGIHOSTING")
                    if as_number and as_name:
                        as_info = f"{as_number} {as_name}"
                    elif as_name:
                        as_info = as_name
                    else:
                        as_info = 'Unknown ISP'
                    
                    # Get decision info if available
                    decisions = alert_entry.get('decisions', [])
                    decision_type = 'ban'
                    if decisions:
                        decision_type = decisions[0].get('type', 'ban')
                    
                    alert_ips[ip_str] = {
                        'timestamp': timestamp,
                        'reason': scenario,
                        'events': events_count,
                        'scenario': scenario,
                        'type': decision_type,
                        'country': country,
                        'as_name': as_info,
                        'source': 'alert'  # Mark as from alerts vs decisions
                    }
                    
                    self.logger.debug(
                        f"Parsed CrowdSec alert: {ip_str} ({scenario}, {events_count} events, "
                        f"{country}, {as_info})"
                    )
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing CrowdSec alert entry: {e}")
                    continue
            
            return alert_ips
            
        except subprocess.TimeoutExpired:
            self.logger.error("cscli alerts command timed out after 30 seconds")
            return {}
        except FileNotFoundError:
            self.logger.error("cscli command not found - is CrowdSec installed?")
            return {}
        except Exception as e:
            self.logger.error(f"Error querying CrowdSec alerts: {e}")
            return {}
    
    def _format_crowdsec_reason(self, metadata: Dict) -> str:
        """Format human-readable blocking reason from CrowdSec metadata."""
        scenario = metadata.get('scenario', 'Unknown')
        events = metadata.get('events', 1)

        # Remove 'crowdsecurity/' prefix if present
        scenario_key = scenario.replace('crowdsecurity/', '')

        # Look up human-readable name from mapping
        if scenario_key in self.SCENARIO_NAMES:
            scenario_name = self.SCENARIO_NAMES[scenario_key]
        else:
            # Fallback: capitalize and replace hyphens with spaces
            scenario_name = scenario_key.replace('-', ' ').replace('_', ' ').title()

        return f"CrowdSec: {scenario_name} ({events} events)"
    
    def enrich_from_historical_alerts(self, existing_ips: set) -> Dict[str, Dict]:
        """
        Query CrowdSec historical alerts and return ALL alert IPs with metadata.
        
        Returns both:
        - IPs already in blacklist (for enrichment)
        - NEW IPs not in blacklist (for import)
        
        Fetches from CrowdSec alerts API:
        - Original detection reason (scenario)
        - Event counts
        - Timestamps (created_at)
        - Geolocation (country, AS/ISP)
        
        Uses: cscli alerts list -o json
        
        Args:
            existing_ips: Set of IP strings currently in blacklist (used for logging only)
            
        Returns:
            Dict of metadata for ALL alert IPs (existing + new):
            {
                '1.2.3.4': {
                    'ip': IPv4Address('1.2.3.4'),
                    'reason': 'CrowdSec: ...',
                    'confidence': 'high',
                    'event_count': 5,
                    'first_seen': datetime(...),
                    'last_seen': datetime(...),
                    'geolocation': {'country': 'US', 'isp': '...'},
                    'source': 'crowdsec_alerts'
                }
            }
        """
        try:
            # Query historical alerts
            alert_ips = self._get_crowdsec_alerts()
            
            if not alert_ips:
                self.logger.debug("No CrowdSec historical alerts found")
                return {}
            
            # Process ALL alert IPs (not just existing ones)
            enrichment_data = {}
            new_ips_count = 0
            
            for ip_str, alert_metadata in alert_ips.items():
                # Track if this is a new import or enrichment
                if ip_str not in existing_ips:
                    new_ips_count += 1
                
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    
                    # Build enrichment metadata
                    enrichment_data[ip_str] = {
                        'ip': ip_obj,
                        'reason': self._format_crowdsec_reason(alert_metadata),
                        'confidence': 'high',
                        'event_count': alert_metadata.get('events', 1),
                        'first_seen': alert_metadata.get('timestamp'),
                        'last_seen': alert_metadata.get('timestamp'),
                        'date_added': alert_metadata.get('timestamp'),
                        'source': 'crowdsec_alerts'
                    }
                    
                    # Add geolocation if available
                    if alert_metadata.get('country') or alert_metadata.get('as_name'):
                        enrichment_data[ip_str]['geolocation'] = {
                            'country': alert_metadata.get('country', 'Unknown'),
                            'isp': alert_metadata.get('as_name', 'Unknown ISP'),
                            'city': ''
                        }
                    
                except ValueError as e:
                    self.logger.warning(f"Invalid IP in CrowdSec alerts: {ip_str}: {e}")
                    continue
            
            if enrichment_data:
                existing_count = len(enrichment_data) - new_ips_count
                self.logger.info(
                    f"Found metadata for {len(enrichment_data)} IPs from CrowdSec alerts "
                    f"({new_ips_count} new, {existing_count} existing)"
                )
            
            return enrichment_data

        except Exception as e:
            self.logger.error(f"Error enriching from CrowdSec alerts: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {}

    def import_from_csv(self, csv_file_path: str) -> Dict[str, Dict]:
        """
        Import CrowdSec decisions from CSV export file.

        This method replaces untrusted blacklist data with accurate CrowdSec metadata.

        CSV Format (from cscli decisions list -o csv):
            startAt,scenario,sourceIp,sourceAs,sourceCountry
            2025-11-01T00:55:18.588Z,crowdsecurity/ssh-bf,171.243.151.74,Viettel Group,VN

        Args:
            csv_file_path: Path to CrowdSec CSV export file

        Returns:
            Dict mapping IP to metadata:
            {
                '1.2.3.4': {
                    'ip': IPv4Address('1.2.3.4'),
                    'reason': 'CrowdSec: SSH Brute Force (1 events)',
                    'confidence': 'high',
                    'event_count': 1,
                    'first_seen': datetime(...),
                    'last_seen': datetime(...),
                    'geolocation': {'country': 'US', 'isp': 'ISP Name'},
                    'source': 'crowdsec_csv_import'
                }
            }
        """
        csv_path = Path(csv_file_path)
        if not csv_path.exists():
            self.logger.error(f"CSV file not found: {csv_file_path}")
            return {}

        imported_data = {}
        skipped_count = 0

        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        # Extract fields from CSV
                        ip_str = row.get('sourceIp', '').strip()
                        scenario = row.get('scenario', '').strip()
                        as_name = row.get('sourceAs', '').strip()
                        country = row.get('sourceCountry', '').strip()
                        start_at = row.get('startAt', '').strip()

                        # Validate IP
                        if not ip_str:
                            skipped_count += 1
                            continue

                        try:
                            ip_obj = ipaddress.ip_address(ip_str)
                        except ValueError:
                            self.logger.warning(f"Invalid IP in CSV: {ip_str}")
                            skipped_count += 1
                            continue

                        # Parse timestamp (ensure timezone-aware for consistent comparisons)
                        timestamp = datetime.now(timezone.utc)
                        if start_at:
                            try:
                                if start_at.endswith('Z'):
                                    timestamp = datetime.fromisoformat(start_at.replace('Z', '+00:00'))
                                else:
                                    # If no timezone in CSV, assume UTC
                                    parsed = datetime.fromisoformat(start_at)
                                    if parsed.tzinfo is None:
                                        timestamp = parsed.replace(tzinfo=timezone.utc)
                                    else:
                                        timestamp = parsed
                            except (ValueError, AttributeError) as e:
                                self.logger.debug(f"CSV timestamp parse error for {ip_str}: {e}")

                        # Build metadata dict
                        metadata = {
                            'scenario': scenario,
                            'events': 1  # CSV doesn't provide event count
                        }

                        imported_data[ip_str] = {
                            'ip': ip_obj,
                            'reason': self._format_crowdsec_reason(metadata),
                            'confidence': 'high',
                            'event_count': 1,
                            'first_seen': timestamp,
                            'last_seen': timestamp,
                            'date_added': timestamp,
                            'source': 'crowdsec_csv_import'
                        }

                        # Add geolocation if available
                        if country or as_name:
                            imported_data[ip_str]['geolocation'] = {
                                'country': country if country else 'Unknown',
                                'isp': as_name if as_name else 'Unknown ISP',
                                'city': ''
                            }

                    except Exception as e:
                        self.logger.warning(f"Error parsing CSV row: {e}")
                        skipped_count += 1
                        continue

            if imported_data:
                self.logger.info(
                    f"Imported {len(imported_data)} IPs from CrowdSec CSV "
                    f"(skipped {skipped_count} invalid entries)"
                )
            else:
                self.logger.warning(f"No valid IPs found in CSV file: {csv_file_path}")

            return imported_data

        except Exception as e:
            self.logger.error(f"Error reading CSV file {csv_file_path}: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {}