"""
TribanFT Threat Feed Detector

Integrates with external threat intelligence feeds to detect known malicious IPs:
- AbuseIPDB: Community-driven IP abuse database
- Spamhaus DROP/EDROP: Known spam/malware sources
- AlienVault OTX: Open Threat Exchange indicators

Caches results to minimize API calls and respect rate limits.
"""

import logging
import ipaddress
import json
import time
from typing import List, Dict, Optional, Set
from datetime import datetime, timezone, timedelta
from pathlib import Path

from ...detectors.base import BaseDetector
from ...models import DetectionResult, EventType


class ThreatFeedDetector(BaseDetector):
    """Detector for known malicious IPs from threat intelligence feeds."""

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'threat_feed_detector',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Integrates with threat feeds (AbuseIPDB, Spamhaus, AlienVault OTX)',
        'dependencies': ['config', 'blacklist_manager'],
        'enabled_by_default': False  # Disabled by default (requires API keys)
    }

    # Supported threat feed sources
    SUPPORTED_FEEDS = {
        'abuseipdb': 'AbuseIPDB API',
        'spamhaus': 'Spamhaus DROP/EDROP lists',
        'alienvault': 'AlienVault OTX API'
    }

    def __init__(self, config, blacklist_manager=None):
        """
        Initialize threat feed detector.

        Args:
            config: Configuration object
            blacklist_manager: Optional BlacklistManager for checking existing IPs
        """
        super().__init__(config, EventType.KNOWN_MALICIOUS_IP)
        self.logger = logging.getLogger(__name__)
        self.blacklist_manager = blacklist_manager

        # Load configuration
        self.enabled = getattr(config, 'threat_feeds_enabled', False)
        self.feed_sources = self._parse_feed_sources(
            getattr(config, 'threat_feed_sources', 'spamhaus')
        )
        self.cache_hours = getattr(config, 'threat_feed_cache_hours', 24)

        # API key file paths
        config_dir = Path(getattr(config, 'config_dir', '~/.local/share/tribanft')).expanduser()
        self.abuseipdb_key_file = config_dir / 'abuseipdb_key.txt'

        # Cache file location
        state_dir = Path(getattr(config, 'state_dir', '~/.local/share/tribanft')).expanduser()
        self.cache_file = state_dir / 'threat_feed_cache.json'

        # In-memory cache
        self.cache: Dict[str, Dict] = self._load_cache()

        if not self.enabled:
            self.logger.debug("Threat feed detector is disabled (set threat_feeds_enabled=true to enable)")
        else:
            self.logger.info(f"Threat feed detector enabled with sources: {', '.join(self.feed_sources)}")

    def _parse_feed_sources(self, sources_str: str) -> List[str]:
        """Parse comma-separated feed sources from config."""
        if not sources_str:
            return []

        sources = [s.strip().lower() for s in sources_str.split(',')]

        # Validate sources
        valid_sources = []
        for source in sources:
            if source in self.SUPPORTED_FEEDS:
                valid_sources.append(source)
            else:
                self.logger.warning(
                    f"Unknown threat feed source '{source}' (supported: {', '.join(self.SUPPORTED_FEEDS.keys())})"
                )

        return valid_sources

    def _load_cache(self) -> Dict[str, Dict]:
        """Load threat feed cache from disk."""
        if not self.cache_file.exists():
            return {}

        try:
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)

            # Filter expired entries
            current_time = time.time()
            cache_expiry = self.cache_hours * 3600

            valid_cache = {}
            for ip_str, data in cache_data.items():
                timestamp = data.get('cached_at', 0)
                if current_time - timestamp < cache_expiry:
                    valid_cache[ip_str] = data

            self.logger.debug(f"Loaded {len(valid_cache)} cached threat feed entries")
            return valid_cache

        except Exception as e:
            self.logger.error(f"Error loading threat feed cache: {e}")
            return {}

    def _save_cache(self):
        """Save threat feed cache to disk."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)

            self.logger.debug(f"Saved {len(self.cache)} entries to threat feed cache")

        except Exception as e:
            self.logger.error(f"Error saving threat feed cache: {e}")

    def _get_existing_blocked_ips(self) -> Set[str]:
        """Get set of already-blocked IP addresses to avoid re-detection."""
        if not self.blacklist_manager:
            return set()

        try:
            all_blocked = self.blacklist_manager.get_all_blacklisted_ips()

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
        """Query threat feeds for known malicious IPs."""
        if not self.enabled:
            return []

        if not self.feed_sources:
            self.logger.warning("No threat feed sources configured")
            return []

        try:
            malicious_ips = {}

            # Query each enabled feed source
            for source in self.feed_sources:
                if source == 'spamhaus':
                    ips = self._query_spamhaus()
                    malicious_ips.update(ips)
                elif source == 'abuseipdb':
                    ips = self._query_abuseipdb()
                    malicious_ips.update(ips)
                elif source == 'alienvault':
                    ips = self._query_alienvault()
                    malicious_ips.update(ips)

            if not malicious_ips:
                self.logger.debug("No malicious IPs found from threat feeds")
                return []

            self.logger.debug(f"Found {len(malicious_ips)} IPs from threat feeds")

            # Filter out already-blocked IPs
            existing_blocked = self._get_existing_blocked_ips()
            if existing_blocked:
                original_count = len(malicious_ips)
                malicious_ips = {
                    ip: meta for ip, meta in malicious_ips.items()
                    if ip not in existing_blocked
                }
                filtered_count = original_count - len(malicious_ips)

                if filtered_count > 0:
                    self.logger.debug(
                        f"Filtered {filtered_count} already-blocked IPs "
                        f"({len(malicious_ips)} new IPs remain)"
                    )

            if not malicious_ips:
                self.logger.info("All threat feed IPs already in blacklist")
                return []

            self.logger.info(f"Found {len(malicious_ips)} NEW malicious IPs from threat feeds")

            # Create detections
            detections = []
            for ip_str, metadata in malicious_ips.items():
                try:
                    result = self._create_detection_result(
                        ip_str=ip_str,
                        reason=metadata.get('reason', 'Known malicious IP from threat feed'),
                        confidence='high',
                        event_count=metadata.get('abuse_score', 1),
                        source_events=[],
                        first_seen=metadata.get('first_seen'),
                        last_seen=metadata.get('last_seen')
                    )

                    if result:
                        # Add threat feed metadata
                        if metadata.get('country') or metadata.get('isp'):
                            result.geolocation = {
                                'country': metadata.get('country', 'Unknown'),
                                'isp': metadata.get('isp', 'Unknown ISP'),
                                'city': metadata.get('city', '')
                            }
                        detections.append(result)

                except Exception as e:
                    self.logger.warning(f"Error processing threat feed IP {ip_str}: {e}")
                    continue

            # Save updated cache
            self._save_cache()

            return detections

        except Exception as e:
            self.logger.error(f"Threat feed detection error: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return []

    def _query_spamhaus(self) -> Dict[str, Dict]:
        """
        Query Spamhaus DROP/EDROP lists for known malicious IPs.

        Spamhaus DROP (Don't Route Or Peer) lists are publicly available
        at https://www.spamhaus.org/drop/

        Returns:
            Dict mapping IP to metadata
        """
        self.logger.debug("Querying Spamhaus DROP/EDROP lists")

        malicious_ips = {}

        # Spamhaus DROP/EDROP are text files with CIDR ranges
        # Format: <CIDR> ; SBL<number>
        # Example: 1.10.16.0/20 ; SBL12345

        # For initial implementation, we'll return cached entries
        # Real implementation would download from:
        # - https://www.spamhaus.org/drop/drop.txt (IPv4)
        # - https://www.spamhaus.org/drop/edrop.txt (IPv4 extended)
        # - https://www.spamhaus.org/drop/dropv6.txt (IPv6)

        # Check cache for Spamhaus entries
        for ip_str, data in self.cache.items():
            if data.get('source') == 'spamhaus':
                malicious_ips[ip_str] = data

        # TODO: Implement actual Spamhaus DROP/EDROP download and parsing
        # This would require:
        # 1. Download text files via HTTP
        # 2. Parse CIDR ranges
        # 3. Cache individual IPs or ranges
        # 4. Update cache timestamp

        if not malicious_ips:
            self.logger.debug("No Spamhaus entries in cache (download not yet implemented)")

        return malicious_ips

    def _query_abuseipdb(self) -> Dict[str, Dict]:
        """
        Query AbuseIPDB API for known malicious IPs.

        Requires API key in config_dir/abuseipdb_key.txt
        Free tier: 1,000 checks/day

        Returns:
            Dict mapping IP to metadata
        """
        self.logger.debug("AbuseIPDB integration not yet implemented")

        # Check for API key
        if not self.abuseipdb_key_file.exists():
            self.logger.warning(
                f"AbuseIPDB API key not found at {self.abuseipdb_key_file}. "
                "Create this file with your API key to enable AbuseIPDB integration."
            )
            return {}

        # TODO: Implement AbuseIPDB API integration
        # This would require:
        # 1. Read API key from file
        # 2. Make HTTP requests to https://api.abuseipdb.com/api/v2/blacklist
        # 3. Parse JSON response
        # 4. Cache results with timestamp
        # 5. Respect rate limits (1,000/day for free tier)

        return {}

    def _query_alienvault(self) -> Dict[str, Dict]:
        """
        Query AlienVault OTX (Open Threat Exchange) for known malicious IPs.

        AlienVault OTX provides free threat intelligence indicators.

        Returns:
            Dict mapping IP to metadata
        """
        self.logger.debug("AlienVault OTX integration not yet implemented")

        # TODO: Implement AlienVault OTX API integration
        # This would require:
        # 1. Register for OTX API key
        # 2. Make HTTP requests to OTX API
        # 3. Parse JSON response for malicious IPs
        # 4. Cache results with timestamp

        return {}

    def add_to_cache(self, ip_str: str, metadata: Dict):
        """
        Manually add an IP to the threat feed cache.

        Useful for testing or manual threat feed imports.

        Args:
            ip_str: IP address string
            metadata: Dict with keys: reason, abuse_score, country, isp, source
        """
        metadata['cached_at'] = time.time()
        self.cache[ip_str] = metadata
        self._save_cache()
        self.logger.debug(f"Added {ip_str} to threat feed cache")
