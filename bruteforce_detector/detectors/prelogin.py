"""
TribanFT Prelogin Brute Force Detector

Detects MSSQL reconnaissance attacks via invalid prelogin packets.

Attack pattern:
Attackers send malformed prelogin packets to MSSQL servers to probe for
vulnerabilities or gather information. These appear in logs as "prelogin packet
used to open a connection" errors.

Detection logic:
- Counts prelogin events per IP within time window
- Triggers when threshold exceeded (default: 20 events in 7 days)
- High confidence - strong indicator of automated attack
- Uses timestamp helper to guarantee proper first_seen/last_seen

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import List
from datetime import datetime
from collections import defaultdict
import logging

from .base import BaseDetector
from ..models import SecurityEvent, DetectionResult, DetectionConfidence, EventType
from ..config import get_config


class PreloginDetector(BaseDetector):
    """
    Detects MSSQL prelogin brute force attacks.
    
    This detector identifies reconnaissance attempts where attackers send
    invalid prelogin packets to probe MSSQL servers.
    """
    
    def __init__(self, whitelist_manager):
        """
        Initialize prelogin detector.
        
        Args:
            whitelist_manager: WhitelistManager instance for filtering trusted IPs
        """
        super().__init__("prelogin_detector", whitelist_manager)
        self.enabled = get_config().enable_prelogin_detection
        self.logger = logging.getLogger(__name__)
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze events and identify prelogin brute force attacks.
        
        Process:
        1. Filter for prelogin-type events
        2. Remove whitelisted IPs
        3. Apply time window filtering
        4. Group by IP and count events
        5. Create DetectionResult for IPs exceeding threshold
        
        Args:
            events: List of SecurityEvent objects from log parsers
            
        Returns:
            List of DetectionResult objects for detected threats
        """
        if not self.enabled:
            return []
        
        # Filter for prelogin events only
        prelogin_events = [e for e in events if e.event_type == EventType.PRELOGIN_INVALID]
        self.logger.info(f"Total prelogin events: {len(prelogin_events)}")
        
        # Remove whitelisted IPs
        filtered_events = self.filter_whitelisted(prelogin_events)
        self.logger.info(f"After whitelist filtering: {len(filtered_events)} events")
        
        # Apply time window
        recent_events = self.calculate_time_window_events(
            filtered_events, get_config().time_window_minutes
        )
        self.logger.info(
            f"After time window filtering ({get_config().time_window_minutes}min): "
            f"{len(recent_events)} events"
        )
        
        # Group by IP and check thresholds
        results = []
        grouped_events = self.group_events_by_ip(recent_events)
        self.logger.info(f"Grouped into {len(grouped_events)} unique IPs")
        
        for ip_str, ip_events in grouped_events.items():
            event_count = len(ip_events)
            threshold = get_config().prelogin_pattern_threshold
            self.logger.info(f"IP {ip_str}: {event_count} events (threshold: {threshold})")
            
            if event_count >= threshold:
                self.logger.warning(
                    f"🚨 DETECTION: {ip_str} exceeded threshold with "
                    f"{event_count} prelogin invalid packets"
                )
                
                # Use helper method to create result with guaranteed timestamps
                results.append(self._create_detection_result(
                    ip_events=ip_events,
                    reason=f"Prelogin brute force detected: {event_count} invalid packets",
                    confidence=DetectionConfidence.HIGH
                ))
        
        return results