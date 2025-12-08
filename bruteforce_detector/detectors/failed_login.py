"""
TribanFT Failed Login Detector

Detects brute force attacks through failed login attempts.

Attack pattern:
Attackers attempt multiple authentication failures to gain unauthorized access
through credential guessing or dictionary attacks.

Detection logic:
- Counts failed login events per IP within time window
- Triggers when threshold exceeded (default: 20 events in 7 days)
- High confidence - strong indicator of brute force attack

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import List
from datetime import datetime
import ipaddress
import logging

from .base import BaseDetector
from ..models import SecurityEvent, DetectionResult, DetectionConfidence, EventType
from ..config import get_config


class FailedLoginDetector(BaseDetector):
    """Detects failed login attempts from MSSQL logs"""
    
    def __init__(self, whitelist_manager):
        """
        Initialize failed login detector.
        
        Args:
            whitelist_manager: WhitelistManager for filtering trusted IPs
        """
        super().__init__("failed_login_detector", whitelist_manager)
        self.config = get_config()
        self.enabled = self.config.enable_failed_login_detection
        self.logger = logging.getLogger(__name__)
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze events and identify failed login brute force attacks.
        
        Process:
        1. Filter for failed login events
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
        
        # Filter for failed login events only
        failed_login_events = [e for e in events if e.event_type == EventType.FAILED_LOGIN]
        self.logger.info(f"Total failed login events: {len(failed_login_events)}")
        
        filtered_events = self.filter_whitelisted(failed_login_events)
        self.logger.info(f"After whitelist filtering: {len(filtered_events)} events")
        
        # Apply time window
        recent_events = self.calculate_time_window_events(
            filtered_events, self.config.time_window_minutes
        )
        self.logger.info(f"After time window filtering ({self.config.time_window_minutes}min): {len(recent_events)} events")
        
        # Group by IP and check thresholds
        results = []
        grouped_events = self.group_events_by_ip(recent_events)
        self.logger.info(f"Grouped into {len(grouped_events)} unique IPs")
        
        for ip_str, ip_events in grouped_events.items():
            event_count = len(ip_events)
            threshold = self.config.failed_login_threshold
            self.logger.info(f"IP {ip_str}: {event_count} events (threshold: {threshold})")
            
            if event_count >= threshold:
                self.logger.warning(f"🚨 DETECTION: {ip_str} exceeded threshold with {event_count} failed logins")
                results.append(DetectionResult(
                    ip=ip_events[0].source_ip,
                    reason=f"Failed login brute force detected: {event_count} failed logins",
                    confidence=DetectionConfidence.HIGH,
                    event_count=event_count,
                    source_events=ip_events,
                    first_seen=min(e.timestamp for e in ip_events),
                    last_seen=max(e.timestamp for e in ip_events)
                ))
        
        return results