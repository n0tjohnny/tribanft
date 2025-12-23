"""
TribanFT Prelogin Bruteforce Detector

Detects MSSQL prelogin bruteforce attacks.

Identifies rapid prelogin connection attempts indicating automated
scanning or brute force tools targeting MSSQL servers.

Detection criteria:
- Multiple prelogin events from same IP
- Within configured time window
- Exceeds threshold count

Author: TribanFT Project
License: GNU GPL v3
"""

import ipaddress
from collections import defaultdict
from typing import List
from datetime import datetime

from ...detectors.base import BaseDetector
from ...models import DetectionResult, SecurityEvent, EventType


class PreloginDetector(BaseDetector):
    """
    Detects MSSQL prelogin bruteforce attempts.

    Analyzes prelogin events for patterns indicating automated attacks.
    """

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'prelogin_detector',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Detects MSSQL prelogin bruteforce attacks',
        'dependencies': ['config'],
        'enabled_by_default': True
    }

    def __init__(self, config):
        """Initialize prelogin detector with configuration."""
        super().__init__(config, EventType.PRELOGIN_INVALID)
        self.threshold = config.prelogin_pattern_threshold
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze prelogin events and detect bruteforce patterns.
        
        Groups events by IP and counts occurrences within time window.
        
        Args:
            events: List of SecurityEvent objects (filtered for PRELOGIN_INVALID)
            
        Returns:
            List of DetectionResult for IPs exceeding threshold
        """
        # Group events by source IP
        events_by_ip = defaultdict(list)
        for event in events:
            if event.event_type == EventType.PRELOGIN_INVALID:
                events_by_ip[event.source_ip].append(event)
        
        detections = []
        
        # Analyze each IP's activity
        for ip_str, ip_events in events_by_ip.items():
            event_count = len(ip_events)
            
            # Check if exceeds threshold
            if event_count >= self.threshold:
                # Use helper to create result with guaranteed timestamps
                result = self._create_detection_result(
                    ip_str=ip_str,
                    reason=f"MSSQL prelogin bruteforce detected - {event_count} attempts",
                    confidence='high' if event_count >= self.threshold * 2 else 'medium',
                    event_count=event_count,
                    source_events=ip_events
                )
                
                if result:
                    detections.append(result)
        
        return detections