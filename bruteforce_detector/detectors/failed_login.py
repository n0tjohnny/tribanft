"""
TribanFT Failed Login Detector

Detects failed login bruteforce attempts.

Monitors authentication failures from various services:
- MSSQL login failures
- SSH authentication failures
- System authentication failures

Detection criteria:
- Multiple failed attempts from same IP
- Within configured time window
- Exceeds threshold count

Author: TribanFT Project
License: GNU GPL v3
"""

import ipaddress
from collections import defaultdict
from typing import List
from datetime import datetime

from .base import BaseDetector
from ..models import DetectionResult, SecurityEvent, EventType


class FailedLoginDetector(BaseDetector):
    """
    Detects failed login bruteforce patterns.
    
    Analyzes authentication failure events to identify brute force attacks.
    """
    
    def __init__(self, config):
        """Initialize failed login detector with configuration."""
        super().__init__(config, EventType.FAILED_LOGIN)
        self.threshold = config.failed_login_threshold
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze failed login events and detect bruteforce patterns.
        
        Groups events by IP and counts occurrences within time window.
        
        Args:
            events: List of SecurityEvent objects (filtered for FAILED_LOGIN)
            
        Returns:
            List of DetectionResult for IPs exceeding threshold
        """
        # Group events by source IP
        events_by_ip = defaultdict(list)
        for event in events:
            if event.event_type == EventType.FAILED_LOGIN:
                events_by_ip[event.source_ip].append(event)
        
        detections = []
        
        # Analyze each IP's activity
        for ip_str, ip_events in events_by_ip.items():
            event_count = len(ip_events)
            
            # Check if exceeds threshold
            if event_count >= self.threshold:
                # Determine service being attacked
                services = set()
                for event in ip_events:
                    if 'mssql' in event.raw_log.lower() or 'sql' in event.raw_log.lower():
                        services.add('MSSQL')
                    elif 'ssh' in event.raw_log.lower():
                        services.add('SSH')
                    else:
                        services.add('System')
                
                service_str = '/'.join(services) if services else 'Unknown'
                
                # Use helper to create result with guaranteed timestamps
                result = self._create_detection_result(
                    ip_str=ip_str,
                    reason=f"Failed login bruteforce detected on {service_str} - {event_count} attempts",
                    confidence='high' if event_count >= self.threshold * 2 else 'medium',
                    event_count=event_count,
                    source_events=ip_events
                )
                
                if result:
                    detections.append(result)
        
        return detections