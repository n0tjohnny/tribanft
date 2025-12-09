"""
TribanFT Port Scan Detector

Detects port scanning activity.

Identifies reconnaissance attempts by monitoring:
- Connection attempts to multiple ports
- Rapid sequential connections
- Firewall drop patterns

Detection criteria:
- Multiple port access attempts from same IP
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


class PortScanDetector(BaseDetector):
    """
    Detects port scanning reconnaissance activity.
    
    Analyzes connection patterns for scanning behavior.
    """
    
    def __init__(self, config):
        """Initialize port scan detector with configuration."""
        super().__init__(config, EventType.PORT_SCAN)
        self.threshold = config.port_scan_threshold
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze port access events and detect scanning patterns.
        
        Groups events by IP and counts occurrences within time window.
        
        Args:
            events: List of SecurityEvent objects (filtered for PORT_SCAN)
            
        Returns:
            List of DetectionResult for IPs exceeding threshold
        """
        # Group events by source IP
        events_by_ip = defaultdict(list)
        for event in events:
            if event.event_type == EventType.PORT_SCAN:
                events_by_ip[event.source_ip].append(event)
        
        detections = []
        
        # Analyze each IP's activity
        for ip_str, ip_events in events_by_ip.items():
            event_count = len(ip_events)
            
            # Check if exceeds threshold
            if event_count >= self.threshold:
                # Identify unique ports if available
                ports = set()
                for event in ip_events:
                    if hasattr(event, 'destination_port') and event.destination_port:
                        ports.add(event.destination_port)
                
                if ports:
                    port_info = f"{len(ports)} ports" if len(ports) > 1 else f"port {list(ports)[0]}"
                else:
                    port_info = "multiple ports"
                
                # Use helper to create result with guaranteed timestamps
                result = self._create_detection_result(
                    ip_str=ip_str,
                    reason=f"Port scan detected - {event_count} attempts on {port_info}",
                    confidence='high' if event_count >= self.threshold * 2 else 'medium',
                    event_count=event_count,
                    source_events=ip_events
                )
                
                if result:
                    detections.append(result)
        
        return detections