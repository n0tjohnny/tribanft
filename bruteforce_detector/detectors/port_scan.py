"""
TribanFT Port Scan Detector

Detects port scanning activity from attackers probing for open services.

Attack pattern:
Attackers systematically probe multiple ports on target systems to identify
vulnerable services. These attempts are logged by firewalls and intrusion detection systems.

Detection logic:
- Counts port scan events per IP within time window
- Triggers when threshold exceeded (default: 20 events in 7 days)
- Medium confidence - automated scanning tools generate distinctive patterns

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import List
from .base import BaseDetector
from ..models import SecurityEvent, DetectionResult, DetectionConfidence, EventType
from ..config import config


class PortScanDetector(BaseDetector):
    """Detects port scanning activity"""
    
    def __init__(self, whitelist_manager):
        """
        Initialize port scan detector.
        
        Args:
            whitelist_manager: WhitelistManager for filtering trusted IPs
        """
        super().__init__("port_scan_detector", whitelist_manager)
        self.enabled = config.enable_port_scan_detection
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze events and identify port scanning attacks.
        
        Args:
            events: List of SecurityEvent objects from log parsers
            
        Returns:
            List of DetectionResult objects for detected threats
        """
        if not self.enabled:
            return []
        
        port_scan_events = [e for e in events if e.event_type == EventType.PORT_SCAN]
        filtered_events = self.filter_whitelisted(port_scan_events)
        recent_events = self.calculate_time_window_events(
            filtered_events, config.time_window_minutes
        )
        
        results = []
        grouped_events = self.group_events_by_ip(recent_events)
        
        for ip_str, ip_events in grouped_events.items():
            if len(ip_events) >= config.port_scan_threshold:
                results.append(DetectionResult(
                    ip=ip_events[0].source_ip,
                    reason=f"Port scan detected: {len(ip_events)} scan attempts",
                    confidence=DetectionConfidence.MEDIUM,
                    event_count=len(ip_events),
                    source_events=ip_events,
                    first_seen=min(e.timestamp for e in ip_events),
                    last_seen=max(e.timestamp for e in ip_events)
                ))
        
        return results