from typing import List
from .base import BaseDetector
from ..models import SecurityEvent, DetectionResult, DetectionConfidence, EventType
from ..config import config

class PortScanDetector(BaseDetector):
    """Detects port scanning activity"""
    
    def __init__(self, whitelist_manager):
        super().__init__("port_scan_detector", whitelist_manager)
        self.enabled = config.enable_port_scan_detection
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
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